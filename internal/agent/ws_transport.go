package agent

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/coder/websocket"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

var ErrWebSocketTransportConfig = errors.New("invalid WebSocket transport configuration")

type WebSocketTransportConfig struct {
	HTTPClient *http.Client
	BackoffMin time.Duration
	BackoffMax time.Duration
	DialTimeout time.Duration
}

type WebSocketTransport struct {
	relay *RelayClient
	wsHTTP *http.Client
	backoffMin time.Duration
	backoffMax time.Duration
	dialTimeout time.Duration

	mu sync.Mutex
	conn *websocket.Conn
	deviceID string
	sessionToken string
}

func NewWebSocketTransport(rawURL string, cfg WebSocketTransportConfig) (*WebSocketTransport, error) {
	relayClient, err := NewRelayClient(rawURL, cfg.HTTPClient)
	if err != nil {
		return nil, err
	}
	if cfg.BackoffMin <= 0 {
		cfg.BackoffMin = 250 * time.Millisecond
	}
	if cfg.BackoffMax <= 0 {
		cfg.BackoffMax = 5 * time.Second
	}
	if cfg.BackoffMax < cfg.BackoffMin {
		return nil, ErrWebSocketTransportConfig
	}
	if cfg.DialTimeout <= 0 {
		cfg.DialTimeout = 10 * time.Second
	}

	wsHTTP := *relayClient.http
	wsHTTP.Timeout = 0
	return &WebSocketTransport{
		relay: relayClient,
		wsHTTP: &wsHTTP,
		backoffMin: cfg.BackoffMin,
		backoffMax: cfg.BackoffMax,
		dialTimeout: cfg.DialTimeout,
	}, nil
}

func (t *WebSocketTransport) DeviceSession(ctx context.Context, assertion relay.DeviceAssertion) (relay.Session, error) {
	session, err := t.relay.DeviceSession(ctx, assertion)
	if err == nil {
		t.closeConnection()
	}
	return session, err
}

func (t *WebSocketTransport) SubmitResult(ctx context.Context, deviceID, sessionToken, requestID string, result any) error {
	return t.relay.SubmitResult(ctx, deviceID, sessionToken, requestID, result)
}

func (t *WebSocketTransport) NextCommand(ctx context.Context, deviceID, sessionToken string, _ time.Duration) (protocol.CommandEnvelope, bool, error) {
	backoff := t.backoffMin
	for {
		conn, err := t.connection(ctx, deviceID, sessionToken)
		if err != nil {
			if !retryableStreamError(err) {
				return protocol.CommandEnvelope{}, false, err
			}
			if err := waitStreamBackoff(ctx, backoff); err != nil {
				return protocol.CommandEnvelope{}, false, err
			}
			backoff = nextStreamBackoff(backoff, t.backoffMax)
			continue
		}

		messageType, data, err := conn.Read(ctx)
		if err != nil {
			t.dropConnection(conn)
			if ctx.Err() != nil {
				return protocol.CommandEnvelope{}, false, ctx.Err()
			}
			if websocket.CloseStatus(err) == websocket.StatusPolicyViolation {
				return protocol.CommandEnvelope{}, false, &RelayError{Status: http.StatusUnauthorized, Message: "device session expired"}
			}
			if err := waitStreamBackoff(ctx, backoff); err != nil {
				return protocol.CommandEnvelope{}, false, err
			}
			backoff = nextStreamBackoff(backoff, t.backoffMax)
			continue
		}
		if messageType != websocket.MessageText {
			t.dropConnection(conn)
			return protocol.CommandEnvelope{}, false, fmt.Errorf("%w: non-text stream message", ErrRelayResponse)
		}
		message, err := protocol.DecodeStreamMessage(data)
		if err != nil {
			t.dropConnection(conn)
			return protocol.CommandEnvelope{}, false, fmt.Errorf("%w: %v", ErrRelayResponse, err)
		}
		envelope, err := decodeRelayCommand(message.RequestID, message.Payload)
		if err != nil {
			t.dropConnection(conn)
			return protocol.CommandEnvelope{}, false, err
		}
		return envelope, true, nil
	}
}

func (t *WebSocketTransport) connection(ctx context.Context, deviceID, sessionToken string) (*websocket.Conn, error) {
	t.mu.Lock()
	if t.conn != nil && t.deviceID == deviceID && t.sessionToken == sessionToken {
		conn := t.conn
		t.mu.Unlock()
		return conn, nil
	}
	old := t.conn
	t.conn = nil
	t.deviceID = ""
	t.sessionToken = ""
	t.mu.Unlock()
	if old != nil {
		_ = old.CloseNow()
	}

	streamURL := t.streamURL(deviceID)
	header := make(http.Header)
	header.Set("Authorization", "Bearer "+sessionToken)
	dialCtx, cancel := context.WithTimeout(ctx, t.dialTimeout)
	conn, response, err := websocket.Dial(dialCtx, streamURL, &websocket.DialOptions{
		HTTPClient: t.wsHTTP,
		HTTPHeader: header,
		CompressionMode: websocket.CompressionDisabled,
	})
	cancel()
	if err != nil {
		if response != nil {
			return nil, &RelayError{Status: response.StatusCode}
		}
		return nil, err
	}
	conn.SetReadLimit(maxRelayResponseBytes)

	t.mu.Lock()
	if t.conn != nil {
		existing := t.conn
		if t.deviceID == deviceID && t.sessionToken == sessionToken {
			t.mu.Unlock()
			_ = conn.CloseNow()
			return existing, nil
		}
		_ = t.conn.CloseNow()
	}
	t.conn = conn
	t.deviceID = deviceID
	t.sessionToken = sessionToken
	t.mu.Unlock()
	return conn, nil
}

func (t *WebSocketTransport) streamURL(deviceID string) string {
	u := *t.relay.base
	if u.Scheme == "https" {
		u.Scheme = "wss"
	} else {
		u.Scheme = "ws"
	}
	u.Path = strings.TrimRight(t.relay.base.Path, "/") + "/v1/devices/" + url.PathEscape(deviceID) + "/stream"
	u.RawQuery = ""
	u.Fragment = ""
	return u.String()
}

func (t *WebSocketTransport) dropConnection(expected *websocket.Conn) {
	t.mu.Lock()
	if t.conn != expected {
		t.mu.Unlock()
		return
	}
	t.conn = nil
	t.deviceID = ""
	t.sessionToken = ""
	t.mu.Unlock()
	_ = expected.CloseNow()
}

func (t *WebSocketTransport) closeConnection() {
	t.mu.Lock()
	conn := t.conn
	t.conn = nil
	t.deviceID = ""
	t.sessionToken = ""
	t.mu.Unlock()
	if conn != nil {
		_ = conn.CloseNow()
	}
}

func retryableStreamError(err error) bool {
	var relayErr *RelayError
	if errors.As(err, &relayErr) {
		return relayErr.Status == http.StatusRequestTimeout ||
			relayErr.Status == http.StatusTooManyRequests ||
			relayErr.Status >= http.StatusInternalServerError
	}
	return true
}

func waitStreamBackoff(ctx context.Context, delay time.Duration) error {
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func nextStreamBackoff(current, maximum time.Duration) time.Duration {
	if current >= maximum {
		return maximum
	}
	next := current * 2
	if next > maximum {
		return maximum
	}
	return next
}
