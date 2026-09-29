package agent

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
)

func wsTestCommand(t *testing.T) []byte {
	t.Helper()
	envelope := protocol.CommandEnvelope{
		Version: protocol.CurrentVersion,
		RequestID: "req-reconnect",
		DeviceID: "device-test",
		SessionID: "session-test",
		IssuedAt: time.Now().Unix(),
		ExpiresAt: time.Now().Add(time.Minute).Unix(),
		Nonce: "nonce-reconnect",
		Tool: "filesystem.read",
		Arguments: json.RawMessage(`{"path":"note.txt"}`),
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	data, err := protocol.EncodeStreamMessage(protocol.StreamMessage{
		Version: protocol.StreamVersion,
		Type: protocol.StreamTypeCommand,
		RequestID: envelope.RequestID,
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func TestWebSocketTransportReconnectsWithBoundedBackoff(t *testing.T) {
	var attempts atomic.Int32
	message := wsTestCommand(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasSuffix(r.URL.Path, "/v1/devices/device-test/stream") {
			http.NotFound(w, r)
			return
		}
		if r.Header.Get("Authorization") != "Bearer session-token" {
			http.Error(w, "unauthorized", http.StatusUnauthorized)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		if attempts.Add(1) == 1 {
			_ = conn.Close(websocket.StatusGoingAway, "retry")
			return
		}
		_ = conn.Write(context.Background(), websocket.MessageText, message)
	}))
	defer server.Close()

	transport, err := NewWebSocketTransport(server.URL, WebSocketTransportConfig{
		BackoffMin: time.Millisecond,
		BackoffMax: 5 * time.Millisecond,
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	envelope, ok, err := transport.NextCommand(ctx, "device-test", "session-token", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || envelope.RequestID != "req-reconnect" || attempts.Load() < 2 {
		t.Fatalf("ok=%v envelope=%#v attempts=%d", ok, envelope, attempts.Load())
	}
}

func TestWebSocketTransportDoesNotRetryUnauthorizedHandshake(t *testing.T) {
	var attempts atomic.Int32
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		attempts.Add(1)
		http.Error(w, "unauthorized", http.StatusUnauthorized)
	}))
	defer server.Close()

	transport, err := NewWebSocketTransport(server.URL, WebSocketTransportConfig{
		BackoffMin: time.Millisecond,
		BackoffMax: 5 * time.Millisecond,
		DialTimeout: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = transport.NextCommand(context.Background(), "device-test", "bad-token", time.Hour)
	var relayErr *RelayError
	if !errors.As(err, &relayErr) || relayErr.Status != http.StatusUnauthorized {
		t.Fatalf("err=%v", err)
	}
	if attempts.Load() != 1 {
		t.Fatalf("unauthorized handshake retried %d times", attempts.Load())
	}
}

func TestWebSocketTransportRejectsInvalidBackoffConfig(t *testing.T) {
	if _, err := NewWebSocketTransport("http://127.0.0.1:8787", WebSocketTransportConfig{
		BackoffMin: time.Second,
		BackoffMax: time.Millisecond,
	}); !errors.Is(err, ErrWebSocketTransportConfig) {
		t.Fatalf("err=%v", err)
	}
}
