package controller

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/protocol"
	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

const maxResponseBytes int64 = 4 << 20

var (
	ErrInsecureRelayURL = errors.New("relay URL must use HTTPS unless it is loopback")
	ErrRelayResponse    = errors.New("relay request failed")
)

type RelayError struct {
	Status  int
	Message string
}

func (e *RelayError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%v: HTTP %d", ErrRelayResponse, e.Status)
	}
	return fmt.Sprintf("%v: HTTP %d: %s", ErrRelayResponse, e.Status, e.Message)
}

func (e *RelayError) Unwrap() error { return ErrRelayResponse }

type Client struct {
	base *url.URL
	http *http.Client
	now  func() time.Time
}

type Pairing struct {
	DeviceID   string
	Generation uint64
	PairedAt   time.Time
}

func NewClient(rawURL string, client *http.Client) (*Client, error) {
	u, err := url.Parse(rawURL)
	if err != nil || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, ErrInsecureRelayURL
	}
	if u.Scheme != "https" {
		if u.Scheme != "http" || !loopbackHost(u.Hostname()) {
			return nil, ErrInsecureRelayURL
		}
	}
	u.Path = strings.TrimRight(u.Path, "/")
	if client == nil {
		client = &http.Client{Timeout: 40 * time.Second}
	}
	return &Client{base: u, http: client, now: time.Now}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *Client) endpoint(path string) string {
	copyURL := *c.base
	copyURL.Path = strings.TrimRight(c.base.Path, "/") + path
	return copyURL.String()
}

func (c *Client) doJSON(ctx context.Context, method, path, bearer string, body any, expected int, target any) error {
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			return err
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequestWithContext(ctx, method, c.endpoint(path), reader)
	if err != nil {
		return err
	}
	if bearer != "" {
		req.Header.Set("Authorization", "Bearer "+bearer)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	resp, err := c.http.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
	if err != nil {
		return err
	}
	if int64(len(data)) > maxResponseBytes {
		return fmt.Errorf("%w: response too large", ErrRelayResponse)
	}
	if resp.StatusCode != expected {
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &payload)
		return &RelayError{Status: resp.StatusCode, Message: payload.Error}
	}
	if target != nil && len(data) > 0 {
		if err := json.Unmarshal(data, target); err != nil {
			return fmt.Errorf("%w: invalid response JSON", ErrRelayResponse)
		}
	}
	return nil
}

func (c *Client) RedeemPairing(ctx context.Context, deviceID, code string, controllerPublicKey ed25519.PublicKey) (Pairing, error) {
	body := map[string]any{
		"code": code,
		"controller_public_key": base64.RawURLEncoding.EncodeToString(controllerPublicKey),
	}
	var raw struct {
		DeviceID   string    `json:"device_id"`
		Generation uint64    `json:"generation"`
		PairedAt   time.Time `json:"paired_at"`
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(deviceID)+"/pairing/redeem", "", body, http.StatusCreated, &raw)
	if err != nil {
		return Pairing{}, err
	}
	if raw.DeviceID != deviceID || raw.Generation == 0 {
		return Pairing{}, fmt.Errorf("%w: invalid pairing response", ErrRelayResponse)
	}
	return Pairing{DeviceID: raw.DeviceID, Generation: raw.Generation, PairedAt: raw.PairedAt}, nil
}

func (c *Client) OpenSession(ctx context.Context, pairing Pairing, privateKey ed25519.PrivateKey) (relay.ControllerSession, error) {
	nonce, err := protocol.NewSessionID()
	if err != nil {
		return relay.ControllerSession{}, err
	}
	now := c.now()
	assertion := relay.ControllerAssertion{
		DeviceID: pairing.DeviceID,
		Generation: pairing.Generation,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30 * time.Second).Unix(),
		Nonce: nonce,
	}
	if err := relay.SignControllerAssertion(&assertion, privateKey); err != nil {
		return relay.ControllerSession{}, err
	}
	var session relay.ControllerSession
	err = c.doJSON(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(pairing.DeviceID)+"/controller-session", "", assertion, http.StatusCreated, &session)
	if err != nil {
		return relay.ControllerSession{}, err
	}
	if session.Token == "" || session.DeviceID != pairing.DeviceID || session.Generation != pairing.Generation ||
		session.AgentSessionID == "" || !session.ExpiresAt.After(now) {
		return relay.ControllerSession{}, fmt.Errorf("%w: invalid controller session", ErrRelayResponse)
	}
	return session, nil
}

func (c *Client) QueueTool(ctx context.Context, session relay.ControllerSession, privateKey ed25519.PrivateKey, requestID, tool string, arguments json.RawMessage) error {
	if requestID == "" || tool == "" || len(arguments) == 0 || !json.Valid(arguments) {
		return protocol.ErrInvalidEnvelope
	}
	nonce, err := protocol.NewSessionID()
	if err != nil {
		return err
	}
	now := c.now()
	envelope := protocol.CommandEnvelope{
		Version: protocol.CurrentVersion,
		RequestID: requestID,
		DeviceID: session.DeviceID,
		SessionID: session.AgentSessionID,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Nonce: nonce,
		Tool: tool,
		Arguments: append(json.RawMessage(nil), arguments...),
	}
	if err := envelope.Sign(privateKey); err != nil {
		return err
	}
	body := map[string]any{"request_id": requestID, "payload": envelope}
	return c.doJSON(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(session.DeviceID)+"/commands", session.Token, body, http.StatusAccepted, nil)
}

func (c *Client) WaitResult(ctx context.Context, sessionToken, requestID string) (json.RawMessage, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("/v1/results/"+url.PathEscape(requestID)+"/events"), nil)
	if err != nil {
		return nil, false, err
	}
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return nil, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return nil, false, nil
	}
	if resp.StatusCode != http.StatusOK {
		data, _ := io.ReadAll(io.LimitReader(resp.Body, maxResponseBytes+1))
		var payload struct {
			Error string `json:"error"`
		}
		_ = json.Unmarshal(data, &payload)
		return nil, false, &RelayError{Status: resp.StatusCode, Message: payload.Error}
	}
	if contentType := resp.Header.Get("Content-Type"); !strings.HasPrefix(contentType, "text/event-stream") {
		return nil, false, fmt.Errorf("%w: invalid SSE content type", ErrRelayResponse)
	}

	reader := bufio.NewReader(io.LimitReader(resp.Body, maxResponseBytes+1))
	var event, dataLine string
	var total int64
	for {
		line, readErr := reader.ReadString('\n')
		total += int64(len(line))
		if total > maxResponseBytes {
			return nil, false, fmt.Errorf("%w: response too large", ErrRelayResponse)
		}
		line = strings.TrimRight(line, "\r\n")
		if line == "" {
			break
		}
		if strings.HasPrefix(line, "event:") {
			event = strings.TrimSpace(strings.TrimPrefix(line, "event:"))
		} else if strings.HasPrefix(line, "data:") {
			dataLine = strings.TrimSpace(strings.TrimPrefix(line, "data:"))
		}
		if readErr != nil {
			if !errors.Is(readErr, io.EOF) {
				return nil, false, readErr
			}
			break
		}
	}
	if event != "result" || dataLine == "" {
		return nil, false, fmt.Errorf("%w: malformed SSE result", ErrRelayResponse)
	}
	raw, err := base64.RawURLEncoding.DecodeString(dataLine)
	if err != nil || !json.Valid(raw) {
		return nil, false, fmt.Errorf("%w: invalid result payload", ErrRelayResponse)
	}
	return json.RawMessage(raw), true, nil
}

func (c *Client) WaitResultUntil(ctx context.Context, sessionToken, requestID string, pollInterval time.Duration) (json.RawMessage, error) {
	if pollInterval <= 0 {
		pollInterval = 250 * time.Millisecond
	}
	for {
		result, ok, err := c.WaitResult(ctx, sessionToken, requestID)
		if err != nil {
			return nil, err
		}
		if ok {
			return result, nil
		}
		timer := time.NewTimer(pollInterval)
		select {
		case <-ctx.Done():
			timer.Stop()
			return nil, ctx.Err()
		case <-timer.C:
		}
	}
}

func NewRequestID() (string, error) {
	id, err := protocol.NewSessionID()
	if err != nil {
		return "", err
	}
	return "req-" + strconv.FormatInt(time.Now().UnixMilli(), 36) + "-" + id[:12], nil
}
