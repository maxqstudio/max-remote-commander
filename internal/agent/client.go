package agent

import (
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

const maxRelayResponseBytes int64 = 4 << 20

var (
	ErrInsecureRelayURL = errors.New("relay URL must use HTTPS unless it is loopback")
	ErrRelayResponse    = errors.New("relay request failed")
	ErrPairingPending   = errors.New("pairing is still pending")
)

type RelayError struct {
	Status int
	Message string
}

func (e *RelayError) Error() string {
	if e.Message == "" {
		return fmt.Sprintf("%v: HTTP %d", ErrRelayResponse, e.Status)
	}
	return fmt.Sprintf("%v: HTTP %d: %s", ErrRelayResponse, e.Status, e.Message)
}

func (e *RelayError) Unwrap() error { return ErrRelayResponse }

type RelayClient struct {
	base *url.URL
	http *http.Client
}

func NewRelayClient(rawURL string, client *http.Client) (*RelayClient, error) {
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
	return &RelayClient{base: u, http: client}, nil
}

func loopbackHost(host string) bool {
	if strings.EqualFold(host, "localhost") {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func (c *RelayClient) endpoint(path string) string {
	copyURL := *c.base
	copyURL.Path = strings.TrimRight(c.base.Path, "/") + path
	return copyURL.String()
}

func (c *RelayClient) doJSON(ctx context.Context, method, path, bearer string, body any, expected int, target any) error {
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
	limited := io.LimitReader(resp.Body, maxRelayResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return err
	}
	if int64(len(data)) > maxRelayResponseBytes {
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

func (c *RelayClient) BootstrapSession(ctx context.Context, deviceID, registrationKey string) (relay.Session, error) {
	var session relay.Session
	err := c.doJSON(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(deviceID)+"/bootstrap-session", registrationKey, nil, http.StatusCreated, &session)
	return session, err
}

type PairingOfferReceipt struct {
	Token     string    `json:"receipt_token"`
	ExpiresAt time.Time `json:"receipt_expires_at"`
}

func (c *RelayClient) PublishPairingOffer(ctx context.Context, deviceID, sessionToken string, codeHash [32]byte, publicKey ed25519.PublicKey, ttl time.Duration) (PairingOfferReceipt, error) {
	var receipt PairingOfferReceipt
	body := map[string]any{
		"code_hash": base64.RawURLEncoding.EncodeToString(codeHash[:]),
		"device_public_key": base64.RawURLEncoding.EncodeToString(publicKey),
		"ttl_seconds": int64(ttl / time.Second),
	}
	err := c.doJSON(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(deviceID)+"/pairing-offer", sessionToken, body, http.StatusCreated, &receipt)
	return receipt, err
}

type PairingStatus struct {
	DeviceID            string
	Generation          uint64
	ControllerPublicKey ed25519.PublicKey
	PairedAt            time.Time
}

func (c *RelayClient) PairingStatus(ctx context.Context, deviceID, receiptToken string) (PairingStatus, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint("/v1/devices/"+url.PathEscape(deviceID)+"/pairing/status"), nil)
	if err != nil {
		return PairingStatus{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+receiptToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return PairingStatus{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return PairingStatus{}, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBytes+1))
	if err != nil {
		return PairingStatus{}, false, err
	}
	if int64(len(data)) > maxRelayResponseBytes {
		return PairingStatus{}, false, fmt.Errorf("%w: response too large", ErrRelayResponse)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct{ Error string `json:"error"` }
		_ = json.Unmarshal(data, &payload)
		return PairingStatus{}, false, &RelayError{Status: resp.StatusCode, Message: payload.Error}
	}
	var raw struct {
		DeviceID string `json:"device_id"`
		Generation uint64 `json:"generation"`
		ControllerPublicKey string `json:"controller_public_key"`
		PairedAt time.Time `json:"paired_at"`
	}
	if err := json.Unmarshal(data, &raw); err != nil {
		return PairingStatus{}, false, fmt.Errorf("%w: invalid response JSON", ErrRelayResponse)
	}
	key, err := base64.RawURLEncoding.DecodeString(raw.ControllerPublicKey)
	if err != nil || len(key) != ed25519.PublicKeySize {
		return PairingStatus{}, false, fmt.Errorf("%w: invalid controller public key", ErrRelayResponse)
	}
	return PairingStatus{
		DeviceID: raw.DeviceID,
		Generation: raw.Generation,
		ControllerPublicKey: ed25519.PublicKey(key),
		PairedAt: raw.PairedAt,
	}, true, nil
}

func (c *RelayClient) DeviceSession(ctx context.Context, assertion relay.DeviceAssertion) (relay.Session, error) {
	var session relay.Session
	err := c.doJSON(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(assertion.DeviceID)+"/session", "", assertion, http.StatusCreated, &session)
	return session, err
}

func decodeRelayCommand(requestID string, payload json.RawMessage) (protocol.CommandEnvelope, error) {
	var envelope protocol.CommandEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return protocol.CommandEnvelope{}, fmt.Errorf("%w: invalid command envelope", ErrRelayResponse)
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return protocol.CommandEnvelope{}, fmt.Errorf("%w: invalid command envelope", ErrRelayResponse)
	}
	if envelope.RequestID != requestID {
		return protocol.CommandEnvelope{}, fmt.Errorf("%w: command request id mismatch", ErrRelayResponse)
	}
	return envelope, nil
}

func (c *RelayClient) NextCommand(ctx context.Context, deviceID, sessionToken string, wait time.Duration) (protocol.CommandEnvelope, bool, error) {
	ms := wait.Milliseconds()
	if ms < 0 {
		ms = 0
	}
	if ms > 30000 {
		ms = 30000
	}
	path := "/v1/devices/"+url.PathEscape(deviceID)+"/commands/next?wait_ms="+strconv.FormatInt(ms, 10)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint(path), nil)
	if err != nil {
		return protocol.CommandEnvelope{}, false, err
	}
	req.Header.Set("Authorization", "Bearer "+sessionToken)
	resp, err := c.http.Do(req)
	if err != nil {
		return protocol.CommandEnvelope{}, false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusNoContent {
		return protocol.CommandEnvelope{}, false, nil
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxRelayResponseBytes+1))
	if err != nil {
		return protocol.CommandEnvelope{}, false, err
	}
	if int64(len(data)) > maxRelayResponseBytes {
		return protocol.CommandEnvelope{}, false, fmt.Errorf("%w: response too large", ErrRelayResponse)
	}
	if resp.StatusCode != http.StatusOK {
		var payload struct{ Error string `json:"error"` }
		_ = json.Unmarshal(data, &payload)
		return protocol.CommandEnvelope{}, false, &RelayError{Status: resp.StatusCode, Message: payload.Error}
	}
	var body struct {
		RequestID string          `json:"request_id"`
		Payload   json.RawMessage `json:"payload"`
	}
	if err := json.Unmarshal(data, &body); err != nil {
		return protocol.CommandEnvelope{}, false, fmt.Errorf("%w: invalid command response", ErrRelayResponse)
	}
	envelope, err := decodeRelayCommand(body.RequestID, body.Payload)
	if err != nil {
		return protocol.CommandEnvelope{}, false, err
	}
	return envelope, true, nil
}

func (c *RelayClient) SubmitResult(ctx context.Context, deviceID, sessionToken, requestID string, result any) error {
	body := map[string]any{"request_id": requestID, "payload": result}
	return c.doJSON(ctx, http.MethodPost, "/v1/devices/"+url.PathEscape(deviceID)+"/results", sessionToken, body, http.StatusAccepted, nil)
}
