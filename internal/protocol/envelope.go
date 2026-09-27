package protocol

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

const CurrentVersion = 1

var (
	ErrInvalidEnvelope = errors.New("invalid command envelope")
	ErrExpired         = errors.New("command expired")
	ErrFutureIssued    = errors.New("command issued too far in the future")
	ErrInvalidSig      = errors.New("invalid command signature")
	ErrInvalidKey      = errors.New("invalid Ed25519 key")
	ErrReplay          = errors.New("replayed command")
)

type CommandEnvelope struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	DeviceID  string          `json:"device_id"`
	SessionID string          `json:"session_id"`
	IssuedAt  int64           `json:"issued_at"`
	ExpiresAt int64           `json:"expires_at"`
	Nonce     string          `json:"nonce"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
	Signature string          `json:"signature,omitempty"`
}

type signingPayload struct {
	Version   int             `json:"version"`
	RequestID string          `json:"request_id"`
	DeviceID  string          `json:"device_id"`
	SessionID string          `json:"session_id"`
	IssuedAt  int64           `json:"issued_at"`
	ExpiresAt int64           `json:"expires_at"`
	Nonce     string          `json:"nonce"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

func (e CommandEnvelope) canonicalBytes() ([]byte, error) {
	return json.Marshal(signingPayload{
		Version: e.Version, RequestID: e.RequestID, DeviceID: e.DeviceID,
		SessionID: e.SessionID, IssuedAt: e.IssuedAt, ExpiresAt: e.ExpiresAt,
		Nonce: e.Nonce, Tool: e.Tool, Arguments: e.Arguments,
	})
}

func (e *CommandEnvelope) Sign(privateKey ed25519.PrivateKey) error {
	if err := e.validateShape(); err != nil {
		return err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return ErrInvalidKey
	}
	payload, err := e.canonicalBytes()
	if err != nil {
		return err
	}
	e.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

type ReplayStore interface {
	Use(deviceID, nonce string, expiresAt int64, now time.Time) bool
}

func (e CommandEnvelope) Verify(publicKey ed25519.PublicKey, now time.Time, maxClockSkew time.Duration, replay ReplayStore) error {
	if err := e.validateShape(); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return ErrInvalidKey
	}
	unixNow := now.Unix()
	if e.ExpiresAt <= unixNow {
		return ErrExpired
	}
	if e.IssuedAt > now.Add(maxClockSkew).Unix() {
		return ErrFutureIssued
	}
	if e.ExpiresAt <= e.IssuedAt {
		return fmt.Errorf("%w: expiry must follow issue time", ErrInvalidEnvelope)
	}
	if e.ExpiresAt-e.IssuedAt > int64((5*time.Minute).Seconds()) {
		return fmt.Errorf("%w: lifetime exceeds 5 minutes", ErrInvalidEnvelope)
	}
	signature, err := base64.RawURLEncoding.DecodeString(e.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ErrInvalidSig
	}
	payload, err := e.canonicalBytes()
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return ErrInvalidSig
	}
	if replay != nil && !replay.Use(e.DeviceID, e.Nonce, e.ExpiresAt, now) {
		return ErrReplay
	}
	return nil
}

func (e CommandEnvelope) validateShape() error {
	if e.Version != CurrentVersion || e.RequestID == "" || e.DeviceID == "" || e.SessionID == "" || e.Nonce == "" || e.Tool == "" {
		return ErrInvalidEnvelope
	}
	if len(e.Arguments) == 0 || !json.Valid(e.Arguments) {
		return fmt.Errorf("%w: arguments must be valid JSON", ErrInvalidEnvelope)
	}
	return nil
}

type replayKey struct {
	deviceID string
	nonce    string
}

type MemoryReplayStore struct {
	mu   sync.Mutex
	seen map[replayKey]int64
}

func NewMemoryReplayStore() *MemoryReplayStore {
	return &MemoryReplayStore{seen: make(map[replayKey]int64)}
}

func (s *MemoryReplayStore) Use(deviceID, nonce string, expiresAt int64, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	nowUnix := now.Unix()
	for key, expiry := range s.seen {
		if expiry <= nowUnix {
			delete(s.seen, key)
		}
	}
	key := replayKey{deviceID: deviceID, nonce: nonce}
	if _, exists := s.seen[key]; exists {
		return false
	}
	s.seen[key] = expiresAt
	return true
}
