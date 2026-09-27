package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"time"
)

var (
	ErrWrongDevice  = errors.New("command targets another device")
	ErrWrongSession = errors.New("command belongs to another agent session")
)

type Verifier struct {
	PublicKey    ed25519.PublicKey
	DeviceID     string
	SessionID    string
	MaxClockSkew time.Duration
	Replay       ReplayStore
}

func NewSessionID() (string, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}

func NewVerifier(publicKey ed25519.PublicKey, deviceID, sessionID string, maxClockSkew time.Duration, replay ReplayStore) (*Verifier, error) {
	if len(publicKey) != ed25519.PublicKeySize {
		return nil, ErrInvalidKey
	}
	if deviceID == "" || sessionID == "" || maxClockSkew < 0 {
		return nil, ErrInvalidEnvelope
	}
	if replay == nil {
		replay = NewMemoryReplayStore()
	}
	return &Verifier{
		PublicKey: append(ed25519.PublicKey(nil), publicKey...),
		DeviceID: deviceID,
		SessionID: sessionID,
		MaxClockSkew: maxClockSkew,
		Replay: replay,
	}, nil
}

func (v *Verifier) Verify(envelope CommandEnvelope, now time.Time) error {
	if err := envelope.Verify(v.PublicKey, now, v.MaxClockSkew, nil); err != nil {
		return err
	}
	if envelope.DeviceID != v.DeviceID {
		return ErrWrongDevice
	}
	if envelope.SessionID != v.SessionID {
		return ErrWrongSession
	}
	if v.Replay != nil && !v.Replay.Use(envelope.DeviceID, envelope.Nonce, envelope.ExpiresAt, now) {
		return ErrReplay
	}
	return nil
}
