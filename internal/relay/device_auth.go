package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const maxDeviceAssertionLifetime = time.Minute

var (
	ErrDeviceAssertion        = errors.New("invalid device assertion")
	ErrDeviceReplay           = errors.New("replayed device assertion")
	ErrDeviceIdentityRequired = errors.New("paired device requires Ed25519 authentication")
)

type DeviceAssertion struct {
	DeviceID       string `json:"device_id"`
	Generation     uint64 `json:"generation"`
	AgentSessionID string `json:"agent_session_id"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
	Nonce          string `json:"nonce"`
	Signature      string `json:"signature,omitempty"`
}

type deviceAssertionPayload struct {
	DeviceID       string `json:"device_id"`
	Generation     uint64 `json:"generation"`
	AgentSessionID string `json:"agent_session_id"`
	IssuedAt       int64  `json:"issued_at"`
	ExpiresAt      int64  `json:"expires_at"`
	Nonce          string `json:"nonce"`
}

func (a DeviceAssertion) signingBytes() ([]byte, error) {
	if !validID(a.DeviceID, 64) || a.Generation == 0 || !validID(a.AgentSessionID, 128) ||
		a.IssuedAt <= 0 || a.ExpiresAt <= a.IssuedAt || !validID(a.Nonce, 128) {
		return nil, ErrDeviceAssertion
	}
	return json.Marshal(deviceAssertionPayload{
		DeviceID: a.DeviceID,
		Generation: a.Generation,
		AgentSessionID: a.AgentSessionID,
		IssuedAt: a.IssuedAt,
		ExpiresAt: a.ExpiresAt,
		Nonce: a.Nonce,
	})
}

func SignDeviceAssertion(assertion *DeviceAssertion, privateKey ed25519.PrivateKey) error {
	if len(privateKey) != ed25519.PrivateKeySize {
		return ErrInvalidPublicKey
	}
	payload, err := assertion.signingBytes()
	if err != nil {
		return err
	}
	assertion.Signature = base64.RawURLEncoding.EncodeToString(ed25519.Sign(privateKey, payload))
	return nil
}

type deviceNonceKey struct {
	deviceID   string
	generation uint64
	nonce      string
}

func (s *Store) AuthenticateDevice(assertion DeviceAssertion, now time.Time) (Session, error) {
	payload, err := assertion.signingBytes()
	if err != nil {
		return Session{}, err
	}
	if assertion.ExpiresAt-assertion.IssuedAt > int64(maxDeviceAssertionLifetime.Seconds()) {
		return Session{}, ErrDeviceAssertion
	}
	if assertion.ExpiresAt <= now.Unix() || assertion.IssuedAt > now.Add(s.deviceClockSkew).Unix() {
		return Session{}, ErrDeviceAssertion
	}
	signature, err := base64.RawURLEncoding.DecodeString(assertion.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return Session{}, ErrDeviceAssertion
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pairing, ok := s.pairings[assertion.DeviceID]
	if !ok {
		return Session{}, ErrNotPaired
	}
	if pairing.Generation != assertion.Generation {
		return Session{}, ErrPairingGeneration
	}
	if !ed25519.Verify(pairing.DevicePublicKey, payload, signature) {
		return Session{}, ErrUnauthorized
	}

	nowUnix := now.Unix()
	for key, expiry := range s.deviceNonces {
		if expiry <= nowUnix {
			delete(s.deviceNonces, key)
		}
	}
	nonceKey := deviceNonceKey{deviceID: assertion.DeviceID, generation: assertion.Generation, nonce: assertion.Nonce}
	if _, exists := s.deviceNonces[nonceKey]; exists {
		return Session{}, ErrDeviceReplay
	}
	token, hash, err := randomToken()
	if err != nil {
		return Session{}, fmt.Errorf("issue device session: %w", err)
	}

	before := s.durableStateLocked()
	s.deviceNonces[nonceKey] = assertion.ExpiresAt
	removedRequests := s.pruneQueuedCommandsForSessionLocked(assertion.DeviceID, assertion.AgentSessionID, now)
	if err := s.commitDurableLocked(before); err != nil {
		return Session{}, err
	}

	expiresAt := now.Add(s.sessionTTL)
	s.sessions[assertion.DeviceID] = sessionState{
		tokenHash: hash,
		expiresAt: expiresAt,
		generation: assertion.Generation,
		paired: true,
		agentSessionID: assertion.AgentSessionID,
	}
	delete(s.controllerSessions, assertion.DeviceID)
	for _, requestID := range removedRequests {
		s.signalResultLocked(requestID)
	}
	s.signalQueueLocked(assertion.DeviceID)
	return Session{
		Token: token,
		ExpiresAt: expiresAt,
		AgentSessionID: assertion.AgentSessionID,
		Generation: assertion.Generation,
	}, nil
}
