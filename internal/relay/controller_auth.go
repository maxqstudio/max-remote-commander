package relay

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

const maxControllerAssertionLifetime = time.Minute

var (
	ErrControllerAssertion = errors.New("invalid controller assertion")
	ErrControllerReplay    = errors.New("replayed controller assertion")
	ErrPairingGeneration   = errors.New("pairing generation mismatch")
	ErrDeviceOffline       = errors.New("paired device has no active authenticated session")
)

type ControllerAssertion struct {
	DeviceID   string `json:"device_id"`
	Generation uint64 `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Nonce      string `json:"nonce"`
	Signature  string `json:"signature,omitempty"`
}

type controllerAssertionPayload struct {
	DeviceID   string `json:"device_id"`
	Generation uint64 `json:"generation"`
	IssuedAt   int64  `json:"issued_at"`
	ExpiresAt  int64  `json:"expires_at"`
	Nonce      string `json:"nonce"`
}

func (a ControllerAssertion) signingBytes() ([]byte, error) {
	if !validID(a.DeviceID, 64) || a.Generation == 0 || a.IssuedAt <= 0 || a.ExpiresAt <= a.IssuedAt || !validID(a.Nonce, 128) {
		return nil, ErrControllerAssertion
	}
	return json.Marshal(controllerAssertionPayload{
		DeviceID: a.DeviceID,
		Generation: a.Generation,
		IssuedAt: a.IssuedAt,
		ExpiresAt: a.ExpiresAt,
		Nonce: a.Nonce,
	})
}

func SignControllerAssertion(assertion *ControllerAssertion, privateKey ed25519.PrivateKey) error {
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

type ControllerSession struct {
	Token          string
	ExpiresAt      time.Time
	DeviceID       string
	Generation     uint64
	AgentSessionID string
}

type controllerSessionState struct {
	tokenHash      [32]byte
	expiresAt      time.Time
	generation     uint64
	agentSessionID string
}

type controllerNonceKey struct {
	deviceID   string
	generation uint64
	nonce      string
}

func (s *Store) AuthenticateController(assertion ControllerAssertion, now time.Time) (ControllerSession, error) {
	payload, err := assertion.signingBytes()
	if err != nil {
		return ControllerSession{}, err
	}
	if assertion.ExpiresAt-assertion.IssuedAt > int64(maxControllerAssertionLifetime.Seconds()) {
		return ControllerSession{}, ErrControllerAssertion
	}
	if assertion.ExpiresAt <= now.Unix() || assertion.IssuedAt > now.Add(s.controllerClockSkew).Unix() {
		return ControllerSession{}, ErrControllerAssertion
	}
	signature, err := base64.RawURLEncoding.DecodeString(assertion.Signature)
	if err != nil || len(signature) != ed25519.SignatureSize {
		return ControllerSession{}, ErrControllerAssertion
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	pairing, ok := s.pairings[assertion.DeviceID]
	if !ok {
		return ControllerSession{}, ErrNotPaired
	}
	if pairing.Generation != assertion.Generation {
		return ControllerSession{}, ErrPairingGeneration
	}
	if !ed25519.Verify(pairing.ControllerPublicKey, payload, signature) {
		return ControllerSession{}, ErrUnauthorized
	}
	deviceSession, online := s.sessions[assertion.DeviceID]
	if !online || !deviceSession.paired || deviceSession.generation != pairing.Generation ||
		!now.Before(deviceSession.expiresAt) || deviceSession.agentSessionID == "" {
		return ControllerSession{}, ErrDeviceOffline
	}

	nowUnix := now.Unix()
	for key, expiry := range s.controllerNonces {
		if expiry <= nowUnix {
			delete(s.controllerNonces, key)
		}
	}
	nonceKey := controllerNonceKey{deviceID: assertion.DeviceID, generation: assertion.Generation, nonce: assertion.Nonce}
	if _, exists := s.controllerNonces[nonceKey]; exists {
		return ControllerSession{}, ErrControllerReplay
	}
	token, hash, err := randomToken()
	if err != nil {
		return ControllerSession{}, fmt.Errorf("issue controller session: %w", err)
	}

	before := s.durableStateLocked()
	s.controllerNonces[nonceKey] = assertion.ExpiresAt
	if err := s.commitDurableLocked(before); err != nil {
		return ControllerSession{}, err
	}

	expiresAt := now.Add(s.controllerSessionTTL)
	s.controllerSessions[assertion.DeviceID] = controllerSessionState{
		tokenHash: hash,
		expiresAt: expiresAt,
		generation: assertion.Generation,
		agentSessionID: deviceSession.agentSessionID,
	}
	return ControllerSession{
		Token: token,
		ExpiresAt: expiresAt,
		DeviceID: assertion.DeviceID,
		Generation: assertion.Generation,
		AgentSessionID: deviceSession.agentSessionID,
	}, nil
}

func (s *Store) pairedControllerAuthorizedLocked(deviceID, token string, now time.Time) bool {
	if token == "" {
		return false
	}
	pairing, paired := s.pairings[deviceID]
	session, ok := s.controllerSessions[deviceID]
	deviceSession, online := s.sessions[deviceID]
	if !paired || !ok || !online || pairing.Generation != session.generation ||
		!deviceSession.paired || deviceSession.generation != pairing.Generation ||
		deviceSession.agentSessionID == "" || deviceSession.agentSessionID != session.agentSessionID ||
		!now.Before(session.expiresAt) || !now.Before(deviceSession.expiresAt) {
		return false
	}
	return secureEqual(session.tokenHash, token)
}

func (s *Store) PairedControllerAuthorized(deviceID, token string, now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.pairedControllerAuthorizedLocked(deviceID, token, now)
}
