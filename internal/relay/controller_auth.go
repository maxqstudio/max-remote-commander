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
	Token     string
	ExpiresAt time.Time
	DeviceID  string
	Generation uint64
}

type controllerSessionState struct {
	tokenHash   [32]byte
	expiresAt   time.Time
	generation  uint64
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
	s.controllerNonces[nonceKey] = assertion.ExpiresAt

	token, hash, err := randomToken()
	if err != nil {
		delete(s.controllerNonces, nonceKey)
		return ControllerSession{}, fmt.Errorf("issue controller session: %w", err)
	}
	expiresAt := now.Add(s.controllerSessionTTL)
	s.controllerSessions[assertion.DeviceID] = controllerSessionState{
		tokenHash: hash,
		expiresAt: expiresAt,
		generation: assertion.Generation,
	}
	return ControllerSession{
		Token: token,
		ExpiresAt: expiresAt,
		DeviceID: assertion.DeviceID,
		Generation: assertion.Generation,
	}, nil
}

func (s *Store) PairedControllerAuthorized(deviceID, token string, now time.Time) bool {
	if token == "" {
		return false
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	pairing, paired := s.pairings[deviceID]
	session, ok := s.controllerSessions[deviceID]
	if !paired || !ok || pairing.Generation != session.generation || !now.Before(session.expiresAt) {
		return false
	}
	return secureEqual(session.tokenHash, token)
}
