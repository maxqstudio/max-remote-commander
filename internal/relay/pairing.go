package relay

import (
	"crypto/ed25519"
	"crypto/sha256"
	"errors"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

const (
	maxPairingTTL = 5 * time.Minute
	maxPairingReceiptTTL = 10 * time.Minute
)

var (
	ErrPairingOfferMissing = errors.New("pairing offer not found")
	ErrPairingOfferExpired = errors.New("pairing offer expired")
	ErrPairingCodeInvalid  = errors.New("pairing code invalid")
	ErrPairingAttempts     = errors.New("pairing attempts exhausted")
	ErrAlreadyPaired       = errors.New("device already paired")
	ErrPairingMismatch     = errors.New("device public key does not match device id")
	ErrInvalidPublicKey    = errors.New("invalid Ed25519 public key")
	ErrNotPaired           = errors.New("device is not paired")
	ErrPairingReceipt       = errors.New("invalid pairing receipt")
)

type pairingOffer struct {
	codeHash        [32]byte
	devicePublicKey ed25519.PublicKey
	expiresAt       time.Time
	attempts        int
}

type pairingReceiptState struct {
	tokenHash [32]byte
	expiresAt time.Time
}

type PairingReceipt struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type Pairing struct {
	DeviceID            string
	DevicePublicKey     ed25519.PublicKey
	ControllerPublicKey ed25519.PublicKey
	Generation          uint64
	PairedAt            time.Time
}

func clonePublicKey(key ed25519.PublicKey) ed25519.PublicKey {
	return append(ed25519.PublicKey(nil), key...)
}

func validPublicKey(key ed25519.PublicKey) bool {
	return len(key) == ed25519.PublicKeySize
}

func (s *Store) PublishPairingOffer(deviceID, sessionToken string, codeHash [32]byte, devicePublicKey ed25519.PublicKey, ttl time.Duration, now time.Time) error {
	_, err := s.publishPairingOffer(deviceID, sessionToken, codeHash, devicePublicKey, ttl, now, false)
	return err
}

func (s *Store) PublishPairingOfferWithReceipt(deviceID, sessionToken string, codeHash [32]byte, devicePublicKey ed25519.PublicKey, ttl time.Duration, now time.Time) (PairingReceipt, error) {
	return s.publishPairingOffer(deviceID, sessionToken, codeHash, devicePublicKey, ttl, now, true)
}

func (s *Store) publishPairingOffer(deviceID, sessionToken string, codeHash [32]byte, devicePublicKey ed25519.PublicKey, ttl time.Duration, now time.Time, issueReceipt bool) (PairingReceipt, error) {
	if !validID(deviceID, 64) || !validPublicKey(devicePublicKey) || ttl <= 0 || ttl > maxPairingTTL {
		return PairingReceipt{}, ErrInvalidIdentifier
	}
	expectedID, err := identity.DeviceID(devicePublicKey)
	if err != nil || expectedID != deviceID {
		return PairingReceipt{}, ErrPairingMismatch
	}
	if codeHash == sha256.Sum256(nil) {
		return PairingReceipt{}, ErrInvalidIdentifier
	}

	var receipt PairingReceipt
	var receiptHash [32]byte
	if issueReceipt {
		token, hash, err := randomToken()
		if err != nil {
			return PairingReceipt{}, err
		}
		receipt = PairingReceipt{Token: token, ExpiresAt: now.Add(maxPairingReceiptTTL)}
		receiptHash = hash
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessionAuthorizedLocked(deviceID, sessionToken, now) {
		return PairingReceipt{}, ErrUnauthorized
	}
	if _, exists := s.pairings[deviceID]; exists {
		return PairingReceipt{}, ErrAlreadyPaired
	}
	s.pairingOffers[deviceID] = pairingOffer{
		codeHash: codeHash,
		devicePublicKey: clonePublicKey(devicePublicKey),
		expiresAt: now.Add(ttl),
	}
	if issueReceipt {
		s.pairingReceipts[deviceID] = pairingReceiptState{tokenHash: receiptHash, expiresAt: receipt.ExpiresAt}
	} else {
		delete(s.pairingReceipts, deviceID)
	}
	return receipt, nil
}

func (s *Store) RedeemPairing(deviceID, code string, controllerPublicKey ed25519.PublicKey, now time.Time) (Pairing, error) {
	if !validID(deviceID, 64) || code == "" || !validPublicKey(controllerPublicKey) {
		return Pairing{}, ErrInvalidIdentifier
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, exists := s.pairings[deviceID]; exists {
		return Pairing{}, ErrAlreadyPaired
	}
	offer, ok := s.pairingOffers[deviceID]
	if !ok {
		return Pairing{}, ErrPairingOfferMissing
	}
	if !now.Before(offer.expiresAt) {
		delete(s.pairingOffers, deviceID)
		delete(s.pairingReceipts, deviceID)
		return Pairing{}, ErrPairingOfferExpired
	}
	if !identity.PairingCodeMatches(offer.codeHash, code) {
		offer.attempts++
		if offer.attempts >= s.maxPairingAttempts {
			delete(s.pairingOffers, deviceID)
			delete(s.pairingReceipts, deviceID)
			return Pairing{}, ErrPairingAttempts
		}
		s.pairingOffers[deviceID] = offer
		return Pairing{}, ErrPairingCodeInvalid
	}

	generation := s.pairingGeneration[deviceID] + 1
	s.pairingGeneration[deviceID] = generation
	pairing := Pairing{
		DeviceID: deviceID,
		DevicePublicKey: clonePublicKey(offer.devicePublicKey),
		ControllerPublicKey: clonePublicKey(controllerPublicKey),
		Generation: generation,
		PairedAt: now,
	}
	s.pairings[deviceID] = pairing
	delete(s.pairingOffers, deviceID)
	delete(s.sessions, deviceID)
	for key := range s.deviceNonces {
		if key.deviceID == deviceID {
			delete(s.deviceNonces, key)
		}
	}
	return clonePairing(pairing), nil
}

func (s *Store) PairingStatus(deviceID, receiptToken string, now time.Time) (Pairing, bool, error) {
	if !validID(deviceID, 64) || receiptToken == "" {
		return Pairing{}, false, ErrPairingReceipt
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	receipt, ok := s.pairingReceipts[deviceID]
	if !ok || !now.Before(receipt.expiresAt) || !secureEqual(receipt.tokenHash, receiptToken) {
		if ok && !now.Before(receipt.expiresAt) {
			delete(s.pairingReceipts, deviceID)
		}
		return Pairing{}, false, ErrPairingReceipt
	}
	pairing, paired := s.pairings[deviceID]
	if !paired {
		return Pairing{}, false, nil
	}
	return clonePairing(pairing), true, nil
}

func clonePairing(pairing Pairing) Pairing {
	pairing.DevicePublicKey = clonePublicKey(pairing.DevicePublicKey)
	pairing.ControllerPublicKey = clonePublicKey(pairing.ControllerPublicKey)
	return pairing
}

func (s *Store) Pairing(deviceID string) (Pairing, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	pairing, ok := s.pairings[deviceID]
	if !ok {
		return Pairing{}, ErrNotPaired
	}
	return clonePairing(pairing), nil
}

func (s *Store) RevokePairing(deviceID, sessionToken string, now time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessionAuthorizedLocked(deviceID, sessionToken, now) {
		return ErrUnauthorized
	}
	if _, ok := s.pairings[deviceID]; !ok {
		return ErrNotPaired
	}
	delete(s.pairings, deviceID)
	delete(s.pairingOffers, deviceID)
	delete(s.pairingReceipts, deviceID)
	delete(s.sessions, deviceID)
	delete(s.controllerSessions, deviceID)
	for key := range s.controllerNonces {
		if key.deviceID == deviceID {
			delete(s.controllerNonces, key)
		}
	}
	for key := range s.deviceNonces {
		if key.deviceID == deviceID {
			delete(s.deviceNonces, key)
		}
	}
	s.pairingGeneration[deviceID]++
	return nil
}
