package approval

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/json"
	"errors"
	"sync"
	"time"
)

var (
	ErrInvalidApproval = errors.New("invalid approval request")
	ErrApprovalMissing = errors.New("approval token not found")
	ErrApprovalExpired = errors.New("approval token expired")
	ErrApprovalBinding = errors.New("approval token does not match request")
)

type record struct {
	requestID string
	capability string
	argsHash  [32]byte
	expiresAt time.Time
}

type Store struct {
	mu     sync.Mutex
	maxTTL time.Duration
	items  map[[32]byte]record
}

func NewStore(maxTTL time.Duration) *Store {
	if maxTTL <= 0 {
		maxTTL = 2 * time.Minute
	}
	return &Store{maxTTL: maxTTL, items: make(map[[32]byte]record)}
}

func tokenHash(token string) [32]byte {
	return sha256.Sum256([]byte(token))
}

func argsHash(args []byte) [32]byte {
	return sha256.Sum256(args)
}

func (s *Store) Issue(requestID, capability string, arguments json.RawMessage, ttl time.Duration, now time.Time) (string, error) {
	if requestID == "" || capability == "" || len(arguments) == 0 || !json.Valid(arguments) || ttl <= 0 || ttl > s.maxTTL {
		return "", ErrInvalidApproval
	}
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	hash := tokenHash(token)

	s.mu.Lock()
	defer s.mu.Unlock()
	for key, item := range s.items {
		if !now.Before(item.expiresAt) {
			delete(s.items, key)
		}
	}
	s.items[hash] = record{
		requestID: requestID,
		capability: capability,
		argsHash: argsHash(arguments),
		expiresAt: now.Add(ttl),
	}
	return token, nil
}

func (s *Store) Consume(token, requestID, capability string, arguments json.RawMessage, now time.Time) error {
	if token == "" {
		return ErrApprovalMissing
	}
	hash := tokenHash(token)

	s.mu.Lock()
	item, ok := s.items[hash]
	if ok {
		delete(s.items, hash)
	}
	s.mu.Unlock()

	if !ok {
		return ErrApprovalMissing
	}
	if !now.Before(item.expiresAt) {
		return ErrApprovalExpired
	}
	gotArgs := argsHash(arguments)
	if item.requestID != requestID || item.capability != capability || subtle.ConstantTimeCompare(item.argsHash[:], gotArgs[:]) != 1 {
		return ErrApprovalBinding
	}
	return nil
}
