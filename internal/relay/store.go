package relay

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"errors"
	"sync"
	"time"
)

var (
	ErrUnauthorized      = errors.New("unauthorized")
	ErrInvalidIdentifier = errors.New("invalid identifier")
	ErrUnknownDevice     = errors.New("unknown device")
	ErrQueueFull         = errors.New("device command queue is full")
	ErrDuplicateRequest  = errors.New("duplicate request id")
	ErrUnknownRequest    = errors.New("unknown request id")
	ErrWrongDevice       = errors.New("request belongs to another device")
)

type Config struct {
	RegistrationKey string
	ControllerKey   string
	SessionTTL      time.Duration
	LeaseTTL        time.Duration
	MaxQueue        int
	MaxResults      int
	MaxPairingAttempts int
	ControllerSessionTTL time.Duration
	ControllerClockSkew  time.Duration
}

type Command struct {
	RequestID string `json:"request_id"`
	Payload   []byte `json:"payload"`
}

type Result struct {
	RequestID string `json:"request_id"`
	Payload   []byte `json:"payload"`
}

type Session struct {
	Token     string    `json:"token"`
	ExpiresAt time.Time `json:"expires_at"`
}

type queuedCommand struct {
	command    Command
	leasedTill time.Time
}

type sessionState struct {
	tokenHash [32]byte
	expiresAt time.Time
}

type Store struct {
	mu sync.Mutex

	registrationHash [32]byte
	controllerHash   [32]byte
	sessionTTL       time.Duration
	leaseTTL         time.Duration
	maxQueue         int
	maxResults       int
	maxPairingAttempts int
	controllerSessionTTL time.Duration
	controllerClockSkew  time.Duration

	knownDevices map[string]struct{}
	sessions     map[string]sessionState
	queues       map[string][]*queuedCommand
	requests     map[string]string
	results      map[string]Result
	queueNotify  map[string]chan struct{}
	resultNotify map[string]chan struct{}
	resultOrder  []string
	pairingOffers map[string]pairingOffer
	pairings      map[string]Pairing
	pairingGeneration map[string]uint64
	controllerSessions map[string]controllerSessionState
	controllerNonces   map[controllerNonceKey]int64
}

func NewStore(cfg Config) (*Store, error) {
	if len(cfg.RegistrationKey) < 32 || len(cfg.ControllerKey) < 32 {
		return nil, errors.New("relay bootstrap keys must be at least 32 bytes")
	}
	if cfg.RegistrationKey == cfg.ControllerKey {
		return nil, errors.New("registration and controller keys must be distinct")
	}
	if cfg.SessionTTL <= 0 {
		cfg.SessionTTL = 15 * time.Minute
	}
	if cfg.LeaseTTL <= 0 {
		cfg.LeaseTTL = 30 * time.Second
	}
	if cfg.MaxQueue <= 0 {
		cfg.MaxQueue = 128
	}
	if cfg.MaxResults <= 0 {
		cfg.MaxResults = 1024
	}
	if cfg.MaxPairingAttempts <= 0 {
		cfg.MaxPairingAttempts = 5
	}
	if cfg.ControllerSessionTTL <= 0 {
		cfg.ControllerSessionTTL = 5 * time.Minute
	}
	if cfg.ControllerClockSkew <= 0 {
		cfg.ControllerClockSkew = 30 * time.Second
	}
	return &Store{
		registrationHash: sha256.Sum256([]byte(cfg.RegistrationKey)),
		controllerHash: sha256.Sum256([]byte(cfg.ControllerKey)),
		sessionTTL: cfg.SessionTTL,
		leaseTTL: cfg.LeaseTTL,
		maxQueue: cfg.MaxQueue,
		maxResults: cfg.MaxResults,
		maxPairingAttempts: cfg.MaxPairingAttempts,
		controllerSessionTTL: cfg.ControllerSessionTTL,
		controllerClockSkew: cfg.ControllerClockSkew,
		knownDevices: make(map[string]struct{}),
		sessions: make(map[string]sessionState),
		queues: make(map[string][]*queuedCommand),
		requests: make(map[string]string),
		results: make(map[string]Result),
		queueNotify: make(map[string]chan struct{}),
		resultNotify: make(map[string]chan struct{}),
		pairingOffers: make(map[string]pairingOffer),
		pairings: make(map[string]Pairing),
		pairingGeneration: make(map[string]uint64),
		controllerSessions: make(map[string]controllerSessionState),
		controllerNonces: make(map[controllerNonceKey]int64),
	}, nil
}

func secureEqual(expected [32]byte, supplied string) bool {
	got := sha256.Sum256([]byte(supplied))
	return subtle.ConstantTimeCompare(expected[:], got[:]) == 1
}

func validID(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}

func randomToken() (string, [32]byte, error) {
	raw := make([]byte, 32)
	if _, err := rand.Read(raw); err != nil {
		return "", [32]byte{}, err
	}
	token := base64.RawURLEncoding.EncodeToString(raw)
	return token, sha256.Sum256([]byte(token)), nil
}

func (s *Store) ControllerAuthorized(secret string) bool {
	return secureEqual(s.controllerHash, secret)
}

func (s *Store) Register(deviceID, registrationKey string, now time.Time) (Session, error) {
	if !validID(deviceID, 64) {
		return Session{}, ErrInvalidIdentifier
	}
	if !secureEqual(s.registrationHash, registrationKey) {
		return Session{}, ErrUnauthorized
	}
	token, hash, err := randomToken()
	if err != nil {
		return Session{}, err
	}
	expires := now.Add(s.sessionTTL)

	s.mu.Lock()
	s.knownDevices[deviceID] = struct{}{}
	s.sessions[deviceID] = sessionState{tokenHash: hash, expiresAt: expires}
	s.signalQueueLocked(deviceID)
	s.mu.Unlock()

	return Session{Token: token, ExpiresAt: expires}, nil
}

func (s *Store) sessionAuthorizedLocked(deviceID, token string, now time.Time) bool {
	session, ok := s.sessions[deviceID]
	if !ok || !now.Before(session.expiresAt) {
		return false
	}
	return secureEqual(session.tokenHash, token)
}

func (s *Store) QueueCommand(deviceID string, command Command) error {
	if !validID(deviceID, 64) || !validID(command.RequestID, 128) || len(command.Payload) == 0 {
		return ErrInvalidIdentifier
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.knownDevices[deviceID]; !ok {
		return ErrUnknownDevice
	}
	if _, exists := s.requests[command.RequestID]; exists {
		return ErrDuplicateRequest
	}
	if len(s.queues[deviceID]) >= s.maxQueue {
		return ErrQueueFull
	}
	copyPayload := append([]byte(nil), command.Payload...)
	s.queues[deviceID] = append(s.queues[deviceID], &queuedCommand{
		command: Command{RequestID: command.RequestID, Payload: copyPayload},
	})
	s.requests[command.RequestID] = deviceID
	s.signalQueueLocked(deviceID)
	return nil
}

func (s *Store) NextCommand(ctx context.Context, deviceID, token string, now func() time.Time) (Command, error) {
	if now == nil {
		now = time.Now
	}
	for {
		current := now()
		s.mu.Lock()
		if !s.sessionAuthorizedLocked(deviceID, token, current) {
			s.mu.Unlock()
			return Command{}, ErrUnauthorized
		}
		for _, item := range s.queues[deviceID] {
			if item.leasedTill.IsZero() || !current.Before(item.leasedTill) {
				item.leasedTill = current.Add(s.leaseTTL)
				command := Command{RequestID: item.command.RequestID, Payload: append([]byte(nil), item.command.Payload...)}
				s.mu.Unlock()
				return command, nil
			}
		}
		ch := s.queueChannelLocked(deviceID)
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return Command{}, ctx.Err()
		case <-ch:
		}
	}
}

func (s *Store) SubmitResult(deviceID, token string, result Result, now time.Time) error {
	if !validID(result.RequestID, 128) || len(result.Payload) == 0 {
		return ErrInvalidIdentifier
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.sessionAuthorizedLocked(deviceID, token, now) {
		return ErrUnauthorized
	}
	owner, ok := s.requests[result.RequestID]
	if !ok {
		return ErrUnknownRequest
	}
	if owner != deviceID {
		return ErrWrongDevice
	}
	result.Payload = append([]byte(nil), result.Payload...)
	if _, exists := s.results[result.RequestID]; !exists {
		for len(s.results) >= s.maxResults && len(s.resultOrder) > 0 {
			evict := s.resultOrder[0]
			s.resultOrder = s.resultOrder[1:]
			delete(s.results, evict)
			delete(s.requests, evict)
			delete(s.resultNotify, evict)
		}
		s.resultOrder = append(s.resultOrder, result.RequestID)
	}
	s.results[result.RequestID] = result

	queue := s.queues[deviceID]
	for i, item := range queue {
		if item.command.RequestID == result.RequestID {
			s.queues[deviceID] = append(queue[:i], queue[i+1:]...)
			break
		}
	}
	s.signalResultLocked(result.RequestID)
	return nil
}

func (s *Store) WaitResult(ctx context.Context, requestID string) (Result, error) {
	if !validID(requestID, 128) {
		return Result{}, ErrInvalidIdentifier
	}
	for {
		s.mu.Lock()
		if result, ok := s.results[requestID]; ok {
			result.Payload = append([]byte(nil), result.Payload...)
			s.mu.Unlock()
			return result, nil
		}
		if _, ok := s.requests[requestID]; !ok {
			s.mu.Unlock()
			return Result{}, ErrUnknownRequest
		}
		ch := s.resultChannelLocked(requestID)
		s.mu.Unlock()

		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		case <-ch:
		}
	}
}

func (s *Store) queueChannelLocked(deviceID string) chan struct{} {
	ch := s.queueNotify[deviceID]
	if ch == nil {
		ch = make(chan struct{})
		s.queueNotify[deviceID] = ch
	}
	return ch
}

func (s *Store) resultChannelLocked(requestID string) chan struct{} {
	ch := s.resultNotify[requestID]
	if ch == nil {
		ch = make(chan struct{})
		s.resultNotify[requestID] = ch
	}
	return ch
}

func (s *Store) signalQueueLocked(deviceID string) {
	if ch := s.queueNotify[deviceID]; ch != nil {
		close(ch)
		delete(s.queueNotify, deviceID)
	}
}

func (s *Store) signalResultLocked(requestID string) {
	if ch := s.resultNotify[requestID]; ch != nil {
		close(ch)
		delete(s.resultNotify, requestID)
	}
}
