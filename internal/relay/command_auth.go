package relay

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/protocol"
)

var (
	ErrInvalidCommandEnvelope = errors.New("invalid signed command envelope")
	ErrAgentSessionMismatch   = errors.New("command targets a stale agent session")
	ErrCommandReplay          = errors.New("replayed signed command")
)

type commandNonceKey struct {
	deviceID string
	nonce    string
}

func decodeCommandEnvelope(payload []byte) (protocol.CommandEnvelope, error) {
	var envelope protocol.CommandEnvelope
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&envelope); err != nil {
		return protocol.CommandEnvelope{}, ErrInvalidCommandEnvelope
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return protocol.CommandEnvelope{}, ErrInvalidCommandEnvelope
	} else if !errors.Is(err, io.EOF) {
		return protocol.CommandEnvelope{}, ErrInvalidCommandEnvelope
	}
	return envelope, nil
}

func (s *Store) QueuePairedCommand(deviceID, controllerToken string, command Command, now time.Time) error {
	if !validID(deviceID, 64) || !validID(command.RequestID, 128) || len(command.Payload) == 0 {
		return ErrInvalidIdentifier
	}
	envelope, err := decodeCommandEnvelope(command.Payload)
	if err != nil {
		return err
	}
	if envelope.RequestID != command.RequestID || envelope.DeviceID != deviceID {
		return ErrInvalidCommandEnvelope
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.pairedControllerAuthorizedLocked(deviceID, controllerToken, now) {
		return ErrUnauthorized
	}
	pairing := s.pairings[deviceID]
	deviceSession := s.sessions[deviceID]
	if envelope.SessionID != deviceSession.agentSessionID {
		return ErrAgentSessionMismatch
	}
	if err := envelope.Verify(pairing.ControllerPublicKey, now, s.controllerClockSkew, nil); err != nil {
		return ErrInvalidCommandEnvelope
	}

	nowUnix := now.Unix()
	for key, expiry := range s.commandNonces {
		if expiry <= nowUnix {
			delete(s.commandNonces, key)
		}
	}
	nonceKey := commandNonceKey{deviceID: deviceID, nonce: envelope.Nonce}
	if _, exists := s.commandNonces[nonceKey]; exists {
		return ErrCommandReplay
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
	s.commandNonces[nonceKey] = envelope.ExpiresAt
	s.signalQueueLocked(deviceID)
	return nil
}
