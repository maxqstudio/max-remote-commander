package protocol

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
)

const (
	StreamVersion     = 1
	StreamTypeCommand = "command"
)

var ErrInvalidStreamMessage = errors.New("invalid transport stream message")

type StreamMessage struct {
	Version   int             `json:"version"`
	Type      string          `json:"type"`
	RequestID string          `json:"request_id"`
	Payload   json.RawMessage `json:"payload"`
}

func EncodeStreamMessage(message StreamMessage) ([]byte, error) {
	if err := message.validate(); err != nil {
		return nil, err
	}
	return json.Marshal(message)
}

func DecodeStreamMessage(data []byte) (StreamMessage, error) {
	var message StreamMessage
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&message); err != nil {
		return StreamMessage{}, ErrInvalidStreamMessage
	}
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return StreamMessage{}, ErrInvalidStreamMessage
	}
	if err := message.validate(); err != nil {
		return StreamMessage{}, err
	}
	return message, nil
}

func (m StreamMessage) validate() error {
	if m.Version != StreamVersion || m.Type != StreamTypeCommand || !validStreamRequestID(m.RequestID) ||
		len(m.Payload) == 0 || !json.Valid(m.Payload) {
		return ErrInvalidStreamMessage
	}
	return nil
}

func validStreamRequestID(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == ':' {
			continue
		}
		return false
	}
	return true
}
