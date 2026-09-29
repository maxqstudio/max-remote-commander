package protocol

import (
	"encoding/json"
	"errors"
	"testing"
)

func TestStreamMessageRoundTrip(t *testing.T) {
	payload := json.RawMessage(`{"version":1,"request_id":"req-1"}`)
	data, err := EncodeStreamMessage(StreamMessage{
		Version: StreamVersion,
		Type: StreamTypeCommand,
		RequestID: "req-1",
		Payload: payload,
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := DecodeStreamMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if got.Version != StreamVersion || got.Type != StreamTypeCommand || got.RequestID != "req-1" ||
		string(got.Payload) != string(payload) {
		t.Fatalf("got %#v", got)
	}
}

func TestStreamMessageRejectsUnknownTrailingAndInvalidShape(t *testing.T) {
	cases := [][]byte{
		[]byte(`{"version":1,"type":"command","request_id":"req-1","payload":{},"extra":true}`),
		[]byte(`{"version":1,"type":"command","request_id":"req-1","payload":{}} {}`),
		[]byte(`{"version":2,"type":"command","request_id":"req-1","payload":{}}`),
		[]byte(`{"version":1,"type":"result","request_id":"req-1","payload":{}}`),
		[]byte(`{"version":1,"type":"command","request_id":"bad id","payload":{}}`),
	}
	for _, raw := range cases {
		if _, err := DecodeStreamMessage(raw); !errors.Is(err, ErrInvalidStreamMessage) {
			t.Fatalf("input %s: %v", raw, err)
		}
	}
}
