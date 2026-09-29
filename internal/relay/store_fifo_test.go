package relay

import (
	"context"
	"testing"
	"time"
)

func TestNextCommandPreservesFIFOAcrossLeaseExpiry(t *testing.T) {
	store, err := NewStore(Config{
		RegistrationKey: testRegistrationKey,
		SessionTTL:      time.Minute,
		LeaseTTL:        20 * time.Millisecond,
		MaxQueue:        4,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	session, err := store.Register("device-fifo", testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}
	for _, requestID := range []string{"req-head", "req-second"} {
		if err := store.QueueCommand("device-fifo", Command{RequestID: requestID, Payload: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
	}

	first, err := store.NextCommand(context.Background(), "device-fifo", session.Token, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if first.RequestID != "req-head" {
		t.Fatalf("first=%q", first.RequestID)
	}

	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	retry, err := store.NextCommand(ctx, "device-fifo", session.Token, time.Now)
	if err != nil {
		t.Fatal(err)
	}
	if retry.RequestID != "req-head" {
		t.Fatalf("leased head was bypassed by %q", retry.RequestID)
	}
}
