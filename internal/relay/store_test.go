package relay

import (
	"context"
	"errors"
	"testing"
	"time"
)

const (
	testRegistrationKey = "registration-key-0123456789-abcdef"
	testControllerKey   = "controller-key-0123456789-abcdefgh"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(Config{
		RegistrationKey: testRegistrationKey,
		ControllerKey: testControllerKey,
		SessionTTL: time.Minute,
		LeaseTTL: 50 * time.Millisecond,
		MaxQueue: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func TestSessionRotationInvalidatesOldToken(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	first, err := store.Register("device-a", testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}
	second, err := store.Register("device-a", testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if first.Token == second.Token {
		t.Fatal("session token did not rotate")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	defer cancel()
	if _, err := store.NextCommand(ctx, "device-a", first.Token, func() time.Time { return now }); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("old token: %v", err)
	}
}

func TestDeviceIsolationAndResultFlow(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	a, _ := store.Register("device-a", testRegistrationKey, now)
	b, _ := store.Register("device-b", testRegistrationKey, now)
	if err := store.QueueCommand("device-a", Command{RequestID:"req-1", Payload:[]byte(`{"tool":"filesystem.read"}`)}); err != nil {
		t.Fatal(err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := store.NextCommand(ctx, "device-a", b.Token, func() time.Time { return now }); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("cross-device poll: %v", err)
	}
	command, err := store.NextCommand(context.Background(), "device-a", a.Token, func() time.Time { return now })
	if err != nil {
		t.Fatal(err)
	}
	if command.RequestID != "req-1" {
		t.Fatalf("command %#v", command)
	}
	if err := store.SubmitResult("device-b", b.Token, Result{RequestID:"req-1", Payload:[]byte(`{"ok":false}`)}, now); !errors.Is(err, ErrWrongDevice) {
		t.Fatalf("wrong-device result: %v", err)
	}
	if err := store.SubmitResult("device-a", a.Token, Result{RequestID:"req-1", Payload:[]byte(`{"ok":true}`)}, now); err != nil {
		t.Fatal(err)
	}
	result, err := store.WaitResult(context.Background(), "req-1")
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Payload) != `{"ok":true}` {
		t.Fatalf("result %q", result.Payload)
	}
}

func TestQueueBoundsAndDuplicateRequest(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	if _, err := store.Register("device-a", testRegistrationKey, now); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueCommand("device-a", Command{RequestID:"req-1", Payload:[]byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueCommand("device-a", Command{RequestID:"req-1", Payload:[]byte("{}")}); !errors.Is(err, ErrDuplicateRequest) {
		t.Fatalf("duplicate: %v", err)
	}
	if err := store.QueueCommand("device-a", Command{RequestID:"req-2", Payload:[]byte("{}")}); err != nil {
		t.Fatal(err)
	}
	if err := store.QueueCommand("device-a", Command{RequestID:"req-3", Payload:[]byte("{}")}); !errors.Is(err, ErrQueueFull) {
		t.Fatalf("queue full: %v", err)
	}
}


func TestStoreRejectsSharedBootstrapKeys(t *testing.T) {
	_, err := NewStore(Config{
		RegistrationKey: testRegistrationKey,
		ControllerKey: testRegistrationKey,
	})
	if err == nil {
		t.Fatal("shared registration/controller key was accepted")
	}
}

func TestResultRetentionIsBounded(t *testing.T) {
	store, err := NewStore(Config{
		RegistrationKey: testRegistrationKey,
		ControllerKey: testControllerKey,
		SessionTTL: time.Minute,
		LeaseTTL: 50 * time.Millisecond,
		MaxQueue: 4,
		MaxResults: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	session, err := store.Register("device-a", testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}

	for _, requestID := range []string{"req-1", "req-2"} {
		if err := store.QueueCommand("device-a", Command{RequestID: requestID, Payload: []byte("{}")}); err != nil {
			t.Fatal(err)
		}
		if _, err := store.NextCommand(context.Background(), "device-a", session.Token, func() time.Time { return now }); err != nil {
			t.Fatal(err)
		}
		if err := store.SubmitResult("device-a", session.Token, Result{RequestID: requestID, Payload: []byte("{}")}, now); err != nil {
			t.Fatal(err)
		}
		now = now.Add(time.Second)
	}

	if _, err := store.WaitResult(context.Background(), "req-1"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("evicted result: got %v", err)
	}
	if _, err := store.WaitResult(context.Background(), "req-2"); err != nil {
		t.Fatalf("latest result missing: %v", err)
	}
}
