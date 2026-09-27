package approval

import (
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func TestApprovalIsBoundAndOneUse(t *testing.T) {
	store := NewStore(time.Minute)
	now := time.Unix(1_800_000_000, 0)
	args := json.RawMessage(`{"path":"note.txt","content":"hello"}`)
	token, err := store.Issue("req-1", "filesystem.write", args, 30*time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(token, "req-1", "filesystem.write", json.RawMessage(`{"path":"note.txt","content":"tampered"}`), now); !errors.Is(err, ErrApprovalBinding) {
		t.Fatalf("tampered consume: %v", err)
	}
	if err := store.Consume(token, "req-1", "filesystem.write", args, now); !errors.Is(err, ErrApprovalMissing) {
		t.Fatalf("replay after mismatch: %v", err)
	}
}

func TestApprovalExpires(t *testing.T) {
	store := NewStore(time.Minute)
	now := time.Unix(1_800_000_000, 0)
	args := json.RawMessage(`{}`)
	token, err := store.Issue("req-1", "process.run", args, time.Second, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Consume(token, "req-1", "process.run", args, now.Add(time.Second)); !errors.Is(err, ErrApprovalExpired) {
		t.Fatalf("expired consume: %v", err)
	}
}

func TestApprovalRejectsOverlongTTL(t *testing.T) {
	store := NewStore(time.Second)
	_, err := store.Issue("req-1", "git.clone", json.RawMessage(`{}`), 2*time.Second, time.Now())
	if !errors.Is(err, ErrInvalidApproval) {
		t.Fatalf("got %v", err)
	}
}
