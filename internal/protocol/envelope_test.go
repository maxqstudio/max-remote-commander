package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func signedEnvelope(t *testing.T, now time.Time) (CommandEnvelope, ed25519.PublicKey) {
	t.Helper()
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	args, _ := json.Marshal(map[string]any{"path": "workspace/file.txt"})
	env := CommandEnvelope{
		Version: CurrentVersion, RequestID: "req-1", DeviceID: "dev-1", SessionID: "sess-1",
		IssuedAt: now.Unix(), ExpiresAt: now.Add(time.Minute).Unix(), Nonce: "nonce-1",
		Tool: "filesystem.read", Arguments: args,
	}
	if err := env.Sign(priv); err != nil {
		t.Fatal(err)
	}
	return env, pub
}

func TestVerifyAcceptsValidSignedEnvelope(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	env, pub := signedEnvelope(t, now)
	if err := env.Verify(pub, now, 5*time.Second, NewMemoryReplayStore()); err != nil {
		t.Fatalf("verify: %v", err)
	}
}

func TestVerifyRejectsTamper(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	env, pub := signedEnvelope(t, now)
	env.Tool = "shell.exec"
	if err := env.Verify(pub, now, 5*time.Second, NewMemoryReplayStore()); !errors.Is(err, ErrInvalidSig) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRejectsReplay(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	env, pub := signedEnvelope(t, now)
	store := NewMemoryReplayStore()
	if err := env.Verify(pub, now, 5*time.Second, store); err != nil {
		t.Fatal(err)
	}
	if err := env.Verify(pub, now, 5*time.Second, store); !errors.Is(err, ErrReplay) {
		t.Fatalf("got %v", err)
	}
}

func TestVerifyRejectsExpiredAndFutureCommands(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	env, pub := signedEnvelope(t, now)
	if err := env.Verify(pub, now.Add(2*time.Minute), 5*time.Second, NewMemoryReplayStore()); !errors.Is(err, ErrExpired) {
		t.Fatalf("expired: %v", err)
	}

	env, pub = signedEnvelope(t, now.Add(30*time.Second))
	if err := env.Verify(pub, now, 5*time.Second, NewMemoryReplayStore()); !errors.Is(err, ErrFutureIssued) {
		t.Fatalf("future: %v", err)
	}
}
