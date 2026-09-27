package protocol

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"
)

func signedForSession(t *testing.T, privateKey ed25519.PrivateKey, now time.Time, deviceID, sessionID, nonce string) CommandEnvelope {
	t.Helper()
	args, _ := json.Marshal(map[string]any{"path":"note.txt"})
	envelope := CommandEnvelope{
		Version: CurrentVersion,
		RequestID: "req-" + nonce,
		DeviceID: deviceID,
		SessionID: sessionID,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Nonce: nonce,
		Tool: "filesystem.read",
		Arguments: args,
	}
	if err := envelope.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return envelope
}

func TestVerifierBindsDeviceAndPerStartSession(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionA, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	sessionB, err := NewSessionID()
	if err != nil {
		t.Fatal(err)
	}
	if sessionA == sessionB {
		t.Fatal("session IDs unexpectedly repeated")
	}

	verifierA, err := NewVerifier(pub, "device-a", sessionA, 5*time.Second, NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	commandA := signedForSession(t, priv, now, "device-a", sessionA, "nonce-a")
	if err := verifierA.Verify(commandA, now); err != nil {
		t.Fatalf("current session: %v", err)
	}

	verifierAfterRestart, err := NewVerifier(pub, "device-a", sessionB, 5*time.Second, NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifierAfterRestart.Verify(commandA, now); !errors.Is(err, ErrWrongSession) {
		t.Fatalf("old-session replay: %v", err)
	}

	wrongDevice := signedForSession(t, priv, now, "device-b", sessionB, "nonce-b")
	if err := verifierAfterRestart.Verify(wrongDevice, now); !errors.Is(err, ErrWrongDevice) {
		t.Fatalf("wrong device: %v", err)
	}
}

func TestVerifierStillRejectsReplayWithinSession(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionID, _ := NewSessionID()
	verifier, err := NewVerifier(pub, "device-a", sessionID, 5*time.Second, NewMemoryReplayStore())
	if err != nil {
		t.Fatal(err)
	}
	command := signedForSession(t, priv, now, "device-a", sessionID, "nonce-1")
	if err := verifier.Verify(command, now); err != nil {
		t.Fatal(err)
	}
	if err := verifier.Verify(command, now); !errors.Is(err, ErrReplay) {
		t.Fatalf("replay: %v", err)
	}
}

func TestReplayStoreKeyCannotCollideOnEmbeddedSeparators(t *testing.T) {
	store := NewMemoryReplayStore()
	now := time.Unix(1_800_000_000, 0)
	expiry := now.Add(time.Minute).Unix()
	if !store.Use("a", "\x00b", expiry, now) {
		t.Fatal("first key rejected")
	}
	if !store.Use("a\x00", "b", expiry, now) {
		t.Fatal("distinct structured key collided")
	}
}
