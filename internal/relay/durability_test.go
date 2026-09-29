package relay

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func durableStoreForTest(t *testing.T, path string, key []byte) *Store {
	t.Helper()
	store, err := NewStore(Config{
		RegistrationKey:testRegistrationKey,
		SessionTTL:time.Minute,
		LeaseTTL:time.Second,
		MaxQueue:4,
		MaxResults:4,
		ControllerSessionTTL:time.Minute,
		StatePath:path,
		StateKey:key,
		MaxStateBytes:1<<20,
	})
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func durablePairedFixture(t *testing.T, store *Store, now time.Time) (*identity.Device, Pairing, ed25519.PrivateKey, Session, ControllerSession) {
	t.Helper()
	device, deviceID := pairingDevice(t)
	bootstrap := registerPairingDevice(t, store, deviceID, now)
	code, hash, err := identity.GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PublishPairingOffer(deviceID, bootstrap.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := store.RedeemPairing(deviceID, code, controllerPublic, now)
	if err != nil {
		t.Fatal(err)
	}
	deviceAssertion := signedDeviceAssertion(t, device, pairing, now, "agent-session-durable", "device-nonce-1")
	deviceSession, err := store.AuthenticateDevice(deviceAssertion, now)
	if err != nil {
		t.Fatal(err)
	}
	controllerAssertion := signedControllerAssertion(t, pairing, controllerPrivate, now, "controller-nonce-1")
	controllerSession, err := store.AuthenticateController(controllerAssertion, now)
	if err != nil {
		t.Fatal(err)
	}
	return device, pairing, controllerPrivate, deviceSession, controllerSession
}

func TestDurableRelayRestartPreservesTrustQueueReplayAndResults(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "relay-state.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}

	first := durableStoreForTest(t, path, key)
	device, pairing, controllerPrivate, oldDeviceSession, oldControllerSession := durablePairedFixture(t, first, now)
	command := signedCommandForPairing(t, pairing, controllerPrivate, oldControllerSession.AgentSessionID, "req-durable", "command-nonce-1", now)
	if err := first.QueuePairedCommand(pairing.DeviceID, oldControllerSession.Token, command, now); err != nil {
		t.Fatal(err)
	}

	second := durableStoreForTest(t, path, key)
	loadedPairing, err := second.Pairing(pairing.DeviceID)
	if err != nil {
		t.Fatal(err)
	}
	if loadedPairing.Generation != pairing.Generation ||
		string(loadedPairing.ControllerPublicKey) != string(pairing.ControllerPublicKey) {
		t.Fatalf("loaded pairing %#v", loadedPairing)
	}
	if second.sessionAuthorizedLocked(pairing.DeviceID, oldDeviceSession.Token, now) {
		t.Fatal("device session survived relay restart")
	}
	if second.PairedControllerAuthorized(pairing.DeviceID, oldControllerSession.Token, now) {
		t.Fatal("controller session survived relay restart")
	}

	replayedDevice := signedDeviceAssertion(t, device, pairing, now, "agent-session-durable", "device-nonce-1")
	if _, err := second.AuthenticateDevice(replayedDevice, now); !errors.Is(err, ErrDeviceReplay) {
		t.Fatalf("device replay after restart: %v", err)
	}
	newDeviceAssertion := signedDeviceAssertion(t, device, pairing, now, "agent-session-durable", "device-nonce-2")
	newDeviceSession, err := second.AuthenticateDevice(newDeviceAssertion, now)
	if err != nil {
		t.Fatal(err)
	}

	replayedController := signedControllerAssertion(t, pairing, controllerPrivate, now, "controller-nonce-1")
	if _, err := second.AuthenticateController(replayedController, now); !errors.Is(err, ErrControllerReplay) {
		t.Fatalf("controller replay after restart: %v", err)
	}
	newControllerAssertion := signedControllerAssertion(t, pairing, controllerPrivate, now, "controller-nonce-2")
	newControllerSession, err := second.AuthenticateController(newControllerAssertion, now)
	if err != nil {
		t.Fatal(err)
	}

	next, err := second.NextCommand(context.Background(), pairing.DeviceID, newDeviceSession.Token, func() time.Time{return now})
	if err != nil {
		t.Fatal(err)
	}
	if next.RequestID != "req-durable" {
		t.Fatalf("next command %#v", next)
	}

	replayCommand := signedCommandForPairing(t, pairing, controllerPrivate, newControllerSession.AgentSessionID, "req-replay", "command-nonce-1", now)
	if err := second.QueuePairedCommand(pairing.DeviceID, newControllerSession.Token, replayCommand, now); !errors.Is(err, ErrCommandReplay) {
		t.Fatalf("command replay after restart: %v", err)
	}
	if err := second.SubmitResult(pairing.DeviceID, newDeviceSession.Token, Result{
		RequestID:"req-durable",
		Payload:[]byte(`{"status":"completed"}`),
	}, now); err != nil {
		t.Fatal(err)
	}

	third := durableStoreForTest(t, path, key)
	result, err := third.WaitResult(context.Background(), "req-durable")
	if err != nil {
		t.Fatal(err)
	}
	if string(result.Payload) != `{"status":"completed"}` {
		t.Fatalf("result %s", result.Payload)
	}
	if third.PairedControllerAuthorized(pairing.DeviceID, newControllerSession.Token, now) {
		t.Fatal("second controller session survived restart")
	}

	revokeAssertion := signedDeviceAssertion(t, device, pairing, now, "agent-session-durable", "device-nonce-3")
	revokeSession, err := third.AuthenticateDevice(revokeAssertion, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := third.RevokePairing(pairing.DeviceID, revokeSession.Token, now); err != nil {
		t.Fatal(err)
	}

	fourth := durableStoreForTest(t, path, key)
	if _, err := fourth.Pairing(pairing.DeviceID); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("pairing survived revoke: %v", err)
	}
	if _, err := fourth.WaitResult(context.Background(), "req-durable"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("old result survived revoke: %v", err)
	}
	bootstrap, err := fourth.Register(pairing.DeviceID, testRegistrationKey, now)
	if err != nil || bootstrap.Token == "" {
		t.Fatalf("fresh bootstrap after revoke: session=%#v err=%v", bootstrap, err)
	}
}

func TestDurableAgentSessionChangeDropsStaleQueuedCommands(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "relay-state.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	first := durableStoreForTest(t, path, key)
	device, pairing, controllerPrivate, _, controllerSession := durablePairedFixture(t, first, now)
	command := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-stale", "command-stale", now)
	if err := first.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, command, now); err != nil {
		t.Fatal(err)
	}

	second := durableStoreForTest(t, path, key)
	rotated := signedDeviceAssertion(t, device, pairing, now, "agent-session-rotated", "device-nonce-rotated")
	if _, err := second.AuthenticateDevice(rotated, now); err != nil {
		t.Fatal(err)
	}
	if _, err := second.RequestOwner("req-stale"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("stale request survived session rotation: %v", err)
	}

	third := durableStoreForTest(t, path, key)
	if _, err := third.RequestOwner("req-stale"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("stale request returned after second restart: %v", err)
	}
}

func TestDurableMutationRollsBackWhenStateWriteFails(t *testing.T) {
	now := time.Now().Truncate(time.Second)
	path := filepath.Join(t.TempDir(), "relay-state.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	store := durableStoreForTest(t, path, key)
	_, pairing, controllerPrivate, _, controllerSession := durablePairedFixture(t, store, now)

	command := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-rollback", "nonce-rollback", now)
	store.stateFile.maxBytes = 64
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, command, now); !errors.Is(err, ErrDurableStateTooLarge) {
		t.Fatalf("expected durable size failure, got %v", err)
	}
	if _, err := store.RequestOwner("req-rollback"); !errors.Is(err, ErrUnknownRequest) {
		t.Fatalf("request mutation was not rolled back: %v", err)
	}

	store.stateFile.maxBytes = 1 << 20
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, command, now); err != nil {
		t.Fatalf("same command should succeed after rollback: %v", err)
	}
}
