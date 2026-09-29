package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func signedDeviceAssertion(t *testing.T, device *identity.Device, pairing Pairing, now time.Time, agentSessionID, nonce string) DeviceAssertion {
	t.Helper()
	assertion := DeviceAssertion{
		DeviceID: pairing.DeviceID,
		Generation: pairing.Generation,
		AgentSessionID: agentSessionID,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30 * time.Second).Unix(),
		Nonce: nonce,
	}
	if err := SignDeviceAssertion(&assertion, device.PrivateKey()); err != nil {
		t.Fatal(err)
	}
	return assertion
}

func authenticatePairingDevice(t *testing.T, store *Store, device *identity.Device, pairing Pairing, now time.Time, nonce string) Session {
	t.Helper()
	assertion := signedDeviceAssertion(t, device, pairing, now, "agent-session-1", nonce)
	session, err := store.AuthenticateDevice(assertion, now)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func TestPairedDeviceSessionRequiresPrivateKeyAndRejectsReplay(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	device, deviceID := pairingDevice(t)
	bootstrap := registerPairingDevice(t, store, deviceID, now)
	code, hash, _ := identity.GeneratePairingCode()
	if err := store.PublishPairingOffer(deviceID, bootstrap.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	controller := controllerPublicKey(t)
	pairing, err := store.RedeemPairing(deviceID, code, controller, now)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := store.Register(deviceID, testRegistrationKey, now); !errors.Is(err, ErrDeviceIdentityRequired) {
		t.Fatalf("bootstrap session after pairing: %v", err)
	}
	if store.sessionAuthorizedLocked(deviceID, bootstrap.Token, now) {
		t.Fatal("pre-pairing bootstrap session remained authorized")
	}

	assertion := signedDeviceAssertion(t, device, pairing, now, "agent-session-1", "device-nonce-1")
	session, err := store.AuthenticateDevice(assertion, now)
	if err != nil {
		t.Fatal(err)
	}
	if session.Generation != pairing.Generation || session.AgentSessionID != "agent-session-1" {
		t.Fatalf("session %#v", session)
	}
	if !store.sessionAuthorizedLocked(deviceID, session.Token, now) {
		t.Fatal("paired device session was not authorized")
	}
	if _, err := store.AuthenticateDevice(assertion, now); !errors.Is(err, ErrDeviceReplay) {
		t.Fatalf("assertion replay: %v", err)
	}

	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	wrong := DeviceAssertion{
		DeviceID: deviceID,
		Generation: pairing.Generation,
		AgentSessionID: "agent-session-2",
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30 * time.Second).Unix(),
		Nonce: "device-nonce-2",
	}
	if err := SignDeviceAssertion(&wrong, wrongPrivate); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateDevice(wrong, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong private key: %v", err)
	}
}

func TestDeviceAssertionLifetimeAndGenerationAreBound(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	device, deviceID := pairingDevice(t)
	bootstrap := registerPairingDevice(t, store, deviceID, now)
	code, hash, _ := identity.GeneratePairingCode()
	if err := store.PublishPairingOffer(deviceID, bootstrap.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	pairing, err := store.RedeemPairing(deviceID, code, controllerPublicKey(t), now)
	if err != nil {
		t.Fatal(err)
	}

	overlong := DeviceAssertion{
		DeviceID: deviceID,
		Generation: pairing.Generation,
		AgentSessionID: "agent-session-long",
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(2 * time.Minute).Unix(),
		Nonce: "device-nonce-long",
	}
	if err := SignDeviceAssertion(&overlong, device.PrivateKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateDevice(overlong, now); !errors.Is(err, ErrDeviceAssertion) {
		t.Fatalf("overlong assertion: %v", err)
	}

	staleGeneration := signedDeviceAssertion(t, device, pairing, now, "agent-session-old", "device-nonce-old")
	staleGeneration.Generation++
	if err := SignDeviceAssertion(&staleGeneration, device.PrivateKey()); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateDevice(staleGeneration, now); !errors.Is(err, ErrPairingGeneration) {
		t.Fatalf("wrong generation: %v", err)
	}
}
