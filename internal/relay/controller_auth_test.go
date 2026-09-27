package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func pairedControllerFixture(t *testing.T, store *Store, now time.Time) (*identity.Device, Session, ed25519.PublicKey, ed25519.PrivateKey, Pairing) {
	t.Helper()
	device, deviceID := pairingDevice(t)
	session := registerPairingDevice(t, store, deviceID, now)
	code, hash, err := identity.GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PublishPairingOffer(deviceID, session.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := store.RedeemPairing(deviceID, code, pub, now)
	if err != nil {
		t.Fatal(err)
	}
	return device, session, pub, priv, pairing
}

func signedControllerAssertion(t *testing.T, pairing Pairing, privateKey ed25519.PrivateKey, now time.Time, nonce string) ControllerAssertion {
	t.Helper()
	assertion := ControllerAssertion{
		DeviceID: pairing.DeviceID,
		Generation: pairing.Generation,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30*time.Second).Unix(),
		Nonce: nonce,
	}
	if err := SignControllerAssertion(&assertion, privateKey); err != nil {
		t.Fatal(err)
	}
	return assertion
}

func TestControllerSessionRequiresPairedPrivateKeyAndRejectsReplay(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	_, _, _, privateKey, pairing := pairedControllerFixture(t, store, now)
	assertion := signedControllerAssertion(t, pairing, privateKey, now, "nonce-1")

	session, err := store.AuthenticateController(assertion, now)
	if err != nil {
		t.Fatal(err)
	}
	if !store.PairedControllerAuthorized(pairing.DeviceID, session.Token, now) {
		t.Fatal("issued controller token was not authorized")
	}
	if _, err := store.AuthenticateController(assertion, now); !errors.Is(err, ErrControllerReplay) {
		t.Fatalf("assertion replay: %v", err)
	}

	_, wrongPrivate, _ := ed25519.GenerateKey(rand.Reader)
	wrong := signedControllerAssertion(t, pairing, wrongPrivate, now, "nonce-2")
	if _, err := store.AuthenticateController(wrong, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong key: %v", err)
	}
}

func TestControllerSessionExpiresAndIsDeviceBound(t *testing.T) {
	store, err := NewStore(Config{
		RegistrationKey: testRegistrationKey,
		ControllerKey: testControllerKey,
		SessionTTL: time.Minute,
		LeaseTTL: time.Second,
		MaxQueue: 4,
		MaxResults: 4,
		ControllerSessionTTL: time.Second,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	_, _, _, privateKey, pairing := pairedControllerFixture(t, store, now)
	assertion := signedControllerAssertion(t, pairing, privateKey, now, "nonce-1")
	session, err := store.AuthenticateController(assertion, now)
	if err != nil {
		t.Fatal(err)
	}
	if store.PairedControllerAuthorized("other-device", session.Token, now) {
		t.Fatal("controller token crossed device boundary")
	}
	if store.PairedControllerAuthorized(pairing.DeviceID, session.Token, now.Add(time.Second)) {
		t.Fatal("expired controller token remained valid")
	}
}

func TestRevocationInvalidatesControllerSessionAndGeneration(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	device, deviceSession, _, privateKey, pairing := pairedControllerFixture(t, store, now)
	assertion := signedControllerAssertion(t, pairing, privateKey, now, "nonce-1")
	controllerSession, err := store.AuthenticateController(assertion, now)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.RevokePairing(pairing.DeviceID, deviceSession.Token, now); err != nil {
		t.Fatal(err)
	}
	if store.PairedControllerAuthorized(pairing.DeviceID, controllerSession.Token, now) {
		t.Fatal("revoked controller token remained authorized")
	}

	code, hash, _ := identity.GeneratePairingCode()
	if err := store.PublishPairingOffer(pairing.DeviceID, deviceSession.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	pub2, priv2, _ := ed25519.GenerateKey(rand.Reader)
	second, err := store.RedeemPairing(pairing.DeviceID, code, pub2, now)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation <= pairing.Generation {
		t.Fatalf("generation did not advance: %d -> %d", pairing.Generation, second.Generation)
	}

	oldGenerationAssertion := signedControllerAssertion(t, pairing, privateKey, now, "nonce-old-generation")
	if _, err := store.AuthenticateController(oldGenerationAssertion, now); !errors.Is(err, ErrPairingGeneration) {
		t.Fatalf("old generation: %v", err)
	}
	newAssertion := signedControllerAssertion(t, second, priv2, now, "nonce-new")
	if _, err := store.AuthenticateController(newAssertion, now); err != nil {
		t.Fatalf("new pairing authentication: %v", err)
	}
}

func TestControllerAssertionLifetimeIsBounded(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	_, _, _, privateKey, pairing := pairedControllerFixture(t, store, now)
	assertion := ControllerAssertion{
		DeviceID: pairing.DeviceID,
		Generation: pairing.Generation,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(2*time.Minute).Unix(),
		Nonce: "nonce-long",
	}
	if err := SignControllerAssertion(&assertion, privateKey); err != nil {
		t.Fatal(err)
	}
	if _, err := store.AuthenticateController(assertion, now); !errors.Is(err, ErrControllerAssertion) {
		t.Fatalf("overlong assertion: %v", err)
	}
}
