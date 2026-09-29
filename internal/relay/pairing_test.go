package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func pairingDevice(t *testing.T) (*identity.Device, string) {
	t.Helper()
	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	return device, device.ID()
}

func registerPairingDevice(t *testing.T, store *Store, deviceID string, now time.Time) Session {
	t.Helper()
	session, err := store.Register(deviceID, testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}
	return session
}

func controllerPublicKey(t *testing.T) ed25519.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return pub
}

func TestPairingOfferRequiresOwningSessionAndMatchingDeviceKey(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	device, deviceID := pairingDevice(t)
	session := registerPairingDevice(t, store, deviceID, now)
	code, hash, err := identity.GeneratePairingCode()
	if err != nil || code == "" {
		t.Fatal(err)
	}

	if err := store.PublishPairingOffer(deviceID, "wrong", hash, device.PublicKey(), time.Minute, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("wrong session: %v", err)
	}

	other, _ := identity.New()
	if err := store.PublishPairingOffer(deviceID, session.Token, hash, other.PublicKey(), time.Minute, now); !errors.Is(err, ErrPairingMismatch) {
		t.Fatalf("wrong key: %v", err)
	}

	if err := store.PublishPairingOffer(deviceID, session.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
}

func TestPairingCodeIsOneUseAndControllerKeyIsBound(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	device, deviceID := pairingDevice(t)
	session := registerPairingDevice(t, store, deviceID, now)
	code, hash, _ := identity.GeneratePairingCode()
	if err := store.PublishPairingOffer(deviceID, session.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	controller := controllerPublicKey(t)
	pairing, err := store.RedeemPairing(deviceID, code, controller, now)
	if err != nil {
		t.Fatal(err)
	}
	if pairing.DeviceID != deviceID || pairing.Generation == 0 {
		t.Fatalf("pairing %#v", pairing)
	}
	if string(pairing.ControllerPublicKey) != string(controller) {
		t.Fatal("controller public key not bound")
	}
	if _, err := store.RedeemPairing(deviceID, code, controller, now); !errors.Is(err, ErrAlreadyPaired) {
		t.Fatalf("pairing code replay: %v", err)
	}
}

func TestPairingOfferExpiresAndLocksAfterFailedAttempts(t *testing.T) {
	store, err := NewStore(Config{
		RegistrationKey: testRegistrationKey,
		SessionTTL: time.Minute,
		LeaseTTL: time.Second,
		MaxQueue: 4,
		MaxResults: 4,
		MaxPairingAttempts: 2,
	})
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	device, deviceID := pairingDevice(t)
	session := registerPairingDevice(t, store, deviceID, now)
	code, hash, _ := identity.GeneratePairingCode()
	controller := controllerPublicKey(t)

	if err := store.PublishPairingOffer(deviceID, session.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemPairing(deviceID, code+"X", controller, now); !errors.Is(err, ErrPairingCodeInvalid) {
		t.Fatalf("attempt 1: %v", err)
	}
	if _, err := store.RedeemPairing(deviceID, code+"Y", controller, now); !errors.Is(err, ErrPairingAttempts) {
		t.Fatalf("attempt 2: %v", err)
	}
	if _, err := store.RedeemPairing(deviceID, code, controller, now); !errors.Is(err, ErrPairingOfferMissing) {
		t.Fatalf("offer remained after lockout: %v", err)
	}

	_, hash, _ = identity.GeneratePairingCode()
	if err := store.PublishPairingOffer(deviceID, session.Token, hash, device.PublicKey(), time.Second, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.RedeemPairing(deviceID, "anything", controller, now.Add(time.Second)); !errors.Is(err, ErrPairingOfferExpired) {
		t.Fatalf("expired: %v", err)
	}
}

func TestRevocationRequiresDeviceSessionAndAllowsFreshPairing(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	device, deviceID := pairingDevice(t)
	session := registerPairingDevice(t, store, deviceID, now)
	code, hash, _ := identity.GeneratePairingCode()
	if err := store.PublishPairingOffer(deviceID, session.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	first, err := store.RedeemPairing(deviceID, code, controllerPublicKey(t), now)
	if err != nil {
		t.Fatal(err)
	}
	pairedSession := authenticatePairingDevice(t, store, device, first, now, "revoke-device-nonce")
	if err := store.RevokePairing(deviceID, "wrong", now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("unauthorized revoke: %v", err)
	}
	if err := store.RevokePairing(deviceID, pairedSession.Token, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.Pairing(deviceID); !errors.Is(err, ErrNotPaired) {
		t.Fatalf("still paired: %v", err)
	}

	bootstrapAgain, err := store.Register(deviceID, testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}
	code2, hash2, _ := identity.GeneratePairingCode()
	if err := store.PublishPairingOffer(deviceID, bootstrapAgain.Token, hash2, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	second, err := store.RedeemPairing(deviceID, code2, controllerPublicKey(t), now)
	if err != nil {
		t.Fatal(err)
	}
	if second.Generation <= first.Generation {
		t.Fatalf("generation did not advance: %d -> %d", first.Generation, second.Generation)
	}
}
