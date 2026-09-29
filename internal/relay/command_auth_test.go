package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
)

func signedCommandForPairing(t *testing.T, pairing Pairing, privateKey ed25519.PrivateKey, sessionID, requestID, nonce string, now time.Time) Command {
	t.Helper()
	envelope := protocol.CommandEnvelope{
		Version: protocol.CurrentVersion,
		RequestID: requestID,
		DeviceID: pairing.DeviceID,
		SessionID: sessionID,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Nonce: nonce,
		Tool: "filesystem.read",
		Arguments: json.RawMessage(`{"path":"note.txt"}`),
	}
	if err := envelope.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	payload, err := json.Marshal(envelope)
	if err != nil {
		t.Fatal(err)
	}
	return Command{RequestID: requestID, Payload: payload}
}

func TestQueuePairedCommandRequiresCurrentAgentSessionAndRejectsReplay(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	device, _, _, controllerPrivate, pairing := pairedControllerFixture(t, store, now)

	controllerAssertion := signedControllerAssertion(t, pairing, controllerPrivate, now, "controller-command-session")
	controllerSession, err := store.AuthenticateController(controllerAssertion, now)
	if err != nil {
		t.Fatal(err)
	}

	command := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-signed", "command-nonce-1", now)
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, command, now); err != nil {
		t.Fatal(err)
	}

	replay := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-replay", "command-nonce-1", now)
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, replay, now); !errors.Is(err, ErrCommandReplay) {
		t.Fatalf("replay: %v", err)
	}

	newAssertion := signedDeviceAssertion(t, device, pairing, now, "agent-session-rotated", "device-session-rotate")
	if _, err := store.AuthenticateDevice(newAssertion, now); err != nil {
		t.Fatal(err)
	}
	stale := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-stale", "command-nonce-stale", now)
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, stale, now); !errors.Is(err, ErrUnauthorized) {
		t.Fatalf("stale controller session: %v", err)
	}
}

func TestQueuePairedCommandRejectsWrongControllerSignature(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	_, _, _, controllerPrivate, pairing := pairedControllerFixture(t, store, now)
	assertion := signedControllerAssertion(t, pairing, controllerPrivate, now, "controller-command-session-2")
	controllerSession, err := store.AuthenticateController(assertion, now)
	if err != nil {
		t.Fatal(err)
	}
	_, wrongPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	command := signedCommandForPairing(t, pairing, wrongPrivate, controllerSession.AgentSessionID, "req-wrong-sig", "command-nonce-wrong", now)
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, command, now); !errors.Is(err, ErrInvalidCommandEnvelope) {
		t.Fatalf("wrong signature: %v", err)
	}
}

func TestPairingDeviceHelperStillUsesIdentityPackage(t *testing.T) {
	device, err := identity.New()
	if err != nil || device.ID() == "" {
		t.Fatalf("device identity unavailable: %v", err)
	}
}
