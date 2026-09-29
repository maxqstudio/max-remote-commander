package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

const testRegistrationKey = "controller-test-registration-key-0123456789"

func TestControllerRelayRoundTrip(t *testing.T) {
	now := time.Unix(1_800_000_000, 0)
	store, err := relay.NewStore(relay.Config{
		RegistrationKey: testRegistrationKey,
		SessionTTL: time.Minute,
		LeaseTTL: time.Second,
		MaxQueue: 4,
		MaxResults: 4,
		ControllerSessionTTL: time.Minute,
	})
	if err != nil {
		t.Fatal(err)
	}
	server := httptest.NewServer((&relay.HTTPServer{Store:store, Now:func() time.Time{return now}}).Handler())
	defer server.Close()

	client, err := NewClient(server.URL, nil)
	if err != nil {
		t.Fatal(err)
	}
	client.now = func() time.Time { return now }

	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	bootstrap, err := store.Register(device.ID(), testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}
	code, hash, err := identity.GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	if err := store.PublishPairingOffer(device.ID(), bootstrap.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}

	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	pairing, err := client.RedeemPairing(context.Background(), device.ID(), code, controllerPublic)
	if err != nil {
		t.Fatal(err)
	}
	if pairing.DeviceID != device.ID() || pairing.Generation == 0 {
		t.Fatalf("pairing %#v", pairing)
	}

	deviceAssertion := relay.DeviceAssertion{
		DeviceID: device.ID(),
		Generation: pairing.Generation,
		AgentSessionID: "agent-session-test",
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30*time.Second).Unix(),
		Nonce: "device-nonce",
	}
	if err := relay.SignDeviceAssertion(&deviceAssertion, device.PrivateKey()); err != nil {
		t.Fatal(err)
	}
	deviceSession, err := store.AuthenticateDevice(deviceAssertion, now)
	if err != nil {
		t.Fatal(err)
	}

	controllerSession, err := client.OpenSession(context.Background(), pairing, controllerPrivate)
	if err != nil {
		t.Fatal(err)
	}
	if controllerSession.AgentSessionID != deviceAssertion.AgentSessionID {
		t.Fatalf("controller bound to %q", controllerSession.AgentSessionID)
	}

	requestID := "req-controller-roundtrip"
	arguments := json.RawMessage(`{"path":"."}`)
	if err := client.QueueTool(context.Background(), controllerSession, controllerPrivate, requestID, "filesystem.list", arguments); err != nil {
		t.Fatal(err)
	}

	command, err := store.NextCommand(context.Background(), device.ID(), deviceSession.Token, func() time.Time{return now})
	if err != nil {
		t.Fatal(err)
	}
	if command.RequestID != requestID {
		t.Fatalf("command %#v", command)
	}
	if err := store.SubmitResult(device.ID(), deviceSession.Token, relay.Result{
		RequestID: requestID,
		Payload: []byte(`{"status":"completed","result":{"entries":[]}}`),
	}, now); err != nil {
		t.Fatal(err)
	}

	result, ok, err := client.WaitResult(context.Background(), controllerSession.Token, requestID)
	if err != nil {
		t.Fatal(err)
	}
	if !ok || string(result) != `{"status":"completed","result":{"entries":[]}}` {
		t.Fatalf("result ok=%v payload=%s", ok, result)
	}
}

func TestControllerRejectsInsecureRemoteRelayURL(t *testing.T) {
	if _, err := NewClient("http://example.com", nil); !errors.Is(err, ErrInsecureRelayURL) {
		t.Fatalf("got %v", err)
	}
	if _, err := NewClient("http://127.0.0.1:8787", nil); err != nil {
		t.Fatalf("loopback HTTP rejected: %v", err)
	}
}

func TestControllerQueueRejectsInvalidArguments(t *testing.T) {
	client, err := NewClient("http://127.0.0.1:8787", nil)
	if err != nil {
		t.Fatal(err)
	}
	_, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	err = client.QueueTool(context.Background(), relay.ControllerSession{
		Token: "token",
		DeviceID: "dev_test",
		Generation: 1,
		AgentSessionID: "session",
	}, privateKey, "req-1", "filesystem.read", json.RawMessage("{"))
	if !errors.Is(err, ErrRelayResponse) && !errors.Is(err, context.Canceled) {
		if !errors.Is(err, json.InvalidUnmarshalError{}) && err == nil {
			t.Fatal("invalid arguments accepted")
		}
	}
}
