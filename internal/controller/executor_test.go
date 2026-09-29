package controller

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

type executorFixture struct {
	store            *relay.Store
	server           *httptest.Server
	client           *Client
	executor         *RemoteExecutor
	device           *identity.Device
	deviceSession    relay.Session
	pairing          Pairing
	controllerPrivate ed25519.PrivateKey
	now              time.Time
}

func newExecutorFixture(t *testing.T) *executorFixture {
	t.Helper()
	now := time.Unix(1_800_000_000, 0)
	store, err := relay.NewStore(relay.Config{
		RegistrationKey:testRegistrationKey,
		SessionTTL:time.Minute,
		LeaseTTL:time.Second,
		MaxQueue:4,
		MaxResults:4,
		ControllerSessionTTL:time.Minute,
	})
	if err != nil { t.Fatal(err) }
	server := httptest.NewServer((&relay.HTTPServer{Store:store, Now:func() time.Time{return now}}).Handler())
	t.Cleanup(server.Close)

	client, err := NewClient(server.URL, nil)
	if err != nil { t.Fatal(err) }
	client.now = func() time.Time { return now }

	device, err := identity.New()
	if err != nil { t.Fatal(err) }
	bootstrap, err := store.Register(device.ID(), testRegistrationKey, now)
	if err != nil { t.Fatal(err) }
	code, hash, err := identity.GeneratePairingCode()
	if err != nil { t.Fatal(err) }
	if err := store.PublishPairingOffer(device.ID(), bootstrap.Token, hash, device.PublicKey(), time.Minute, now); err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil { t.Fatal(err) }
	pairing, err := client.RedeemPairing(context.Background(), device.ID(), code, controllerPublic)
	if err != nil { t.Fatal(err) }

	deviceSession := authenticateTestDevice(t, store, device, pairing, "agent-session-1", "device-nonce-1", now)
	executor, err := NewRemoteExecutor(client, pairing, controllerPrivate)
	if err != nil { t.Fatal(err) }

	return &executorFixture{
		store:store, server:server, client:client, executor:executor, device:device,
		deviceSession:deviceSession, pairing:pairing, controllerPrivate:controllerPrivate, now:now,
	}
}

func authenticateTestDevice(t *testing.T, store *relay.Store, device *identity.Device, pairing Pairing, sessionID, nonce string, now time.Time) relay.Session {
	t.Helper()
	assertion := relay.DeviceAssertion{
		DeviceID:device.ID(),
		Generation:pairing.Generation,
		AgentSessionID:sessionID,
		IssuedAt:now.Unix(),
		ExpiresAt:now.Add(30*time.Second).Unix(),
		Nonce:nonce,
	}
	if err := relay.SignDeviceAssertion(&assertion, device.PrivateKey()); err != nil { t.Fatal(err) }
	session, err := store.AuthenticateDevice(assertion, now)
	if err != nil { t.Fatal(err) }
	return session
}

func completeNextCommand(t *testing.T, fixture *executorFixture, deviceSession relay.Session, payload string) <-chan error {
	t.Helper()
	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		command, err := fixture.store.NextCommand(ctx, fixture.device.ID(), deviceSession.Token, func() time.Time{return fixture.now})
		if err != nil {
			done <- err
			return
		}
		done <- fixture.store.SubmitResult(fixture.device.ID(), deviceSession.Token, relay.Result{
			RequestID:command.RequestID,
			Payload:[]byte(payload),
		}, fixture.now)
	}()
	return done
}

func TestRemoteExecutorRunsSignedToolRoundTrip(t *testing.T) {
	fixture := newExecutorFixture(t)
	done := completeNextCommand(t, fixture, fixture.deviceSession, `{"status":"completed"}`)
	result, err := fixture.executor.Execute(context.Background(), "filesystem.list", json.RawMessage(`{"path":"."}`))
	if err != nil { t.Fatal(err) }
	if string(result) != `{"status":"completed"}` { t.Fatalf("result %s", result) }
	if err := <-done; err != nil { t.Fatal(err) }
}

func TestRemoteExecutorRefreshesAfterAgentSessionChange(t *testing.T) {
	fixture := newExecutorFixture(t)

	// Prime a controller session bound to agent-session-1.
	if _, err := fixture.executor.ensureSession(context.Background(), false); err != nil { t.Fatal(err) }

	deviceSession2 := authenticateTestDevice(t, fixture.store, fixture.device, fixture.pairing, "agent-session-2", "device-nonce-2", fixture.now)
	done := completeNextCommand(t, fixture, deviceSession2, `{"status":"completed","refreshed":true}`)

	result, err := fixture.executor.Execute(context.Background(), "git.status", json.RawMessage(`{}`))
	if err != nil { t.Fatal(err) }
	if string(result) != `{"status":"completed","refreshed":true}` { t.Fatalf("result %s", result) }
	if err := <-done; err != nil { t.Fatal(err) }

	fixture.executor.mu.Lock()
	sessionID := fixture.executor.session.AgentSessionID
	fixture.executor.mu.Unlock()
	if sessionID != "agent-session-2" {
		t.Fatalf("controller session stayed on %q", sessionID)
	}
}
