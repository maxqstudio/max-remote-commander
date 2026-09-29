package relay

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/coder/websocket"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
)

func websocketURL(serverURL, path string) string {
	return "ws" + strings.TrimPrefix(serverURL, "http") + path
}

func TestDeviceStreamDeliversCommandsAndWaitsForHTTPResult(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	_, pairing, controllerPrivate, deviceSession, controllerSession := durablePairedFixture(t, store, now)
	server := httptest.NewServer((&HTTPServer{
		Store: store,
		Now: func() time.Time { return now },
		HeartbeatInterval: time.Hour,
	}).Handler())
	defer server.Close()

	header := make(http.Header)
	header.Set("Authorization", "Bearer "+deviceSession.Token)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, websocketURL(server.URL, "/v1/devices/"+pairing.DeviceID+"/stream"), &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		if response != nil {
			t.Fatalf("dial status %d: %v", response.StatusCode, err)
		}
		t.Fatal(err)
	}
	defer conn.CloseNow()

	first := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-ws-1", "nonce-ws-1", now)
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, first, now); err != nil {
		t.Fatal(err)
	}

	messageType, data, err := conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	if messageType != websocket.MessageText {
		t.Fatalf("message type %v", messageType)
	}
	message, err := protocol.DecodeStreamMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if message.RequestID != first.RequestID {
		t.Fatalf("message %#v", message)
	}

	if err := store.SubmitResult(pairing.DeviceID, deviceSession.Token, Result{
		RequestID: first.RequestID,
		Payload: []byte(`{"status":"completed"}`),
	}, now); err != nil {
		t.Fatal(err)
	}
	if _, err := store.WaitResult(ctx, first.RequestID); err != nil {
		t.Fatal(err)
	}

	second := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-ws-2", "nonce-ws-2", now)
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, second, now); err != nil {
		t.Fatal(err)
	}
	_, data, err = conn.Read(ctx)
	if err != nil {
		t.Fatal(err)
	}
	message, err = protocol.DecodeStreamMessage(data)
	if err != nil {
		t.Fatal(err)
	}
	if message.RequestID != second.RequestID {
		t.Fatalf("second message %#v", message)
	}
}

func TestDeviceStreamRejectsUnauthorizedHandshake(t *testing.T) {
	store := testStore(t)
	server := httptest.NewServer((&HTTPServer{Store: store}).Handler())
	defer server.Close()

	header := make(http.Header)
	header.Set("Authorization", "Bearer invalid")
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	conn, response, err := websocket.Dial(ctx, websocketURL(server.URL, "/v1/devices/device-missing/stream"), &websocket.DialOptions{HTTPHeader: header})
	if conn != nil {
		_ = conn.CloseNow()
	}
	if err == nil || response == nil || response.StatusCode != http.StatusUnauthorized {
		t.Fatalf("conn=%v response=%v err=%v", conn, response, err)
	}
}

func TestDeviceStreamHeartbeatClosesExpiredSession(t *testing.T) {
	store := testStore(t)
	start := time.Unix(1_800_000_000, 0)
	_, pairing, _, deviceSession, _ := durablePairedFixture(t, store, start)

	var mu sync.Mutex
	current := start
	now := func() time.Time {
		mu.Lock()
		defer mu.Unlock()
		return current
	}
	server := httptest.NewServer((&HTTPServer{
		Store: store,
		Now: now,
		HeartbeatInterval: 5 * time.Millisecond,
		HeartbeatTimeout: 100 * time.Millisecond,
	}).Handler())
	defer server.Close()

	header := make(http.Header)
	header.Set("Authorization", "Bearer "+deviceSession.Token)
	conn, _, err := websocket.Dial(context.Background(), websocketURL(server.URL, "/v1/devices/"+pairing.DeviceID+"/stream"), &websocket.DialOptions{HTTPHeader: header})
	if err != nil {
		t.Fatal(err)
	}
	defer conn.CloseNow()

	mu.Lock()
	current = start.Add(2 * time.Hour)
	mu.Unlock()

	errs := make(chan error, 1)
	go func() {
		_, _, err := conn.Read(context.Background())
		errs <- err
	}()
	select {
	case err := <-errs:
		if websocket.CloseStatus(err) != websocket.StatusPolicyViolation && !errors.Is(err, io.EOF) {
			t.Fatalf("close status %v: %v", websocket.CloseStatus(err), err)
		}
	case <-time.After(time.Second):
		t.Fatal("stream remained open after device session expiry")
	}
}

func TestSubmitResultWakesStreamAfterReconnectLease(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	_, pairing, controllerPrivate, deviceSession, controllerSession := durablePairedFixture(t, store, now)
	first := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-lease-1", "nonce-lease-1", now)
	second := signedCommandForPairing(t, pairing, controllerPrivate, controllerSession.AgentSessionID, "req-lease-2", "nonce-lease-2", now)
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, first, now); err != nil {
		t.Fatal(err)
	}
	if err := store.QueuePairedCommand(pairing.DeviceID, controllerSession.Token, second, now); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	leased, err := store.NextCommand(ctx, pairing.DeviceID, deviceSession.Token, func() time.Time { return now })
	cancel()
	if err != nil || leased.RequestID != first.RequestID {
		t.Fatalf("leased=%#v err=%v", leased, err)
	}

	waitCtx, waitCancel := context.WithTimeout(context.Background(), time.Second)
	defer waitCancel()
	next := make(chan Command, 1)
	errs := make(chan error, 1)
	go func() {
		command, err := store.NextCommand(waitCtx, pairing.DeviceID, deviceSession.Token, func() time.Time { return now })
		if err != nil {
			errs <- err
			return
		}
		next <- command
	}()

	if err := store.SubmitResult(pairing.DeviceID, deviceSession.Token, Result{RequestID: first.RequestID, Payload: json.RawMessage(`{"ok":true}`)}, now); err != nil {
		t.Fatal(err)
	}
	select {
	case command := <-next:
		if command.RequestID != second.RequestID {
			t.Fatalf("next %#v", command)
		}
	case err := <-errs:
		t.Fatal(err)
	case <-waitCtx.Done():
		t.Fatal("next command was not woken after prior result")
	}
}
