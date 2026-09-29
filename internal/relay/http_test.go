package relay

import (
	"bufio"
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func authRequest(t *testing.T, method, url, token string, body any) *http.Request {
	t.Helper()
	var reader io.Reader
	if body != nil {
		data, err := json.Marshal(body)
		if err != nil {
			t.Fatal(err)
		}
		reader = bytes.NewReader(data)
	}
	req, err := http.NewRequest(method, url, reader)
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func decodeJSONResponse(t *testing.T, resp *http.Response, target any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(target); err != nil {
		t.Fatal(err)
	}
}

func TestHTTPPairedRelayRoundTripAndNoBootstrapControllerBypass(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	server := httptest.NewServer((&HTTPServer{Store:store, Now:func() time.Time{return now}}).Handler())
	defer server.Close()

	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	deviceID := device.ID()
	registerReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/bootstrap-session", testRegistrationKey, nil)
	registerResp, err := http.DefaultClient.Do(registerReq)
	if err != nil {
		t.Fatal(err)
	}
	if registerResp.StatusCode != http.StatusCreated {
		t.Fatalf("register status %d", registerResp.StatusCode)
	}
	var bootstrapSession Session
	decodeJSONResponse(t, registerResp, &bootstrapSession)

	code, codeHash, err := identity.GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	offerReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/pairing-offer", bootstrapSession.Token, map[string]any{
		"code_hash": base64.RawURLEncoding.EncodeToString(codeHash[:]),
		"device_public_key": base64.RawURLEncoding.EncodeToString(device.PublicKey()),
		"ttl_seconds": 60,
	})
	offerResp, err := http.DefaultClient.Do(offerReq)
	if err != nil {
		t.Fatal(err)
	}
	offerResp.Body.Close()
	if offerResp.StatusCode != http.StatusCreated {
		t.Fatalf("offer status %d", offerResp.StatusCode)
	}

	controllerPub, controllerPriv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	redeemReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/pairing/redeem", "", map[string]any{
		"code": code,
		"controller_public_key": base64.RawURLEncoding.EncodeToString(controllerPub),
	})
	redeemResp, err := http.DefaultClient.Do(redeemReq)
	if err != nil {
		t.Fatal(err)
	}
	if redeemResp.StatusCode != http.StatusCreated {
		t.Fatalf("redeem status %d", redeemResp.StatusCode)
	}
	var paired map[string]any
	decodeJSONResponse(t, redeemResp, &paired)
	generation := uint64(paired["generation"].(float64))

	bootstrapPoll := authRequest(t, http.MethodGet, server.URL+"/v1/devices/"+deviceID+"/commands/next?wait_ms=1", bootstrapSession.Token, nil)
	bootstrapPollResp, err := http.DefaultClient.Do(bootstrapPoll)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapPollResp.Body.Close()
	if bootstrapPollResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("old bootstrap device session remained valid: %d", bootstrapPollResp.StatusCode)
	}

	deviceAssertion := DeviceAssertion{
		DeviceID: deviceID,
		Generation: generation,
		AgentSessionID: "http-agent-session",
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30*time.Second).Unix(),
		Nonce: "http-device-nonce",
	}
	if err := SignDeviceAssertion(&deviceAssertion, device.PrivateKey()); err != nil {
		t.Fatal(err)
	}
	deviceSessionReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/session", "", deviceAssertion)
	deviceSessionResp, err := http.DefaultClient.Do(deviceSessionReq)
	if err != nil {
		t.Fatal(err)
	}
	if deviceSessionResp.StatusCode != http.StatusCreated {
		t.Fatalf("device session status %d", deviceSessionResp.StatusCode)
	}
	var deviceSession Session
	decodeJSONResponse(t, deviceSessionResp, &deviceSession)

	rebootstrapReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/bootstrap-session", testRegistrationKey, nil)
	rebootstrapResp, err := http.DefaultClient.Do(rebootstrapReq)
	if err != nil {
		t.Fatal(err)
	}
	rebootstrapResp.Body.Close()
	if rebootstrapResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("paired device accepted shared bootstrap key: %d", rebootstrapResp.StatusCode)
	}

	assertion := ControllerAssertion{
		DeviceID: deviceID,
		Generation: generation,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30*time.Second).Unix(),
		Nonce: "http-controller-nonce",
	}
	if err := SignControllerAssertion(&assertion, controllerPriv); err != nil {
		t.Fatal(err)
	}
	controllerReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/controller-session", "", assertion)
	controllerResp, err := http.DefaultClient.Do(controllerReq)
	if err != nil {
		t.Fatal(err)
	}
	if controllerResp.StatusCode != http.StatusCreated {
		t.Fatalf("controller session status %d", controllerResp.StatusCode)
	}
	var controllerSession ControllerSession
	decodeJSONResponse(t, controllerResp, &controllerSession)

	bootstrapQueue := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/commands", testControllerKey, map[string]any{
		"request_id":"req-bootstrap",
		"payload":map[string]any{"tool":"filesystem.read"},
	})
	bootstrapResp, err := http.DefaultClient.Do(bootstrapQueue)
	if err != nil {
		t.Fatal(err)
	}
	bootstrapResp.Body.Close()
	if bootstrapResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("bootstrap controller bypass status %d", bootstrapResp.StatusCode)
	}

	queueReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/commands", controllerSession.Token, map[string]any{
		"request_id":"req-http",
		"payload":map[string]any{"tool":"filesystem.read"},
	})
	queueResp, err := http.DefaultClient.Do(queueReq)
	if err != nil {
		t.Fatal(err)
	}
	queueResp.Body.Close()
	if queueResp.StatusCode != http.StatusAccepted {
		t.Fatalf("queue status %d", queueResp.StatusCode)
	}

	pollReq := authRequest(t, http.MethodGet, server.URL+"/v1/devices/"+deviceID+"/commands/next?wait_ms=100", deviceSession.Token, nil)
	pollResp, err := http.DefaultClient.Do(pollReq)
	if err != nil {
		t.Fatal(err)
	}
	defer pollResp.Body.Close()
	if pollResp.StatusCode != http.StatusOK {
		t.Fatalf("poll status %d", pollResp.StatusCode)
	}
	var command commandBody
	if err := json.NewDecoder(pollResp.Body).Decode(&command); err != nil {
		t.Fatal(err)
	}
	if command.RequestID != "req-http" {
		t.Fatalf("command %#v", command)
	}

	sseCtx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	sseReq := authRequest(t, http.MethodGet, server.URL+"/v1/results/req-http/events", controllerSession.Token, nil).WithContext(sseCtx)
	sseResult := make(chan string, 1)
	go func() {
		resp, err := http.DefaultClient.Do(sseReq)
		if err != nil {
			sseResult <- "ERR:" + err.Error()
			return
		}
		defer resp.Body.Close()
		reader := bufio.NewReader(resp.Body)
		line, _ := reader.ReadString('\n')
		line2, _ := reader.ReadString('\n')
		line3, _ := reader.ReadString('\n')
		sseResult <- line + line2 + line3
	}()

	resultReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/results", deviceSession.Token, map[string]any{
		"request_id":"req-http",
		"payload":map[string]any{"ok":true},
	})
	resultResp, err := http.DefaultClient.Do(resultReq)
	if err != nil {
		t.Fatal(err)
	}
	resultResp.Body.Close()
	if resultResp.StatusCode != http.StatusAccepted {
		t.Fatalf("result status %d", resultResp.StatusCode)
	}

	select {
	case got := <-sseResult:
		want := base64.RawURLEncoding.EncodeToString([]byte(`{"ok":true}`))
		if !strings.Contains(got, "event: result") || !strings.Contains(got, want) {
			t.Fatalf("SSE %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("timed out waiting for SSE")
	}

	revokeReq := authRequest(t, http.MethodDelete, server.URL+"/v1/devices/"+deviceID+"/pairing", deviceSession.Token, nil)
	revokeResp, err := http.DefaultClient.Do(revokeReq)
	if err != nil {
		t.Fatal(err)
	}
	revokeResp.Body.Close()
	if revokeResp.StatusCode != http.StatusNoContent {
		t.Fatalf("revoke status %d", revokeResp.StatusCode)
	}
	afterRevoke := authRequest(t, http.MethodPost, server.URL+"/v1/devices/"+deviceID+"/commands", controllerSession.Token, map[string]any{
		"request_id":"req-after-revoke",
		"payload":map[string]any{"tool":"filesystem.read"},
	})
	afterResp, err := http.DefaultClient.Do(afterRevoke)
	if err != nil {
		t.Fatal(err)
	}
	afterResp.Body.Close()
	if afterResp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("revoked controller status %d", afterResp.StatusCode)
	}
}

func TestHTTPRejectsCrossDeviceSession(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	a, _ := store.Register("device-a", testRegistrationKey, now)
	server := httptest.NewServer((&HTTPServer{Store:store, Now:func() time.Time{return now}}).Handler())
	defer server.Close()

	req := authRequest(t, http.MethodGet, server.URL+"/v1/devices/device-b/commands/next?wait_ms=1", a.Token, nil)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusUnauthorized {
		t.Fatalf("status %d", resp.StatusCode)
	}
}
