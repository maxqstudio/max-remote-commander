package relay

import (
	"bufio"
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
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
	req.Header.Set("Authorization", "Bearer "+token)
	if body != nil {
		req.Header.Set("Content-Type", "application/json")
	}
	return req
}

func TestHTTPRelayRoundTripAndSSE(t *testing.T) {
	store := testStore(t)
	now := time.Unix(1_800_000_000, 0)
	server := httptest.NewServer((&HTTPServer{Store:store, Now:func() time.Time{return now}}).Handler())
	defer server.Close()

	registerReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/device-a/session", testRegistrationKey, nil)
	registerResp, err := http.DefaultClient.Do(registerReq)
	if err != nil {
		t.Fatal(err)
	}
	defer registerResp.Body.Close()
	if registerResp.StatusCode != http.StatusCreated {
		t.Fatalf("register status %d", registerResp.StatusCode)
	}
	var session Session
	if err := json.NewDecoder(registerResp.Body).Decode(&session); err != nil {
		t.Fatal(err)
	}

	queueReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/device-a/commands", testControllerKey, map[string]any{
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

	pollReq := authRequest(t, http.MethodGet, server.URL+"/v1/devices/device-a/commands/next?wait_ms=100", session.Token, nil)
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
	sseReq := authRequest(t, http.MethodGet, server.URL+"/v1/results/req-http/events", testControllerKey, nil).WithContext(sseCtx)
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
		sseResult <- line + line2
	}()

	resultReq := authRequest(t, http.MethodPost, server.URL+"/v1/devices/device-a/results", session.Token, map[string]any{
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
