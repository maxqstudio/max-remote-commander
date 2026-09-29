package relay

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"errors"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func durableTestState(t *testing.T, now time.Time) durableState {
	t.Helper()
	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	deviceID := device.ID()
	return durableState{
		Version: durableStateVersion,
		Pairings: []durablePairing{{
			DeviceID: deviceID,
			DevicePublicKey: base64.RawURLEncoding.EncodeToString(device.PublicKey()),
			ControllerPublicKey: base64.RawURLEncoding.EncodeToString(controllerPublic),
			Generation: 2,
			PairedAt: now,
		}},
		PairingGeneration: map[string]uint64{deviceID:2},
		Queues: map[string][]Command{
			deviceID: {{RequestID:"req-queued", Payload:[]byte(`{"signed":true}`)}},
		},
		Requests: map[string]string{
			"req-queued":deviceID,
			"req-result":deviceID,
		},
		Results: map[string]Result{
			"req-result":{RequestID:"req-result", Payload:[]byte(`{"status":"completed"}`)},
		},
		ResultOrder: []string{"req-result"},
		DeviceNonces: []durableDeviceNonce{{
			DeviceID:deviceID, Generation:2, Nonce:"device-nonce", ExpiresAt:now.Add(time.Minute).Unix(),
		}},
		ControllerNonces: []durableControllerNonce{{
			DeviceID:deviceID, Generation:2, Nonce:"controller-nonce", ExpiresAt:now.Add(time.Minute).Unix(),
		}},
		CommandNonces: []durableCommandNonce{{
			DeviceID:deviceID, Nonce:"command-nonce", ExpiresAt:now.Add(time.Minute).Unix(),
		}},
	}
}

func TestStateFileEncryptedRoundTripAndReplace(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "relay-state.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	file, err := newStateFile(path, key, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	first := durableTestState(t, now)
	if err := file.Save(first); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) == "" || string(raw) == string(first.Queues[first.Pairings[0].DeviceID][0].Payload) {
		t.Fatal("state file was not encrypted")
	}
	loaded, ok, err := file.Load(now, 4, 4)
	if err != nil || !ok {
		t.Fatalf("load ok=%v err=%v", ok, err)
	}
	if len(loaded.Pairings) != 1 || len(loaded.Queues) != 1 || len(loaded.Results) != 1 {
		t.Fatalf("loaded %#v", loaded)
	}

	second := durableTestState(t, now.Add(time.Second))
	second.Results["req-result"] = Result{RequestID:"req-result", Payload:[]byte(`{"status":"updated"}`)}
	if err := file.Save(second); err != nil {
		t.Fatal(err)
	}
	loaded, ok, err = file.Load(now, 4, 4)
	if err != nil || !ok {
		t.Fatalf("reload ok=%v err=%v", ok, err)
	}
	if string(loaded.Results["req-result"].Payload) != `{"status":"updated"}` {
		t.Fatalf("result %s", loaded.Results["req-result"].Payload)
	}
}

func TestStateFileRejectsWrongKeyAndCorruption(t *testing.T) {
	now := time.Now()
	path := filepath.Join(t.TempDir(), "relay-state.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	file, _ := newStateFile(path, key, 1<<20)
	if err := file.Save(durableTestState(t, now)); err != nil {
		t.Fatal(err)
	}

	wrong := make([]byte, 32)
	if _, err := rand.Read(wrong); err != nil {
		t.Fatal(err)
	}
	wrongFile, _ := newStateFile(path, wrong, 1<<20)
	if _, _, err := wrongFile.Load(now, 4, 4); !errors.Is(err, ErrDurableStateCorrupt) {
		t.Fatalf("wrong key: %v", err)
	}

	if err := os.WriteFile(path, []byte("{not-json"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, _, err := file.Load(now, 4, 4); !errors.Is(err, ErrDurableStateCorrupt) {
		t.Fatalf("corrupt: %v", err)
	}
}

func TestStateFileRejectsOversizeAndUnsafePath(t *testing.T) {
	now := time.Now()
	dir := t.TempDir()
	path := filepath.Join(dir, "relay-state.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	small, _ := newStateFile(path, key, 64)
	if err := small.Save(durableTestState(t, now)); !errors.Is(err, ErrDurableStateTooLarge) {
		t.Fatalf("oversize: %v", err)
	}

	if runtime.GOOS != "windows" {
		target := filepath.Join(dir, "target")
		if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, path); err != nil {
			t.Fatal(err)
		}
		full, _ := newStateFile(path, key, 1<<20)
		if _, _, err := full.Load(now, 4, 4); !errors.Is(err, ErrDurableStateSymlink) {
			t.Fatalf("symlink load: %v", err)
		}
		if err := full.Save(durableTestState(t, now)); !errors.Is(err, ErrDurableStateSymlink) {
			t.Fatalf("symlink save: %v", err)
		}
	}
}

func TestStateFileRejectsBroadPOSIXPermissions(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX mode bits are not authoritative on Windows")
	}
	now := time.Now()
	path := filepath.Join(t.TempDir(), "relay-state.json")
	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	file, _ := newStateFile(path, key, 1<<20)
	if err := file.Save(durableTestState(t, now)); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0o644); err != nil {
		t.Fatal(err)
	}
	if _, _, err := file.Load(now, 4, 4); !errors.Is(err, ErrDurableStatePerms) {
		t.Fatalf("permissions: %v", err)
	}
}

func TestDurableSnapshotExcludesSessions(t *testing.T) {
	store := testStore(t)
	now := time.Now()
	session, err := store.Register("device-a", testRegistrationKey, now)
	if err != nil {
		t.Fatal(err)
	}
	if session.Token == "" {
		t.Fatal("missing session")
	}
	store.mu.Lock()
	state := store.durableStateLocked()
	store.mu.Unlock()
	if len(state.Pairings) != 0 || len(state.DeviceNonces) != 0 || len(state.ControllerNonces) != 0 {
		t.Fatalf("unexpected durable auth state %#v", state)
	}
	data, err := json.Marshal(state)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(data, []byte(session.Token)) {
		t.Fatal("session token leaked into durable snapshot")
	}
}
