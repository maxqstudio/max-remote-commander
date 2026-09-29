package agent

import (
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func testPairingState(t *testing.T) PairingState {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return PairingState{DeviceID:"dev_test", Generation:1, ControllerPublicKey:pub}
}

func TestPairingStateRoundTripAndNoSilentOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairing.json")
	state := testPairingState(t)
	if err := SavePairingState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := LoadPairingState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got.DeviceID != state.DeviceID || got.Generation != state.Generation || string(got.ControllerPublicKey) != string(state.ControllerPublicKey) {
		t.Fatalf("got %#v", got)
	}
	if err := SavePairingState(path, state); !errors.Is(err, ErrPairingStateExists) {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestPairingStateStrictDecodeAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "pairing.json")
	if err := os.WriteFile(path, []byte(`{"device_id":"d","generation":1,"controller_public_key":"bad","extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadPairingState(path); !errors.Is(err, ErrPairingStateInvalid) {
		t.Fatalf("strict decode: %v", err)
	}
	if runtime.GOOS != "windows" {
		state := testPairingState(t)
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := SavePairingState(path, state); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadPairingState(path); !errors.Is(err, ErrPairingStatePerms) {
			t.Fatalf("permissions: %v", err)
		}
	}
}

func TestPairingStateRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "pairing.json")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := LoadPairingState(link); !errors.Is(err, ErrPairingStateSymlink) {
		t.Fatalf("load symlink: %v", err)
	}
	if err := RemovePairingState(link); !errors.Is(err, ErrPairingStateSymlink) {
		t.Fatalf("remove symlink: %v", err)
	}
}
