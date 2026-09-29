package controller

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestControllerStateRoundTripAndNoOverwrite(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.json")
	state := State{DeviceID:"dev_test", Generation:3}
	if err := SaveState(path, state); err != nil {
		t.Fatal(err)
	}
	got, err := LoadState(path)
	if err != nil {
		t.Fatal(err)
	}
	if got != state {
		t.Fatalf("got %#v want %#v", got, state)
	}
	if err := SaveState(path, state); !errors.Is(err, ErrStateExists) {
		t.Fatalf("overwrite: %v", err)
	}
}

func TestControllerStateStrictDecodeAndPermissions(t *testing.T) {
	path := filepath.Join(t.TempDir(), "controller.json")
	if err := os.WriteFile(path, []byte(`{"device_id":"dev_test","generation":1,"extra":true}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := LoadState(path); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("strict decode: %v", err)
	}

	if runtime.GOOS != "windows" {
		if err := os.Remove(path); err != nil {
			t.Fatal(err)
		}
		if err := SaveState(path, State{DeviceID:"dev_test", Generation:1}); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := LoadState(path); !errors.Is(err, ErrStatePerms) {
			t.Fatalf("permissions: %v", err)
		}
	}
}

func TestControllerStateRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.json")
	if err := os.WriteFile(target, []byte(`{"device_id":"dev_test","generation":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "controller.json")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := LoadState(link); !errors.Is(err, ErrStateSymlink) {
		t.Fatalf("load symlink: %v", err)
	}
	if err := RemoveState(link); !errors.Is(err, ErrStateSymlink) {
		t.Fatalf("remove symlink: %v", err)
	}
}

func TestControllerStateRejectsMissingAndInvalid(t *testing.T) {
	path := filepath.Join(t.TempDir(), "missing.json")
	if _, err := LoadState(path); !errors.Is(err, ErrStateMissing) {
		t.Fatalf("missing: %v", err)
	}
	if err := SaveState(path, State{}); !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("invalid: %v", err)
	}
}
