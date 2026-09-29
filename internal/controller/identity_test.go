package controller

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func TestLoadIdentityForStateCreatesOnlyBeforePairing(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "controller.seed")
	statePath := filepath.Join(dir, "controller.json")

	first, err := LoadIdentityForState(seedPath, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if first == nil {
		t.Fatal("identity not created")
	}
	if _, err := os.Stat(seedPath); err != nil {
		t.Fatal(err)
	}

	if err := SaveState(statePath, State{DeviceID:"dev_test", Generation:1}); err != nil {
		t.Fatal(err)
	}
	second, err := LoadIdentityForState(seedPath, statePath)
	if err != nil {
		t.Fatal(err)
	}
	if string(first.PrivateKey()) != string(second.PrivateKey()) {
		t.Fatal("persisted controller identity changed")
	}
}

func TestLoadIdentityForStateDoesNotRegenerateMissingPairedSeed(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "controller.seed")
	statePath := filepath.Join(dir, "controller.json")
	if err := SaveState(statePath, State{DeviceID:"dev_test", Generation:1}); err != nil {
		t.Fatal(err)
	}

	_, err := LoadIdentityForState(seedPath, statePath)
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
	if _, statErr := os.Stat(seedPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("missing paired seed was regenerated: %v", statErr)
	}
}

func TestLoadIdentityForStateRejectsInvalidStateBeforeKeyMutation(t *testing.T) {
	dir := t.TempDir()
	seedPath := filepath.Join(dir, "controller.seed")
	statePath := filepath.Join(dir, "controller.json")
	if err := os.WriteFile(statePath, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadIdentityForState(seedPath, statePath)
	if !errors.Is(err, ErrStateInvalid) {
		t.Fatalf("got %v", err)
	}
	if _, statErr := os.Stat(seedPath); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("identity changed despite invalid state: %v", statErr)
	}
}

func TestIdentityLoadRejectsMissingPath(t *testing.T) {
	_, err := identity.Load(filepath.Join(t.TempDir(), "missing.seed"))
	if !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("got %v", err)
	}
}
