package main

import (
	"crypto/rand"
	"encoding/base64"
	"testing"
)

func TestDurableStateConfigAllowsExplicitEphemeralMode(t *testing.T) {
	t.Setenv("MAXRC_STATE_FILE", "")
	t.Setenv("MAXRC_STATE_KEY", "")
	path, key, err := durableStateConfig()
	if err != nil {
		t.Fatal(err)
	}
	if path != "" || key != nil {
		t.Fatalf("path=%q key=%x", path, key)
	}
}

func TestDurableStateConfigRequiresPathAndKeyTogether(t *testing.T) {
	t.Setenv("MAXRC_STATE_FILE", "state.json")
	t.Setenv("MAXRC_STATE_KEY", "")
	if _, _, err := durableStateConfig(); err == nil {
		t.Fatal("state path without key was accepted")
	}

	t.Setenv("MAXRC_STATE_FILE", "")
	t.Setenv("MAXRC_STATE_KEY", "abc")
	if _, _, err := durableStateConfig(); err == nil {
		t.Fatal("state key without path was accepted")
	}
}

func TestDurableStateConfigRequiresExactRandomKeyLength(t *testing.T) {
	t.Setenv("MAXRC_STATE_FILE", "state.json")
	t.Setenv("MAXRC_STATE_KEY", base64.RawURLEncoding.EncodeToString(make([]byte, 31)))
	if _, _, err := durableStateConfig(); err == nil {
		t.Fatal("31-byte state key was accepted")
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		t.Fatal(err)
	}
	encoded := base64.RawURLEncoding.EncodeToString(key)
	t.Setenv("MAXRC_STATE_KEY", encoded)
	path, got, err := durableStateConfig()
	if err != nil {
		t.Fatal(err)
	}
	if path != "state.json" || string(got) != string(key) {
		t.Fatalf("path=%q key=%x", path, got)
	}
}
