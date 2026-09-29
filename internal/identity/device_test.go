package identity

import (
	"crypto/ed25519"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestLoadOrCreatePersistsStableIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.seed")
	first, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	second, err := LoadOrCreate(path)
	if err != nil {
		t.Fatal(err)
	}
	if first.ID() == "" || first.ID() != second.ID() {
		t.Fatalf("identity changed: %q vs %q", first.ID(), second.ID())
	}
	seed, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(seed) != ed25519.SeedSize {
		t.Fatalf("seed size %d", len(seed))
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		if info.Mode().Perm()&0o077 != 0 {
			t.Fatalf("permissions %o", info.Mode().Perm())
		}
	}
}

func TestLoadRejectsSymlinkIdentity(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	if err := os.WriteFile(target, make([]byte, ed25519.SeedSize), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "device.seed")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := LoadOrCreate(link); !errors.Is(err, ErrIdentitySymlink) {
		t.Fatalf("got %v", err)
	}
}

func TestDeviceIDIsDeterministic(t *testing.T) {
	device, err := New()
	if err != nil {
		t.Fatal(err)
	}
	first, err := DeviceID(device.PublicKey())
	if err != nil {
		t.Fatal(err)
	}
	second, _ := DeviceID(device.PublicKey())
	if first != second || first != device.ID() {
		t.Fatalf("IDs %q %q %q", first, second, device.ID())
	}
}

func TestPairingCodeIsHighEntropyAndHashed(t *testing.T) {
	codeA, hashA, err := GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	codeB, _, err := GeneratePairingCode()
	if err != nil {
		t.Fatal(err)
	}
	if len(codeA) != 32 {
		t.Fatalf("pairing code length %d", len(codeA))
	}
	if codeA == codeB {
		t.Fatal("pairing code repeated")
	}
	if !PairingCodeMatches(hashA, codeA) {
		t.Fatal("pairing hash did not match")
	}
	if PairingCodeMatches(hashA, codeB) {
		t.Fatal("different pairing code matched")
	}
}


func TestConcurrentLoadOrCreateConvergesOnOneIdentity(t *testing.T) {
	path := filepath.Join(t.TempDir(), "device.seed")
	type result struct {
		id  string
		err error
	}
	start := make(chan struct{})
	results := make(chan result, 2)
	for i := 0; i < 2; i++ {
		go func() {
			<-start
			device, err := LoadOrCreate(path)
			if err != nil {
				results <- result{err: err}
				return
			}
			results <- result{id: device.ID()}
		}()
	}
	close(start)
	first := <-results
	second := <-results
	if first.err != nil || second.err != nil {
		t.Fatalf("concurrent load/create errors: %v / %v", first.err, second.err)
	}
	if first.id == "" || first.id != second.id {
		t.Fatalf("identity diverged: %q vs %q", first.id, second.id)
	}
}
