package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestAuditLoggerWritesOnlyStructuredSecretSafeFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := Open(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	argsDigest := sha256.Sum256([]byte(`{"path":"note.txt","token":"do-not-log"}`))
	event := Event{
		Time: time.Unix(1_800_000_000, 0).UTC(),
		Kind: "capability.decision",
		DeviceID: "dev_abc",
		RequestID: "req-1",
		Capability: "filesystem.write",
		Decision: "APPROVAL_REQUIRED",
		Outcome: "pending",
		ArgumentsSHA256: hex.EncodeToString(argsDigest[:]),
	}
	if err := logger.Append(event); err != nil {
		t.Fatal(err)
	}
	if err := logger.Close(); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "do-not-log") || strings.Contains(string(data), "note.txt") {
		t.Fatalf("raw secret-bearing arguments leaked: %s", data)
	}
	var got Event
	if err := json.Unmarshal(data, &got); err != nil {
		t.Fatal(err)
	}
	if got.RequestID != event.RequestID || got.ArgumentsSHA256 != event.ArgumentsSHA256 {
		t.Fatalf("event %#v", got)
	}
}

func TestAuditLoggerRejectsFreeFormOrMalformedFields(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := Open(path, 4096)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	bad := Event{
		Time: time.Now().UTC(),
		Kind: "capability decision with spaces",
		RequestID: "req-1",
	}
	if err := logger.Append(bad); !errors.Is(err, ErrInvalidEvent) {
		t.Fatalf("got %v", err)
	}
}

func TestAuditLoggerIsBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.jsonl")
	logger, err := Open(path, 180)
	if err != nil {
		t.Fatal(err)
	}
	defer logger.Close()
	event := Event{Time: time.Now().UTC(), Kind: "session.created", DeviceID: "dev_abc"}
	for {
		err := logger.Append(event)
		if errors.Is(err, ErrAuditFull) {
			break
		}
		if err != nil {
			t.Fatal(err)
		}
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() > 180 {
		t.Fatalf("audit log exceeded bound: %d", info.Size())
	}
}

func TestAuditLoggerRejectsSymlink(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "target.log")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "audit.log")
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable: %v", err)
		}
		t.Fatal(err)
	}
	if _, err := Open(link, 1024); !errors.Is(err, ErrAuditSymlink) {
		t.Fatalf("got %v", err)
	}
}
