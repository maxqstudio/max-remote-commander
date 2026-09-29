package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/approval"
	"github.com/maxqstudio/max-remote-commander/internal/audit"
	"github.com/maxqstudio/max-remote-commander/internal/executor"
	"github.com/maxqstudio/max-remote-commander/internal/identity"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

type memoryAudit struct {
	mu     sync.Mutex
	events []audit.Event
	fail   bool
}

func (m *memoryAudit) Append(event audit.Event) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.fail {
		return errors.New("audit unavailable")
	}
	m.events = append(m.events, event)
	return nil
}

type staticApprover bool

func (a staticApprover) Approve(context.Context, ApprovalPrompt) (bool, error) {
	return bool(a), nil
}

type fakeTransport struct {
	sessionID  string
	generation uint64
	commands   []protocol.CommandEnvelope
	results    []WireResult
	cancel     context.CancelFunc
	badBinding bool
}

func (f *fakeTransport) DeviceSession(context.Context, relay.DeviceAssertion) (relay.Session, error) {
	sessionID := f.sessionID
	if f.badBinding {
		sessionID = "wrong-session"
	}
	return relay.Session{
		Token: "device-token",
		ExpiresAt: time.Now().Add(time.Hour),
		AgentSessionID: sessionID,
		Generation: f.generation,
	}, nil
}

func (f *fakeTransport) NextCommand(ctx context.Context, _, _ string, _ time.Duration) (protocol.CommandEnvelope, bool, error) {
	if len(f.commands) == 0 {
		<-ctx.Done()
		return protocol.CommandEnvelope{}, false, ctx.Err()
	}
	command := f.commands[0]
	f.commands = f.commands[1:]
	return command, true, nil
}

func (f *fakeTransport) SubmitResult(_ context.Context, _, _, _ string, value any) error {
	data, err := json.Marshal(value)
	if err != nil {
		return err
	}
	var result WireResult
	if err := json.Unmarshal(data, &result); err != nil {
		return err
	}
	f.results = append(f.results, result)
	if f.cancel != nil {
		f.cancel()
	}
	return nil
}

func signedRunnerCommand(t *testing.T, privateKey ed25519.PrivateKey, deviceID, sessionID, requestID, nonce, tool string, arguments any) protocol.CommandEnvelope {
	t.Helper()
	raw, err := json.Marshal(arguments)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	command := protocol.CommandEnvelope{
		Version: protocol.CurrentVersion,
		RequestID: requestID,
		DeviceID: deviceID,
		SessionID: sessionID,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(),
		Nonce: nonce,
		Tool: tool,
		Arguments: raw,
	}
	if err := command.Sign(privateKey); err != nil {
		t.Fatal(err)
	}
	return command
}

type runnerFixture struct {
	runner    *Runner
	transport *fakeTransport
	audit     *memoryAudit
	root      string
	ctx       context.Context
}

func newRunnerFixture(t *testing.T, tool string, arguments any, approver TrustedApprover) runnerFixture {
	t.Helper()
	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, controllerPrivate, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	sessionID := "session-test"
	pairing := PairingState{
		DeviceID: device.ID(),
		Generation: 1,
		ControllerPublicKey: controllerPublic,
	}
	root := t.TempDir()
	filesystem, err := executor.OpenFilesystem(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = filesystem.Close() })
	dispatcher := &executor.Dispatcher{
		Filesystem: filesystem,
		Approvals: approval.NewStore(time.Minute),
	}
	auditLog := &memoryAudit{}
	ctx, cancel := context.WithCancel(context.Background())
	transport := &fakeTransport{
		sessionID: sessionID,
		generation: 1,
		cancel: cancel,
		commands: []protocol.CommandEnvelope{
			signedRunnerCommand(t, controllerPrivate, device.ID(), sessionID, "req-1", "nonce-1", tool, arguments),
		},
	}
	runner, err := NewRunner(RunnerConfig{
		Device: device,
		Pairing: pairing,
		Transport: transport,
		Dispatcher: dispatcher,
		Audit: auditLog,
		Approver: approver,
		SessionID: sessionID,
		PollWait: time.Millisecond,
	})
	if err != nil {
		t.Fatal(err)
	}
	return runnerFixture{runner: runner, transport: transport, audit: auditLog, root: root, ctx: ctx}
}

func TestRunnerExecutesAutomaticallyAllowedCapability(t *testing.T) {
	fixture := newRunnerFixture(t, "filesystem.list", map[string]any{"path":"."}, nil)
	err := fixture.runner.Run(fixture.ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	if len(fixture.transport.results) != 1 || fixture.transport.results[0].Status != "completed" {
		t.Fatalf("results %#v", fixture.transport.results)
	}
}

func TestRunnerPrivilegedCommandNeedsLocalApproval(t *testing.T) {
	fixture := newRunnerFixture(t, "filesystem.write", map[string]any{"path":"note.txt","content":"blocked"}, nil)
	_ = fixture.runner.Run(fixture.ctx)
	if len(fixture.transport.results) != 1 || fixture.transport.results[0].Status != "approval_required" {
		t.Fatalf("results %#v", fixture.transport.results)
	}
	if _, err := os.Stat(filepath.Join(fixture.root, "note.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("privileged side effect occurred: %v", err)
	}
}

func TestRunnerLocalApprovalExecutesExactRequest(t *testing.T) {
	fixture := newRunnerFixture(t, "filesystem.write", map[string]any{"path":"note.txt","content":"approved"}, staticApprover(true))
	_ = fixture.runner.Run(fixture.ctx)
	if len(fixture.transport.results) != 1 || fixture.transport.results[0].Status != "completed" {
		t.Fatalf("results %#v", fixture.transport.results)
	}
	data, err := os.ReadFile(filepath.Join(fixture.root, "note.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(data) != "approved" {
		t.Fatalf("content %q", data)
	}
}

func TestRunnerAuditFailureStopsBeforePrivilegedSideEffect(t *testing.T) {
	fixture := newRunnerFixture(t, "filesystem.write", map[string]any{"path":"note.txt","content":"must-not-write"}, staticApprover(true))
	fixture.audit.fail = true
	err := fixture.runner.Run(fixture.ctx)
	if err == nil || err.Error() != "audit unavailable" {
		t.Fatalf("run: %v", err)
	}
	if len(fixture.transport.results) != 0 {
		t.Fatalf("result sent despite audit failure: %#v", fixture.transport.results)
	}
	if _, err := os.Stat(filepath.Join(fixture.root, "note.txt")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("side effect occurred: %v", err)
	}
}

func TestRunnerRejectsRelaySessionBindingMismatch(t *testing.T) {
	fixture := newRunnerFixture(t, "filesystem.list", map[string]any{"path":"."}, nil)
	fixture.transport.badBinding = true
	if err := fixture.runner.Run(fixture.ctx); !errors.Is(err, ErrSessionBinding) {
		t.Fatalf("run: %v", err)
	}
}
