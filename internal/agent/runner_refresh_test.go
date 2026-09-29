package agent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/executor"
	"github.com/maxqstudio/max-remote-commander/internal/identity"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

type refreshTransport struct {
	cancel    context.CancelFunc
	sessions  int
	nextCalls int
}

func (t *refreshTransport) DeviceSession(_ context.Context, assertion relay.DeviceAssertion) (relay.Session, error) {
	t.sessions++
	if t.sessions >= 2 && t.cancel != nil {
		t.cancel()
	}
	return relay.Session{
		Token:          "device-token",
		ExpiresAt:      time.Now().Add(5100 * time.Millisecond),
		AgentSessionID: assertion.AgentSessionID,
		Generation:     assertion.Generation,
	}, nil
}

func (t *refreshTransport) NextCommand(ctx context.Context, _, _ string, _ time.Duration) (protocol.CommandEnvelope, bool, error) {
	t.nextCalls++
	<-ctx.Done()
	return protocol.CommandEnvelope{}, false, ctx.Err()
}

func (t *refreshTransport) SubmitResult(context.Context, string, string, string, any) error {
	return nil
}

func TestRunnerRefreshesSessionWhilePushTransportIsIdle(t *testing.T) {
	device, err := identity.New()
	if err != nil {
		t.Fatal(err)
	}
	controllerPublic, _, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	filesystem, err := executor.OpenFilesystem(t.TempDir(), 0)
	if err != nil {
		t.Fatal(err)
	}
	defer filesystem.Close()

	ctx, cancel := context.WithCancel(context.Background())
	transport := &refreshTransport{cancel: cancel}
	runner, err := NewRunner(RunnerConfig{
		Device: device,
		Pairing: PairingState{
			DeviceID:            device.ID(),
			Generation:          1,
			ControllerPublicKey: controllerPublic,
		},
		Transport:  transport,
		Dispatcher: &executor.Dispatcher{Filesystem: filesystem},
		Audit:      &memoryAudit{},
		SessionID:  "session-refresh-test",
	})
	if err != nil {
		t.Fatal(err)
	}

	err = runner.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("run: %v", err)
	}
	if transport.sessions < 2 {
		t.Fatalf("device sessions=%d, want refresh", transport.sessions)
	}
	if transport.nextCalls == 0 {
		t.Fatal("push transport was never entered")
	}
}
