package main

import (
	"bufio"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/agent"
	"github.com/maxqstudio/max-remote-commander/internal/approval"
	"github.com/maxqstudio/max-remote-commander/internal/audit"
	"github.com/maxqstudio/max-remote-commander/internal/executor"
	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

var version = "dev"

type executableFlags []string

func (f *executableFlags) String() string { return strings.Join(*f, ",") }
func (f *executableFlags) Set(value string) error {
	*f = append(*f, value)
	return nil
}

type consoleApprover struct {
	reader *bufio.Reader
	writer io.Writer
}

func (a *consoleApprover) Approve(_ context.Context, prompt agent.ApprovalPrompt) (bool, error) {
	if a == nil || a.reader == nil || a.writer == nil {
		return false, nil
	}
	_, _ = fmt.Fprintf(a.writer,
		"\nLocal approval required\nRequest: %s\nCapability: %s\nSummary: %s\nArguments SHA-256: %s\nApprove once? [y/N]: ",
		prompt.RequestID, prompt.Capability, prompt.Summary, prompt.ArgumentsSHA256,
	)
	line, err := a.reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return false, err
	}
	switch strings.ToLower(strings.TrimSpace(line)) {
	case "y", "yes":
		return true, nil
	default:
		return false, nil
	}
}

func defaultDataDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "max-remote-commander"), nil
}

func parseExecutables(values []string) ([]executor.Executable, error) {
	result := make([]executor.Executable, 0, len(values))
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		name, path, ok := strings.Cut(value, "=")
		name = strings.TrimSpace(name)
		path = strings.TrimSpace(path)
		if !ok || name == "" || path == "" || !filepath.IsAbs(path) {
			return nil, fmt.Errorf("--allow-exec requires name=ABSOLUTE_PATH: %q", value)
		}
		if strings.ContainsAny(name, "/\\") {
			return nil, fmt.Errorf("invalid executable name %q", name)
		}
		if _, exists := seen[name]; exists {
			return nil, fmt.Errorf("duplicate executable name %q", name)
		}
		seen[name] = struct{}{}
		result = append(result, executor.Executable{Name: name, Path: path})
	}
	return result, nil
}

func ensurePairing(ctx context.Context, client *agent.RelayClient, device *identity.Device, statePath, registrationKey string, output io.Writer) (agent.PairingState, error) {
	state, err := agent.LoadPairingState(statePath)
	if err == nil {
		if state.DeviceID != device.ID() {
			return agent.PairingState{}, errors.New("pairing state belongs to another device identity")
		}
		return state, nil
	}
	if !errors.Is(err, agent.ErrPairingStateMissing) {
		return agent.PairingState{}, err
	}
	if registrationKey == "" {
		return agent.PairingState{}, errors.New("MAXRC_REGISTRATION_KEY is required for first pairing only")
	}

	session, err := client.BootstrapSession(ctx, device.ID(), registrationKey)
	if err != nil {
		return agent.PairingState{}, err
	}
	code, codeHash, err := identity.GeneratePairingCode()
	if err != nil {
		return agent.PairingState{}, err
	}
	receipt, err := client.PublishPairingOffer(ctx, device.ID(), session.Token, codeHash, device.PublicKey(), 5*time.Minute)
	if err != nil {
		return agent.PairingState{}, err
	}
	_, _ = fmt.Fprintf(output, "Pairing code: %s\nDevice ID: %s\nWaiting for controller pairing...\n", code, device.ID())

	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		status, paired, err := client.PairingStatus(ctx, device.ID(), receipt.Token)
		if err != nil {
			return agent.PairingState{}, err
		}
		if paired {
			if status.DeviceID != device.ID() {
				return agent.PairingState{}, errors.New("relay returned pairing for another device")
			}
			state := agent.PairingState{
				DeviceID: status.DeviceID,
				Generation: status.Generation,
				ControllerPublicKey: status.ControllerPublicKey,
			}
			if err := agent.SavePairingState(statePath, state); err != nil {
				if !errors.Is(err, agent.ErrPairingStateExists) {
					return agent.PairingState{}, err
				}
				existing, loadErr := agent.LoadPairingState(statePath)
				if loadErr != nil {
					return agent.PairingState{}, loadErr
				}
				if existing.DeviceID != state.DeviceID || existing.Generation != state.Generation ||
					string(existing.ControllerPublicKey) != string(state.ControllerPublicKey) {
					return agent.PairingState{}, errors.New("concurrent pairing state does not match relay")
				}
				state = existing
			}
			_, _ = fmt.Fprintln(output, "Pairing complete.")
			return state, nil
		}
		if !time.Now().Before(receipt.ExpiresAt) {
			return agent.PairingState{}, errors.New("pairing receipt expired")
		}
		select {
		case <-ctx.Done():
			return agent.PairingState{}, ctx.Err()
		case <-ticker.C:
		}
	}
}

func run() error {
	var allowed executableFlags
	showVersion := flag.Bool("version", false, "print version")
	relayURL := flag.String("relay", "", "relay base URL; HTTPS required except loopback")
	transportMode := flag.String("transport", "websocket", "command transport: websocket or long-poll")
	workspace := flag.String("workspace", "", "explicit workspace root exposed to the agent")
	dataDirFlag := flag.String("data-dir", "", "agent state directory")
	interactiveApprovals := flag.Bool("interactive-approvals", false, "ask on local stdin before each privileged capability")
	enableGit := flag.Bool("enable-git", true, "enable bounded Git status/diff and approval-gated clone")
	flag.Var(&allowed, "allow-exec", "allow process executable as name=ABSOLUTE_PATH; repeatable")
	flag.Parse()

	if *showVersion {
		fmt.Println("max-agent", version)
		return nil
	}
	if *relayURL == "" || *workspace == "" {
		return errors.New("--relay and --workspace are required")
	}
	workspaceAbs, err := filepath.Abs(*workspace)
	if err != nil {
		return err
	}
	dataDir := *dataDirFlag
	if dataDir == "" {
		dataDir, err = defaultDataDir()
		if err != nil {
			return err
		}
	}
	dataDir, err = filepath.Abs(dataDir)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		return err
	}

	client, err := agent.NewRelayClient(*relayURL, nil)
	if err != nil {
		return err
	}
	device, err := identity.LoadOrCreate(filepath.Join(dataDir, "device.seed"))
	if err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	pairing, err := ensurePairing(
		ctx, client, device, filepath.Join(dataDir, "pairing.json"),
		os.Getenv("MAXRC_REGISTRATION_KEY"), os.Stderr,
	)
	if err != nil {
		return err
	}

	filesystem, err := executor.OpenFilesystem(workspaceAbs, 4<<20)
	if err != nil {
		return err
	}
	defer filesystem.Close()

	approvals := approval.NewStore(2 * time.Minute)
	dispatcher := &executor.Dispatcher{Filesystem: filesystem, Approvals: approvals}

	executables, err := parseExecutables(allowed)
	if err != nil {
		return err
	}
	if len(executables) > 0 {
		processRunner, err := executor.NewProcessRunner(workspaceAbs, executables, nil, 30*time.Second, 1<<20)
		if err != nil {
			return err
		}
		dispatcher.Process = processRunner
	}
	if *enableGit {
		gitRunner, err := executor.NewGit(workspaceAbs, os.Environ(), 30*time.Second, 1<<20)
		if err == nil {
			dispatcher.Git = gitRunner
		} else {
			_, _ = fmt.Fprintln(os.Stderr, "max-agent: Git unavailable; Git capabilities disabled:", err)
		}
	}

	auditLog, err := audit.Open(filepath.Join(dataDir, "audit.jsonl"), 10<<20)
	if err != nil {
		return err
	}
	defer auditLog.Close()

	var approver agent.TrustedApprover
	if *interactiveApprovals {
		approver = &consoleApprover{reader: bufio.NewReader(os.Stdin), writer: os.Stderr}
	}

	var commandTransport agent.CommandTransport
	switch *transportMode {
	case "websocket":
		wsTransport, err := agent.NewWebSocketTransport(*relayURL, agent.WebSocketTransportConfig{})
		if err != nil {
			return err
		}
		commandTransport = wsTransport
	case "long-poll":
		commandTransport = client
	default:
		return errors.New("--transport must be websocket or long-poll")
	}

	runner, err := agent.NewRunner(agent.RunnerConfig{
		Device: device,
		Pairing: pairing,
		Transport: commandTransport,
		Dispatcher: dispatcher,
		Audit: auditLog,
		Approver: approver,
	})
	if err != nil {
		return err
	}
	_, _ = fmt.Fprintf(os.Stderr, "max-agent connected identity=%s workspace=%s transport=%s session=%s\n", device.ID(), workspaceAbs, *transportMode, runner.SessionID())
	err = runner.Run(ctx)
	if errors.Is(err, context.Canceled) {
		return nil
	}
	return err
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "max-agent:", err)
		os.Exit(2)
	}
}
