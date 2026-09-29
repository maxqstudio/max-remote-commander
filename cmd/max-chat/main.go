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

	"github.com/maxqstudio/max-remote-commander/internal/chat"
	"github.com/maxqstudio/max-remote-commander/internal/controller"
	"github.com/maxqstudio/max-remote-commander/internal/identity"
	"github.com/maxqstudio/max-remote-commander/internal/providers/openaicompat"
)

var version = "dev"

const defaultSystemPrompt = "You are controlling a paired remote computer through constrained tools. Prefer read-only inspection before changes. Privileged tools require explicit local approval on the remote computer. Never claim an operation succeeded unless the tool result says it completed."

func defaultDataDir() (string, error) {
	root, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(root, "max-remote-commander", "controller"), nil
}

func readPairingCode(reader *bufio.Reader, writer io.Writer) (string, error) {
	if reader == nil {
		return "", errors.New("pairing input unavailable")
	}
	if writer != nil {
		_, _ = fmt.Fprint(writer, "Pairing code: ")
	}
	line, err := reader.ReadString('\n')
	if err != nil && !errors.Is(err, io.EOF) {
		return "", err
	}
	code := strings.TrimSpace(line)
	if code == "" {
		return "", errors.New("pairing code is required")
	}
	return code, nil
}

func loadOrPair(ctx context.Context, client *controller.Client, key *identity.Device, statePath, requestedDevice string, input *bufio.Reader, output io.Writer) (controller.State, error) {
	state, err := controller.LoadState(statePath)
	if err == nil {
		if requestedDevice != "" && requestedDevice != state.DeviceID {
			return controller.State{}, errors.New("--device does not match persisted pairing")
		}
		return state, nil
	}
	if !errors.Is(err, controller.ErrStateMissing) {
		return controller.State{}, err
	}
	if requestedDevice == "" {
		return controller.State{}, errors.New("--device is required for first pairing")
	}
	code, err := readPairingCode(input, output)
	if err != nil {
		return controller.State{}, err
	}
	pairing, err := client.RedeemPairing(ctx, requestedDevice, code, key.PublicKey())
	if err != nil {
		return controller.State{}, err
	}
	state = controller.State{DeviceID: pairing.DeviceID, Generation: pairing.Generation}
	if err := controller.SaveState(statePath, state); err != nil {
		if !errors.Is(err, controller.ErrStateExists) {
			return controller.State{}, err
		}
		existing, loadErr := controller.LoadState(statePath)
		if loadErr != nil {
			return controller.State{}, loadErr
		}
		if existing != state {
			return controller.State{}, errors.New("concurrent controller pairing state mismatch")
		}
		state = existing
	}
	if output != nil {
		_, _ = fmt.Fprintf(output, "Paired with %s (generation %d).\n", state.DeviceID, state.Generation)
	}
	return state, nil
}

func runREPL(ctx context.Context, session *chat.Session, input *bufio.Reader, output io.Writer) error {
	if session == nil || input == nil || output == nil {
		return errors.New("chat session input and output are required")
	}
	history := []chat.Message{{Role:chat.RoleSystem, Content:defaultSystemPrompt}}
	for {
		_, _ = fmt.Fprint(output, "> ")
		line, err := input.ReadString('\n')
		if err != nil && !errors.Is(err, io.EOF) {
			return err
		}
		prompt := strings.TrimSpace(line)
		if prompt == "" {
			if errors.Is(err, io.EOF) {
				return nil
			}
			continue
		}
		switch strings.ToLower(prompt) {
		case "/exit", "/quit":
			return nil
		}
		history = append(history, chat.Message{Role:chat.RoleUser, Content:prompt})
		answer, updated, runErr := session.Run(ctx, history)
		if runErr != nil {
			_, _ = fmt.Fprintf(output, "error: %v\n", runErr)
		} else {
			history = updated
			_, _ = fmt.Fprintln(output, answer)
		}
		if errors.Is(err, io.EOF) {
			return nil
		}
	}
}

func run() error {
	showVersion := flag.Bool("version", false, "print version")
	relayURL := flag.String("relay", "", "relay base URL; HTTPS required except loopback")
	deviceID := flag.String("device", "", "device ID; required only for first pairing")
	providerURL := flag.String("provider-url", "", "OpenAI-compatible API base URL, e.g. https://api.openai.com/v1")
	model := flag.String("model", "", "provider model name")
	dataDirFlag := flag.String("data-dir", "", "controller state directory")
	flag.Parse()

	if *showVersion {
		fmt.Println("max-chat", version)
		return nil
	}
	if *relayURL == "" || *providerURL == "" || *model == "" {
		return errors.New("--relay, --provider-url, and --model are required")
	}
	dataDir := *dataDirFlag
	var err error
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

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()

	relayClient, err := controller.NewClient(*relayURL, nil)
	if err != nil {
		return err
	}
	statePath := filepath.Join(dataDir, "controller.json")
	controllerKey, err := controller.LoadIdentityForState(filepath.Join(dataDir, "controller.seed"), statePath)
	if err != nil {
		return err
	}
	input := bufio.NewReader(os.Stdin)
	state, err := loadOrPair(
		ctx,
		relayClient,
		controllerKey,
		statePath,
		*deviceID,
		input,
		os.Stderr,
	)
	if err != nil {
		return err
	}
	remoteExecutor, err := controller.NewRemoteExecutor(
		relayClient,
		controller.Pairing{DeviceID:state.DeviceID, Generation:state.Generation},
		controllerKey.PrivateKey(),
	)
	if err != nil {
		return err
	}
	provider, err := openaicompat.New(openaicompat.Config{
		BaseURL:*providerURL,
		APIKey:os.Getenv("MAXRC_LLM_API_KEY"),
		Model:*model,
	})
	if err != nil {
		return err
	}
	session := &chat.Session{
		Provider:provider,
		Executor:remoteExecutor,
		Tools:chat.RemoteTools(),
		MaxRounds:12,
	}
	_, _ = fmt.Fprintf(os.Stderr, "max-chat paired device=%s model=%s\n", state.DeviceID, *model)
	return runREPL(ctx, session, input, os.Stdout)
}

func main() {
	if err := run(); err != nil {
		fmt.Fprintln(os.Stderr, "max-chat:", err)
		os.Exit(2)
	}
}
