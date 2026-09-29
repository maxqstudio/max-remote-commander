package main

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/maxqstudio/max-remote-commander/internal/chat"
)

func TestReadPairingCodeRejectsBlankAndTrimsInput(t *testing.T) {
	if _, err := readPairingCode(bufio.NewReader(strings.NewReader("\n")), &bytes.Buffer{}); err == nil {
		t.Fatal("blank pairing code accepted")
	}
	var output bytes.Buffer
	code, err := readPairingCode(bufio.NewReader(strings.NewReader("  ABCD-EFGH  \n")), &output)
	if err != nil {
		t.Fatal(err)
	}
	if code != "ABCD-EFGH" {
		t.Fatalf("code %q", code)
	}
	if !strings.Contains(output.String(), "Pairing code:") {
		t.Fatalf("prompt %q", output.String())
	}
}

type replProvider struct {
	calls int
}

func (p *replProvider) Complete(_ context.Context, req chat.CompletionRequest) (chat.Completion, error) {
	p.calls++
	if len(req.Messages) < 2 || req.Messages[len(req.Messages)-1].Role != chat.RoleUser {
		return chat.Completion{}, errors.New("missing user message")
	}
	return chat.Completion{Content:"done"}, nil
}

type replExecutor struct{}

func (replExecutor) Execute(context.Context, string, json.RawMessage) (json.RawMessage, error) {
	return nil, errors.New("unexpected tool execution")
}

func TestRunREPLProcessesPromptAndExit(t *testing.T) {
	provider := &replProvider{}
	session := &chat.Session{
		Provider:provider,
		Executor:replExecutor{},
		Tools:chat.RemoteTools(),
		MaxRounds:2,
	}
	input := bufio.NewReader(strings.NewReader("hello\n/exit\n"))
	var output bytes.Buffer
	if err := runREPL(context.Background(), session, input, &output); err != nil {
		t.Fatal(err)
	}
	if provider.calls != 1 {
		t.Fatalf("provider calls %d", provider.calls)
	}
	if !strings.Contains(output.String(), "done") {
		t.Fatalf("output %q", output.String())
	}
}

func TestRunREPLReturnsProviderErrorAsChatOutputAndContinues(t *testing.T) {
	provider := &failingThenSuccessProvider{}
	session := &chat.Session{
		Provider:provider,
		Executor:replExecutor{},
		Tools:chat.RemoteTools(),
		MaxRounds:2,
	}
	input := bufio.NewReader(strings.NewReader("first\nsecond\n/quit\n"))
	var output bytes.Buffer
	if err := runREPL(context.Background(), session, input, &output); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(output.String(), "error: provider failed") ||
		!strings.Contains(output.String(), "recovered") {
		t.Fatalf("output %q", output.String())
	}
}

type failingThenSuccessProvider struct {
	calls int
}

func (p *failingThenSuccessProvider) Complete(context.Context, chat.CompletionRequest) (chat.Completion, error) {
	p.calls++
	if p.calls == 1 {
		return chat.Completion{}, errors.New("provider failed")
	}
	return chat.Completion{Content:"recovered"}, nil
}
