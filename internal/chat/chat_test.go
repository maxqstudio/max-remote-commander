package chat

import (
	"context"
	"encoding/json"
	"errors"
	"testing"
)

type scriptedProvider struct {
	responses []Completion
	calls     int
}

func (p *scriptedProvider) Complete(_ context.Context, _ CompletionRequest) (Completion, error) {
	if p.calls >= len(p.responses) {
		return Completion{}, errors.New("unexpected provider call")
	}
	response := p.responses[p.calls]
	p.calls++
	return response, nil
}

type recordingExecutor struct {
	names []string
}

func (e *recordingExecutor) Execute(_ context.Context, name string, _ json.RawMessage) (json.RawMessage, error) {
	e.names = append(e.names, name)
	return json.RawMessage(`{"status":"completed","result":{"entries":[]}}`), nil
}

func TestRemoteToolsAreValidAndUnique(t *testing.T) {
	seen := map[string]bool{}
	for _, tool := range RemoteTools() {
		if tool.Name == "" || seen[tool.Name] {
			t.Fatalf("invalid or duplicate tool %q", tool.Name)
		}
		seen[tool.Name] = true
		if !json.Valid(tool.Parameters) {
			t.Fatalf("tool %s has invalid schema: %s", tool.Name, tool.Parameters)
		}
		var schema map[string]any
		if err := json.Unmarshal(tool.Parameters, &schema); err != nil {
			t.Fatal(err)
		}
		if schema["type"] != "object" || schema["additionalProperties"] != false {
			t.Fatalf("tool %s schema is not fail-closed: %#v", tool.Name, schema)
		}
	}
}

func TestSessionExecutesAdvertisedToolAndReturnsFinalText(t *testing.T) {
	provider := &scriptedProvider{responses: []Completion{
		{
			Content: "",
			ToolCalls: []ToolCall{{
				ID: "call-1",
				Name: "filesystem.list",
				Arguments: json.RawMessage(`{"path":"."}`),
			}},
		},
		{Content: "Workspace inspected."},
	}}
	executor := &recordingExecutor{}
	session := &Session{
		Provider: provider,
		Executor: executor,
		Tools: RemoteTools(),
		MaxRounds: 4,
	}
	text, history, err := session.Run(context.Background(), []Message{{Role:RoleUser, Content:"Inspect the workspace"}})
	if err != nil {
		t.Fatal(err)
	}
	if text != "Workspace inspected." {
		t.Fatalf("text %q", text)
	}
	if len(executor.names) != 1 || executor.names[0] != "filesystem.list" {
		t.Fatalf("executed %#v", executor.names)
	}
	if len(history) != 4 || history[2].Role != RoleTool || history[2].ToolCallID != "call-1" {
		t.Fatalf("history %#v", history)
	}
}

func TestSessionRejectsUnadvertisedToolBeforeExecution(t *testing.T) {
	provider := &scriptedProvider{responses: []Completion{{
		ToolCalls: []ToolCall{{
			ID:"call-1",
			Name:"shell.exec",
			Arguments:json.RawMessage(`{"command":"unsafe"}`),
		}},
	}}}
	executor := &recordingExecutor{}
	session := &Session{Provider:provider, Executor:executor, Tools:RemoteTools()}
	_, _, err := session.Run(context.Background(), []Message{{Role:RoleUser, Content:"Do it"}})
	if !errors.Is(err, ErrInvalidToolCall) {
		t.Fatalf("got %v", err)
	}
	if len(executor.names) != 0 {
		t.Fatalf("unadvertised tool executed: %#v", executor.names)
	}
}

func TestSessionStopsAtToolLoopLimit(t *testing.T) {
	provider := &scriptedProvider{responses: []Completion{
		{ToolCalls:[]ToolCall{{ID:"call-1",Name:"git.status",Arguments:json.RawMessage(`{}`)}}},
		{ToolCalls:[]ToolCall{{ID:"call-2",Name:"git.status",Arguments:json.RawMessage(`{}`)}}},
	}}
	executor := &recordingExecutor{}
	session := &Session{Provider:provider, Executor:executor, Tools:RemoteTools(), MaxRounds:2}
	_, _, err := session.Run(context.Background(), []Message{{Role:RoleUser, Content:"Loop"}})
	if !errors.Is(err, ErrToolLoopLimit) {
		t.Fatalf("got %v", err)
	}
	if len(executor.names) != 2 {
		t.Fatalf("executions %#v", executor.names)
	}
}
