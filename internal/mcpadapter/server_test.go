package mcpadapter

import (
	"context"
	"encoding/json"
	"errors"
	"sort"
	"sync"
	"testing"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type recordedCall struct {
	tool string
	args string
}

type fakeExecutor struct {
	mu       sync.Mutex
	calls    []recordedCall
	response json.RawMessage
	err      error
}

func (f *fakeExecutor) Execute(_ context.Context, tool string, args json.RawMessage) (json.RawMessage, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls = append(f.calls, recordedCall{tool: tool, args: string(args)})
	if f.err != nil {
		return nil, f.err
	}
	return append(json.RawMessage(nil), f.response...), nil
}

func connectTestServer(t *testing.T, executor ToolExecutor) (*mcp.ClientSession, *mcp.ServerSession) {
	t.Helper()
	server, err := NewServer(executor, "test")
	if err != nil {
		t.Fatal(err)
	}
	serverTransport, clientTransport := mcp.NewInMemoryTransports()
	ctx := context.Background()
	serverSession, err := server.Connect(ctx, serverTransport, nil)
	if err != nil {
		t.Fatal(err)
	}
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "test"}, nil)
	clientSession, err := client.Connect(ctx, clientTransport, nil)
	if err != nil {
		_ = serverSession.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = clientSession.Close()
		_ = serverSession.Close()
	})
	return clientSession, serverSession
}

func TestServerAdvertisesExactConstrainedTools(t *testing.T) {
	executor := &fakeExecutor{response: json.RawMessage(`{"status":"completed"}`)}
	client, _ := connectTestServer(t, executor)

	var names []string
	annotations := map[string]*mcp.ToolAnnotations{}
	for tool, err := range client.Tools(context.Background(), nil) {
		if err != nil {
			t.Fatal(err)
		}
		names = append(names, tool.Name)
		annotations[tool.Name] = tool.Annotations
	}
	sort.Strings(names)
	want := []string{
		"filesystem.list", "filesystem.patch", "filesystem.read", "filesystem.write",
		"git.clone", "git.diff", "git.status", "process.run",
	}
	if len(names) != len(want) {
		t.Fatalf("tools %#v", names)
	}
	for i := range want {
		if names[i] != want[i] {
			t.Fatalf("tools %#v want %#v", names, want)
		}
	}
	if annotations["filesystem.read"] == nil || !annotations["filesystem.read"].ReadOnlyHint {
		t.Fatal("filesystem.read missing read-only annotation")
	}
	if annotations["filesystem.write"] == nil || annotations["filesystem.write"].ReadOnlyHint {
		t.Fatal("filesystem.write incorrectly marked read-only")
	}
	if annotations["git.clone"] == nil || annotations["git.clone"].OpenWorldHint == nil || !*annotations["git.clone"].OpenWorldHint {
		t.Fatal("git.clone missing open-world annotation")
	}
}

func TestToolCallBridgesNormalizedArgumentsAndStructuredResult(t *testing.T) {
	executor := &fakeExecutor{response: json.RawMessage(`{"status":"completed","result":{"entries":[]}}`)}
	client, _ := connectTestServer(t, executor)

	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "filesystem.list",
		Arguments: map[string]any{"path":"."},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatalf("unexpected tool error: %#v", result.Content)
	}
	executor.mu.Lock()
	calls := append([]recordedCall(nil), executor.calls...)
	executor.mu.Unlock()
	if len(calls) != 1 || calls[0].tool != "filesystem.list" || calls[0].args != `{"path":"."}` {
		t.Fatalf("calls %#v", calls)
	}
	structured, ok := result.StructuredContent.(map[string]any)
	if !ok || structured["status"] != "completed" {
		t.Fatalf("structured %#v", result.StructuredContent)
	}
}

func TestInvalidArgumentsFailBeforeRemoteExecution(t *testing.T) {
	executor := &fakeExecutor{response: json.RawMessage(`{"status":"completed"}`)}
	client, _ := connectTestServer(t, executor)

	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "filesystem.read",
		Arguments: map[string]any{"path":"note.txt","unexpected":true},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("invalid arguments were not reported as tool error")
	}
	executor.mu.Lock()
	defer executor.mu.Unlock()
	if len(executor.calls) != 0 {
		t.Fatalf("remote executor called: %#v", executor.calls)
	}
}

func TestRemoteDeniedAndApprovalRequiredRemainToolErrors(t *testing.T) {
	for _, status := range []string{"denied", "approval_required", "failed", "rejected"} {
		t.Run(status, func(t *testing.T) {
			executor := &fakeExecutor{response: json.RawMessage(`{"status":"` + status + `","code":"blocked"}`)}
			client, _ := connectTestServer(t, executor)
			result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
				Name: "git.status",
				Arguments: map[string]any{},
			})
			if err != nil {
				t.Fatal(err)
			}
			if !result.IsError {
				t.Fatalf("status %q was not a tool error", status)
			}
		})
	}
}

func TestRemoteTransportFailureBecomesToolErrorWithoutClosingSession(t *testing.T) {
	executor := &fakeExecutor{err: errors.New("relay unavailable")}
	client, _ := connectTestServer(t, executor)

	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "git.status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("remote failure was not reported as tool error")
	}

	executor.mu.Lock()
	executor.err = nil
	executor.response = json.RawMessage(`{"status":"completed"}`)
	executor.mu.Unlock()
	result, err = client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "git.status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.IsError {
		t.Fatal("MCP session did not recover after tool error")
	}
}

func TestMalformedRemoteResultFailsClosed(t *testing.T) {
	executor := &fakeExecutor{response: json.RawMessage(`{"result":{}}`)}
	client, _ := connectTestServer(t, executor)
	result, err := client.CallTool(context.Background(), &mcp.CallToolParams{
		Name: "git.status",
		Arguments: map[string]any{},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !result.IsError {
		t.Fatal("malformed remote result was accepted")
	}
}
