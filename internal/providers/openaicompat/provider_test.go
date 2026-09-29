package openaicompat

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/maxqstudio/max-remote-commander/internal/chat"
)

func TestProviderMapsToolCallingContract(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/v1/chat/completions" {
			t.Fatalf("path %q", r.URL.Path)
		}
		if r.Header.Get("Authorization") != "Bearer test-key" {
			t.Fatalf("authorization %q", r.Header.Get("Authorization"))
		}
		var body map[string]any
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if body["model"] != "test-model" || body["tool_choice"] != "auto" {
			t.Fatalf("body %#v", body)
		}
		tools, ok := body["tools"].([]any)
		if !ok || len(tools) == 0 {
			t.Fatalf("tools %#v", body["tools"])
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{
			"choices":[{
				"message":{
					"role":"assistant",
					"tool_calls":[{
						"id":"call-1",
						"type":"function",
						"function":{"name":"filesystem.list","arguments":"{\\\"path\\\":\\\".\\\"}"}
					}]
				}
			}]
		}`))
	}))
	defer server.Close()

	provider, err := New(Config{
		BaseURL: server.URL + "/v1",
		APIKey: "test-key",
		Model: "test-model",
	})
	if err != nil {
		t.Fatal(err)
	}
	completion, err := provider.Complete(context.Background(), chat.CompletionRequest{
		Messages: []chat.Message{{Role:chat.RoleUser, Content:"Inspect"}},
		Tools: chat.RemoteTools(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(completion.ToolCalls) != 1 ||
		completion.ToolCalls[0].Name != "filesystem.list" ||
		string(completion.ToolCalls[0].Arguments) != `{"path":"."}` {
		t.Fatalf("completion %#v", completion)
	}
}

func TestProviderMapsAssistantAndToolHistory(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var body struct {
			Messages []map[string]any `json:"messages"`
		}
		if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
			t.Fatal(err)
		}
		if len(body.Messages) != 3 {
			t.Fatalf("messages %#v", body.Messages)
		}
		assistant := body.Messages[1]
		if _, ok := assistant["tool_calls"]; !ok {
			t.Fatalf("assistant tool call missing: %#v", assistant)
		}
		tool := body.Messages[2]
		if tool["role"] != "tool" || tool["tool_call_id"] != "call-1" {
			t.Fatalf("tool message %#v", tool)
		}
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","content":"Done."}}]}`))
	}))
	defer server.Close()

	provider, err := New(Config{BaseURL:server.URL, Model:"test"})
	if err != nil {
		t.Fatal(err)
	}
	text := "tool result"
	completion, err := provider.Complete(context.Background(), chat.CompletionRequest{
		Messages: []chat.Message{
			{Role:chat.RoleUser, Content:"Inspect"},
			{Role:chat.RoleAssistant, ToolCalls:[]chat.ToolCall{{ID:"call-1",Name:"git.status",Arguments:json.RawMessage(`{}`)}}},
			{Role:chat.RoleTool, ToolCallID:"call-1", Content:text},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if completion.Content != "Done." {
		t.Fatalf("content %q", completion.Content)
	}
}

func TestProviderRejectsInsecureRemoteHTTP(t *testing.T) {
	_, err := New(Config{BaseURL:"http://example.com/v1", Model:"test"})
	if !errors.Is(err, ErrInvalidConfig) {
		t.Fatalf("got %v", err)
	}
	if _, err := New(Config{BaseURL:"http://127.0.0.1:11434/v1", Model:"local"}); err != nil {
		t.Fatalf("loopback HTTP rejected: %v", err)
	}
}

func TestProviderRejectsMalformedToolArguments(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(`{"choices":[{"message":{"role":"assistant","tool_calls":[{"id":"c","type":"function","function":{"name":"git.status","arguments":"{"}}]}}]}`))
	}))
	defer server.Close()
	provider, _ := New(Config{BaseURL:server.URL, Model:"test"})
	_, err := provider.Complete(context.Background(), chat.CompletionRequest{
		Messages:[]chat.Message{{Role:chat.RoleUser, Content:"status"}},
		Tools:chat.RemoteTools(),
	})
	if !errors.Is(err, ErrProviderResponse) {
		t.Fatalf("got %v", err)
	}
}

func TestDefaultClientRefusesRedirect(t *testing.T) {
	target := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		t.Fatal("redirect target should not be reached")
	}))
	defer target.Close()
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, target.URL, http.StatusFound)
	}))
	defer server.Close()

	provider, _ := New(Config{BaseURL:server.URL, APIKey:"secret", Model:"test"})
	_, err := provider.Complete(context.Background(), chat.CompletionRequest{
		Messages:[]chat.Message{{Role:chat.RoleUser, Content:"hi"}},
	})
	if err == nil || !strings.Contains(err.Error(), "redirect refused") {
		t.Fatalf("got %v", err)
	}
}
