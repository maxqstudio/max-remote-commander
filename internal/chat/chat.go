package chat

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
)

var (
	ErrInvalidToolCall = errors.New("invalid tool call")
	ErrToolLoopLimit   = errors.New("tool loop limit reached")
)

type Role string

const (
	RoleSystem    Role = "system"
	RoleUser      Role = "user"
	RoleAssistant Role = "assistant"
	RoleTool      Role = "tool"
)

type ToolCall struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

type Message struct {
	Role       Role       `json:"role"`
	Content    string     `json:"content,omitempty"`
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

type ToolDefinition struct {
	Name        string          `json:"name"`
	Description string          `json:"description"`
	Parameters  json.RawMessage `json:"parameters"`
}

type CompletionRequest struct {
	Messages []Message
	Tools    []ToolDefinition
}

type Completion struct {
	Content   string
	ToolCalls []ToolCall
}

type Provider interface {
	Complete(context.Context, CompletionRequest) (Completion, error)
}

type ToolExecutor interface {
	Execute(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

type Session struct {
	Provider  Provider
	Executor  ToolExecutor
	Tools     []ToolDefinition
	MaxRounds int
}

func (s *Session) Run(ctx context.Context, messages []Message) (string, []Message, error) {
	if s.Provider == nil || s.Executor == nil {
		return "", nil, errors.New("chat provider and tool executor are required")
	}
	maxRounds := s.MaxRounds
	if maxRounds <= 0 {
		maxRounds = 12
	}
	toolMap := make(map[string]ToolDefinition, len(s.Tools))
	for _, tool := range s.Tools {
		if tool.Name == "" || len(tool.Parameters) == 0 || !json.Valid(tool.Parameters) {
			return "", nil, fmt.Errorf("%w: invalid tool definition", ErrInvalidToolCall)
		}
		toolMap[tool.Name] = tool
	}

	history := append([]Message(nil), messages...)
	for round := 0; round < maxRounds; round++ {
		completion, err := s.Provider.Complete(ctx, CompletionRequest{
			Messages: append([]Message(nil), history...),
			Tools: append([]ToolDefinition(nil), s.Tools...),
		})
		if err != nil {
			return "", history, err
		}
		assistant := Message{
			Role: RoleAssistant,
			Content: completion.Content,
			ToolCalls: append([]ToolCall(nil), completion.ToolCalls...),
		}
		history = append(history, assistant)
		if len(completion.ToolCalls) == 0 {
			return completion.Content, history, nil
		}

		seenIDs := make(map[string]struct{}, len(completion.ToolCalls))
		for _, call := range completion.ToolCalls {
			if call.ID == "" || call.Name == "" || len(call.Arguments) == 0 || !json.Valid(call.Arguments) {
				return "", history, ErrInvalidToolCall
			}
			if _, ok := toolMap[call.Name]; !ok {
				return "", history, fmt.Errorf("%w: unknown tool %q", ErrInvalidToolCall, call.Name)
			}
			if _, duplicate := seenIDs[call.ID]; duplicate {
				return "", history, fmt.Errorf("%w: duplicate tool call id", ErrInvalidToolCall)
			}
			seenIDs[call.ID] = struct{}{}

			result, err := s.Executor.Execute(ctx, call.Name, call.Arguments)
			if err != nil {
				return "", history, err
			}
			if len(result) == 0 || !json.Valid(result) {
				return "", history, fmt.Errorf("%w: invalid tool result", ErrInvalidToolCall)
			}
			history = append(history, Message{
				Role: RoleTool,
				ToolCallID: call.ID,
				Content: string(result),
			})
		}
	}
	return "", history, ErrToolLoopLimit
}

func RemoteTools() []ToolDefinition {
	object := func(properties string, required string) json.RawMessage {
		raw := `{"type":"object","properties":` + properties + `,"additionalProperties":false`
		if required != "" {
			raw += `,"required":` + required
		}
		raw += "}"
		return json.RawMessage(raw)
	}
	return []ToolDefinition{
		{Name:"filesystem.read", Description:"Read one file inside the configured workspace.", Parameters:object(`{"path":{"type":"string"}}`, `["path"]`)},
		{Name:"filesystem.list", Description:"List one directory inside the configured workspace.", Parameters:object(`{"path":{"type":"string"}}`, `["path"]`)},
		{Name:"filesystem.write", Description:"Write a file inside the workspace. Requires trusted local approval on the PC.", Parameters:object(`{"path":{"type":"string"},"content":{"type":"string"}}`, `["path","content"]`)},
		{Name:"filesystem.patch", Description:"Replace an exact byte-string occurrence in a workspace file. Requires trusted local approval.", Parameters:object(`{"path":{"type":"string"},"old":{"type":"string"},"replacement":{"type":"string"},"expected_replacements":{"type":"integer","minimum":1}}`, `["path","old","replacement","expected_replacements"]`)},
		{Name:"process.run", Description:"Run one explicitly allowlisted executable in the workspace. Requires trusted local approval.", Parameters:object(`{"executable":{"type":"string"},"args":{"type":"array","items":{"type":"string"}},"timeout_ms":{"type":"integer","minimum":0}}`, `["executable","args","timeout_ms"]`)},
		{Name:"git.status", Description:"Read Git status for the workspace.", Parameters:object(`{}`, "")},
		{Name:"git.diff", Description:"Read Git diff for the workspace.", Parameters:object(`{"staged":{"type":"boolean"}}`, "")},
		{Name:"git.clone", Description:"Clone a credential-free HTTPS repository into a new direct child directory. Requires trusted local approval.", Parameters:object(`{"url":{"type":"string"},"destination":{"type":"string"}}`, `["url","destination"]`)},
	}
}
