package mcpadapter

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/maxqstudio/max-remote-commander/internal/chat"
	"github.com/maxqstudio/max-remote-commander/internal/policy"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

var (
	ErrInvalidArguments = errors.New("invalid MCP tool arguments")
	ErrInvalidResult    = errors.New("invalid remote tool result")
)

type ToolExecutor interface {
	Execute(context.Context, string, json.RawMessage) (json.RawMessage, error)
}

type pathArguments struct {
	Path *string `json:"path"`
}

type writeArguments struct {
	Path    *string `json:"path"`
	Content *string `json:"content"`
}

type patchArguments struct {
	Path                 *string `json:"path"`
	Old                  *string `json:"old"`
	Replacement          *string `json:"replacement"`
	ExpectedReplacements *int    `json:"expected_replacements"`
}

type processArguments struct {
	Executable *string   `json:"executable"`
	Args       *[]string `json:"args"`
	TimeoutMS  *int64    `json:"timeout_ms"`
}

type gitDiffArguments struct {
	Staged bool `json:"staged"`
}

type gitCloneArguments struct {
	URL         *string `json:"url"`
	Destination *string `json:"destination"`
}

func decodeStrict(raw json.RawMessage, target any) error {
	if len(raw) == 0 {
		raw = json.RawMessage("{}")
	}
	if !json.Valid(raw) {
		return ErrInvalidArguments
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArguments, err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return fmt.Errorf("%w: multiple JSON values", ErrInvalidArguments)
	} else if !errors.Is(err, io.EOF) {
		return fmt.Errorf("%w: %v", ErrInvalidArguments, err)
	}
	return nil
}

func normalizeArguments(tool string, raw json.RawMessage) (json.RawMessage, error) {
	var value any
	switch tool {
	case "filesystem.read", "filesystem.list":
		var args pathArguments
		if err := decodeStrict(raw, &args); err != nil || args.Path == nil || *args.Path == "" {
			return nil, ErrInvalidArguments
		}
		value = args
	case "filesystem.write":
		var args writeArguments
		if err := decodeStrict(raw, &args); err != nil || args.Path == nil || *args.Path == "" || args.Content == nil {
			return nil, ErrInvalidArguments
		}
		value = args
	case "filesystem.patch":
		var args patchArguments
		if err := decodeStrict(raw, &args); err != nil ||
			args.Path == nil || *args.Path == "" ||
			args.Old == nil || args.Replacement == nil ||
			args.ExpectedReplacements == nil || *args.ExpectedReplacements <= 0 {
			return nil, ErrInvalidArguments
		}
		value = args
	case "process.run":
		var args processArguments
		if err := decodeStrict(raw, &args); err != nil ||
			args.Executable == nil || *args.Executable == "" ||
			args.Args == nil || args.TimeoutMS == nil || *args.TimeoutMS < 0 {
			return nil, ErrInvalidArguments
		}
		value = args
	case "git.status":
		var args struct{}
		if err := decodeStrict(raw, &args); err != nil {
			return nil, err
		}
		value = args
	case "git.diff":
		var args gitDiffArguments
		if err := decodeStrict(raw, &args); err != nil {
			return nil, err
		}
		value = args
	case "git.clone":
		var args gitCloneArguments
		if err := decodeStrict(raw, &args); err != nil ||
			args.URL == nil || *args.URL == "" ||
			args.Destination == nil || *args.Destination == "" {
			return nil, ErrInvalidArguments
		}
		value = args
	default:
		return nil, ErrInvalidArguments
	}
	normalized, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return normalized, nil
}

func boolPtr(value bool) *bool { return &value }

func annotationsFor(tool string) *mcp.ToolAnnotations {
	decision := policy.DecideCapability(tool)
	readOnly := decision == policy.Allow
	destructive := false
	openWorld := false
	switch tool {
	case "filesystem.write", "filesystem.patch", "process.run":
		destructive = true
	case "git.clone":
		openWorld = true
	}
	if tool == "process.run" {
		openWorld = true
	}
	return &mcp.ToolAnnotations{
		ReadOnlyHint:    readOnly,
		IdempotentHint:  readOnly,
		DestructiveHint: boolPtr(destructive),
		OpenWorldHint:   boolPtr(openWorld),
	}
}

func toolResult(raw json.RawMessage) (*mcp.CallToolResult, error) {
	if len(raw) == 0 || !json.Valid(raw) {
		return nil, ErrInvalidResult
	}
	var structured any
	if err := json.Unmarshal(raw, &structured); err != nil {
		return nil, ErrInvalidResult
	}
	var status struct {
		Status string `json:"status"`
	}
	if err := json.Unmarshal(raw, &status); err != nil || status.Status == "" {
		return nil, ErrInvalidResult
	}
	return &mcp.CallToolResult{
		Content: []mcp.Content{&mcp.TextContent{Text: string(raw)}},
		StructuredContent: structured,
		IsError: status.Status != "completed",
	}, nil
}

func handler(executor ToolExecutor, tool string) mcp.ToolHandler {
	return func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		args, err := normalizeArguments(tool, req.Params.Arguments)
		if err != nil {
			result := &mcp.CallToolResult{}
			result.SetError(err)
			return result, nil
		}
		raw, err := executor.Execute(ctx, tool, args)
		if err != nil {
			result := &mcp.CallToolResult{}
			result.SetError(fmt.Errorf("remote tool failed: %w", err))
			return result, nil
		}
		result, err := toolResult(raw)
		if err != nil {
			failed := &mcp.CallToolResult{}
			failed.SetError(err)
			return failed, nil
		}
		return result, nil
	}
}

func NewServer(executor ToolExecutor, version string) (*mcp.Server, error) {
	if executor == nil {
		return nil, errors.New("MCP tool executor is required")
	}
	if version == "" {
		version = "dev"
	}
	server := mcp.NewServer(
		&mcp.Implementation{Name: "max-remote-commander", Version: version},
		&mcp.ServerOptions{
			Instructions: "Remote computer tools are constrained by the paired device policy. Privileged operations require trusted local approval on the remote PC; MCP input never grants that approval.",
		},
	)
	for _, definition := range chat.RemoteTools() {
		if definition.Name == "" || !json.Valid(definition.Parameters) {
			return nil, fmt.Errorf("invalid remote tool definition %q", definition.Name)
		}
		server.AddTool(&mcp.Tool{
			Name: definition.Name,
			Description: definition.Description,
			InputSchema: append(json.RawMessage(nil), definition.Parameters...),
			Annotations: annotationsFor(definition.Name),
		}, handler(executor, definition.Name))
	}
	return server, nil
}
