package executor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/approval"
	"github.com/maxqstudio/max-remote-commander/internal/policy"
)

type CapabilityRequest struct {
	RequestID string          `json:"request_id"`
	Tool      string          `json:"tool"`
	Arguments json.RawMessage `json:"arguments"`
}

type CapabilityResult struct {
	Data    []byte         `json:"data,omitempty"`
	Entries []Entry        `json:"entries,omitempty"`
	Process *ProcessResult `json:"process,omitempty"`
}

type Dispatcher struct {
	Filesystem *Filesystem
	Process    *ProcessRunner
	Git        *Git
	Approvals  *approval.Store
}

type pathArguments struct {
	Path string `json:"path"`
}

type writeArguments struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type patchArguments struct {
	Path                 string `json:"path"`
	Old                  string `json:"old"`
	Replacement          string `json:"replacement"`
	ExpectedReplacements int    `json:"expected_replacements"`
}

type processArguments struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	TimeoutMS  int64    `json:"timeout_ms"`
}

type gitDiffArguments struct {
	Staged bool `json:"staged"`
}

type gitCloneArguments struct {
	URL         string `json:"url"`
	Destination string `json:"destination"`
}

func decodeStrict(raw json.RawMessage, target any) error {
	if len(raw) == 0 || !json.Valid(raw) {
		return errors.New("invalid JSON arguments")
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (d *Dispatcher) Dispatch(ctx context.Context, req CapabilityRequest) (CapabilityResult, error) {
	if err := policy.AuthorizeAutomatic(req.Tool); err != nil {
		return CapabilityResult{}, err
	}
	return d.dispatchAllowed(ctx, req)
}

func (d *Dispatcher) DispatchApproved(ctx context.Context, req CapabilityRequest, token string) (CapabilityResult, error) {
	switch policy.DecideCapability(req.Tool) {
	case policy.Allow:
		return d.dispatchAllowed(ctx, req)
	case policy.Deny:
		return CapabilityResult{}, policy.ErrCapabilityDenied
	case policy.ApprovalRequired:
		if d.Approvals == nil || req.RequestID == "" {
			return CapabilityResult{}, policy.ErrApprovalRequired
		}
		if err := d.Approvals.Consume(token, req.RequestID, req.Tool, req.Arguments, time.Now()); err != nil {
			return CapabilityResult{}, err
		}
		return d.dispatchPrivileged(ctx, req)
	default:
		return CapabilityResult{}, policy.ErrCapabilityDenied
	}
}

func (d *Dispatcher) dispatchAllowed(ctx context.Context, req CapabilityRequest) (CapabilityResult, error) {
	switch req.Tool {
	case "filesystem.read":
		if d.Filesystem == nil {
			return CapabilityResult{}, errors.New("filesystem capability unavailable")
		}
		var args pathArguments
		if err := decodeStrict(req.Arguments, &args); err != nil {
			return CapabilityResult{}, err
		}
		data, err := d.Filesystem.Read(args.Path)
		if err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{Data: data}, nil
	case "filesystem.list":
		if d.Filesystem == nil {
			return CapabilityResult{}, errors.New("filesystem capability unavailable")
		}
		var args pathArguments
		if err := decodeStrict(req.Arguments, &args); err != nil {
			return CapabilityResult{}, err
		}
		entries, err := d.Filesystem.List(args.Path)
		if err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{Entries: entries}, nil
	case "git.status":
		if d.Git == nil {
			return CapabilityResult{}, errors.New("git capability unavailable")
		}
		if len(req.Arguments) > 0 && string(req.Arguments) != "{}" {
			var empty struct{}
			if err := decodeStrict(req.Arguments, &empty); err != nil {
				return CapabilityResult{}, err
			}
		}
		result, err := d.Git.Status(ctx)
		if err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{Process: &result}, nil
	case "git.diff":
		if d.Git == nil {
			return CapabilityResult{}, errors.New("git capability unavailable")
		}
		var args gitDiffArguments
		if len(req.Arguments) > 0 {
			if err := decodeStrict(req.Arguments, &args); err != nil {
				return CapabilityResult{}, err
			}
		}
		result, err := d.Git.Diff(ctx, args.Staged)
		if err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{Process: &result}, nil
	default:
		return CapabilityResult{}, policy.ErrCapabilityDenied
	}
}

func (d *Dispatcher) dispatchPrivileged(ctx context.Context, req CapabilityRequest) (CapabilityResult, error) {
	switch req.Tool {
	case "filesystem.write":
		if d.Filesystem == nil {
			return CapabilityResult{}, errors.New("filesystem capability unavailable")
		}
		var args writeArguments
		if err := decodeStrict(req.Arguments, &args); err != nil {
			return CapabilityResult{}, err
		}
		if err := d.Filesystem.Write(args.Path, []byte(args.Content)); err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{}, nil
	case "filesystem.patch":
		if d.Filesystem == nil {
			return CapabilityResult{}, errors.New("filesystem capability unavailable")
		}
		var args patchArguments
		if err := decodeStrict(req.Arguments, &args); err != nil {
			return CapabilityResult{}, err
		}
		if err := d.Filesystem.Patch(args.Path, []byte(args.Old), []byte(args.Replacement), args.ExpectedReplacements); err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{}, nil
	case "process.run":
		if d.Process == nil {
			return CapabilityResult{}, errors.New("process capability unavailable")
		}
		var args processArguments
		if err := decodeStrict(req.Arguments, &args); err != nil {
			return CapabilityResult{}, err
		}
		if args.Executable == "" || args.TimeoutMS < 0 {
			return CapabilityResult{}, fmt.Errorf("invalid process arguments")
		}
		result, err := d.Process.Run(ctx, args.Executable, args.Args, time.Duration(args.TimeoutMS)*time.Millisecond)
		if err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{Process: &result}, nil
	case "git.clone":
		if d.Git == nil {
			return CapabilityResult{}, errors.New("git capability unavailable")
		}
		var args gitCloneArguments
		if err := decodeStrict(req.Arguments, &args); err != nil {
			return CapabilityResult{}, err
		}
		result, err := d.Git.Clone(ctx, args.URL, args.Destination)
		if err != nil {
			return CapabilityResult{}, err
		}
		return CapabilityResult{Process: &result}, nil
	default:
		return CapabilityResult{}, policy.ErrCapabilityDenied
	}
}
