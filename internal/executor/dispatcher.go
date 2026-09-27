package executor

import (
	"context"
	"encoding/json"
	"errors"

	"github.com/maxqstudio/max-remote-commander/internal/policy"
)

type CapabilityRequest struct {
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
	Git        *Git
}

type pathArguments struct {
	Path string `json:"path"`
}

type gitDiffArguments struct {
	Staged bool `json:"staged"`
}

func (d *Dispatcher) Dispatch(ctx context.Context, req CapabilityRequest) (CapabilityResult, error) {
	if err := policy.AuthorizeAutomatic(req.Tool); err != nil {
		return CapabilityResult{}, err
	}

	switch req.Tool {
	case "filesystem.read":
		if d.Filesystem == nil {
			return CapabilityResult{}, errors.New("filesystem capability unavailable")
		}
		var args pathArguments
		if err := json.Unmarshal(req.Arguments, &args); err != nil {
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
		if err := json.Unmarshal(req.Arguments, &args); err != nil {
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
			if err := json.Unmarshal(req.Arguments, &args); err != nil {
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
