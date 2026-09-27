package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"time"
)

var (
	ErrUnknownCapability = errors.New("unknown capability")
	ErrApprovalRequired  = errors.New("explicit approval required")
	ErrInvalidArguments  = errors.New("invalid capability arguments")
)

type Dispatcher struct {
	Filesystem *Filesystem
	Process    *ProcessRunner
	Git        *Git
}

type Request struct {
	Capability string
	Arguments  json.RawMessage
	Approved   bool
}

type Response struct {
	Data      any
	Process   *ProcessResult
	Completed bool
}

type pathArgs struct {
	Path string `json:"path"`
}

type writeArgs struct {
	Path    string `json:"path"`
	Content string `json:"content"`
}

type patchArgs struct {
	Path                 string `json:"path"`
	Old                  string `json:"old"`
	Replacement          string `json:"replacement"`
	ExpectedReplacements int    `json:"expected_replacements"`
}

type processArgs struct {
	Executable string   `json:"executable"`
	Args       []string `json:"args"`
	TimeoutMS  int64    `json:"timeout_ms"`
}

type gitDiffArgs struct {
	Staged bool `json:"staged"`
}

type gitCloneArgs struct {
	URL         string `json:"url"`
	Destination string `json:"destination"`
}

func decodeArguments(raw json.RawMessage, target any) error {
	if len(raw) == 0 || !json.Valid(raw) {
		return ErrInvalidArguments
	}
	decoder := json.NewDecoder(bytesReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return fmt.Errorf("%w: %v", ErrInvalidArguments, err)
	}
	if decoder.More() {
		return ErrInvalidArguments
	}
	return nil
}

func (d *Dispatcher) Execute(ctx context.Context, req Request) (Response, error) {
	switch req.Capability {
	case "filesystem.read":
		if d.Filesystem == nil {
			return Response{}, errors.New("filesystem executor unavailable")
		}
		var args pathArgs
		if err := decodeArguments(req.Arguments, &args); err != nil {
			return Response{}, err
		}
		data, err := d.Filesystem.Read(args.Path)
		if err != nil {
			return Response{}, err
		}
		return Response{Data: data, Completed: true}, nil

	case "filesystem.list":
		if d.Filesystem == nil {
			return Response{}, errors.New("filesystem executor unavailable")
		}
		var args pathArgs
		if err := decodeArguments(req.Arguments, &args); err != nil {
			return Response{}, err
		}
		data, err := d.Filesystem.List(args.Path)
		if err != nil {
			return Response{}, err
		}
		return Response{Data: data, Completed: true}, nil

	case "filesystem.write":
		if d.Filesystem == nil {
			return Response{}, errors.New("filesystem executor unavailable")
		}
		var args writeArgs
		if err := decodeArguments(req.Arguments, &args); err != nil {
			return Response{}, err
		}
		if err := d.Filesystem.Write(args.Path, []byte(args.Content)); err != nil {
			return Response{}, err
		}
		return Response{Completed: true}, nil

	case "filesystem.patch":
		if d.Filesystem == nil {
			return Response{}, errors.New("filesystem executor unavailable")
		}
		var args patchArgs
		if err := decodeArguments(req.Arguments, &args); err != nil {
			return Response{}, err
		}
		if err := d.Filesystem.Patch(args.Path, []byte(args.Old), []byte(args.Replacement), args.ExpectedReplacements); err != nil {
			return Response{}, err
		}
		return Response{Completed: true}, nil

	case "process.run":
		if !req.Approved {
			return Response{}, ErrApprovalRequired
		}
		if d.Process == nil {
			return Response{}, errors.New("process executor unavailable")
		}
		var args processArgs
		if err := decodeArguments(req.Arguments, &args); err != nil {
			return Response{}, err
		}
		if args.Executable == "" || args.TimeoutMS < 0 {
			return Response{}, ErrInvalidArguments
		}
		timeout := time.Duration(args.TimeoutMS) * time.Millisecond
		result, err := d.Process.Run(ctx, args.Executable, args.Args, timeout)
		if err != nil {
			return Response{}, err
		}
		return Response{Process: &result, Completed: true}, nil

	case "git.status":
		if d.Git == nil {
			return Response{}, errors.New("git executor unavailable")
		}
		if err := decodeArguments(req.Arguments, &struct{}{}); err != nil {
			return Response{}, err
		}
		result, err := d.Git.Status(ctx)
		if err != nil {
			return Response{}, err
		}
		return Response{Process: &result, Completed: true}, nil

	case "git.diff":
		if d.Git == nil {
			return Response{}, errors.New("git executor unavailable")
		}
		var args gitDiffArgs
		if err := decodeArguments(req.Arguments, &args); err != nil {
			return Response{}, err
		}
		result, err := d.Git.Diff(ctx, args.Staged)
		if err != nil {
			return Response{}, err
		}
		return Response{Process: &result, Completed: true}, nil

	case "git.clone":
		if !req.Approved {
			return Response{}, ErrApprovalRequired
		}
		if d.Git == nil {
			return Response{}, errors.New("git executor unavailable")
		}
		var args gitCloneArgs
		if err := decodeArguments(req.Arguments, &args); err != nil {
			return Response{}, err
		}
		result, err := d.Git.Clone(ctx, args.URL, args.Destination)
		if err != nil {
			return Response{}, err
		}
		return Response{Process: &result, Completed: true}, nil

	default:
		return Response{}, ErrUnknownCapability
	}
}
