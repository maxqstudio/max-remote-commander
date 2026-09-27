package executor

import (
	"context"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"
)

var (
	ErrCloneURLDenied       = errors.New("clone URL must be credential-free HTTPS")
	ErrCloneDestination     = errors.New("clone destination must be a new direct child of the workspace")
	ErrCloneDestinationExists = errors.New("clone destination already exists")
)

type Git struct {
	runner  *ProcessRunner
	timeout time.Duration
}

func NewGit(workspaceRoot string, env []string, maxTimeout time.Duration, maxOutput int) (*Git, error) {
	runner, err := NewProcessRunner(
		workspaceRoot,
		[]Executable{{Name: "git"}},
		env,
		maxTimeout,
		maxOutput,
	)
	if err != nil {
		return nil, err
	}
	if maxTimeout <= 0 {
		maxTimeout = DefaultProcessTimeout
	}
	return &Git{runner: runner, timeout: maxTimeout}, nil
}

func (g *Git) Status(ctx context.Context) (ProcessResult, error) {
	return g.runner.Run(ctx, "git", []string{
		"--no-optional-locks",
		"status",
		"--porcelain=v1",
		"--branch",
	}, g.timeout)
}

func (g *Git) Diff(ctx context.Context, staged bool) (ProcessResult, error) {
	args := []string{
		"--no-optional-locks",
		"diff",
		"--no-ext-diff",
		"--no-textconv",
	}
	if staged {
		args = append(args, "--cached")
	}
	args = append(args, "--")
	return g.runner.Run(ctx, "git", args, g.timeout)
}

func (g *Git) Clone(ctx context.Context, rawURL, destination string) (ProcessResult, error) {
	if err := validateCloneURL(rawURL); err != nil {
		return ProcessResult{}, err
	}
	if err := g.validateCloneDestination(destination); err != nil {
		return ProcessResult{}, err
	}
	return g.runner.Run(ctx, "git", []string{
		"-c", "core.hooksPath=",
		"-c", "protocol.file.allow=never",
		"clone",
		"--no-recurse-submodules",
		"--",
		rawURL,
		destination,
	}, g.timeout)
}

func validateCloneURL(rawURL string) error {
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil {
		return ErrCloneURLDenied
	}
	if u.Fragment != "" {
		return ErrCloneURLDenied
	}
	return nil
}

func (g *Git) validateCloneDestination(destination string) error {
	if destination == "" || !filepath.IsLocal(destination) {
		return ErrCloneDestination
	}
	clean := filepath.Clean(destination)
	if clean == "." || filepath.Dir(clean) != "." || strings.ContainsAny(clean, "/\\") {
		return ErrCloneDestination
	}
	full := filepath.Join(g.runner.workspaceRoot, clean)
	_, err := os.Lstat(full)
	if err == nil {
		return ErrCloneDestinationExists
	}
	if !os.IsNotExist(err) {
		return err
	}
	return nil
}
