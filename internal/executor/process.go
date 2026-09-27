package executor

import (
	"bytes"
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

const (
	DefaultProcessTimeout = 30 * time.Second
	DefaultMaxOutputBytes = 1 << 20
)

var (
	ErrExecutableDenied = errors.New("executable is not allowlisted")
	ErrInvalidTimeout   = errors.New("process timeout exceeds configured maximum")
)

type Executable struct {
	Name string
	Path string
}

type ProcessRunner struct {
	workspaceRoot string
	allowed       map[string]string
	env           []string
	maxTimeout    time.Duration
	maxOutput     int
}

type ProcessResult struct {
	Stdout    []byte
	Stderr    []byte
	ExitCode  int
	TimedOut  bool
	Truncated bool
}

func NewProcessRunner(workspaceRoot string, executables []Executable, env []string, maxTimeout time.Duration, maxOutput int) (*ProcessRunner, error) {
	root, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return nil, err
	}
	root, err = filepath.EvalSymlinks(root)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(root)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, errors.New("workspace root is not a directory")
	}

	allowed := make(map[string]string, len(executables))
	for _, item := range executables {
		if item.Name == "" {
			return nil, errors.New("allowlisted executable requires a name")
		}
		path := item.Path
		if path == "" {
			path, err = exec.LookPath(item.Name)
			if err != nil {
				return nil, err
			}
		}
		path, err = filepath.Abs(path)
		if err != nil {
			return nil, err
		}
		allowed[item.Name] = filepath.Clean(path)
	}
	if maxTimeout <= 0 {
		maxTimeout = DefaultProcessTimeout
	}
	if maxOutput <= 0 {
		maxOutput = DefaultMaxOutputBytes
	}
	return &ProcessRunner{
		workspaceRoot: filepath.Clean(root),
		allowed:       allowed,
		env:           append([]string(nil), env...),
		maxTimeout:    maxTimeout,
		maxOutput:     maxOutput,
	}, nil
}

func (r *ProcessRunner) Run(ctx context.Context, executable string, args []string, timeout time.Duration) (ProcessResult, error) {
	path, ok := r.allowed[executable]
	if !ok {
		return ProcessResult{}, ErrExecutableDenied
	}
	if timeout <= 0 {
		timeout = r.maxTimeout
	}
	if timeout > r.maxTimeout {
		return ProcessResult{}, ErrInvalidTimeout
	}

	runCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	stdout := &limitedBuffer{limit: r.maxOutput}
	stderr := &limitedBuffer{limit: r.maxOutput}
	cmd := exec.CommandContext(runCtx, path, args...)
	cmd.Dir = r.workspaceRoot
	cmd.Env = append([]string{}, r.env...)
	cmd.Stdout = stdout
	cmd.Stderr = stderr

	err := cmd.Run()
	result := ProcessResult{
		Stdout: append([]byte(nil), stdout.Bytes()...),
		Stderr: append([]byte(nil), stderr.Bytes()...),
		Truncated: stdout.truncated || stderr.truncated,
	}
	if runCtx.Err() == context.DeadlineExceeded {
		result.TimedOut = true
		result.ExitCode = -1
		return result, nil
	}
	if err == nil {
		result.ExitCode = 0
		return result, nil
	}
	var exitErr *exec.ExitError
	if errors.As(err, &exitErr) {
		result.ExitCode = exitErr.ExitCode()
		return result, nil
	}
	return result, err
}

type limitedBuffer struct {
	bytes.Buffer
	limit     int
	truncated bool
}

func (b *limitedBuffer) Write(p []byte) (int, error) {
	if b.limit <= 0 {
		b.truncated = b.truncated || len(p) > 0
		return len(p), nil
	}
	remaining := b.limit - b.Len()
	if remaining > 0 {
		n := len(p)
		if n > remaining {
			n = remaining
		}
		_, _ = b.Buffer.Write(p[:n])
	}
	if len(p) > remaining {
		b.truncated = true
	}
	return len(p), nil
}
