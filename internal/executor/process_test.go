package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func helperRunner(t *testing.T, maxTimeout time.Duration, maxOutput int) *ProcessRunner {
	t.Helper()
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewProcessRunner(
		t.TempDir(),
		[]Executable{{Name: "helper", Path: exe}},
		append(os.Environ(), "MAXRC_HELPER_PROCESS=1"),
		maxTimeout,
		maxOutput,
	)
	if err != nil {
		t.Fatal(err)
	}
	return runner
}

func TestProcessHelper(t *testing.T) {
	if os.Getenv("MAXRC_HELPER_PROCESS") != "1" {
		return
	}
	mode := ""
	for i, arg := range os.Args {
		if arg == "--" && i+1 < len(os.Args) {
			mode = os.Args[i+1]
			break
		}
	}
	switch mode {
	case "cwd":
		cwd, _ := os.Getwd()
		fmt.Print(cwd)
		fmt.Fprint(os.Stderr, "helper-stderr")
	case "large":
		fmt.Print(strings.Repeat("x", 128))
	case "sleep":
		time.Sleep(2 * time.Second)
	case "exit7":
		os.Exit(7)
	default:
		os.Exit(9)
	}
	os.Exit(0)
}

func TestProcessRunnerUsesArgvAndTrustedWorkspace(t *testing.T) {
	runner := helperRunner(t, time.Second, 1024)
	result, err := runner.Run(context.Background(), "helper", []string{"-test.run=TestProcessHelper", "--", "cwd"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 0 || result.TimedOut || result.Truncated {
		t.Fatalf("result %#v", result)
	}
	got := filepath.Clean(string(result.Stdout))
	if got != runner.workspaceRoot {
		t.Fatalf("cwd %q want %q", got, runner.workspaceRoot)
	}
	if string(result.Stderr) != "helper-stderr" {
		t.Fatalf("stderr %q", result.Stderr)
	}
}

func TestProcessRunnerDeniesUnknownExecutable(t *testing.T) {
	runner := helperRunner(t, time.Second, 1024)
	if _, err := runner.Run(context.Background(), "sh", []string{"-c", "echo unsafe"}, time.Second); !errors.Is(err, ErrExecutableDenied) {
		t.Fatalf("got %v", err)
	}
}

func TestProcessRunnerRejectsExcessiveTimeout(t *testing.T) {
	runner := helperRunner(t, 100*time.Millisecond, 1024)
	if _, err := runner.Run(context.Background(), "helper", []string{"-test.run=TestProcessHelper", "--", "cwd"}, time.Second); !errors.Is(err, ErrInvalidTimeout) {
		t.Fatalf("got %v", err)
	}
}

func TestProcessRunnerReportsTimeoutWithoutHanging(t *testing.T) {
	runner := helperRunner(t, 150*time.Millisecond, 1024)
	result, err := runner.Run(context.Background(), "helper", []string{"-test.run=TestProcessHelper", "--", "sleep"}, 100*time.Millisecond)
	if err != nil {
		t.Fatal(err)
	}
	if !result.TimedOut || result.ExitCode != -1 {
		t.Fatalf("result %#v", result)
	}
}

func TestProcessRunnerBoundsOutput(t *testing.T) {
	runner := helperRunner(t, time.Second, 16)
	result, err := runner.Run(context.Background(), "helper", []string{"-test.run=TestProcessHelper", "--", "large"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Truncated || len(result.Stdout) != 16 {
		t.Fatalf("result %#v len=%d", result, len(result.Stdout))
	}
}

func TestProcessRunnerReturnsNonZeroExitAsResult(t *testing.T) {
	runner := helperRunner(t, time.Second, 1024)
	result, err := runner.Run(context.Background(), "helper", []string{"-test.run=TestProcessHelper", "--", "exit7"}, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if result.ExitCode != 7 || result.TimedOut {
		t.Fatalf("result %#v", result)
	}
}
