package executor

import (
	"context"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func requireGit(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("git")
	if err != nil {
		t.Skip("git not available")
	}
	return path
}

func initGitRepo(t *testing.T) string {
	t.Helper()
	git := requireGit(t)
	root := t.TempDir()
	cmd := exec.Command(git, "init", root)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("git init: %v: %s", err, out)
	}
	return root
}

func TestGitStatusAndDiff(t *testing.T) {
	root := initGitRepo(t)
	git, err := NewGit(root, os.Environ(), 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("one\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gitPath := requireGit(t)
	add := exec.Command(gitPath, "-C", root, "add", "tracked.txt")
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("git add: %v: %s", err, out)
	}
	if err := os.WriteFile(filepath.Join(root, "tracked.txt"), []byte("one\ntwo\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	status, err := git.Status(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.ExitCode != 0 || !strings.Contains(string(status.Stdout), "tracked.txt") {
		t.Fatalf("status %#v stdout=%q stderr=%q", status, status.Stdout, status.Stderr)
	}

	diff, err := git.Diff(context.Background(), false)
	if err != nil {
		t.Fatal(err)
	}
	if diff.ExitCode != 0 || !strings.Contains(string(diff.Stdout), "+two") {
		t.Fatalf("diff %#v stdout=%q stderr=%q", diff, diff.Stdout, diff.Stderr)
	}
}

func TestGitCloneValidationFailsClosed(t *testing.T) {
	root := t.TempDir()
	git, err := NewGit(root, os.Environ(), 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}

	for _, raw := range []string{
		"file:///tmp/repo",
		"ssh://example.com/repo.git",
		"https://user:secret@example.com/repo.git",
		"https://example.com/repo.git#fragment",
		"not-a-url",
	} {
		if _, err := git.Clone(context.Background(), raw, "repo"); !errors.Is(err, ErrCloneURLDenied) {
			t.Fatalf("URL %q: got %v", raw, err)
		}
	}

	for _, destination := range []string{"", ".", "../repo", filepath.Join("nested", "repo")} {
		if _, err := git.Clone(context.Background(), "https://example.com/repo.git", destination); !errors.Is(err, ErrCloneDestination) {
			t.Fatalf("destination %q: got %v", destination, err)
		}
	}

	existing := filepath.Join(root, "existing")
	if err := os.Mkdir(existing, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := git.Clone(context.Background(), "https://example.com/repo.git", "existing"); !errors.Is(err, ErrCloneDestinationExists) {
		t.Fatalf("existing destination: got %v", err)
	}
}

func TestValidateCloneURLAllowsCredentialFreeHTTPS(t *testing.T) {
	if err := validateCloneURL("https://example.com/org/repo.git"); err != nil {
		t.Fatal(err)
	}
}


func TestGitEnvironmentDropsCredentialAndUserConfigState(t *testing.T) {
	root := t.TempDir()
	git, err := NewGit(root, []string{
		"PATH=/sensitive/path",
		"HOME=/home/with-credentials",
		"USERPROFILE=C:\\Users\\secret",
		"GITHUB_TOKEN=top-secret",
		"GIT_ASKPASS=/tmp/steal",
		"GIT_TERMINAL_PROMPT=1",
		"TEMP=/tmp/safe",
		"LANG=C",
	}, 5*time.Second, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	joined := "\n" + strings.Join(git.runner.env, "\n") + "\n"
	for _, forbidden := range []string{
		"PATH=/sensitive/path",
		"HOME=/home/with-credentials",
		"USERPROFILE=C:\\Users\\secret",
		"GITHUB_TOKEN=top-secret",
		"GIT_ASKPASS=/tmp/steal",
		"GIT_TERMINAL_PROMPT=1",
	} {
		if strings.Contains(joined, "\n"+forbidden+"\n") {
			t.Fatalf("sensitive environment survived: %q in %#v", forbidden, git.runner.env)
		}
	}
	for _, required := range []string{
		"TEMP=/tmp/safe",
		"LANG=C",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL="+os.DevNull,
		"GIT_TERMINAL_PROMPT=0",
		"GIT_ASKPASS=",
	} {
		if !strings.Contains(joined, "\n"+required+"\n") {
			t.Fatalf("required isolated environment missing: %q in %#v", required, git.runner.env)
		}
	}
}
