package policy

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestWorkspaceAllowsInsideAndRejectsTraversal(t *testing.T) {
	root := t.TempDir()
	inside := filepath.Join(root, "nested", "file.txt")
	if err := os.MkdirAll(filepath.Dir(inside), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(inside, []byte("ok"), 0o600); err != nil {
		t.Fatal(err)
	}
	w, err := NewWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w.Resolve(inside); err != nil {
		t.Fatalf("inside rejected: %v", err)
	}
	outside := filepath.Join(root, "..", "outside.txt")
	if _, err := w.Resolve(outside); !errors.Is(err, ErrPathOutsideWorkspace) {
		t.Fatalf("outside got %v", err)
	}
}

func TestWorkspaceRejectsSymlinkEscapeIncludingMissingChild(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()
	link := filepath.Join(root, "escape")
	if err := os.Symlink(outside, link); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	w, err := NewWorkspace(root)
	if err != nil {
		t.Fatal(err)
	}

	if _, err := w.Resolve(filepath.Join(link, "missing.txt")); !errors.Is(err, ErrPathOutsideWorkspace) {
		t.Fatalf("missing child through symlink escaped guard: %v", err)
	}
	target := filepath.Join(outside, "secret.txt")
	if err := os.WriteFile(target, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := w.Resolve(filepath.Join(link, "secret.txt")); !errors.Is(err, ErrPathOutsideWorkspace) {
		t.Fatalf("existing target through symlink escaped guard: %v", err)
	}
}
