package executor

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func openTestFS(t *testing.T, maxBytes int64) (*Filesystem, string) {
	t.Helper()
	root := t.TempDir()
	fs, err := OpenFilesystem(root, maxBytes)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if err := fs.Close(); err != nil {
			t.Errorf("close filesystem: %v", err)
		}
	})
	return fs, root
}

func TestFilesystemReadWriteListPatch(t *testing.T) {
	fs, root := openTestFS(t, 0)
	if err := os.Mkdir(filepath.Join(root, "src"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := fs.Write(filepath.Join("src", "main.txt"), []byte("alpha beta")); err != nil {
		t.Fatal(err)
	}
	got, err := fs.Read(filepath.Join("src", "main.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "alpha beta" {
		t.Fatalf("read %q", got)
	}
	if err := fs.Patch(filepath.Join("src", "main.txt"), []byte("beta"), []byte("gamma"), 1); err != nil {
		t.Fatal(err)
	}
	got, err = fs.Read(filepath.Join("src", "main.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "alpha gamma" {
		t.Fatalf("patched %q", got)
	}
	entries, err := fs.List("src")
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 1 || entries[0].Name != "main.txt" || entries[0].IsDir {
		t.Fatalf("entries %#v", entries)
	}
}

func TestFilesystemRejectsTraversalAndAbsolutePath(t *testing.T) {
	fs, root := openTestFS(t, 0)
	outside := filepath.Join(filepath.Dir(root), "outside.txt")
	if err := os.WriteFile(outside, []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Remove(outside) })

	for _, name := range []string{filepath.Join("..", "outside.txt"), outside} {
		if _, err := fs.Read(name); !errors.Is(err, ErrInvalidPath) {
			t.Fatalf("read %q: got %v", name, err)
		}
	}
}

func TestFilesystemRejectsSymlinkEscape(t *testing.T) {
	fs, root := openTestFS(t, 0)
	outside := t.TempDir()
	if err := os.WriteFile(filepath.Join(outside, "secret.txt"), []byte("secret"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symlink unavailable on this Windows runner: %v", err)
		}
		t.Fatal(err)
	}
	if data, err := fs.Read(filepath.Join("escape", "secret.txt")); err == nil {
		t.Fatalf("symlink escape returned %q", data)
	}
}

func TestFilesystemEnforcesSizeLimit(t *testing.T) {
	fs, root := openTestFS(t, 4)
	if err := fs.Write("too-big.txt", []byte("12345")); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("write: got %v", err)
	}
	if err := os.WriteFile(filepath.Join(root, "external.txt"), []byte("12345"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := fs.Read("external.txt"); !errors.Is(err, ErrTooLarge) {
		t.Fatalf("read: got %v", err)
	}
}

func TestFilesystemPatchIsFailClosedOnMismatch(t *testing.T) {
	fs, _ := openTestFS(t, 0)
	if err := fs.Write("note.txt", []byte("one two two")); err != nil {
		t.Fatal(err)
	}
	if err := fs.Patch("note.txt", []byte("two"), []byte("three"), 1); !errors.Is(err, ErrPatchConflict) {
		t.Fatalf("patch: got %v", err)
	}
	got, err := fs.Read("note.txt")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "one two two" {
		t.Fatalf("patch mutated file on conflict: %q", got)
	}
}
