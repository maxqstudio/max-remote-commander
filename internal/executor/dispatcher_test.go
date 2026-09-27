package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/maxqstudio/max-remote-commander/internal/policy"
)

func TestDispatcherAllowsReadAndList(t *testing.T) {
	root := t.TempDir()
	fs, err := OpenFilesystem(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	if err := os.WriteFile(filepath.Join(root, "note.txt"), []byte("hello"), 0o600); err != nil {
		t.Fatal(err)
	}

	d := &Dispatcher{Filesystem: fs}
	readArgs, _ := json.Marshal(pathArguments{Path: "note.txt"})
	read, err := d.Dispatch(context.Background(), CapabilityRequest{Tool: "filesystem.read", Arguments: readArgs})
	if err != nil {
		t.Fatal(err)
	}
	if string(read.Data) != "hello" {
		t.Fatalf("read %q", read.Data)
	}

	listArgs, _ := json.Marshal(pathArguments{Path: "."})
	list, err := d.Dispatch(context.Background(), CapabilityRequest{Tool: "filesystem.list", Arguments: listArgs})
	if err != nil {
		t.Fatal(err)
	}
	if len(list.Entries) != 1 || list.Entries[0].Name != "note.txt" {
		t.Fatalf("entries %#v", list.Entries)
	}
}

func TestDispatcherDoesNotTrustRemoteApprovalForPrivilegedTools(t *testing.T) {
	root := t.TempDir()
	fs, err := OpenFilesystem(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	d := &Dispatcher{Filesystem: fs}

	writeArgs := json.RawMessage(`{"path":"created.txt","content":"ignored"}`)
	for _, tool := range []string{"filesystem.write", "filesystem.patch", "process.run", "git.clone"} {
		_, err := d.Dispatch(context.Background(), CapabilityRequest{Tool: tool, Arguments: writeArgs})
		if !errors.Is(err, policy.ErrApprovalRequired) {
			t.Fatalf("%s: got %v", tool, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "created.txt")); !os.IsNotExist(err) {
		t.Fatalf("privileged request caused side effect: %v", err)
	}
}

func TestDispatcherDeniesShellAndUnknownTools(t *testing.T) {
	d := &Dispatcher{}
	for _, tool := range []string{"shell.exec", "powershell.exec", "bash.exec", "registry.write", ""} {
		_, err := d.Dispatch(context.Background(), CapabilityRequest{Tool: tool, Arguments: json.RawMessage(`{}`)})
		if !errors.Is(err, policy.ErrCapabilityDenied) {
			t.Fatalf("%q: got %v", tool, err)
		}
	}
}
