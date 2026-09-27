package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/approval"
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
		_, err := d.Dispatch(context.Background(), CapabilityRequest{RequestID:"req-remote", Tool: tool, Arguments: writeArgs})
		if !errors.Is(err, policy.ErrApprovalRequired) {
			t.Fatalf("%s: got %v", tool, err)
		}
	}
	if _, err := os.Stat(filepath.Join(root, "created.txt")); !os.IsNotExist(err) {
		t.Fatalf("privileged request caused side effect: %v", err)
	}
}

func TestLocalApprovalBindsExactRequestAndIsOneUse(t *testing.T) {
	root := t.TempDir()
	fs, err := OpenFilesystem(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	approvals := approval.NewStore(time.Minute)
	d := &Dispatcher{Filesystem: fs, Approvals: approvals}

	args := json.RawMessage(`{"path":"approved.txt","content":"hello"}`)
	req := CapabilityRequest{RequestID:"req-1", Tool:"filesystem.write", Arguments:args}
	token, err := approvals.Issue(req.RequestID, req.Tool, req.Arguments, 30*time.Second, time.Now())
	if err != nil {
		t.Fatal(err)
	}

	tampered := req
	tampered.Arguments = json.RawMessage(`{"path":"approved.txt","content":"tampered"}`)
	if _, err := d.DispatchApproved(context.Background(), tampered, token); !errors.Is(err, approval.ErrApprovalBinding) {
		t.Fatalf("tampered approval: %v", err)
	}
	if _, err := os.Stat(filepath.Join(root, "approved.txt")); !os.IsNotExist(err) {
		t.Fatalf("tampered approval caused side effect: %v", err)
	}
	if _, err := d.DispatchApproved(context.Background(), req, token); !errors.Is(err, approval.ErrApprovalMissing) {
		t.Fatalf("consumed token replay: %v", err)
	}

	token, err = approvals.Issue(req.RequestID, req.Tool, req.Arguments, 30*time.Second, time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.DispatchApproved(context.Background(), req, token); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(filepath.Join(root, "approved.txt"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != "hello" {
		t.Fatalf("content %q", got)
	}
	if _, err := d.DispatchApproved(context.Background(), req, token); !errors.Is(err, approval.ErrApprovalMissing) {
		t.Fatalf("approved replay: %v", err)
	}
}

func TestDispatcherDeniesShellEvenWithApprovedPath(t *testing.T) {
	d := &Dispatcher{Approvals: approval.NewStore(time.Minute)}
	req := CapabilityRequest{RequestID:"req-shell", Tool:"shell.exec", Arguments:json.RawMessage(`{}`)}
	if _, err := d.DispatchApproved(context.Background(), req, "anything"); !errors.Is(err, policy.ErrCapabilityDenied) {
		t.Fatalf("got %v", err)
	}
}
