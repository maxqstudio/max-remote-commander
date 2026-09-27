package executor

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"testing"
	"time"
)

func raw(v any) json.RawMessage {
	data, _ := json.Marshal(v)
	return data
}

func TestDispatcherUnknownCapabilityFailsClosed(t *testing.T) {
	d := &Dispatcher{}
	_, err := d.Execute(context.Background(), Request{Capability: "shell.exec", Arguments: raw(struct{}{})})
	if !errors.Is(err, ErrUnknownCapability) {
		t.Fatalf("got %v", err)
	}
}

func TestDispatcherRequiresApprovalBeforePrivilegedExecutors(t *testing.T) {
	d := &Dispatcher{}
	cases := []Request{
		{Capability: "process.run", Arguments: raw(map[string]any{"executable":"helper","args":[]string{},"timeout_ms":1000})},
		{Capability: "git.clone", Arguments: raw(map[string]string{"url":"https://example.com/repo.git","destination":"repo"})},
	}
	for _, req := range cases {
		if _, err := d.Execute(context.Background(), req); !errors.Is(err, ErrApprovalRequired) {
			t.Fatalf("%s: got %v", req.Capability, err)
		}
	}
}

func TestDispatcherRejectsUnknownArgumentFields(t *testing.T) {
	root := t.TempDir()
	fs, err := OpenFilesystem(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	d := &Dispatcher{Filesystem: fs}
	_, err = d.Execute(context.Background(), Request{
		Capability: "filesystem.read",
		Arguments: raw(map[string]any{"path":"x","unexpected":true}),
	})
	if !errors.Is(err, ErrInvalidArguments) {
		t.Fatalf("got %v", err)
	}
}

func TestDispatcherFilesystemRoundTrip(t *testing.T) {
	root := t.TempDir()
	fs, err := OpenFilesystem(root, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer fs.Close()
	d := &Dispatcher{Filesystem: fs}

	if _, err := d.Execute(context.Background(), Request{
		Capability: "filesystem.write",
		Arguments: raw(map[string]string{"path":"note.txt","content":"hello"}),
	}); err != nil {
		t.Fatal(err)
	}
	resp, err := d.Execute(context.Background(), Request{
		Capability: "filesystem.read",
		Arguments: raw(map[string]string{"path":"note.txt"}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if string(resp.Data.([]byte)) != "hello" || !resp.Completed {
		t.Fatalf("response %#v", resp)
	}
}

func TestDispatcherApprovedProcessUsesAllowlist(t *testing.T) {
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	runner, err := NewProcessRunner(
		t.TempDir(),
		[]Executable{{Name:"helper", Path:exe}},
		append(os.Environ(), "MAXRC_HELPER_PROCESS=1"),
		5*time.Second,
		1024,
	)
	if err != nil {
		t.Fatal(err)
	}
	d := &Dispatcher{Process: runner}
	resp, err := d.Execute(context.Background(), Request{
		Capability: "process.run",
		Approved: true,
		Arguments: raw(map[string]any{
			"executable":"helper",
			"args":[]string{"-test.run=TestProcessHelper","--","cwd"},
			"timeout_ms":5000,
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	if resp.Process == nil || resp.Process.ExitCode != 0 || !resp.Completed {
		t.Fatalf("response %#v", resp)
	}
}
