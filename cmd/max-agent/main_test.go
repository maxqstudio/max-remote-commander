package main

import (
	"bufio"
	"bytes"
	"context"
	"path/filepath"
	"strings"
	"testing"

	"github.com/maxqstudio/max-remote-commander/internal/agent"
)

func TestParseExecutablesRequiresAbsoluteUniquePaths(t *testing.T) {
	absolute := filepath.Join(t.TempDir(), "tool")
	got, err := parseExecutables([]string{"tool=" + absolute})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Name != "tool" || got[0].Path != absolute {
		t.Fatalf("got %#v", got)
	}
	if _, err := parseExecutables([]string{"tool=relative"}); err == nil {
		t.Fatal("relative executable path was accepted")
	}
	if _, err := parseExecutables([]string{"tool=" + absolute, "tool=" + absolute}); err == nil {
		t.Fatal("duplicate executable name was accepted")
	}
	if _, err := parseExecutables([]string{"bad/name=" + absolute}); err == nil {
		t.Fatal("path-like executable name was accepted")
	}
}

func TestConsoleApproverDefaultsToDeny(t *testing.T) {
	var output bytes.Buffer
	approver := &consoleApprover{
		reader: bufio.NewReader(strings.NewReader("\n")),
		writer: &output,
	}
	approved, err := approver.Approve(context.Background(), agent.ApprovalPrompt{
		RequestID: "req-1",
		Capability: "filesystem.write",
		Summary: "filesystem.write \"note.txt\"",
		ArgumentsSHA256: strings.Repeat("a", 64),
	})
	if err != nil {
		t.Fatal(err)
	}
	if approved {
		t.Fatal("blank approval input was accepted")
	}
	if !strings.Contains(output.String(), "Approve once? [y/N]") {
		t.Fatalf("prompt missing: %q", output.String())
	}
}

func TestConsoleApproverRequiresExplicitYes(t *testing.T) {
	for _, input := range []string{"y\n", "YES\n"} {
		approver := &consoleApprover{
			reader: bufio.NewReader(strings.NewReader(input)),
			writer: &bytes.Buffer{},
		}
		approved, err := approver.Approve(context.Background(), agent.ApprovalPrompt{
			RequestID: "req-1",
			Capability: "git.clone",
			Summary: "git clone",
			ArgumentsSHA256: strings.Repeat("b", 64),
		})
		if err != nil {
			t.Fatal(err)
		}
		if !approved {
			t.Fatalf("input %q was not accepted", input)
		}
	}
}
