package policy

import (
	"errors"
	"testing"
)

func TestDefaultCapabilityPolicy(t *testing.T) {
	tests := map[string]Decision{
		"filesystem.read":  Allow,
		"filesystem.list":  Allow,
		"git.status":       Allow,
		"git.diff":         Allow,
		"filesystem.write": ApprovalRequired,
		"filesystem.patch": ApprovalRequired,
		"process.run":      ApprovalRequired,
		"git.clone":        ApprovalRequired,
		"shell.exec":       Deny,
		"powershell.exec":  Deny,
		"bash.exec":        Deny,
		"registry.write":   Deny,
	}
	for tool, want := range tests {
		if got := DecideCapability(tool); got != want {
			t.Errorf("%s: got %s want %s", tool, got, want)
		}
	}
}

func TestAuthorizeAutomaticFailsClosed(t *testing.T) {
	if err := AuthorizeAutomatic("filesystem.read"); err != nil {
		t.Fatal(err)
	}
	if err := AuthorizeAutomatic("process.run"); !errors.Is(err, ErrApprovalRequired) {
		t.Fatalf("process.run: %v", err)
	}
	if err := AuthorizeAutomatic("unknown"); !errors.Is(err, ErrCapabilityDenied) {
		t.Fatalf("unknown: %v", err)
	}
}
