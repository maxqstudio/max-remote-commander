package policy

import "errors"

type Decision string

const (
	Allow            Decision = "ALLOW"
	Deny             Decision = "DENY"
	ApprovalRequired Decision = "APPROVAL_REQUIRED"
)

var (
	ErrCapabilityDenied = errors.New("capability denied by local policy")
	ErrApprovalRequired = errors.New("capability requires trusted local approval")
)

func DecideCapability(tool string) Decision {
	switch tool {
	case "filesystem.read", "filesystem.list", "git.status", "git.diff":
		return Allow
	case "filesystem.write", "filesystem.patch", "process.run", "git.clone":
		return ApprovalRequired
	case "shell.exec", "powershell.exec", "bash.exec":
		return Deny
	default:
		return Deny
	}
}

func AuthorizeAutomatic(tool string) error {
	switch DecideCapability(tool) {
	case Allow:
		return nil
	case ApprovalRequired:
		return ErrApprovalRequired
	default:
		return ErrCapabilityDenied
	}
}
