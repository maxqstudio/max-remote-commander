package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/audit"
	"github.com/maxqstudio/max-remote-commander/internal/executor"
	"github.com/maxqstudio/max-remote-commander/internal/identity"
	"github.com/maxqstudio/max-remote-commander/internal/policy"
	"github.com/maxqstudio/max-remote-commander/internal/protocol"
	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

var (
	ErrRunnerConfig   = errors.New("invalid agent runner configuration")
	ErrSessionBinding = errors.New("relay session binding mismatch")
)

type CommandTransport interface {
	DeviceSession(context.Context, relay.DeviceAssertion) (relay.Session, error)
	NextCommand(context.Context, string, string, time.Duration) (protocol.CommandEnvelope, bool, error)
	SubmitResult(context.Context, string, string, string, any) error
}

type AuditSink interface {
	Append(audit.Event) error
}

type ApprovalPrompt struct {
	RequestID       string
	Capability      string
	ArgumentsSHA256 string
}

type TrustedApprover interface {
	Approve(context.Context, ApprovalPrompt) (bool, error)
}

type RunnerConfig struct {
	Device      *identity.Device
	Pairing     PairingState
	Transport   CommandTransport
	Dispatcher  *executor.Dispatcher
	Audit       AuditSink
	Approver    TrustedApprover
	SessionID   string
	PollWait    time.Duration
	ApprovalTTL time.Duration
	ClockSkew   time.Duration
	Now         func() time.Time
}

type Runner struct {
	device      *identity.Device
	pairing     PairingState
	transport   CommandTransport
	dispatcher  *executor.Dispatcher
	audit       AuditSink
	approver    TrustedApprover
	sessionID   string
	pollWait    time.Duration
	approvalTTL time.Duration
	now         func() time.Time
	verifier    *protocol.Verifier
}

type WireResult struct {
	Status string                     `json:"status"`
	Result *executor.CapabilityResult `json:"result,omitempty"`
	Code   string                     `json:"code,omitempty"`
}

func NewRunner(cfg RunnerConfig) (*Runner, error) {
	if cfg.Device == nil || cfg.Transport == nil || cfg.Dispatcher == nil || cfg.Audit == nil {
		return nil, ErrRunnerConfig
	}
	if err := validatePairingState(cfg.Pairing); err != nil || cfg.Pairing.DeviceID != cfg.Device.ID() {
		return nil, ErrRunnerConfig
	}
	sessionID := cfg.SessionID
	if sessionID == "" {
		var err error
		sessionID, err = protocol.NewSessionID()
		if err != nil {
			return nil, err
		}
	}
	if cfg.PollWait <= 0 {
		cfg.PollWait = 25 * time.Second
	}
	if cfg.PollWait > 30*time.Second {
		cfg.PollWait = 30 * time.Second
	}
	if cfg.ApprovalTTL <= 0 {
		cfg.ApprovalTTL = 30 * time.Second
	}
	if cfg.ApprovalTTL > 2*time.Minute || cfg.ClockSkew < 0 {
		return nil, ErrRunnerConfig
	}
	if cfg.ClockSkew == 0 {
		cfg.ClockSkew = 30 * time.Second
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	verifier, err := protocol.NewVerifier(
		cfg.Pairing.ControllerPublicKey,
		cfg.Pairing.DeviceID,
		sessionID,
		cfg.ClockSkew,
		protocol.NewMemoryReplayStore(),
	)
	if err != nil {
		return nil, err
	}
	return &Runner{
		device: cfg.Device, pairing: cfg.Pairing, transport: cfg.Transport,
		dispatcher: cfg.Dispatcher, audit: cfg.Audit, approver: cfg.Approver,
		sessionID: sessionID, pollWait: cfg.PollWait, approvalTTL: cfg.ApprovalTTL,
		now: cfg.Now, verifier: verifier,
	}, nil
}

func (r *Runner) SessionID() string { return r.sessionID }

func (r *Runner) Run(ctx context.Context) error {
	session, err := r.openSession(ctx)
	if err != nil {
		return err
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		now := r.now()
		if !now.Before(session.ExpiresAt.Add(-5 * time.Second)) {
			session, err = r.openSession(ctx)
			if err != nil {
				return err
			}
		}
		envelope, ok, err := r.transport.NextCommand(ctx, r.pairing.DeviceID, session.Token, r.pollWait)
		if err != nil {
			var relayErr *RelayError
			if errors.As(err, &relayErr) && relayErr.Status == 401 {
				session, err = r.openSession(ctx)
				if err != nil {
					return err
				}
				continue
			}
			return err
		}
		if !ok {
			continue
		}
		result, fatalErr := r.handleCommand(ctx, envelope)
		if fatalErr != nil {
			return fatalErr
		}
		if err := r.transport.SubmitResult(ctx, r.pairing.DeviceID, session.Token, envelope.RequestID, result); err != nil {
			var relayErr *RelayError
			if errors.As(err, &relayErr) && relayErr.Status == 401 {
				session, err = r.openSession(ctx)
				if err != nil {
					return err
				}
				if err := r.transport.SubmitResult(ctx, r.pairing.DeviceID, session.Token, envelope.RequestID, result); err != nil {
					return err
				}
				continue
			}
			return err
		}
	}
}

func (r *Runner) openSession(ctx context.Context) (relay.Session, error) {
	now := r.now()
	nonce, err := protocol.NewSessionID()
	if err != nil {
		return relay.Session{}, err
	}
	assertion := relay.DeviceAssertion{
		DeviceID: r.pairing.DeviceID,
		Generation: r.pairing.Generation,
		AgentSessionID: r.sessionID,
		IssuedAt: now.Unix(),
		ExpiresAt: now.Add(30 * time.Second).Unix(),
		Nonce: nonce,
	}
	if err := relay.SignDeviceAssertion(&assertion, r.device.PrivateKey()); err != nil {
		return relay.Session{}, err
	}
	session, err := r.transport.DeviceSession(ctx, assertion)
	if err != nil {
		return relay.Session{}, err
	}
	if session.AgentSessionID != r.sessionID || session.Generation != r.pairing.Generation ||
		session.Token == "" || !session.ExpiresAt.After(now) {
		return relay.Session{}, ErrSessionBinding
	}
	return session, nil
}

func argsDigest(raw json.RawMessage) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func (r *Runner) auditDecision(envelope protocol.CommandEnvelope, decision, outcome string) error {
	return r.audit.Append(audit.Event{
		Time: r.now(), Kind: "command_decision", DeviceID: envelope.DeviceID,
		RequestID: envelope.RequestID, Capability: envelope.Tool,
		Decision: decision, Outcome: outcome, ArgumentsSHA256: argsDigest(envelope.Arguments),
	})
}

func (r *Runner) auditOutcome(envelope protocol.CommandEnvelope, outcome string) error {
	return r.audit.Append(audit.Event{
		Time: r.now(), Kind: "command_result", DeviceID: envelope.DeviceID,
		RequestID: envelope.RequestID, Capability: envelope.Tool,
		Outcome: outcome, ArgumentsSHA256: argsDigest(envelope.Arguments),
	})
}

func (r *Runner) handleCommand(ctx context.Context, envelope protocol.CommandEnvelope) (WireResult, error) {
	if err := r.verifier.Verify(envelope, r.now()); err != nil {
		if auditErr := r.auditDecision(envelope, "deny", "invalid_envelope"); auditErr != nil {
			return WireResult{}, auditErr
		}
		return WireResult{Status: "rejected", Code: "invalid_envelope"}, nil
	}

	req := executor.CapabilityRequest{RequestID: envelope.RequestID, Tool: envelope.Tool, Arguments: envelope.Arguments}
	switch policy.DecideCapability(envelope.Tool) {
	case policy.Deny:
		if err := r.auditDecision(envelope, "deny", "policy_denied"); err != nil {
			return WireResult{}, err
		}
		return WireResult{Status: "denied", Code: "policy_denied"}, nil

	case policy.Allow:
		if err := r.auditDecision(envelope, "allow", "authorized"); err != nil {
			return WireResult{}, err
		}
		result, err := r.dispatcher.Dispatch(ctx, req)
		if err != nil {
			if auditErr := r.auditOutcome(envelope, "execution_failed"); auditErr != nil {
				return WireResult{}, auditErr
			}
			return WireResult{Status: "failed", Code: "execution_failed"}, nil
		}
		if err := r.auditOutcome(envelope, "completed"); err != nil {
			return WireResult{}, err
		}
		return WireResult{Status: "completed", Result: &result}, nil

	case policy.ApprovalRequired:
		if r.approver == nil || r.dispatcher.Approvals == nil {
			if err := r.auditDecision(envelope, "approval_required", "pending"); err != nil {
				return WireResult{}, err
			}
			return WireResult{Status: "approval_required", Code: "local_approval_required"}, nil
		}
		approved, err := r.approver.Approve(ctx, ApprovalPrompt{
			RequestID: envelope.RequestID,
			Capability: envelope.Tool,
			ArgumentsSHA256: argsDigest(envelope.Arguments),
		})
		if err != nil {
			return WireResult{}, err
		}
		if !approved {
			if err := r.auditDecision(envelope, "deny", "local_rejected"); err != nil {
				return WireResult{}, err
			}
			return WireResult{Status: "denied", Code: "local_rejected"}, nil
		}
		token, err := r.dispatcher.Approvals.Issue(
			envelope.RequestID, envelope.Tool, envelope.Arguments,
			r.approvalTTL, time.Now(),
		)
		if err != nil {
			return WireResult{}, err
		}
		if err := r.auditDecision(envelope, "allow", "local_approved"); err != nil {
			return WireResult{}, err
		}
		result, err := r.dispatcher.DispatchApproved(ctx, req, token)
		if err != nil {
			if auditErr := r.auditOutcome(envelope, "execution_failed"); auditErr != nil {
				return WireResult{}, auditErr
			}
			return WireResult{Status: "failed", Code: "execution_failed"}, nil
		}
		if err := r.auditOutcome(envelope, "completed"); err != nil {
			return WireResult{}, err
		}
		return WireResult{Status: "completed", Result: &result}, nil
	default:
		return WireResult{Status: "denied", Code: "policy_denied"}, nil
	}
}
