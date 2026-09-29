package controller

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"errors"
	"sync"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/relay"
)

var ErrExecutorConfig = errors.New("invalid controller executor configuration")

type RemoteExecutor struct {
	Client     *Client
	Pairing    Pairing
	PrivateKey ed25519.PrivateKey

	mu      sync.Mutex
	session relay.ControllerSession
}

func NewRemoteExecutor(client *Client, pairing Pairing, privateKey ed25519.PrivateKey) (*RemoteExecutor, error) {
	if client == nil || pairing.DeviceID == "" || pairing.Generation == 0 || len(privateKey) != ed25519.PrivateKeySize {
		return nil, ErrExecutorConfig
	}
	return &RemoteExecutor{
		Client:client,
		Pairing:pairing,
		PrivateKey:append(ed25519.PrivateKey(nil), privateKey...),
	}, nil
}

func (e *RemoteExecutor) ensureSession(ctx context.Context, force bool) (relay.ControllerSession, error) {
	e.mu.Lock()
	defer e.mu.Unlock()
	now := e.Client.now()
	if !force && e.session.Token != "" && e.session.DeviceID == e.Pairing.DeviceID &&
		e.session.Generation == e.Pairing.Generation && e.session.AgentSessionID != "" &&
		now.Before(e.session.ExpiresAt.Add(-5*time.Second)) {
		return e.session, nil
	}
	session, err := e.Client.OpenSession(ctx, e.Pairing, e.PrivateKey)
	if err != nil {
		return relay.ControllerSession{}, err
	}
	e.session = session
	return session, nil
}

func refreshableRelayError(err error) bool {
	var relayErr *RelayError
	return errors.As(err, &relayErr) && (relayErr.Status == 401 || relayErr.Status == 409)
}

func (e *RemoteExecutor) Execute(ctx context.Context, tool string, arguments json.RawMessage) (json.RawMessage, error) {
	if tool == "" || len(arguments) == 0 || !json.Valid(arguments) {
		return nil, ErrExecutorConfig
	}
	session, err := e.ensureSession(ctx, false)
	if err != nil {
		return nil, err
	}
	requestID, err := NewRequestID()
	if err != nil {
		return nil, err
	}
	if err := e.Client.QueueTool(ctx, session, e.PrivateKey, requestID, tool, arguments); err != nil {
		if !refreshableRelayError(err) {
			return nil, err
		}
		session, err = e.ensureSession(ctx, true)
		if err != nil {
			return nil, err
		}
		requestID, err = NewRequestID()
		if err != nil {
			return nil, err
		}
		if err := e.Client.QueueTool(ctx, session, e.PrivateKey, requestID, tool, arguments); err != nil {
			return nil, err
		}
	}

	for {
		result, ok, err := e.Client.WaitResult(ctx, session.Token, requestID)
		if err != nil {
			if !refreshableRelayError(err) {
				return nil, err
			}
			session, err = e.ensureSession(ctx, true)
			if err != nil {
				return nil, err
			}
			continue
		}
		if ok {
			return result, nil
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
}
