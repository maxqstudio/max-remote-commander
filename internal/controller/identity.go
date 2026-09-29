package controller

import (
	"errors"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

func LoadIdentityForState(seedPath, statePath string) (*identity.Device, error) {
	if seedPath == "" || statePath == "" {
		return nil, ErrStateInvalid
	}
	_, err := LoadState(statePath)
	switch {
	case err == nil:
		return identity.Load(seedPath)
	case errors.Is(err, ErrStateMissing):
		return identity.LoadOrCreate(seedPath)
	default:
		return nil, err
	}
}
