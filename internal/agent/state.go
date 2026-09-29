package agent

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

var (
	ErrPairingStateMissing   = errors.New("pairing state not found")
	ErrPairingStateExists    = errors.New("pairing state already exists")
	ErrPairingStateInvalid   = errors.New("invalid pairing state")
	ErrPairingStateSymlink   = errors.New("pairing state path must not be a symlink")
	ErrPairingStatePerms     = errors.New("pairing state permissions are too broad")
)

type PairingState struct {
	DeviceID            string
	Generation          uint64
	ControllerPublicKey ed25519.PublicKey
}

type pairingStateDisk struct {
	DeviceID            string `json:"device_id"`
	Generation          uint64 `json:"generation"`
	ControllerPublicKey string `json:"controller_public_key"`
}

func validatePairingState(state PairingState) error {
	if state.DeviceID == "" || state.Generation == 0 || len(state.ControllerPublicKey) != ed25519.PublicKeySize {
		return ErrPairingStateInvalid
	}
	return nil
}

func LoadPairingState(path string) (PairingState, error) {
	if path == "" {
		return PairingState{}, ErrPairingStateInvalid
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return PairingState{}, ErrPairingStateMissing
	}
	if err != nil {
		return PairingState{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return PairingState{}, ErrPairingStateSymlink
	}
	if !info.Mode().IsRegular() {
		return PairingState{}, ErrPairingStateInvalid
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return PairingState{}, ErrPairingStatePerms
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return PairingState{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var disk pairingStateDisk
	if err := decoder.Decode(&disk); err != nil {
		return PairingState{}, ErrPairingStateInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return PairingState{}, ErrPairingStateInvalid
	} else if !errors.Is(err, io.EOF) {
		return PairingState{}, ErrPairingStateInvalid
	}
	publicKey, err := base64.RawURLEncoding.DecodeString(disk.ControllerPublicKey)
	if err != nil || len(publicKey) != ed25519.PublicKeySize {
		return PairingState{}, ErrPairingStateInvalid
	}
	state := PairingState{
		DeviceID: disk.DeviceID,
		Generation: disk.Generation,
		ControllerPublicKey: ed25519.PublicKey(publicKey),
	}
	if err := validatePairingState(state); err != nil {
		return PairingState{}, err
	}
	return state, nil
}

func SavePairingState(path string, state PairingState) error {
	if path == "" {
		return ErrPairingStateInvalid
	}
	if err := validatePairingState(state); err != nil {
		return err
	}
	disk := pairingStateDisk{
		DeviceID: state.DeviceID,
		Generation: state.Generation,
		ControllerPublicKey: base64.RawURLEncoding.EncodeToString(state.ControllerPublicKey),
	}
	data, err := json.Marshal(disk)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".maxrc-pairing-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	defer os.Remove(tempPath)
	if err := temp.Chmod(0o600); err != nil {
		_ = temp.Close()
		return err
	}
	if _, err := temp.Write(data); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Sync(); err != nil {
		_ = temp.Close()
		return err
	}
	if err := temp.Close(); err != nil {
		return err
	}
	if err := os.Link(tempPath, path); err != nil {
		if _, statErr := os.Lstat(path); statErr == nil {
			return ErrPairingStateExists
		}
		return err
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			_ = os.Remove(path)
			return err
		}
	}
	return nil
}

func RemovePairingState(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrPairingStateSymlink
	}
	return os.Remove(path)
}
