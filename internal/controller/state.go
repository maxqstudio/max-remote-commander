package controller

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"path/filepath"
	"runtime"
)

var (
	ErrStateMissing = errors.New("controller state not found")
	ErrStateExists  = errors.New("controller state already exists")
	ErrStateInvalid = errors.New("invalid controller state")
	ErrStateSymlink = errors.New("controller state path must not be a symlink")
	ErrStatePerms   = errors.New("controller state permissions are too broad")
)

type State struct {
	DeviceID   string
	Generation uint64
}

type stateDisk struct {
	DeviceID   string `json:"device_id"`
	Generation uint64 `json:"generation"`
}

func validateState(state State) error {
	if state.DeviceID == "" || state.Generation == 0 {
		return ErrStateInvalid
	}
	return nil
}

func LoadState(path string) (State, error) {
	if path == "" {
		return State{}, ErrStateInvalid
	}
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return State{}, ErrStateMissing
	}
	if err != nil {
		return State{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return State{}, ErrStateSymlink
	}
	if !info.Mode().IsRegular() {
		return State{}, ErrStateInvalid
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return State{}, ErrStatePerms
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return State{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var disk stateDisk
	if err := decoder.Decode(&disk); err != nil {
		return State{}, ErrStateInvalid
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return State{}, ErrStateInvalid
	} else if !errors.Is(err, io.EOF) {
		return State{}, ErrStateInvalid
	}
	state := State{DeviceID: disk.DeviceID, Generation: disk.Generation}
	if err := validateState(state); err != nil {
		return State{}, err
	}
	return state, nil
}

func SaveState(path string, state State) error {
	if path == "" {
		return ErrStateInvalid
	}
	if err := validateState(state); err != nil {
		return err
	}
	data, err := json.Marshal(stateDisk{DeviceID:state.DeviceID, Generation:state.Generation})
	if err != nil {
		return err
	}
	data = append(data, '\n')
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	temp, err := os.CreateTemp(dir, ".maxrc-controller-*")
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
			return ErrStateExists
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

func RemoveState(path string) error {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrStateSymlink
	}
	return os.Remove(path)
}
