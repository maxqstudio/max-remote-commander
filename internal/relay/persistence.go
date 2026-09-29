package relay

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"time"

	"github.com/maxqstudio/max-remote-commander/internal/identity"
)

const (
	durableStateVersion = 1
	defaultMaxStateBytes int64 = 64 << 20
)

var (
	ErrDurableStateConfig  = errors.New("invalid durable relay state configuration")
	ErrDurableStateCorrupt = errors.New("durable relay state is corrupt")
	ErrDurableStateSymlink = errors.New("durable relay state path must not be a symlink")
	ErrDurableStatePerms   = errors.New("durable relay state permissions are too broad")
	ErrDurableStateTooLarge = errors.New("durable relay state exceeds configured size limit")
)

var durableStateAAD = []byte("max-remote-commander-relay-state-v1")

type durablePairing struct {
	DeviceID            string    `json:"device_id"`
	DevicePublicKey     string    `json:"device_public_key"`
	ControllerPublicKey string    `json:"controller_public_key"`
	Generation          uint64    `json:"generation"`
	PairedAt            time.Time `json:"paired_at"`
}

type durableDeviceNonce struct {
	DeviceID   string `json:"device_id"`
	Generation uint64 `json:"generation"`
	Nonce      string `json:"nonce"`
	ExpiresAt  int64  `json:"expires_at"`
}

type durableControllerNonce struct {
	DeviceID   string `json:"device_id"`
	Generation uint64 `json:"generation"`
	Nonce      string `json:"nonce"`
	ExpiresAt  int64  `json:"expires_at"`
}

type durableCommandNonce struct {
	DeviceID  string `json:"device_id"`
	Nonce     string `json:"nonce"`
	ExpiresAt int64  `json:"expires_at"`
}

type durableState struct {
	Version            int                         `json:"version"`
	Pairings           []durablePairing            `json:"pairings"`
	PairingGeneration  map[string]uint64           `json:"pairing_generation"`
	Queues             map[string][]Command        `json:"queues"`
	Requests           map[string]string           `json:"requests"`
	Results            map[string]Result           `json:"results"`
	ResultOrder        []string                    `json:"result_order"`
	DeviceNonces       []durableDeviceNonce        `json:"device_nonces"`
	ControllerNonces   []durableControllerNonce    `json:"controller_nonces"`
	CommandNonces      []durableCommandNonce       `json:"command_nonces"`
}

type encryptedStateEnvelope struct {
	Version    int    `json:"version"`
	Nonce      string `json:"nonce"`
	Ciphertext string `json:"ciphertext"`
}

type stateFile struct {
	path     string
	key      [32]byte
	maxBytes int64
}

func newStateFile(path string, key []byte, maxBytes int64) (*stateFile, error) {
	if path == "" || len(key) != 32 {
		return nil, ErrDurableStateConfig
	}
	if maxBytes <= 0 {
		maxBytes = defaultMaxStateBytes
	}
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	var fixed [32]byte
	copy(fixed[:], key)
	return &stateFile{path:absolute, key:fixed, maxBytes:maxBytes}, nil
}

func strictJSON(data []byte, target any) error {
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		return err
	}
	var trailing any
	if err := decoder.Decode(&trailing); err == nil {
		return errors.New("multiple JSON values")
	} else if !errors.Is(err, io.EOF) {
		return err
	}
	return nil
}

func (f *stateFile) aead() (cipher.AEAD, error) {
	block, err := aes.NewCipher(f.key[:])
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func (f *stateFile) ensureParent() error {
	dir := filepath.Dir(f.path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	if runtime.GOOS != "windows" {
		info, err := os.Stat(dir)
		if err != nil {
			return err
		}
		if info.Mode().Perm()&0o077 != 0 {
			return ErrDurableStatePerms
		}
	}
	return nil
}

func validateStateFileInfo(path string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return ErrDurableStateSymlink
	}
	if !info.Mode().IsRegular() {
		return ErrDurableStateCorrupt
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o077 != 0 {
		return ErrDurableStatePerms
	}
	return nil
}

func (f *stateFile) Load(now time.Time, maxQueue, maxResults int) (durableState, bool, error) {
	if err := f.ensureParent(); err != nil {
		return durableState{}, false, err
	}
	if err := validateStateFileInfo(f.path); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return durableState{}, false, nil
		}
		return durableState{}, false, err
	}
	file, err := os.Open(f.path)
	if err != nil {
		return durableState{}, false, err
	}
	data, readErr := io.ReadAll(io.LimitReader(file, f.maxBytes+1))
	closeErr := file.Close()
	if readErr != nil {
		return durableState{}, false, readErr
	}
	if closeErr != nil {
		return durableState{}, false, closeErr
	}
	if int64(len(data)) > f.maxBytes {
		return durableState{}, false, ErrDurableStateTooLarge
	}

	var envelope encryptedStateEnvelope
	if err := strictJSON(data, &envelope); err != nil || envelope.Version != durableStateVersion {
		return durableState{}, false, ErrDurableStateCorrupt
	}
	nonce, err := base64.RawURLEncoding.DecodeString(envelope.Nonce)
	if err != nil {
		return durableState{}, false, ErrDurableStateCorrupt
	}
	ciphertext, err := base64.RawURLEncoding.DecodeString(envelope.Ciphertext)
	if err != nil {
		return durableState{}, false, ErrDurableStateCorrupt
	}
	aead, err := f.aead()
	if err != nil {
		return durableState{}, false, err
	}
	if len(nonce) != aead.NonceSize() {
		return durableState{}, false, ErrDurableStateCorrupt
	}
	plaintext, err := aead.Open(nil, nonce, ciphertext, durableStateAAD)
	if err != nil {
		return durableState{}, false, ErrDurableStateCorrupt
	}
	defer clear(plaintext)
	if int64(len(plaintext)) > f.maxBytes {
		return durableState{}, false, ErrDurableStateTooLarge
	}
	var state durableState
	if err := strictJSON(plaintext, &state); err != nil || state.Version != durableStateVersion {
		return durableState{}, false, ErrDurableStateCorrupt
	}
	if err := validateDurableState(&state, now, maxQueue, maxResults); err != nil {
		return durableState{}, false, err
	}
	return state, true, nil
}

func (f *stateFile) Save(state durableState) error {
	if err := f.ensureParent(); err != nil {
		return err
	}
	if err := validateStateFileInfo(f.path); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	state.Version = durableStateVersion
	plaintext, err := json.Marshal(state)
	if err != nil {
		return err
	}
	defer clear(plaintext)
	if int64(len(plaintext)) > f.maxBytes {
		return ErrDurableStateTooLarge
	}
	aead, err := f.aead()
	if err != nil {
		return err
	}
	nonce := make([]byte, aead.NonceSize())
	if _, err := rand.Read(nonce); err != nil {
		return err
	}
	ciphertext := aead.Seal(nil, nonce, plaintext, durableStateAAD)
	envelope := encryptedStateEnvelope{
		Version:durableStateVersion,
		Nonce:base64.RawURLEncoding.EncodeToString(nonce),
		Ciphertext:base64.RawURLEncoding.EncodeToString(ciphertext),
	}
	data, err := json.Marshal(envelope)
	if err != nil {
		return err
	}
	data = append(data, '\n')
	if int64(len(data)) > f.maxBytes {
		return ErrDurableStateTooLarge
	}

	dir := filepath.Dir(f.path)
	temp, err := os.CreateTemp(dir, ".maxrc-relay-state-*")
	if err != nil {
		return err
	}
	tempPath := temp.Name()
	removeTemp := true
	defer func() {
		if removeTemp {
			_ = os.Remove(tempPath)
		}
	}()
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
	if err := os.Rename(tempPath, f.path); err != nil {
		return err
	}
	removeTemp = false
	if runtime.GOOS != "windows" {
		if err := os.Chmod(f.path, 0o600); err != nil {
			return err
		}
		dirFile, err := os.Open(dir)
		if err != nil {
			return err
		}
		syncErr := dirFile.Sync()
		closeErr := dirFile.Close()
		if syncErr != nil {
			return syncErr
		}
		if closeErr != nil {
			return closeErr
		}
	}
	return nil
}

func validateDurableState(state *durableState, now time.Time, maxQueue, maxResults int) error {
	if state.PairingGeneration == nil {
		state.PairingGeneration = make(map[string]uint64)
	}
	if state.Queues == nil {
		state.Queues = make(map[string][]Command)
	}
	if state.Requests == nil {
		state.Requests = make(map[string]string)
	}
	if state.Results == nil {
		state.Results = make(map[string]Result)
	}

	pairings := make(map[string]durablePairing, len(state.Pairings))
	for _, pairing := range state.Pairings {
		if !validID(pairing.DeviceID, 64) || pairing.Generation == 0 {
			return ErrDurableStateCorrupt
		}
		deviceKey, err := base64.RawURLEncoding.DecodeString(pairing.DevicePublicKey)
		if err != nil || len(deviceKey) != ed25519.PublicKeySize {
			return ErrDurableStateCorrupt
		}
		controllerKey, err := base64.RawURLEncoding.DecodeString(pairing.ControllerPublicKey)
		if err != nil || len(controllerKey) != ed25519.PublicKeySize {
			return ErrDurableStateCorrupt
		}
		expectedID, err := identity.DeviceID(ed25519.PublicKey(deviceKey))
		if err != nil || expectedID != pairing.DeviceID {
			return ErrDurableStateCorrupt
		}
		if _, exists := pairings[pairing.DeviceID]; exists {
			return ErrDurableStateCorrupt
		}
		if state.PairingGeneration[pairing.DeviceID] < pairing.Generation {
			return ErrDurableStateCorrupt
		}
		pairings[pairing.DeviceID] = pairing
	}

	queuedRequests := make(map[string]string)
	for deviceID, queue := range state.Queues {
		if !validID(deviceID, 64) || len(queue) > maxQueue {
			return ErrDurableStateCorrupt
		}
		if _, paired := pairings[deviceID]; !paired && len(queue) > 0 {
			return ErrDurableStateCorrupt
		}
		for _, command := range queue {
			if !validID(command.RequestID, 128) || len(command.Payload) == 0 {
				return ErrDurableStateCorrupt
			}
			if _, duplicate := queuedRequests[command.RequestID]; duplicate {
				return ErrDurableStateCorrupt
			}
			queuedRequests[command.RequestID] = deviceID
		}
	}

	if len(state.Results) > maxResults || len(state.ResultOrder) != len(state.Results) {
		return ErrDurableStateCorrupt
	}
	seenResult := make(map[string]struct{}, len(state.ResultOrder))
	for _, requestID := range state.ResultOrder {
		if !validID(requestID, 128) {
			return ErrDurableStateCorrupt
		}
		result, ok := state.Results[requestID]
		if !ok || result.RequestID != requestID || len(result.Payload) == 0 {
			return ErrDurableStateCorrupt
		}
		if _, duplicate := seenResult[requestID]; duplicate {
			return ErrDurableStateCorrupt
		}
		seenResult[requestID] = struct{}{}
	}

	for requestID, deviceID := range state.Requests {
		if !validID(requestID, 128) || !validID(deviceID, 64) {
			return ErrDurableStateCorrupt
		}
		if queuedDevice, queued := queuedRequests[requestID]; queued {
			if queuedDevice != deviceID {
				return ErrDurableStateCorrupt
			}
			continue
		}
		if _, completed := state.Results[requestID]; !completed {
			return ErrDurableStateCorrupt
		}
	}
	for requestID, deviceID := range queuedRequests {
		if state.Requests[requestID] != deviceID {
			return ErrDurableStateCorrupt
		}
	}
	for requestID := range state.Results {
		if _, ok := state.Requests[requestID]; !ok {
			return ErrDurableStateCorrupt
		}
	}

	nowUnix := now.Unix()
	filteredDevice := state.DeviceNonces[:0]
	for _, item := range state.DeviceNonces {
		if item.ExpiresAt <= nowUnix {
			continue
		}
		pairing, ok := pairings[item.DeviceID]
		if !ok || pairing.Generation != item.Generation || !validID(item.Nonce, 128) {
			return ErrDurableStateCorrupt
		}
		filteredDevice = append(filteredDevice, item)
	}
	state.DeviceNonces = filteredDevice

	filteredController := state.ControllerNonces[:0]
	for _, item := range state.ControllerNonces {
		if item.ExpiresAt <= nowUnix {
			continue
		}
		pairing, ok := pairings[item.DeviceID]
		if !ok || pairing.Generation != item.Generation || !validID(item.Nonce, 128) {
			return ErrDurableStateCorrupt
		}
		filteredController = append(filteredController, item)
	}
	state.ControllerNonces = filteredController

	filteredCommand := state.CommandNonces[:0]
	for _, item := range state.CommandNonces {
		if item.ExpiresAt <= nowUnix {
			continue
		}
		if _, ok := pairings[item.DeviceID]; !ok || !validID(item.Nonce, 128) {
			return ErrDurableStateCorrupt
		}
		filteredCommand = append(filteredCommand, item)
	}
	state.CommandNonces = filteredCommand
	return nil
}

func (s *Store) durableStateLocked() durableState {
	state := durableState{
		Version:durableStateVersion,
		PairingGeneration:make(map[string]uint64, len(s.pairingGeneration)),
		Queues:make(map[string][]Command, len(s.queues)),
		Requests:make(map[string]string, len(s.requests)),
		Results:make(map[string]Result, len(s.results)),
		ResultOrder:append([]string(nil), s.resultOrder...),
	}
	deviceIDs := make([]string, 0, len(s.pairings))
	for deviceID := range s.pairings {
		deviceIDs = append(deviceIDs, deviceID)
	}
	sort.Strings(deviceIDs)
	for _, deviceID := range deviceIDs {
		pairing := s.pairings[deviceID]
		state.Pairings = append(state.Pairings, durablePairing{
			DeviceID:deviceID,
			DevicePublicKey:base64.RawURLEncoding.EncodeToString(pairing.DevicePublicKey),
			ControllerPublicKey:base64.RawURLEncoding.EncodeToString(pairing.ControllerPublicKey),
			Generation:pairing.Generation,
			PairedAt:pairing.PairedAt,
		})
	}
	for deviceID, generation := range s.pairingGeneration {
		state.PairingGeneration[deviceID] = generation
	}
	for deviceID, queue := range s.queues {
		if len(queue) == 0 {
			continue
		}
		commands := make([]Command, 0, len(queue))
		for _, item := range queue {
			commands = append(commands, Command{
				RequestID:item.command.RequestID,
				Payload:append([]byte(nil), item.command.Payload...),
			})
		}
		state.Queues[deviceID] = commands
	}
	for requestID, deviceID := range s.requests {
		state.Requests[requestID] = deviceID
	}
	for requestID, result := range s.results {
		state.Results[requestID] = Result{
			RequestID:result.RequestID,
			Payload:append([]byte(nil), result.Payload...),
		}
	}
	for key, expiry := range s.deviceNonces {
		state.DeviceNonces = append(state.DeviceNonces, durableDeviceNonce{
			DeviceID:key.deviceID, Generation:key.generation, Nonce:key.nonce, ExpiresAt:expiry,
		})
	}
	for key, expiry := range s.controllerNonces {
		state.ControllerNonces = append(state.ControllerNonces, durableControllerNonce{
			DeviceID:key.deviceID, Generation:key.generation, Nonce:key.nonce, ExpiresAt:expiry,
		})
	}
	for key, expiry := range s.commandNonces {
		state.CommandNonces = append(state.CommandNonces, durableCommandNonce{
			DeviceID:key.deviceID, Nonce:key.nonce, ExpiresAt:expiry,
		})
	}
	sort.Slice(state.DeviceNonces, func(i, j int) bool {
		if state.DeviceNonces[i].DeviceID != state.DeviceNonces[j].DeviceID {
			return state.DeviceNonces[i].DeviceID < state.DeviceNonces[j].DeviceID
		}
		if state.DeviceNonces[i].Generation != state.DeviceNonces[j].Generation {
			return state.DeviceNonces[i].Generation < state.DeviceNonces[j].Generation
		}
		return state.DeviceNonces[i].Nonce < state.DeviceNonces[j].Nonce
	})
	sort.Slice(state.ControllerNonces, func(i, j int) bool {
		if state.ControllerNonces[i].DeviceID != state.ControllerNonces[j].DeviceID {
			return state.ControllerNonces[i].DeviceID < state.ControllerNonces[j].DeviceID
		}
		if state.ControllerNonces[i].Generation != state.ControllerNonces[j].Generation {
			return state.ControllerNonces[i].Generation < state.ControllerNonces[j].Generation
		}
		return state.ControllerNonces[i].Nonce < state.ControllerNonces[j].Nonce
	})
	sort.Slice(state.CommandNonces, func(i, j int) bool {
		if state.CommandNonces[i].DeviceID != state.CommandNonces[j].DeviceID {
			return state.CommandNonces[i].DeviceID < state.CommandNonces[j].DeviceID
		}
		return state.CommandNonces[i].Nonce < state.CommandNonces[j].Nonce
	})
	return state
}

func (s *Store) restoreDurableStateLocked(state durableState) error {
	s.pairings = make(map[string]Pairing, len(state.Pairings))
	s.pairingGeneration = make(map[string]uint64, len(state.PairingGeneration))
	s.queues = make(map[string][]*queuedCommand, len(state.Queues))
	s.requests = make(map[string]string, len(state.Requests))
	s.results = make(map[string]Result, len(state.Results))
	s.resultOrder = append([]string(nil), state.ResultOrder...)
	s.deviceNonces = make(map[deviceNonceKey]int64, len(state.DeviceNonces))
	s.controllerNonces = make(map[controllerNonceKey]int64, len(state.ControllerNonces))
	s.commandNonces = make(map[commandNonceKey]int64, len(state.CommandNonces))

	for _, item := range state.Pairings {
		deviceKey, _ := base64.RawURLEncoding.DecodeString(item.DevicePublicKey)
		controllerKey, _ := base64.RawURLEncoding.DecodeString(item.ControllerPublicKey)
		pairing := Pairing{
			DeviceID:item.DeviceID,
			DevicePublicKey:ed25519.PublicKey(append([]byte(nil), deviceKey...)),
			ControllerPublicKey:ed25519.PublicKey(append([]byte(nil), controllerKey...)),
			Generation:item.Generation,
			PairedAt:item.PairedAt,
		}
		s.pairings[item.DeviceID] = pairing
		s.knownDevices[item.DeviceID] = struct{}{}
	}
	for deviceID, generation := range state.PairingGeneration {
		s.pairingGeneration[deviceID] = generation
	}
	for deviceID, commands := range state.Queues {
		queue := make([]*queuedCommand, 0, len(commands))
		for _, command := range commands {
			queue = append(queue, &queuedCommand{command:Command{
				RequestID:command.RequestID,
				Payload:append([]byte(nil), command.Payload...),
			}})
		}
		s.queues[deviceID] = queue
		s.knownDevices[deviceID] = struct{}{}
	}
	for requestID, deviceID := range state.Requests {
		s.requests[requestID] = deviceID
	}
	for requestID, result := range state.Results {
		s.results[requestID] = Result{RequestID:result.RequestID, Payload:append([]byte(nil), result.Payload...)}
	}
	for _, item := range state.DeviceNonces {
		s.deviceNonces[deviceNonceKey{deviceID:item.DeviceID,generation:item.Generation,nonce:item.Nonce}] = item.ExpiresAt
	}
	for _, item := range state.ControllerNonces {
		s.controllerNonces[controllerNonceKey{deviceID:item.DeviceID,generation:item.Generation,nonce:item.Nonce}] = item.ExpiresAt
	}
	for _, item := range state.CommandNonces {
		s.commandNonces[commandNonceKey{deviceID:item.DeviceID,nonce:item.Nonce}] = item.ExpiresAt
	}
	return nil
}

func (s *Store) persistLocked() error {
	if s.stateFile == nil {
		return nil
	}
	return s.stateFile.Save(s.durableStateLocked())
}

func cloneDurableState(state durableState) durableState {
	data, err := json.Marshal(state)
	if err != nil {
		panic(fmt.Sprintf("clone durable state: %v", err))
	}
	var cloned durableState
	if err := json.Unmarshal(data, &cloned); err != nil {
		panic(fmt.Sprintf("clone durable state: %v", err))
	}
	return cloned
}
