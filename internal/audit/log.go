package audit

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"
)

var (
	ErrInvalidEvent = errors.New("invalid audit event")
	ErrAuditFull    = errors.New("audit log reached configured size limit")
	ErrAuditSymlink = errors.New("audit log path must not be a symlink")
)

type Event struct {
	Time            time.Time `json:"time"`
	Kind            string    `json:"kind"`
	DeviceID        string    `json:"device_id,omitempty"`
	RequestID       string    `json:"request_id,omitempty"`
	Capability      string    `json:"capability,omitempty"`
	Decision        string    `json:"decision,omitempty"`
	Outcome         string    `json:"outcome,omitempty"`
	ArgumentsSHA256 string    `json:"arguments_sha256,omitempty"`
}

type Logger struct {
	mu       sync.Mutex
	file     *os.File
	maxBytes int64
	size     int64
}

func Open(path string, maxBytes int64) (*Logger, error) {
	if path == "" || maxBytes <= 0 {
		return nil, ErrInvalidEvent
	}
	if info, err := os.Lstat(path); err == nil {
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, ErrAuditSymlink
		}
		if !info.Mode().IsRegular() {
			return nil, ErrInvalidEvent
		}
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, err
	}
	file, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	info, err := file.Stat()
	if err != nil {
		_ = file.Close()
		return nil, err
	}
	if info.Size() > maxBytes {
		_ = file.Close()
		return nil, ErrAuditFull
	}
	return &Logger{file: file, maxBytes: maxBytes, size: info.Size()}, nil
}

func (l *Logger) Close() error {
	if l == nil || l.file == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	err := l.file.Close()
	l.file = nil
	return err
}

func validAtom(value string, max int) bool {
	if value == "" || len(value) > max {
		return false
	}
	for _, r := range value {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') ||
			r == '-' || r == '_' || r == '.' || r == ':' || r == '/' {
			continue
		}
		return false
	}
	return true
}

func validOptionalAtom(value string, max int) bool {
	return value == "" || validAtom(value, max)
}

func validDigest(value string) bool {
	if value == "" {
		return true
	}
	if len(value) != 64 || strings.ToLower(value) != value {
		return false
	}
	raw, err := hex.DecodeString(value)
	return err == nil && len(raw) == 32
}

func validate(event Event) error {
	if event.Time.IsZero() || !validAtom(event.Kind, 64) ||
		!validOptionalAtom(event.DeviceID, 128) ||
		!validOptionalAtom(event.RequestID, 128) ||
		!validOptionalAtom(event.Capability, 128) ||
		!validOptionalAtom(event.Decision, 64) ||
		!validOptionalAtom(event.Outcome, 64) ||
		!validDigest(event.ArgumentsSHA256) {
		return ErrInvalidEvent
	}
	return nil
}

func (l *Logger) Append(event Event) error {
	if l == nil || l.file == nil {
		return errors.New("audit logger is closed")
	}
	if err := validate(event); err != nil {
		return err
	}
	line, err := json.Marshal(event)
	if err != nil {
		return err
	}
	line = append(line, '\n')

	l.mu.Lock()
	defer l.mu.Unlock()
	if l.file == nil {
		return errors.New("audit logger is closed")
	}
	if l.size+int64(len(line)) > l.maxBytes {
		return ErrAuditFull
	}
	n, err := l.file.Write(line)
	l.size += int64(n)
	if err != nil {
		return err
	}
	if n != len(line) {
		return errors.New("short audit write")
	}
	return l.file.Sync()
}
