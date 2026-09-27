package executor

import (
	"bytes"
	"errors"
	"io"
	"os"
	"path/filepath"
	"sort"
)

const DefaultMaxFileBytes int64 = 4 << 20

var (
	ErrInvalidPath  = errors.New("path must be local to the workspace")
	ErrTooLarge     = errors.New("file exceeds configured size limit")
	ErrPatchConflict = errors.New("patch precondition did not match")
)

type Filesystem struct {
	root     *os.Root
	maxBytes int64
}

type Entry struct {
	Name  string
	IsDir bool
	Type  string
}

func OpenFilesystem(rootPath string, maxBytes int64) (*Filesystem, error) {
	root, err := os.OpenRoot(rootPath)
	if err != nil {
		return nil, err
	}
	if maxBytes <= 0 {
		maxBytes = DefaultMaxFileBytes
	}
	return &Filesystem{root: root, maxBytes: maxBytes}, nil
}

func (f *Filesystem) Close() error {
	if f == nil || f.root == nil {
		return nil
	}
	return f.root.Close()
}

func localPath(name string, allowDot bool) error {
	if name == "" || !filepath.IsLocal(name) {
		return ErrInvalidPath
	}
	clean := filepath.Clean(name)
	if !allowDot && clean == "." {
		return ErrInvalidPath
	}
	return nil
}

func (f *Filesystem) Read(name string) ([]byte, error) {
	if err := localPath(name, false); err != nil {
		return nil, err
	}
	file, err := f.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	data, err := io.ReadAll(io.LimitReader(file, f.maxBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > f.maxBytes {
		return nil, ErrTooLarge
	}
	return data, nil
}

func (f *Filesystem) List(name string) ([]Entry, error) {
	if err := localPath(name, true); err != nil {
		return nil, err
	}
	file, err := f.root.Open(name)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	items, err := file.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	entries := make([]Entry, 0, len(items))
	for _, item := range items {
		entries = append(entries, Entry{
			Name: item.Name(), IsDir: item.IsDir(), Type: item.Type().String(),
		})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name < entries[j].Name })
	return entries, nil
}

func (f *Filesystem) Write(name string, data []byte) error {
	if err := localPath(name, false); err != nil {
		return err
	}
	if int64(len(data)) > f.maxBytes {
		return ErrTooLarge
	}
	file, err := f.root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	if err := file.Sync(); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}

func (f *Filesystem) Patch(name string, old, replacement []byte, expectedReplacements int) error {
	if expectedReplacements <= 0 || len(old) == 0 {
		return ErrPatchConflict
	}
	current, err := f.Read(name)
	if err != nil {
		return err
	}
	if bytes.Count(current, old) != expectedReplacements {
		return ErrPatchConflict
	}
	updated := bytes.ReplaceAll(current, old, replacement)
	return f.Write(name, updated)
}
