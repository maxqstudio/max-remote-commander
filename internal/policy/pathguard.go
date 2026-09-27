package policy

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

var ErrPathOutsideWorkspace = errors.New("path outside allowed workspace")

type Workspace struct{ roots []string }

func NewWorkspace(roots ...string) (*Workspace, error) {
	if len(roots) == 0 {
		return nil, errors.New("at least one workspace root is required")
	}
	w := &Workspace{}
	for _, root := range roots {
		abs, err := filepath.Abs(root)
		if err != nil {
			return nil, err
		}
		info, err := os.Stat(abs)
		if err != nil {
			return nil, fmt.Errorf("workspace root %q: %w", root, err)
		}
		if !info.IsDir() {
			return nil, fmt.Errorf("workspace root %q is not a directory", root)
		}
		real, err := filepath.EvalSymlinks(abs)
		if err != nil {
			return nil, err
		}
		real, err = filepath.Abs(real)
		if err != nil {
			return nil, err
		}
		w.roots = append(w.roots, filepath.Clean(real))
	}
	return w, nil
}

func (w *Workspace) Resolve(path string) (string, error) {
	if path == "" {
		return "", ErrPathOutsideWorkspace
	}
	candidate, err := filepath.Abs(path)
	if err != nil {
		return "", err
	}
	candidate = filepath.Clean(candidate)

	canonical, err := canonicalizeCandidate(candidate)
	if err != nil {
		return "", err
	}
	for _, root := range w.roots {
		if within(root, canonical) {
			return canonical, nil
		}
	}
	return "", ErrPathOutsideWorkspace
}

func canonicalizeCandidate(candidate string) (string, error) {
	ancestor, err := deepestExistingAncestor(candidate)
	if err != nil {
		return "", err
	}
	realAncestor, err := filepath.EvalSymlinks(ancestor)
	if err != nil {
		return "", err
	}
	realAncestor, err = filepath.Abs(realAncestor)
	if err != nil {
		return "", err
	}
	suffix, err := filepath.Rel(ancestor, candidate)
	if err != nil {
		return "", err
	}
	if suffix == "." {
		return filepath.Clean(realAncestor), nil
	}
	return filepath.Clean(filepath.Join(realAncestor, suffix)), nil
}

func deepestExistingAncestor(path string) (string, error) {
	current := path
	for {
		_, err := os.Lstat(current)
		if err == nil {
			return current, nil
		}
		if !os.IsNotExist(err) {
			return "", err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", ErrPathOutsideWorkspace
		}
		current = parent
	}
}

func within(root, target string) bool {
	rel, err := filepath.Rel(root, target)
	if err != nil {
		return false
	}
	if runtime.GOOS == "windows" {
		rel = strings.ToLower(rel)
	}
	return rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) && !filepath.IsAbs(rel)
}
