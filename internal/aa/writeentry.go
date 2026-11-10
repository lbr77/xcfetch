package aa

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
)

// writeEntry materialises one indexed entry below dest.
func writeEntry(dest string, e Entry) error {
	if !safePath(e.Path) {
		return fmt.Errorf("aa: refusing unsafe path %q", e.Path)
	}
	full := filepath.Join(dest, filepath.FromSlash(e.Path))
	switch e.Type {
	case typeDirectory:
		if err := os.MkdirAll(full, 0o755); err != nil {
			return err
		}
		return chmodEntry(full, e)
	case typeRegularFile:
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		mode := os.FileMode(0o644)
		if e.HasMode {
			mode = e.Mode & 0o7777
		}
		f, err := os.OpenFile(full, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
		if err != nil {
			return err
		}
		_, cerr := io.Copy(f, e.Reader())
		if err := f.Close(); cerr == nil {
			cerr = err
		}
		if cerr != nil {
			return fmt.Errorf("aa: writing %q: %w", e.Path, cerr)
		}
		return chmodEntry(full, e)
	case typeSymbolicLink:
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			return err
		}
		_ = os.Remove(full)
		if err := os.Symlink(e.Link, full); err != nil {
			return fmt.Errorf("aa: symlink %q: %w", e.Path, err)
		}
		return nil
	default:
		return nil
	}
}

func chmodEntry(path string, e Entry) error {
	if !e.HasMode {
		return nil
	}
	if err := os.Chmod(path, e.Mode&0o7777); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	return nil
}
