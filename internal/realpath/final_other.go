//go:build !windows

package realpath

import "path/filepath"

// Final resolves symlinks of an existing path.
func Final(p string) (string, error) { return filepath.EvalSymlinks(p) }
