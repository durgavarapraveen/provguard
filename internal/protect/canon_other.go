//go:build !windows

package protect

import "path/filepath"

// finalPath resolves symlinks of an existing path.
func finalPath(p string) (string, error) { return filepath.EvalSymlinks(p) }
