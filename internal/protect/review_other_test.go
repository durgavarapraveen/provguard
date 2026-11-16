//go:build !windows

package protect

import "testing"

// shortName: 8.3 names exist only on Windows.
func shortName(t *testing.T, p string) string { return "" }
