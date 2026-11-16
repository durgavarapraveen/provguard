//go:build windows

package protect

import (
	"syscall"
	"testing"
)

// shortName returns the 8.3 short form of an existing path ("" if none).
func shortName(t *testing.T, p string) string {
	t.Helper()
	in, _ := syscall.UTF16PtrFromString(p)
	buf := make([]uint16, 1024)
	n, err := syscall.GetShortPathName(in, &buf[0], uint32(len(buf)))
	if err != nil || n == 0 {
		return ""
	}
	return syscall.UTF16ToString(buf[:n])
}
