//go:build windows

package realpath

import (
	"strings"
	"syscall"
	"unsafe"
)

var procGetFinalPathNameByHandleW = syscall.NewLazyDLL("kernel32.dll").NewProc("GetFinalPathNameByHandleW")

// Final resolves junctions, symlinks, 8.3 short names and trailing dots
// of an existing path. Go's filepath.EvalSymlinks does not follow junctions,
// which any user can create with "mklink /J".
func Final(p string) (string, error) {
	name, err := syscall.UTF16PtrFromString(p)
	if err != nil {
		return "", err
	}
	// FILE_FLAG_BACKUP_SEMANTICS lets CreateFile open directories.
	h, err := syscall.CreateFile(name, 0,
		syscall.FILE_SHARE_READ|syscall.FILE_SHARE_WRITE|syscall.FILE_SHARE_DELETE,
		nil, syscall.OPEN_EXISTING, syscall.FILE_FLAG_BACKUP_SEMANTICS, 0)
	if err != nil {
		return "", err
	}
	defer syscall.CloseHandle(h)
	buf := make([]uint16, 1024)
	for {
		n, _, callErr := procGetFinalPathNameByHandleW.Call(uintptr(h), uintptr(unsafe.Pointer(&buf[0])), uintptr(len(buf)), 0)
		if n == 0 {
			return "", callErr
		}
		if int(n) < len(buf) {
			s := syscall.UTF16ToString(buf[:n])
			s = strings.TrimPrefix(s, `\\?\UNC\`)
			return strings.TrimPrefix(s, `\\?\`), nil
		}
		buf = make([]uint16, n+1)
	}
}
