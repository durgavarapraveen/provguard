//go:build windows

package main

import (
	"errors"
	"syscall"
	"unsafe"
)

// On Windows the user PATH is the "Path" value under HKCU\Environment. It is
// read and written as stored (REG_EXPAND_SZ keeps entries such as
// %USERPROFILE%\bin unexpanded), and running programs are told about the
// change, so a new terminal sees it without signing out.

var (
	advapi32           = syscall.NewLazyDLL("advapi32.dll")
	procRegSetValueExW = advapi32.NewProc("RegSetValueExW")
	user32             = syscall.NewLazyDLL("user32.dll")
	procSendMessageTO  = user32.NewProc("SendMessageTimeoutW")
)

const (
	regExpandSZ      = 2
	hwndBroadcast    = 0xffff
	wmSettingChange  = 0x001A
	smtoAbortIfHung  = 0x0002
	userPathFoldCase = true
)

func readUserPath() (value string, typ uint32, err error) {
	var k syscall.Handle
	name, _ := syscall.UTF16PtrFromString("Environment")
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, name, 0, syscall.KEY_QUERY_VALUE, &k); err != nil {
		return "", 0, err
	}
	defer syscall.RegCloseKey(k)
	vn, _ := syscall.UTF16PtrFromString("Path")
	var n uint32
	err = syscall.RegQueryValueEx(k, vn, nil, &typ, nil, &n)
	if errors.Is(err, syscall.ERROR_FILE_NOT_FOUND) {
		return "", regExpandSZ, nil // no user PATH yet
	}
	if err != nil {
		return "", 0, err
	}
	buf := make([]uint16, n/2+1)
	if err := syscall.RegQueryValueEx(k, vn, nil, &typ, (*byte)(unsafe.Pointer(&buf[0])), &n); err != nil {
		return "", 0, err
	}
	return syscall.UTF16ToString(buf), typ, nil
}

func writeUserPath(value string, typ uint32) error {
	if typ != syscall.REG_SZ {
		typ = regExpandSZ
	}
	var k syscall.Handle
	name, _ := syscall.UTF16PtrFromString("Environment")
	if err := syscall.RegOpenKeyEx(syscall.HKEY_CURRENT_USER, name, 0, syscall.KEY_SET_VALUE, &k); err != nil {
		return err
	}
	defer syscall.RegCloseKey(k)
	vn, _ := syscall.UTF16PtrFromString("Path")
	data, _ := syscall.UTF16FromString(value)
	r, _, _ := procRegSetValueExW.Call(uintptr(k), uintptr(unsafe.Pointer(vn)), 0, uintptr(typ),
		uintptr(unsafe.Pointer(&data[0])), uintptr(len(data)*2))
	if r != 0 {
		return syscall.Errno(r)
	}
	// Tell Explorer and other programs; new terminals then see the change.
	env, _ := syscall.UTF16PtrFromString("Environment")
	var result uintptr
	procSendMessageTO.Call(hwndBroadcast, wmSettingChange, 0, uintptr(unsafe.Pointer(env)),
		smtoAbortIfHung, 2000, uintptr(unsafe.Pointer(&result)))
	return nil
}

// userPathHas reports whether dir is on the user's saved PATH.
func userPathHas(dir string) bool {
	v, _, err := readUserPath()
	return err == nil && pathListHas(v, dir, ";", userPathFoldCase)
}

// userPathAdd puts dir on the user's PATH and says where.
func userPathAdd(dir string) (string, error) {
	v, typ, err := readUserPath()
	if err != nil {
		return "", err
	}
	if !pathListHas(v, dir, ";", userPathFoldCase) {
		if err := writeUserPath(pathListAdd(v, dir, ";", userPathFoldCase), typ); err != nil {
			return "", err
		}
	}
	return "your user PATH", nil
}

// userPathRemove takes dir off the user's PATH.
func userPathRemove(dir string) error {
	v, typ, err := readUserPath()
	if err != nil || !pathListHas(v, dir, ";", userPathFoldCase) {
		return err
	}
	return writeUserPath(pathListRemove(v, dir, ";", userPathFoldCase), typ)
}
