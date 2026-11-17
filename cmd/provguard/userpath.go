package main

import (
	"path/filepath"
	"strings"
)

// The user's PATH, so `provguard` runs in any folder.
//
// init offers to put <home>/bin on the user's PATH and uninstall takes it
// off again. How depends on the system (userpath_windows.go,
// userpath_other.go); the list handling below is shared and tested on
// every system.

// pathOps are the system PATH operations. Tests swap them for an in-memory
// fake, so they never change the real PATH.
type pathOps struct {
	has    func(dir string) bool
	add    func(dir string) (where string, err error)
	remove func(dir string) error
}

var userPath = pathOps{has: userPathHas, add: userPathAdd, remove: userPathRemove}

// samePathDir compares two PATH entries the way the system would.
func samePathDir(a, b string, foldCase bool) bool {
	a = filepath.Clean(strings.TrimSpace(a))
	b = filepath.Clean(strings.TrimSpace(b))
	if foldCase {
		return strings.EqualFold(a, b)
	}
	return a == b
}

// pathListHas reports whether list (entries joined by sep) holds dir.
func pathListHas(list, dir string, sep string, foldCase bool) bool {
	for _, d := range strings.Split(list, sep) {
		if d != "" && samePathDir(d, dir, foldCase) {
			return true
		}
	}
	return false
}

// pathListAdd appends dir to list unless it is there already.
func pathListAdd(list, dir string, sep string, foldCase bool) string {
	if pathListHas(list, dir, sep, foldCase) {
		return list
	}
	list = strings.TrimRight(list, sep)
	if list == "" {
		return dir
	}
	return list + sep + dir
}

// pathListRemove drops every entry equal to dir and keeps the rest as is.
func pathListRemove(list, dir string, sep string, foldCase bool) string {
	var keep []string
	for _, d := range strings.Split(list, sep) {
		if d == "" || !samePathDir(d, dir, foldCase) {
			keep = append(keep, d)
		}
	}
	return strings.Join(keep, sep)
}
