package core

import (
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
)

// HookCommand returns the command line that runs
// `provguard hook --agent <agent> <event>` with the binary at exe, for a
// POSIX shell (sh, bash) and for Windows. On Windows the path is left
// unquoted when it has no space, because that form works in cmd,
// PowerShell and sh alike; a path with a space needs PowerShell's call
// operator (&).
func HookCommand(exe, agent, event string) (posix, windows string) {
	exe = filepath.ToSlash(exe)
	args := fmt.Sprintf("hook --agent %s %s", agent, event)
	posix = fmt.Sprintf("%q %s", exe, args)
	windows = exe + " " + args
	if strings.ContainsAny(exe, " \t") {
		windows = fmt.Sprintf("& %q %s", exe, args)
	}
	return posix, windows
}

// HookCommandHere is HookCommand for agents that take a single command and
// run it with the platform's shell: the form for the system provguard is
// installed on.
func HookCommandHere(exe, agent, event string) string {
	posix, windows := HookCommand(exe, agent, event)
	if runtime.GOOS == "windows" {
		return windows
	}
	return posix
}
