package core

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/durgavarapraveen/provguard/internal/install"
)

// HookCommand returns the command line that runs
// `provguard hook --agent <agent> <event>` with the binary at exe, for a
// POSIX shell (sh, bash) and for Windows. On Windows the path is left bare
// when it has only plain characters, because that form works in cmd,
// PowerShell and sh alike; any other path needs PowerShell's call
// operator (&). The quoting is in install.QuotePOSIX and QuotePowerShell.
func HookCommand(exe, agent, event string) (posix, windows string) {
	exe = filepath.ToSlash(exe)
	args := fmt.Sprintf(" hook --agent %s %s", agent, event)
	return install.QuotePOSIX(exe) + args, install.QuotePowerShell(exe) + args
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
