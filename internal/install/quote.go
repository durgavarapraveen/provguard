package install

import (
	"path/filepath"
	"strings"
)

// shellSpecial: characters that sh, cmd or PowerShell treat as special in a
// bare word. Letters of any language are not among them.
const shellSpecial = " \t\r\n$`\"'&|;<>(){}[]^%!#*?,@"

// QuotePOSIX quotes a program path for sh and bash. Double quotes are kept
// for ordinary paths; a path with a character that double quotes still
// expand ($, `, ", \, !) is single-quoted instead.
func QuotePOSIX(exe string) string {
	if !strings.ContainsAny(exe, "$`\"\\!") {
		return `"` + exe + `"`
	}
	return "'" + strings.ReplaceAll(exe, "'", `'\''`) + "'"
}

// QuotePowerShell returns a program path for PowerShell: bare when no
// shell treats any of its characters as special (that form also works in
// cmd and sh), else run with the call operator (&) in a quoted string.
// Single quotes are used when double quotes would expand part of the path
// ($ or `).
func QuotePowerShell(exe string) string {
	if exe != "" && !strings.ContainsAny(exe, shellSpecial) {
		return exe
	}
	if !strings.ContainsAny(exe, "$`\"") {
		return `& "` + exe + `"`
	}
	return "& '" + strings.ReplaceAll(exe, "'", "''") + "'"
}

// CommandProgram returns the program path of a hook command line written by
// QuotePOSIX or QuotePowerShell (or by older versions, which used "exe").
func CommandProgram(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	cmd = strings.TrimSpace(strings.TrimPrefix(cmd, "& "))
	switch {
	case strings.HasPrefix(cmd, `"`):
		if i := strings.IndexByte(cmd[1:], '"'); i >= 0 {
			return filepath.FromSlash(cmd[1 : i+1])
		}
	case strings.HasPrefix(cmd, "'"):
		return filepath.FromSlash(singleQuoted(cmd))
	}
	if f := strings.Fields(cmd); len(f) > 0 {
		return filepath.FromSlash(f[0])
	}
	return ""
}

// singleQuoted reads the leading single-quoted word of s, joining the
// POSIX ('\”) and PowerShell (”) escapes of a single quote.
func singleQuoted(s string) string {
	var b strings.Builder
	for i := 1; i < len(s); i++ {
		if s[i] != '\'' {
			b.WriteByte(s[i])
			continue
		}
		switch {
		case strings.HasPrefix(s[i:], `'\''`):
			b.WriteByte('\'')
			i += 3
		case strings.HasPrefix(s[i:], "''"):
			b.WriteByte('\'')
			i++
		default:
			return b.String()
		}
	}
	return b.String()
}
