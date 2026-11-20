package protect

import (
	"strings"

	"github.com/durgavarapraveen/provguard/internal/shell"
)

// A recursive read of a folder that holds provguard's folder (the home
// folder, a drive root) reads the key with everything else. Such a read is
// blocked unless it leaves .provguard out (--exclude-dir=.provguard,
// tar --exclude=.provguard, rsync --exclude=.provguard).

// alwaysRecursive commands read whole folders, hidden ones included.
var alwaysRecursive = map[string]bool{
	"tar": true, "bsdtar": true, "7z": true, "7za": true, "robocopy": true, "compress-archive": true,
}

// recursiveFlags: commands that read whole folders, hidden ones included,
// with one of these options.
var recursiveFlags = map[string][]string{
	"grep": {"-r", "-R", "--recursive", "--dereference-recursive"}, "egrep": {"-r", "-R", "--recursive"},
	"fgrep": {"-r", "-R", "--recursive"}, "zgrep": {"-r", "-R"},
	"cp": {"-r", "-R", "-a", "--recursive", "--archive"}, "rsync": {"-r", "-a", "--recursive", "--archive"},
	"scp": {"-r"}, "zip": {"-r", "--recurse-paths"}, "xcopy": {"/s", "/e"},
	"copy-item": {"-recurse", "-r"}, "cpi": {"-recurse", "-r"}, "copy": {"-recurse", "-r"},
	// ripgrep and ag skip hidden folders such as .provguard unless told not to.
	"rg": {"--hidden", "-uu", "-uuu", "--no-ignore-dot"}, "ag": {"--hidden", "-u", "--unrestricted"},
}

// recursiveListers list whole folders (names only); they read contents
// with -exec, or when a reader in the pipeline takes the names.
var recursiveListers = map[string][]string{
	"find": nil, "fd": {"--hidden", "-H"}, "get-childitem": {"-recurse", "-r", "-depth"}, "gci": {"-recurse", "-r", "-depth"},
	"ls": {"-R", "--recursive"},
}

// pipeReaders read the files whose names come in through the pipeline.
var pipeReaders = map[string]bool{
	"xargs": true, "parallel": true, "get-content": true, "gc": true, "select-string": true, "sls": true,
	"copy-item": true, "cpi": true, "compress-archive": true, "foreach-object": true, "%": true, "rsync": true,
}

// patternFirst: commands whose first plain argument is a pattern, not a path.
var patternFirst = map[string]bool{"grep": true, "egrep": true, "fgrep": true, "zgrep": true, "rg": true, "ag": true}

// shortFlagSet: commands whose one-letter options may be combined (-rn).
var shortFlagSet = map[string]bool{"grep": true, "egrep": true, "fgrep": true, "zgrep": true, "cp": true, "rsync": true, "scp": true, "zip": true, "ls": true, "fd": true}

// recursiveHomeRead returns the folder of a recursive read that holds
// provguard's folder, or "".
func recursiveHomeRead(an *shell.Analysis, home, cwd string) string {
	piped := false
	for _, c := range an.Cmds {
		piped = piped || pipeReaders[c.Name]
	}
	for _, c := range an.Cmds {
		args := c.Args[min(1, len(c.Args)):]
		if excludesHome(args) {
			continue
		}
		recursive := alwaysRecursive[c.Name] || hasFlag(c.Name, args, recursiveFlags[c.Name])
		if fl, ok := recursiveListers[c.Name]; ok && !recursive {
			lists := fl == nil || hasFlag(c.Name, args, fl)
			execs := c.Name == "find" && hasAny(args, "-exec", "-execdir", "-ok", "-okdir") ||
				c.Name == "fd" && hasAny(args, "-x", "--exec", "-X", "--exec-batch")
			recursive = lists && (execs || piped)
		}
		if !recursive {
			continue
		}
		for _, p := range readPaths(c.Name, args) {
			if holdsHome(p, home, cwd, an.Cds) {
				return p
			}
		}
	}
	return ""
}

// readPaths: the folder arguments of a command; the current folder when it
// names none. Option values are skipped only when they are joined (-x=v):
// a stray value is checked as a path, which can only add a block.
func readPaths(name string, args []string) []string {
	var out []string
	skipPattern := patternFirst[name] && !hasAny(args, "-e", "-f", "--regexp", "--file")
	for _, a := range args {
		if strings.HasPrefix(a, "-") || name == "xcopy" && strings.HasPrefix(a, "/") && len(a) == 2 {
			continue
		}
		if skipPattern {
			skipPattern = false
			continue
		}
		out = append(out, a)
	}
	if len(out) == 0 {
		out = []string{"."}
	}
	return out
}

// holdsHome: the folder p contains provguard's folder.
func holdsHome(p, home, cwd string, cds []string) bool {
	for _, f := range pathForms(p, cwd, cds) {
		for _, h := range []string{home, canonical(home, "")} {
			if h != "" && f != "" && f != "." && underDir(h, f) {
				return true
			}
		}
	}
	return false
}

// excludesHome: an option leaves provguard's folder out of the read.
func excludesHome(args []string) bool {
	for i, a := range args {
		l := strings.ToLower(a)
		if !strings.Contains(l, ".provguard") {
			continue
		}
		if strings.Contains(l, "exclude") || strings.Contains(l, "!") ||
			i > 0 && strings.Contains(strings.ToLower(args[i-1]), "exclude") {
			return true
		}
	}
	return false
}

func hasAny(args []string, want ...string) bool {
	for _, a := range args {
		for _, w := range want {
			if a == w {
				return true
			}
		}
	}
	return false
}

// hasFlag: one of flags is among args. For commands that combine one-letter
// options (-rn) it also looks inside them; PowerShell parameters match
// without case and by prefix (-Rec for -Recurse).
func hasFlag(name string, args, flags []string) bool {
	for _, a := range args {
		for _, f := range flags {
			switch {
			case a == f:
				return true
			case shortFlagSet[name]:
				if len(f) == 2 && f[0] == '-' && len(a) > 2 && a[0] == '-' && a[1] != '-' && strings.ContainsRune(a[1:], rune(f[1])) {
					return true
				}
			case strings.EqualFold(a, f):
				return true
			case len(f) > 3 && len(a) > 2 && a[0] == '-' && strings.HasPrefix(strings.ToLower(f), strings.ToLower(a)):
				return true
			}
		}
	}
	return false
}
