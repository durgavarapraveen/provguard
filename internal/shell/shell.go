// Package shell finds out what a Bash or PowerShell command will do:
// which programs it runs, which files it writes, and which risky "sinks"
// (network egress, persistence, destruction, remote code, opaque code) it hits.
//
// It does not run anything. Values it cannot know before run time (variables
// from the environment, command substitution) are marked Dynamic.
package shell

import (
	"path"
	"regexp"
	"slices"
	"strings"
)

// Sink classes.
const (
	Egress     = "EGRESS"      // data can leave the machine
	Persist    = "PERSIST"     // change survives the session (CI, hooks, shell rc, agent config)
	Destroy    = "DESTROY"     // data loss
	ExecRemote = "EXEC_REMOTE" // runs code fetched from outside
	Opaque     = "OPAQUE"      // code provguard cannot analyze
)

// Dialect selects the parser.
type Dialect int

const (
	Bash Dialect = iota
	PowerShell
)

// Sink is one risky action.
type Sink struct {
	Class  string
	Detail string // why, e.g. "curl", "git_push", "path:.github/workflows"
	Target string // URL, host, path or package, when known
}

func (s Sink) String() string {
	if s.Target == "" {
		return s.Class + ":" + s.Detail
	}
	return s.Class + ":" + s.Detail + "->" + s.Target
}

// Cmd is one program invocation after wrappers are removed.
type Cmd struct {
	Name    string   // lower-case base name without .exe
	Args    []string // resolved arguments (Args[0] is the raw name)
	Dynamic bool     // the command name is not known before run time
}

// Write is a file the command writes, creates or deletes.
type Write struct {
	Path    string
	Op      string // "write", "append", "delete", "perm"
	Dynamic bool   // part of the path is not known before run time
}

// Analysis is the result for one command line.
type Analysis struct {
	Cmds   []Cmd
	Writes []Write
	Sinks  []Sink
	// Code holds inline code strings (python -c, eval, iex, ...) so callers
	// can search them as text.
	Code []string
	// Cds holds arguments of cd / Set-Location, for relative-path checks.
	Cds []string
	// Assigns counts shell variable assignments; one can change an exported
	// variable such as PATH or GH_REPO for the commands that follow.
	Assigns    int
	ParseError string
}

// Analyze parses and classifies cmd.
func Analyze(cmd string, d Dialect) *Analysis {
	a := &Analysis{}
	if d == PowerShell {
		analyzePS(a, cmd, 0)
	} else {
		analyzeBash(a, cmd, 0)
	}
	a.finish()
	a.scopeGHTargets()
	return a
}

// AnalyzeUnknown is for commands whose shell is not known (e.g. an MCP tool
// that runs a command in the user's terminal). It analyzes the command as
// Bash and as PowerShell and merges both results, so either reading counts.
func AnalyzeUnknown(cmd string) *Analysis {
	b, p := Analyze(cmd, Bash), Analyze(cmd, PowerShell)
	m := &Analysis{
		Cmds:    append(b.Cmds, p.Cmds...),
		Writes:  append(b.Writes, p.Writes...),
		Sinks:   append(b.Sinks, p.Sinks...),
		Code:    append(b.Code, p.Code...),
		Cds:     append(b.Cds, p.Cds...),
		Assigns: b.Assigns + p.Assigns,
	}
	// A bash parse error is expected for PowerShell syntax; keep it only if
	// the PowerShell reading found nothing either.
	if b.ParseError != "" && len(p.Cmds) == 0 {
		m.ParseError = b.ParseError
	} else {
		var keep []Sink
		for _, s := range m.Sinks {
			if s.Detail != "parse_error" {
				keep = append(keep, s)
			}
		}
		m.Sinks = keep
	}
	return m
}

// maxDepth limits nested "bash -c" style re-parsing.
const maxDepth = 4

// SinkStrings returns sinks in "CLASS:detail->target" form, de-duplicated.
func (a *Analysis) SinkStrings() []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range a.Sinks {
		if k := s.String(); !seen[k] {
			seen[k] = true
			out = append(out, k)
		}
	}
	return out
}

// Has reports whether a sink of class c was found.
func (a *Analysis) Has(c string) bool {
	for _, s := range a.Sinks {
		if s.Class == c {
			return true
		}
	}
	return false
}

func (a *Analysis) sink(class, detail, target string) {
	a.Sinks = append(a.Sinks, Sink{Class: class, Detail: detail, Target: target})
}

func (a *Analysis) write(p, op string, dynamic bool) {
	if p == "" || isNullDevice(p) {
		return
	}
	// classify() only sees resolved strings, so detect run-time parts from
	// the text: substitutions, variables, globs (review: cp/mv targets lost
	// their dynamic flag).
	dynamic = dynamic || strings.ContainsAny(p, "$*?[`") || strings.Contains(p, "<(")
	a.Writes = append(a.Writes, Write{Path: p, Op: op, Dynamic: dynamic})
}

// ghSafeCompanions are commands that may run in the same command line as a
// gh write to the current folder's repository: they cannot change the
// folder, the environment, the git remotes or gh's default repository.
var ghSafeCompanions = set("tail", "head", "grep", "findstr", "sort", "wc", "cat", "echo", "printf", "true",
	"sleep", "start-sleep", "select-object", "where-object", "foreach-object", "measure-object",
	"out-null", "out-string", "out-host", "write-output", "write-host", "format-table", "format-list")

// ghSafeGit are git subcommands that leave remotes and config alone.
var ghSafeGit = set("status", "log", "diff", "show", "add", "commit", "push", "pull", "fetch",
	"switch", "checkout", "branch", "merge", "rebase", "stash", "rev-parse", "tag")

// ghUnsafeGH are gh subcommands that change which repository gh uses.
var ghUnsafeGH = set("repo set-default", "repo clone", "auth login", "auth switch", "config set", "alias set")

// scopeGHTargets resolves "." (the current folder's repository) in gh
// write targets for the whole command line. Review finding (CRIT): the hook
// checked the folder as it was before the command ran, so
// `cd clone-of-attacker && gh issue create …` and
// `gh repo set-default attacker/x && gh issue create …` passed. "." stays
// only when nothing else in the line can change the folder, the
// environment, the remotes or gh's default; one literal cd becomes "@DIR".
func (a *Analysis) scopeGHTargets() {
	uses := false
	for _, s := range a.Sinks {
		if strings.HasPrefix(s.Target, GHRepoPrefix) && slices.Contains(strings.Fields(s.Target[len(GHRepoPrefix):]), ".") {
			uses = true
		}
	}
	if !uses {
		return
	}
	cur := a.ghContext()
	for i, s := range a.Sinks {
		if !strings.HasPrefix(s.Target, GHRepoPrefix) {
			continue
		}
		f := strings.Fields(s.Target[len(GHRepoPrefix):])
		for j := range f {
			if f[j] == "." {
				f[j] = cur
			}
		}
		a.Sinks[i].Target = GHRepoPrefix + strings.Join(f, " ")
	}
}

// ghContext returns ".", "@DIR" or "?" (see scopeGHTargets).
func (a *Analysis) ghContext() string {
	if a.Assigns > 0 {
		return "?" // PATH=… or GH_REPO=… can change which gh runs, or where it writes
	}
	cds := 0
	for _, c := range a.Cmds {
		if c.Dynamic {
			return "?"
		}
		args := []string{}
		if len(c.Args) > 1 {
			args = c.Args[1:]
		}
		pos := positional(args)
		switch {
		case c.Name == "cd" || c.Name == "set-location" || c.Name == "pushd" || c.Name == "push-location":
			cds++
		case c.Name == "gh":
			if len(pos) >= 2 && ghUnsafeGH[pos[0]+" "+pos[1]] {
				return "?"
			}
		case c.Name == "git":
			if hasFlag(args, 'c') || hasFlag(args, 'C') || len(pos) == 0 || !ghSafeGit[pos[0]] {
				return "?"
			}
		case !ghSafeCompanions[c.Name]:
			return "?"
		}
	}
	if len(a.Cds) == 0 {
		if cds > 0 {
			return "?" // cd with no argument: the home folder
		}
		return "."
	}
	dir := a.Cds[0]
	for _, d := range a.Cds[1:] {
		if d != dir {
			return "?"
		}
	}
	// No variables, globs or run-time parts; no spaces (the target list is
	// space-separated).
	if dir == "" || dir == "-" || strings.ContainsAny(dir, "$`*?[(){} \t") {
		return "?"
	}
	return "@" + dir
}

// finish adds PERSIST sinks for writes to persistence locations, and OPAQUE
// sinks for writes whose target is computed at run time.
func (a *Analysis) finish() {
	for _, w := range a.Writes {
		if where := PersistPath(w.Path); where != "" {
			a.sink(Persist, "path:"+where, w.Path)
		}
		if w.Dynamic && (w.Op == "write" || w.Op == "append" || w.Op == "link") && unknownTarget(w.Path) {
			// Review finding: a path built at run time ("$(printf …)") can
			// name any file, including protected ones.
			a.sink(Opaque, "dynamic_write", w.Path)
		}
	}
}

var (
	varRef = regexp.MustCompile(`\$\{?([A-Za-z_][A-Za-z0-9_]*(?::[A-Za-z_][A-Za-z0-9_]*)?)`)
	// knownDirVars are folder variables that do not let a path point anywhere.
	knownDirVars = set("home", "userprofile", "temp", "tmp", "tmpdir", "appdata", "localappdata",
		"pwd", "oldpwd", "programdata", "xdg_cache_home", "xdg_config_home", "xdg_data_home", "runner_temp")
)

// unknownTarget reports whether a dynamic write path can resolve to an
// arbitrary location: command substitution, glob, or an unknown variable.
func unknownTarget(p string) bool {
	if strings.Contains(p, "$(") || strings.Contains(p, "<(") || strings.Contains(p, "$?") || strings.ContainsAny(p, "*?[`") {
		return true
	}
	for _, m := range varRef.FindAllStringSubmatch(p, -1) {
		name := strings.ToLower(strings.TrimPrefix(strings.ToLower(m[1]), "env:"))
		if !knownDirVars[name] {
			return true
		}
	}
	return false
}

// knownProgramPath reports whether a program path is computed only from
// folder variables ($HOME, $env:USERPROFILE, $env:TEMP, …) and ends in a
// literal file name, so the program is known before it runs. Every check
// that goes by program name (self-protection, sinks) then applies to it.
// Found live: & "$env:USERPROFILE\.provguard\bin\provguard.exe" version was
// read as an unknown command.
func knownProgramPath(p string) bool {
	if !strings.Contains(p, "$") || unknownTarget(p) {
		return false
	}
	base := p[strings.LastIndexAny(p, `/\`)+1:]
	return base != "" && !strings.ContainsAny(base, "$")
}

func isNullDevice(p string) bool {
	switch strings.ToLower(p) {
	case "/dev/null", "/dev/stdout", "/dev/stderr", "/dev/tty", "nul", "$null", "nul:":
		return true
	}
	return false
}

// norm lower-cases and uses forward slashes.
func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

// baseName returns the lower-case program name without directory or .exe.
func baseName(s string) string {
	b := path.Base(norm(s))
	for _, ext := range []string{".exe", ".cmd", ".bat", ".com"} {
		b = strings.TrimSuffix(b, ext)
	}
	return b
}

var persistBases = map[string]string{
	".bashrc": "shell_rc", ".bash_profile": "shell_rc", ".bash_login": "shell_rc", ".profile": "shell_rc",
	".zshrc": "shell_rc", ".zprofile": "shell_rc", ".zshenv": "shell_rc", ".zlogin": "shell_rc",
	"config.fish": "shell_rc", "microsoft.powershell_profile.ps1": "shell_rc", "profile.ps1": "shell_rc",
	".gitlab-ci.yml": "ci", "jenkinsfile": "ci", ".travis.yml": "ci", "azure-pipelines.yml": "ci",
	".mcp.json": "agent_config", "claude.md": "agent_config", "agents.md": "agent_config",
	".cursorrules": "agent_config", ".windsurfrules": "agent_config", "authorized_keys": "ssh",
	".npmrc": "package_config", ".pypirc": "package_config",
	// review (MED): more files that run commands later
	"authorized_keys2": "ssh", ".bash_aliases": "shell_rc", ".bash_logout": "shell_rc", ".zlogout": "shell_rc",
	".envrc": "direnv", ".pre-commit-config.yaml": "git_hooks", "lefthook.yml": "git_hooks",
}

var persistDirs = []struct{ dir, name string }{
	{".github/workflows/", "ci"}, {".circleci/", "ci"}, {".git/hooks/", "git_hooks"},
	{".husky/", "git_hooks"}, {".claude/", "agent_config"}, {".cursor/", "agent_config"},
	{".vscode/tasks.json", "editor_tasks"}, {".vscode/settings.json", "editor_settings"},
	{".vscode/launch.json", "editor_tasks"}, {".idea/runConfigurations/", "editor_tasks"},
	{".ssh/config", "ssh"}, {".config/autostart/", "autostart"}, {"library/launchagents/", "autostart"},
	{"/etc/", "system"}, {"start menu/programs/startup/", "autostart"}, {".git/config", "git_config"},
}

// PersistPath returns a short name if writing p can persist across sessions.
func PersistPath(p string) string {
	n := norm(p)
	if strings.Contains(n, "$profile") {
		return "shell_rc"
	}
	if w, ok := persistBases[path.Base(n)]; ok {
		return w
	}
	for _, d := range persistDirs {
		dir := strings.TrimPrefix(d.dir, "/")
		if strings.Contains(n, d.dir) || strings.HasPrefix(n, dir) {
			return d.name
		}
		// The folder itself, without a trailing slash: "cp h .git/hooks".
		if bare := strings.TrimSuffix(dir, "/"); bare != dir && (n == bare || strings.HasSuffix(n, "/"+bare)) {
			return d.name
		}
	}
	return ""
}
