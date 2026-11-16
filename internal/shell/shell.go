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
	Cds        []string
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
	return a
}

// AnalyzeUnknown is for commands whose shell is not known (e.g. an MCP tool
// that runs a command in the user's terminal). It analyzes the command as
// Bash and as PowerShell and merges both results, so either reading counts.
func AnalyzeUnknown(cmd string) *Analysis {
	b, p := Analyze(cmd, Bash), Analyze(cmd, PowerShell)
	m := &Analysis{
		Cmds:   append(b.Cmds, p.Cmds...),
		Writes: append(b.Writes, p.Writes...),
		Sinks:  append(b.Sinks, p.Sinks...),
		Code:   append(b.Code, p.Code...),
		Cds:    append(b.Cds, p.Cds...),
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
