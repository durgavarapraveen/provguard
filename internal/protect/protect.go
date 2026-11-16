// Package protect stops an agent from turning provguard off.
//
// Finding F3: one write of {"disableAllHooks": true} to a project
// .claude/settings.json silently disabled user-level hooks mid-session.
// Settings reload with a lag, so the block must happen in PreToolUse.
//
// Every path is checked in three forms: as written, lexically cleaned, and
// as the OS will really resolve it (canonical: junctions, symlinks, 8.3
// names, trailing dots, "::$DATA"). A path is protected if any form is.
package protect

import (
	"encoding/json"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/event"
	"github.com/durgavarapraveen/provguard/internal/shell"
)

// Verdict is the self-protection result. Zero value means "no objection".
type Verdict struct {
	Deny   bool
	Rule   string
	Reason string
}

const advice = " If you meant this, run it yourself in a terminal. provguard blocks agents from changing hook settings or its own files."

func deny(rule, reason string) Verdict {
	return Verdict{Deny: true, Rule: rule, Reason: "provguard: " + reason + "." + advice}
}

// Check inspects a PreToolUse event. home is provguard's data directory.
// an is the shell analysis for Bash/PowerShell or an MCP terminal tool;
// nil means "analyze here" for Bash/PowerShell.
func Check(e event.Event, home string, an *shell.Analysis) Verdict {
	switch e.ToolName {
	case "Read", "Grep", "NotebookRead":
		for _, k := range []string{"file_path", "path", "notebook_path"} {
			if p, _ := e.ToolInput[k].(string); p != "" && secretPath(p, home, e.Cwd) {
				return deny("self_protect_secret", "blocked reading provguard's key or session files ("+p+")")
			}
		}
		return Verdict{}
	case "Write", "Edit", "MultiEdit", "NotebookEdit":
		return checkFileTool(e, home)
	case "Bash", "PowerShell":
		cmd, _ := e.ToolInput["command"].(string)
		if an == nil {
			d := shell.Bash
			if e.ToolName == "PowerShell" {
				d = shell.PowerShell
			}
			an = shell.Analyze(cmd, d)
		}
		return checkShell(an, cmd, home, e.Cwd)
	}
	if an != nil { // MCP terminal tools
		cmd, _ := e.ToolInput["command"].(string)
		if v := checkShell(an, cmd, home, e.Cwd); v.Deny {
			return v
		}
	}
	return checkToolPaths(e, home)
}

func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

// IsSettingsFile reports whether p names a Claude Code settings file (user
// or project), lexically. Callers that need the real file use protectedPath.
func IsSettingsFile(p string) bool {
	return settingsSegs(strings.Split(path.Clean(norm(lexical(p))), "/"))
}

// settingsSegs: the last two segments are ".claude" and settings[.local].json.
// Segments may be glob patterns from the shell (".cla?de"), so they are
// matched as patterns against the real names.
func settingsSegs(segs []string) bool {
	n := len(segs)
	if n < 2 {
		return false
	}
	// A folder computed at run time ("$(echo .claude)/settings.json",
	// "$D/settings.json") may be .claude.
	dir := segMatch(segs[n-2], ".claude") || strings.Contains(segs[n-2], "$")
	return dir && (segMatch(segs[n-1], "settings.json") || segMatch(segs[n-1], "settings.local.json"))
}

func segMatch(seg, name string) bool {
	if seg == name {
		return true
	}
	ok, err := path.Match(seg, name)
	return err == nil && ok
}

func underDir(p, dir string) bool {
	if dir == "" || p == "" {
		return false
	}
	n, h := path.Clean(norm(p)), strings.TrimSuffix(path.Clean(norm(dir)), "/")
	return n == h || strings.HasPrefix(n, h+"/")
}

// userClaudeDir is ~/.claude, whose settings.json holds provguard's hooks.
func userClaudeDir() string {
	h, err := os.UserHomeDir()
	if err != nil {
		return ""
	}
	return filepath.Join(h, ".claude")
}

// pathForms returns the ways p can be read: raw, lexical, canonical, and
// each of those relative to every directory the command changes into.
func pathForms(p, cwd string, cds []string) []string {
	p = expandHome(p)
	forms := []string{p, lexical(p), canonical(p, cwd)}
	if !filepath.IsAbs(p) {
		for _, d := range cds {
			j := filepath.Join(d, p)
			forms = append(forms, j, canonical(j, cwd))
		}
	}
	return forms
}

// expandHome replaces a leading home reference with the real home folder,
// so "rm -rf ~" is seen as deleting the folder that holds ~/.claude.
func expandHome(p string) string {
	h, err := os.UserHomeDir()
	if err != nil {
		return p
	}
	lp := strings.ToLower(p)
	for _, pre := range []string{"~", "$home", "${home}", "$env:userprofile", "$env:home", "%userprofile%"} {
		if lp == pre {
			return h
		}
		for _, sep := range []string{"/", `\`} {
			if strings.HasPrefix(lp, pre+sep) {
				return filepath.Join(h, p[len(pre)+1:])
			}
		}
	}
	return p
}

// protectedPath explains why writing (op) p is not allowed, or returns "".
func protectedPath(p, op, home, cwd string, cds []string) string {
	if strings.TrimSpace(p) == "" {
		return ""
	}
	homes := []string{home, canonical(home, "")}
	claude := userClaudeDir()
	claudes := []string{claude, canonical(claude, "")}
	for _, f := range pathForms(p, cwd, cds) {
		segs := strings.Split(path.Clean(norm(f)), "/")
		last := segs[len(segs)-1]
		switch {
		case settingsSegs(segs):
			return "a Claude settings file"
		case (segMatch(last, "settings.json") || segMatch(last, "settings.local.json")) && cdIntoClaude(cds):
			return "a Claude settings file"
		case segMatch(last, ".claude"):
			return "a .claude directory"
		}
		for _, s := range segs {
			if segMatch(s, ".provguard") {
				return "provguard's data directory"
			}
		}
		for _, h := range homes {
			if underDir(f, h) {
				return "provguard's data directory"
			}
		}
		// Deleting, moving or unpacking over a folder that contains the
		// protected folders (rm -rf ~, tar -xf … -C ~) changes them too.
		if op == "delete" || op == "bulk" || op == "link" {
			for _, h := range append(homes, claudes...) {
				if h != "" && underDir(h, f) {
					return "a folder that contains provguard's or Claude's settings"
				}
			}
		}
		// Unpacking into a folder that has its own .claude folder can replace
		// the project's settings.
		if op == "bulk" {
			if fi, err := os.Stat(filepath.Join(f, ".claude")); err == nil && fi.IsDir() {
				return "a folder whose .claude settings an archive or patch could replace"
			}
		}
	}
	return ""
}

// listOnly commands show file names, not contents.
var listOnly = map[string]bool{"ls": true, "dir": true, "get-childitem": true, "gci": true, "tree": true, "stat": true, "test-path": true, "du": true}

// secretPath: provguard's HMAC key or its session files (which hold secret
// fingerprints and the taint history). Review finding (LOW): agents could
// read them, because self-protection only blocked writes.
func secretPath(p, home, cwd string) bool {
	lp := strings.ToLower(p)
	if strings.Contains(lp, "://") {
		return false // URLs
	}
	// The OS lookup (canonical) is costly, so run it only for names that can
	// be the key or a session file: base "key", or a path naming sessions or
	// provguard. (A junction renamed to something else that points at the
	// sessions folder is not caught; reading needs no protection as strong as
	// writing does.)
	base := path.Base(norm(p))
	if base != "key" && !strings.Contains(lp, "session") && !strings.Contains(lp, "provguard") {
		return false
	}
	for _, f := range pathForms(p, cwd, nil) {
		n := path.Clean(norm(f))
		if strings.Contains(n, ".provguard/key") || strings.Contains(n, ".provguard/sessions") {
			return true
		}
		for _, h := range []string{home, canonical(home, "")} {
			if h == "" {
				continue
			}
			if underDir(f, filepath.Join(h, "key")) || underDir(f, filepath.Join(h, "sessions")) {
				return true
			}
		}
	}
	return false
}

func cdIntoClaude(cds []string) bool {
	for _, d := range cds {
		for _, s := range strings.Split(path.Clean(norm(lexical(d))), "/") {
			if segMatch(s, ".claude") {
				return true
			}
		}
	}
	return false
}

// --- Write / Edit / MultiEdit / NotebookEdit ---

func checkFileTool(e event.Event, home string) Verdict {
	p, _ := e.ToolInput["file_path"].(string)
	if p == "" {
		p, _ = e.ToolInput["notebook_path"].(string)
	}
	if p == "" {
		return Verdict{}
	}
	why := protectedPath(p, "write", home, e.Cwd, nil)
	switch why {
	case "":
		return Verdict{}
	case "a Claude settings file":
		// handled below: only hook-related keys are protected
	default:
		return deny("self_protect_home", "blocked a "+e.ToolName+" to "+why+" ("+p+")")
	}
	if e.ToolName == "NotebookEdit" {
		return deny("self_protect_settings", "blocked a notebook edit of "+p)
	}
	real := canonical(p, e.Cwd)
	cur, _ := os.ReadFile(real) // missing file = empty
	next, ok := applyEdit(e, string(cur))
	if !ok {
		// Review finding: "old_string not found, the Edit will fail" could be
		// wrong if the agent's Edit matches more loosely than a byte compare.
		return deny("self_protect_settings", "blocked an edit of "+p+" that provguard cannot verify")
	}
	before, okBefore := protectedKeys(string(cur))
	after, okAfter := protectedKeys(next)
	if !okAfter {
		return deny("self_protect_settings", "blocked a change that would make "+p+" invalid JSON, which drops its hooks")
	}
	if !okBefore {
		before, _ = protectedKeys("")
	}
	if before != after {
		return deny("self_protect_settings", "blocked a change to hooks, disableAllHooks, env or command settings in "+p)
	}
	return Verdict{}
}

// applyEdit returns the file content after the tool runs.
func applyEdit(e event.Event, cur string) (string, bool) {
	switch e.ToolName {
	case "Write":
		s, _ := e.ToolInput["content"].(string)
		return s, true
	case "Edit":
		return replace(cur, e.ToolInput)
	case "MultiEdit":
		edits, _ := e.ToolInput["edits"].([]any)
		for _, x := range edits {
			m, _ := x.(map[string]any)
			var ok bool
			if cur, ok = replace(cur, m); !ok {
				return "", false
			}
		}
		return cur, true
	}
	return "", false
}

func replace(cur string, in map[string]any) (string, bool) {
	old, _ := in["old_string"].(string)
	neu, _ := in["new_string"].(string)
	all, _ := in["replace_all"].(bool)
	if old == "" || !strings.Contains(cur, old) {
		return "", false
	}
	if all {
		return strings.ReplaceAll(cur, old, neu), true
	}
	return strings.Replace(cur, old, neu, 1), true
}

// guardedKeys are settings that switch hooks off, redirect provguard
// (env → PROVGUARD_HOME) or run commands outside hooks (review finding).
var guardedKeys = []string{
	"hooks", "disableAllHooks", "allowManagedHooksOnly",
	"env", "statusLine", "apiKeyHelper", "awsAuthRefresh", "awsCredentialExport",
	"otelHeadersHelper", "enabledPlugins", "extraKnownMarketplaces",
}

// protectedKeys returns a canonical form of the guarded keys of a settings file.
func protectedKeys(content string) (string, bool) {
	var v map[string]any
	if strings.TrimSpace(content) == "" {
		v = map[string]any{}
	} else if err := json.Unmarshal([]byte(content), &v); err != nil {
		return "", false
	}
	k := map[string]any{}
	for _, key := range guardedKeys {
		if x, ok := v[key]; ok {
			k[key] = x
		}
	}
	b, _ := json.Marshal(k) // map keys are sorted, so this is canonical
	return string(b), true
}

// --- other tools (MCP filesystem servers etc.) ---

var writingTool = regexp.MustCompile(`(?i)(?:^|_)(?:write|edit|create|move|rename|copy|delete|remove|patch|apply|append|save|put|upload|mkdir|link|update|set|replace|insert)(?:_|$)`)

var pathKeys = []string{"path", "file_path", "filePath", "filepath", "notebook_path", "destination", "dest",
	"target", "new_path", "newPath", "source", "src", "from", "to", "directory", "dir"}

// checkToolPaths: tools that write files outside Write/Edit, e.g.
// mcp__filesystem__write_file / move_file (review finding).
func checkToolPaths(e event.Event, home string) Verdict {
	parts := strings.Split(e.ToolName, "__")
	if !writingTool.MatchString(parts[len(parts)-1]) {
		return Verdict{}
	}
	var paths []string
	for _, k := range pathKeys {
		switch v := e.ToolInput[k].(type) {
		case string:
			paths = append(paths, v)
		case []any:
			for _, x := range v {
				if s, ok := x.(string); ok {
					paths = append(paths, s)
				}
			}
		}
	}
	if es, ok := e.ToolInput["edits"].([]any); ok { // some servers nest paths
		for _, x := range es {
			if m, ok := x.(map[string]any); ok {
				if s, ok := m["path"].(string); ok {
					paths = append(paths, s)
				}
			}
		}
	}
	for _, p := range paths {
		if why := protectedPath(p, "delete", home, e.Cwd, nil); why != "" {
			return deny("self_protect_tool", "blocked "+e.ToolName+" on "+why+" ("+p+")")
		}
	}
	return Verdict{}
}

// --- shell ---

// protectedText finds references to protected things inside code that
// provguard cannot analyze (python -c, eval, iex, script files).
var protectedText = regexp.MustCompile(`(?i)disableAllHooks|allowManagedHooksOnly|\.claude[\\/]+settings(?:\.local)?\.json|\.provguard\b|provguard(?:\.exe)?['"]?\s+(?:uninstall|init|reset)\b`)

// maxScript caps how much of a script file is scanned.
const maxScript = 1 << 20

// Shell-level writes to settings files cannot be compared like Write/Edit
// (the content is often unknown), so any shell write to them is denied.
func checkShell(an *shell.Analysis, raw, home, cwd string) Verdict {
	if v := checkSelfCommands(an); v.Deny {
		return v
	}
	for _, c := range an.Cmds {
		if listOnly[c.Name] {
			continue // listing names (ls ~/.provguard/sessions) reveals no contents
		}
		for _, a := range c.Args[min(1, len(c.Args)):] {
			// Paths hide inside option values: curl -F f=@path, --data=@path, a,b
			for _, part := range strings.FieldsFunc(a, func(r rune) bool { return r == '=' || r == '@' || r == ',' }) {
				if secretPath(part, home, cwd) {
					return deny("self_protect_secret", "blocked a command that uses provguard's key or session files ("+a+")")
				}
			}
		}
	}
	cds := an.Cds
	for _, w := range an.Writes {
		if w.Op == "vcs" {
			continue // pull/merge/switch: allowed; ConfigChange and doctor watch the result
		}
		if why := protectedPath(w.Path, w.Op, home, cwd, cds); why != "" {
			return deny("self_protect_shell", "blocked a shell command that would "+w.Op+" "+why+" ("+w.Path+")")
		}
	}
	// Code provguard cannot analyze: deny if it mentions protected things.
	for _, code := range an.Code {
		if protectedText.MatchString(code) {
			return deny("self_protect_shell", "blocked code that provguard cannot analyze and that refers to hook settings or provguard files")
		}
	}
	// Script files run by the command (python x.py, bash x.sh, make, npm run):
	// review finding — Write a script, then run it, bypassed every check.
	for _, c := range an.Cmds {
		for _, f := range shell.ScriptFiles(c) {
			for _, form := range pathForms(f, cwd, cds) {
				if b := readCapped(canonical(form, cwd)); b != "" && protectedText.MatchString(b) {
					return deny("self_protect_script", "blocked running "+f+", which refers to hook settings or provguard files")
				}
			}
		}
	}
	// A write whose path is fully unknown, in a command that names protected things.
	for _, w := range an.Writes {
		if w.Dynamic && protectedText.MatchString(raw) {
			return deny("self_protect_shell", "blocked a write to a path known only at run time, in a command that refers to hook settings or provguard files")
		}
	}
	return Verdict{}
}

// checkSelfCommands blocks agents from running provguard's install/reset
// commands under any name, and from copying the protected binary out.
func checkSelfCommands(an *shell.Analysis) Verdict {
	for _, c := range an.Cmds {
		if len(c.Args) == 0 {
			continue
		}
		prog := strings.Contains(strings.ToLower(c.Name), "provguard") ||
			c.Name == "go" && containsArg(c.Args, "provguard") // go run ./cmd/provguard
		if prog {
			for _, a := range c.Args[1:] {
				switch strings.ToLower(strings.Trim(a, `'",`)) {
				case "init", "uninstall", "reset":
					return deny("self_protect_install", "blocked an agent from running provguard "+strings.ToLower(a))
				}
			}
		}
		// Copying the binary out of its protected folder lets it run under
		// another name (cp ~/.provguard/bin/provguard /tmp/pg && /tmp/pg uninstall).
		switch c.Name {
		case "cp", "copy", "copy-item", "install", "mv", "move", "move-item", "rsync", "robocopy", "xcopy", "ln", "mklink", "cat", "dd", "tar", "zip", "7z":
			for _, a := range c.Args[1:] {
				if n := norm(a); strings.Contains(n, ".provguard/bin") {
					return deny("self_protect_install", "blocked copying provguard's protected binary ("+a+")")
				}
			}
		}
	}
	return Verdict{}
}

func containsArg(args []string, sub string) bool {
	for _, a := range args[1:] {
		if strings.Contains(strings.ToLower(a), sub) {
			return true
		}
	}
	return false
}

func readCapped(p string) string {
	f, err := os.Open(p)
	if err != nil {
		return ""
	}
	defer f.Close()
	buf := make([]byte, maxScript)
	n, _ := f.Read(buf)
	return string(buf[:n])
}
