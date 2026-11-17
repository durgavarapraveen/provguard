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
	"io"
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
			if p, _ := e.ToolInput[k].(string); p != "" && secretPath(p, home, e.Cwd, true) {
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

// settingsReason marks a settings file that can register or switch off
// hooks; only its hook-related keys are protected (see guardedKeys).
const settingsReason = "an agent settings file"

// settingsSegs: the path is a settings[.local].json that can hold hooks or
// disableAllHooks for an agent provguard protects:
//   - .claude/settings*.json (Claude Code; Cursor and Copilot read it too),
//   - .copilot/settings.json (Copilot, user level),
//   - .github/copilot/settings*.json (Copilot, repository level).
//   - .gemini/settings.json (Gemini CLI, user and project level).
//
// Segments may be glob patterns from the shell (".cla?de"), so they are
// matched as patterns against the real names.
func settingsSegs(segs []string) bool {
	n := len(segs)
	if n < 2 {
		return false
	}
	if !segMatch(segs[n-1], "settings.json") && !segMatch(segs[n-1], "settings.local.json") {
		return false
	}
	// A folder computed at run time ("$(echo .claude)/settings.json",
	// "$D/settings.json") may be any of them.
	dir := segs[n-2]
	return segMatch(dir, ".claude") || segMatch(dir, ".copilot") || segMatch(dir, ".gemini") || strings.Contains(dir, "$") ||
		segMatch(dir, "copilot") && n >= 3 && segMatch(segs[n-3], ".github")
}

// devinConfig: Devin's config files, which can hold hooks and
// read_config_from (turning off read_config_from.claude stops Devin from
// running the Claude Code hooks): .devin/config[.local].json in a project,
// and devin/config.json in the user's config folder (~/.config/devin, or
// %APPDATA%\devin on Windows). Only their guarded keys are protected.
func devinConfig(segs []string) bool {
	n := len(segs)
	if n < 2 || !segMatch(segs[n-2], ".devin") && !segMatch(segs[n-2], "devin") {
		return false
	}
	return segMatch(segs[n-1], "config.json") || segMatch(segs[n-1], "config.local.json")
}

// devinHooksFile: .devin/hooks.v1.json, a file of hooks only.
func devinHooksFile(segs []string) bool {
	n := len(segs)
	return n >= 2 && segMatch(segs[n-2], ".devin") && segMatch(segs[n-1], "hooks.v1.json")
}

// codexConfig: a file in a .codex folder that can register hooks or turn
// them off ([features] hooks = false in config.toml), user or project level.
func codexConfig(segs []string) bool {
	n := len(segs)
	if n < 2 || !segMatch(segs[n-2], ".codex") {
		return false
	}
	for _, name := range []string{"config.toml", "hooks.json", "requirements.toml"} {
		if segMatch(segs[n-1], name) {
			return true
		}
	}
	return false
}

// copilotHooksDir: a .copilot/hooks folder or a file in it. Every file there
// is a Copilot hook configuration, provguard's included, so agents may not
// change or remove any of them.
func copilotHooksDir(segs []string) bool {
	for i := 0; i+1 < len(segs); i++ {
		if segMatch(segs[i], ".copilot") && segMatch(segs[i+1], "hooks") {
			return true
		}
	}
	return false
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
		case settingsSegs(segs) || devinConfig(segs):
			return settingsReason
		case devinHooksFile(segs):
			return "Devin's hook configuration"
		case (segMatch(last, "settings.json") || segMatch(last, "settings.local.json")) && cdIntoClaude(cds):
			return settingsReason
		case segMatch(last, ".claude"):
			return "a .claude directory"
		case copilotHooksDir(segs) || segMatch(last, ".copilot"):
			return "Copilot's hook configuration"
		case codexConfig(segs) || segMatch(last, ".codex"):
			return "Codex's hook configuration"
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

// maxDeepArgs caps the OS lookups spent on one command's arguments.
const maxDeepArgs = 16

// looksLikePath: an argument that can name a file, so it is worth resolving
// through the OS. Options ("-r", "--json") and bare words are not.
func looksLikePath(a string) bool {
	if a == "" || strings.HasPrefix(a, "-") {
		return false
	}
	return strings.ContainsAny(a, `/\~`) || strings.HasPrefix(a, ".") ||
		len(a) > 1 && a[1] == ':' || strings.Contains(a, "$")
}

// listOnly commands show file names, not contents.
var listOnly = map[string]bool{"ls": true, "dir": true, "get-childitem": true, "gci": true, "tree": true, "stat": true, "test-path": true, "du": true}

// secretPath: provguard's HMAC key or its session files (which hold secret
// fingerprints and the taint history). Review finding (LOW): agents could
// read them, because self-protection only blocked writes.
func secretPath(p, home, cwd string, deep bool) bool {
	lp := strings.ToLower(p)
	if strings.Contains(lp, "://") {
		return false // URLs
	}
	// The OS lookup (canonical) costs about 0.4 ms, so it runs for a name
	// that can be the key or a session file (base "key", or a path naming
	// sessions or provguard) and, when deep is set, for any name at all.
	// Review finding (LOW): the name test alone missed a junction or symlink
	// renamed to something else, which is all it takes to read the session
	// files. The tools that read one named file ask for the deep check; a
	// shell command's arguments share a budget, because there can be many.
	base := path.Base(norm(p))
	cheap := base == "key" || strings.Contains(lp, "session") || strings.Contains(lp, "provguard")
	if !cheap && !deep {
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
	case settingsReason:
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
	"hooksConfig",      // Gemini CLI: hooksConfig.enabled and hooksConfig.disabled turn hooks off
	"read_config_from", // Devin: read_config_from.claude = false stops it running the Claude Code hooks
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
// Review findings (HIGH): "allow" was missing, so code provguard cannot
// read could grant itself a blocked call (provguard allow <token>); and a
// glob hid the names from the pattern, because only a shell command's
// arguments are glob-matched, not text inside code.
var protectedText = regexp.MustCompile(`(?i)` + strings.Join([]string{
	`disableAllHooks`,
	`allowManagedHooksOnly`,
	`\.claude[\\/]+settings(?:\.local)?\.json`,
	`\.claude[\\/]+set[a-z0-9._]*[*?\[]`,           // a glob that can expand to a settings file
	`\.copilot[\\/]+(?:hooks|settings)`,            // Copilot hook files and settings
	`\.github[\\/]+copilot[\\/]+settings`,          // Copilot repository settings
	`\.gemini[\\/]+settings`,                       // Gemini CLI settings (hooks, hooksConfig)
	`\.?devin[\\/]+(?:config|hooks\.v1)`,           // Devin config and hooks
	`read_config_from`,                             // Devin's switch for the Claude Code hooks
	`\.codex[\\/]+(?:config|hooks|requirements)\.`, // Codex hook settings
	`\.provguard\b`,
	`\.pro[a-z0-9]*[*?\[]`, // a glob that can expand to .provguard
	// A quoted subcommand or setting counts too (review finding:
	// `provguard config 'mode' audit` in a script was missed).
	`provguard(?:\.exe)?['"]?\s+['"]?(?:uninstall|init|reset|allow)\b`,
	`provguard(?:\.exe)?['"]?\s+['"]?config['"]?\s+['"]?[a-z-]`, // config with a setting changes it
}, "|"))

// Script scanning limits. Review finding (HIGH): one 1 MiB read of the
// start of the file meant that padding a script with filler hid the
// reference, so the whole file is streamed in overlapping windows, up to a
// budget shared by every file one hook process looks at.
const (
	scriptWindow  = 1 << 20
	scriptOverlap = 256
	scriptBudget  = 64 << 20
)

// Shell-level writes to settings files cannot be compared like Write/Edit
// (the content is often unknown), so any shell write to them is denied.
func checkShell(an *shell.Analysis, raw, home, cwd string) Verdict {
	if v := checkSelfCommands(an); v.Deny {
		return v
	}
	// deepLeft budgets the OS lookups for arguments whose name gives no
	// hint, so a renamed junction is still caught in a command of ordinary
	// length without making a 200-argument one slow.
	deepLeft := maxDeepArgs
	for _, c := range an.Cmds {
		if listOnly[c.Name] {
			continue // listing names (ls ~/.provguard/sessions) reveals no contents
		}
		for _, a := range c.Args[min(1, len(c.Args)):] {
			// Paths hide inside option values: curl -F f=@path, --data=@path, a,b
			for _, part := range strings.FieldsFunc(a, func(r rune) bool { return r == '=' || r == '@' || r == ',' }) {
				deep := deepLeft > 0 && looksLikePath(part)
				if deep {
					deepLeft--
				}
				if secretPath(part, home, cwd, deep) {
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
	budget := int64(scriptBudget) // per command, so a long-lived process keeps scanning
	for _, c := range an.Cmds {
		for _, f := range shell.ScriptFiles(c) {
			for _, form := range pathForms(f, cwd, cds) {
				if refersToProtected(canonical(form, cwd), &budget) {
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
// argFeeders run a command with arguments that come from input at run time.
var argFeeders = map[string]bool{"xargs": true, "parallel": true, "find": true, "fd": true, "rush": true, "foreach-object": true}

func checkSelfCommands(an *shell.Analysis) Verdict {
	for _, c := range an.Cmds {
		if len(c.Args) == 0 {
			continue
		}
		prog := strings.Contains(strings.ToLower(c.Name), "provguard") ||
			c.Name == "go" && containsArg(c.Args, "provguard") // go run ./cmd/provguard
		if prog {
			args := c.Args[1:]
			for i, a := range args {
				switch sub := strings.ToLower(strings.Trim(a, `'",`)); sub {
				case "init", "uninstall", "reset", "allow":
					return deny("self_protect_install", "blocked an agent from running provguard "+sub)
				case "config":
					// Reading the settings is fine; changing them is the user's call.
					if i+1 < len(args) {
						return deny("self_protect_install", "blocked an agent from changing provguard settings (provguard config)")
					}
				}
			}
		}
		// Tools that add arguments at run time (xargs, parallel, find -exec)
		// can turn a bare `provguard config` into a change. Review finding:
		// `echo mode audit | xargs provguard config` changed the settings.
		if argFeeders[c.Name] {
			for _, a := range c.Args[1:] {
				if strings.Contains(strings.ToLower(a), "provguard") {
					return deny("self_protect_install", "blocked running provguard through "+c.Name+", which adds arguments provguard cannot check")
				}
			}
		}
		// Copying the binary out of its protected folder lets it run under
		// another name (cp ~/.provguard/bin/provguard /tmp/pg && /tmp/pg uninstall).
		switch c.Name {
		case "cp", "copy", "copy-item", "install", "mv", "move", "move-item", "rsync", "robocopy", "xcopy", "ln", "mklink", "cat", "dd", "tar", "zip", "7z":
			for _, a := range c.Args[1:] {
				if copiesBinary(a) {
					return deny("self_protect_install", "blocked copying provguard's binary ("+a+")")
				}
			}
		// Looking the binary up is the first half of "cp $(which provguard)
		// /tmp/pg": the shell parser turns the substitution into "$(...)",
		// so the path itself never reaches the check above.
		case "which", "where", "whereis", "type", "command", "get-command", "gcm":
			if containsArg(c.Args, "provguard") {
				return deny("self_protect_install", "blocked looking up the path of provguard's binary")
			}
		}
	}
	return Verdict{}
}

// binaryName matches the name provguard's binary has on disk, in any folder.
var binaryName = regexp.MustCompile(`(?:^|[/\\])provguard(?:\.exe)?$`)

// copiesBinary reports whether an argument names provguard's binary. Review
// finding (HIGH): only copies out of ~/.provguard/bin were blocked, so the
// one `go install` put in ~/go/bin could be copied to another name and run
// as `pg allow <token>`.
func copiesBinary(a string) bool {
	n := norm(strings.Trim(a, `'"`))
	if strings.Contains(n, ".provguard/bin") || binaryName.MatchString(n) {
		return true
	}
	// "cp $(which provguard) /tmp/pg": the path is computed at run time.
	return strings.Contains(n, "provguard") && strings.ContainsAny(n, "$`")
}

func containsArg(args []string, sub string) bool {
	for _, a := range args[1:] {
		if strings.Contains(strings.ToLower(a), sub) {
			return true
		}
	}
	return false
}

// refersToProtected reports whether the file at p names a protected thing.
// It reads the whole file in windows that overlap by scriptOverlap bytes, so
// neither filler before the reference nor a window boundary through it hides
// it. One Read can return less than a full window, so the windows are filled
// with ReadFull.
func refersToProtected(p string, budget *int64) bool {
	f, err := os.Open(p)
	if err != nil {
		return false
	}
	defer f.Close()
	if fi, err := f.Stat(); err != nil || fi.IsDir() {
		return false
	}
	buf := make([]byte, scriptOverlap+scriptWindow)
	keep := 0
	for *budget > 0 {
		n, err := io.ReadFull(f, buf[keep:])
		if n > 0 {
			*budget -= int64(n)
			end := keep + n
			if protectedText.Match(buf[:end]) {
				return true
			}
			keep = min(scriptOverlap, end)
			copy(buf, buf[end-keep:end])
		}
		if err != nil { // EOF, a short last window, or a read error
			return false
		}
	}
	return false
}
