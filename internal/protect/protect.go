// Package protect stops an agent from turning provguard off.
//
// Finding F3: one write of {"disableAllHooks": true} to a project
// .claude/settings.json silently disabled user-level hooks mid-session.
// Settings reload with a lag, so the block must happen in PreToolUse.
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
// an is the shell analysis for Bash/PowerShell; nil means "analyze here".
func Check(e event.Event, home string, an *shell.Analysis) Verdict {
	switch e.ToolName {
	case "Write", "Edit":
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
		return checkShell(an, cmd, home)
	}
	return Verdict{}
}

func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

// IsSettingsFile reports whether p is a Claude Code settings file (user or project).
func IsSettingsFile(p string) bool {
	n := norm(p)
	return strings.HasSuffix(n, "/.claude/settings.json") || strings.HasSuffix(n, "/.claude/settings.local.json") ||
		n == ".claude/settings.json" || n == ".claude/settings.local.json"
}

func underHome(p, home string) bool {
	if home == "" {
		return false
	}
	n, h := norm(filepath.Clean(p)), strings.TrimSuffix(norm(filepath.Clean(home)), "/")
	return n == h || strings.HasPrefix(n, h+"/")
}

func checkFileTool(e event.Event, home string) Verdict {
	p, _ := e.ToolInput["file_path"].(string)
	if p == "" {
		return Verdict{}
	}
	if underHome(p, home) {
		return deny("self_protect_home", "blocked a "+e.ToolName+" to provguard's data directory ("+p+")")
	}
	if !IsSettingsFile(p) {
		return Verdict{}
	}
	cur, _ := os.ReadFile(p) // missing file = empty
	var next string
	if e.ToolName == "Write" {
		next, _ = e.ToolInput["content"].(string)
	} else {
		old, _ := e.ToolInput["old_string"].(string)
		neu, _ := e.ToolInput["new_string"].(string)
		all, _ := e.ToolInput["replace_all"].(bool)
		if old == "" || !strings.Contains(string(cur), old) {
			return Verdict{} // the Edit will fail on its own
		}
		if all {
			next = strings.ReplaceAll(string(cur), old, neu)
		} else {
			next = strings.Replace(string(cur), old, neu, 1)
		}
	}
	before, okBefore := hookKeys(string(cur))
	after, okAfter := hookKeys(next)
	if !okAfter {
		return deny("self_protect_settings", "blocked a change that would make "+p+" invalid JSON, which drops its hooks")
	}
	if !okBefore {
		before, _ = hookKeys("")
	}
	if before != after {
		return deny("self_protect_settings", "blocked a change to hooks or disableAllHooks in "+p)
	}
	return Verdict{}
}

// hookKeys returns a canonical form of the hook-related keys of a settings file.
func hookKeys(content string) (string, bool) {
	var v map[string]any
	if strings.TrimSpace(content) == "" {
		v = map[string]any{}
	} else if err := json.Unmarshal([]byte(content), &v); err != nil {
		return "", false
	}
	k := map[string]any{}
	for _, key := range []string{"hooks", "disableAllHooks", "allowManagedHooksOnly"} {
		if x, ok := v[key]; ok {
			k[key] = x
		}
	}
	b, _ := json.Marshal(k) // map keys are sorted, so this is canonical
	return string(b), true
}

// --- shell ---

// protectedText finds references to protected things inside code that
// provguard cannot analyze (python -c, eval, iex, encoded commands).
var protectedText = regexp.MustCompile(`(?i)disableAllHooks|allowManagedHooksOnly|\.claude[\\/]+settings(?:\.local)?\.json|\.provguard\b`)

// Shell-level writes to settings files cannot be compared like Write/Edit
// (the content is often unknown), so any shell write to them is denied.
func checkShell(an *shell.Analysis, raw, home string) Verdict {
	for _, c := range an.Cmds {
		if c.Name == "provguard" && len(c.Args) > 1 {
			if sub := strings.ToLower(c.Args[1]); sub == "init" || sub == "uninstall" {
				return deny("self_protect_install", "blocked an agent from running provguard "+sub)
			}
		}
	}
	claudeCd := false
	for _, d := range an.Cds {
		if strings.Contains(norm(d), ".claude") {
			claudeCd = true
		}
	}
	for _, w := range an.Writes {
		if why := protectedTarget(w.Path, home, claudeCd); why != "" {
			return deny("self_protect_shell", "blocked a shell command that would "+w.Op+" "+why+" ("+w.Path+")")
		}
	}
	// Code provguard cannot analyze: deny if it mentions protected things.
	for _, code := range an.Code {
		if protectedText.MatchString(code) {
			return deny("self_protect_shell", "blocked code that provguard cannot analyze and that refers to hook settings or provguard files")
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

// protectedTarget explains why writing p is not allowed, or returns "".
func protectedTarget(p, home string, claudeCd bool) string {
	n := norm(p)
	base := path.Base(n)
	switch {
	case IsSettingsFile(p):
		return "a Claude settings file"
	case (base == "settings.json" || base == "settings.local.json") && (claudeCd || strings.Contains(n, "$")):
		return "a Claude settings file"
	case base == ".claude" || strings.HasSuffix(n, "/.claude/"):
		return "a .claude directory"
	case strings.Contains(n, ".provguard"), underHome(p, home):
		return "provguard's data directory"
	}
	return ""
}
