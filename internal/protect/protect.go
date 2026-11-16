// Package protect stops an agent from turning provguard off.
//
// Finding F3: one write of {"disableAllHooks": true} to a project
// .claude/settings.json silently disabled user-level hooks mid-session.
// Settings reload with a lag, so the block must happen in PreToolUse.
package protect

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/event"
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
func Check(e event.Event, home string) Verdict {
	switch e.ToolName {
	case "Write", "Edit":
		return checkFileTool(e, home)
	case "Bash", "PowerShell":
		cmd, _ := e.ToolInput["command"].(string)
		return checkShell(cmd)
	}
	return Verdict{}
}

func norm(p string) string { return strings.ToLower(strings.ReplaceAll(p, `\`, "/")) }

// IsSettingsFile reports whether p is a Claude Code settings file (user or project).
func IsSettingsFile(p string) bool {
	n := norm(p)
	return strings.HasSuffix(n, "/.claude/settings.json") || strings.HasSuffix(n, "/.claude/settings.local.json")
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

var (
	settingsRef   = regexp.MustCompile(`(?i)\.claude[\\/]+settings(?:\.local)?\.json`)
	claudeDirRef  = regexp.MustCompile(`(?i)\.claude\b`)
	settingsName  = regexp.MustCompile(`(?i)\bsettings(?:\.local)?\.json\b`)
	disableRef    = regexp.MustCompile(`(?i)disableAllHooks|allowManagedHooksOnly`)
	homeRef       = regexp.MustCompile(`(?i)\.provguard\b`)
	installCmdRef = regexp.MustCompile(`(?i)\bprovguard(?:\.exe)?["']?\s+(?:init|uninstall)\b`)

	harmlessRedirect = regexp.MustCompile(`(?i)\d?>&\d|\d?>\s*(?:/dev/null|\$null|nul)\b`)
	segmentSplit     = regexp.MustCompile(`\|\||&&|[|;&\n]`)
)

// readOnly lists commands that only read files.
var readOnly = map[string]bool{
	"cat": true, "type": true, "head": true, "tail": true, "less": true, "more": true,
	"grep": true, "rg": true, "jq": true, "wc": true, "sort": true, "uniq": true,
	"ls": true, "dir": true, "stat": true, "file": true, "diff": true, "cmp": true,
	"echo": true, "pwd": true, "cd": true, "find": true, "sed": true, "awk": false,
	"sha256sum": true, "md5sum": true, "test": true, "[": true,
	"get-content": true, "gc": true, "select-string": true, "sls": true,
	"get-childitem": true, "gci": true, "test-path": true, "get-item": true,
	"convertfrom-json": true, "select-object": true, "measure-object": true,
	"sort-object": true, "where-object": true, "format-table": true, "format-list": true,
	"out-string": true, "get-filehash": true, "set-location": true, "write-output": true,
}

func checkShell(cmd string) Verdict {
	if cmd == "" {
		return Verdict{}
	}
	if installCmdRef.MatchString(cmd) {
		return deny("self_protect_install", "blocked an agent from running provguard init/uninstall")
	}
	ref := ""
	switch {
	case disableRef.MatchString(cmd):
		ref = "hook settings (disableAllHooks)"
	case settingsRef.MatchString(cmd), claudeDirRef.MatchString(cmd) && settingsName.MatchString(cmd):
		ref = "a Claude settings file"
	case homeRef.MatchString(cmd):
		ref = "provguard's data directory"
	}
	if ref == "" || shellReadOnly(cmd) {
		return Verdict{}
	}
	return deny("self_protect_shell", "blocked a shell command that may change "+ref)
}

// shellReadOnly is conservative: any doubt means "not read-only".
func shellReadOnly(cmd string) bool {
	c := harmlessRedirect.ReplaceAllString(cmd, "")
	if strings.Contains(c, ">") || strings.Contains(c, "`") || strings.Contains(c, "$(") {
		return false
	}
	for _, seg := range segmentSplit.Split(c, -1) {
		f := strings.Fields(strings.TrimLeft(strings.TrimSpace(seg), "("))
		if len(f) == 0 {
			continue
		}
		name := strings.TrimSuffix(strings.ToLower(filepath.Base(strings.Trim(f[0], `"'`))), ".exe")
		if !readOnly[name] {
			return false
		}
		for _, a := range f[1:] {
			la := strings.ToLower(a)
			if (name == "sed" && strings.HasPrefix(la, "-i")) ||
				(name == "find" && (la == "-delete" || la == "-exec" || la == "-execdir" || la == "-fprint")) {
				return false
			}
		}
	}
	return true
}
