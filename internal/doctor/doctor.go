// Package doctor checks that provguard's hooks are intact and scans a
// repository for settings and instruction files that could hijack an agent
// or turn hooks off before any hook runs (finding F3).
package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/install"
	"github.com/durgavarapraveen/provguard/internal/label"
)

// Severity levels.
const (
	High   = "HIGH"
	Medium = "MEDIUM"
	Info   = "INFO"
)

// Finding is one result.
type Finding struct {
	Severity string `json:"severity"`
	Area     string `json:"area"`
	Message  string `json:"message"`
}

// Options say where to look.
type Options struct {
	Home         string   // provguard home
	UserSettings string   // ~/.claude/settings.json
	Repo         string   // repository or project folder to scan ("" = skip)
	Events       []string // hook events provguard must have
}

// Run returns all findings, most severe first.
func Run(o Options) []Finding {
	var f []Finding
	f = append(f, HookIntegrity(o)...)
	if o.Repo != "" {
		f = append(f, ScanRepo(o.Repo, o.Home)...)
	}
	rank := map[string]int{High: 0, Medium: 1, Info: 2}
	sort.SliceStable(f, func(i, j int) bool { return rank[f[i].Severity] < rank[f[j].Severity] })
	return f
}

// HasHigh reports whether any finding is HIGH.
func HasHigh(f []Finding) bool {
	for _, x := range f {
		if x.Severity == High {
			return true
		}
	}
	return false
}

// HookIntegrity checks the user's settings and the provguard binary, and
// whether the project at o.Repo turns hooks off.
func HookIntegrity(o Options) []Finding {
	var out []Finding
	s, err := install.Load(o.UserSettings)
	if err != nil {
		return []Finding{{High, "hooks", "cannot read user settings: " + err.Error()}}
	}
	if b, _ := s["disableAllHooks"].(bool); b {
		out = append(out, Finding{High, "hooks", "user settings set disableAllHooks: provguard is off"})
	}
	hooks, _ := s["hooks"].(map[string]any)
	for _, ev := range o.Events {
		cmd := provguardCommand(hooks, ev)
		if cmd == "" {
			out = append(out, Finding{High, "hooks", "no provguard hook for " + ev + " in " + o.UserSettings + " (run provguard init --yes)"})
			continue
		}
		bin := commandBinary(cmd)
		if _, err := os.Stat(bin); err != nil {
			out = append(out, Finding{High, "binary", ev + " hook runs " + bin + ", which does not exist"})
			continue
		}
		if o.Home != "" && !under(bin, o.Home) {
			out = append(out, Finding{Medium, "binary", ev + " hook runs " + bin + ", outside provguard's protected folder; an agent could replace it (run provguard init --yes)"})
		}
	}
	if o.Repo != "" {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			p := filepath.Join(o.Repo, ".claude", name)
			ps, err := install.Load(p)
			if err != nil {
				out = append(out, Finding{Medium, "repo settings", p + " is not valid JSON"})
				continue
			}
			if b, _ := ps["disableAllHooks"].(bool); b {
				out = append(out, Finding{High, "repo settings", p + " sets disableAllHooks: opening this repo turns provguard off (finding F3)"})
			}
			if ph, ok := ps["hooks"].(map[string]any); ok && len(ph) > 0 {
				for ev, v := range ph {
					for _, c := range hookCommands(v) {
						out = append(out, Finding{Medium, "repo settings", p + " adds a " + ev + " hook that runs: " + c})
					}
				}
			}
			if _, ok := ps["allowManagedHooksOnly"]; ok {
				out = append(out, Finding{Info, "repo settings", p + " sets allowManagedHooksOnly (only effective in managed settings)"})
			}
		}
	}
	return out
}

func provguardCommand(hooks map[string]any, ev string) string {
	for _, c := range hookCommands(hooks[ev]) {
		if install.IsProvguard(c) {
			return c
		}
	}
	return ""
}

func hookCommands(v any) []string {
	var out []string
	groups, _ := v.([]any)
	for _, g := range groups {
		gm, _ := g.(map[string]any)
		inner, _ := gm["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if c, _ := hm["command"].(string); c != "" {
				out = append(out, c)
			}
		}
	}
	return out
}

// commandBinary returns the program path of a hook command line.
func commandBinary(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if strings.HasPrefix(cmd, `"`) {
		if i := strings.Index(cmd[1:], `"`); i >= 0 {
			return filepath.FromSlash(cmd[1 : i+1])
		}
	}
	return filepath.FromSlash(strings.Fields(cmd)[0])
}

func under(p, dir string) bool {
	n := strings.ToLower(filepath.Clean(p))
	d := strings.ToLower(filepath.Clean(dir))
	return strings.HasPrefix(n, d+string(filepath.Separator))
}

// instructionFiles are loaded into the agent's context automatically.
var instructionFiles = []string{
	"CLAUDE.md", "CLAUDE.local.md", ".claude/CLAUDE.md", "AGENTS.md", "GEMINI.md",
	".cursorrules", ".windsurfrules", ".github/copilot-instructions.md",
}

var suspicious = []struct {
	sev, what string
	re        *regexp.Regexp
}{
	{High, "network command", regexp.MustCompile(`(?i)\b(?:curl|wget|nc|ncat|netcat|Invoke-WebRequest|iwr|irm)\b[^\n]{0,80}(?:https?://|\d+\.\d+\.\d+\.\d+)|/dev/(?:tcp|udp)/`)},
	{High, "pipe to shell", regexp.MustCompile(`(?i)\|\s*(?:sudo\s+)?(?:ba|z)?sh\b|\|\s*(?:iex|Invoke-Expression)\b`)},
	{High, "decode and run", regexp.MustCompile(`(?i)base64\s+(?:-d|--decode)|FromBase64String|\beval\s*[\("$]`)},
	{High, "turns hooks off", regexp.MustCompile(`(?i)disableAllHooks`)},
	{High, "prompt-injection phrase", regexp.MustCompile(`(?i)ignore (?:all |any )?(?:previous|prior|above) instructions|do not (?:tell|inform) the user|without (?:asking|telling) the user`)},
	{Medium, "mentions secrets", regexp.MustCompile(`(?i)\.env\b|id_rsa|\.aws/credentials|api[_-]?key|GITHUB_TOKEN`)},
	{Medium, "hidden HTML comment", regexp.MustCompile(`(?s)<!--.{0,400}?-->`)},
}

var invisible = regexp.MustCompile(`[\x{200b}\x{200c}\x{200d}\x{2060}\x{feff}\x{202a}-\x{202e}\x{2066}-\x{2069}]`)

// ScanRepo looks at files the agent reads without a tool call, MCP server
// definitions, and the repo's trust status.
func ScanRepo(repo, home string) []Finding {
	var out []Finding
	for _, name := range instructionFiles {
		p := filepath.Join(repo, filepath.FromSlash(name))
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(b)
		for _, s := range suspicious {
			if m := s.re.FindString(text); m != "" {
				out = append(out, Finding{s.sev, "instructions", name + ": " + s.what + ": " + oneLine(m, 90)})
			}
		}
		if invisible.MatchString(text) {
			out = append(out, Finding{High, "instructions", name + ": contains invisible or bidi characters (hidden text)"})
		}
	}
	if b, err := os.ReadFile(filepath.Join(repo, ".mcp.json")); err == nil {
		var m struct {
			Servers map[string]struct {
				Command string   `json:"command"`
				Args    []string `json:"args"`
				URL     string   `json:"url"`
			} `json:"mcpServers"`
		}
		if json.Unmarshal(b, &m) != nil {
			out = append(out, Finding{Medium, "mcp", ".mcp.json is not valid JSON"})
		}
		for name, s := range m.Servers {
			what := s.URL
			if what == "" {
				what = strings.TrimSpace(s.Command + " " + strings.Join(s.Args, " "))
			}
			out = append(out, Finding{Medium, "mcp", ".mcp.json defines server " + name + ": " + oneLine(what, 90)})
		}
	}
	cfg, err := config.Load(home)
	if err != nil {
		out = append(out, Finding{High, "config", "provguard config is invalid: " + err.Error()})
	}
	if root := label.RepoRoot(filepath.Join(repo, "x")); root != "" {
		owner := label.OriginOwner(root)
		switch {
		case len(cfg.TrustedRepoOwners) == 0:
			out = append(out, Finding{Info, "trust", "trusted_repo_owners is not set, so provguard cannot tell your repos from others'"})
		case owner == "":
			out = append(out, Finding{Info, "trust", "repo has no origin remote"})
		case cfg.RepoOwnerTrusted(owner):
			out = append(out, Finding{Info, "trust", "repo owner " + owner + " is trusted"})
		default:
			out = append(out, Finding{Medium, "trust", "repo owner " + owner + " is not in trusted_repo_owners: sessions here start untrusted"})
		}
	}
	if err != nil {
		cfg = config.FailSafe() // what the hooks use while config.json is broken
	}
	if !cfg.ProfileKnown() {
		out = append(out, Finding{Medium, "config", "unknown profile " + strconvQuote(cfg.Profile) + "; provguard uses balanced (valid: audit, balanced, strict)"})
	}
	out = append(out, Finding{Info, "profile", "active profile: " + cfg.ProfileName()})
	return out
}

func strconvQuote(s string) string { return `"` + s + `"` }

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
