// Package doctor checks that provguard's hooks are intact and scans a
// repository for settings and instruction files that could hijack an agent
// or turn hooks off before any hook runs.
package doctor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/durgavarapraveen/provguard/internal/redact"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"time"

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
	// Version is the version of the provguard running the check. Set it to
	// compare against the binary the hooks actually run ("" = skip).
	Version string
}

// Run returns all findings, most severe first.
func Run(o Options) []Finding {
	var f []Finding
	f = append(f, HookIntegrity(o)...)
	// Not in HookIntegrity: this runs the installed binary, and the hook
	// calls HookIntegrity on every ConfigChange event.
	f = append(f, HookBinaryVersion(o)...)
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
	out = append(out, failClosedFindings(o, hooks)...)
	if o.Repo != "" {
		for _, name := range []string{"settings.json", "settings.local.json"} {
			p := filepath.Join(o.Repo, ".claude", name)
			ps, err := install.Load(p)
			if err != nil {
				out = append(out, Finding{Medium, "repo settings", p + " is not valid JSON"})
				continue
			}
			if b, _ := ps["disableAllHooks"].(bool); b {
				out = append(out, Finding{High, "repo settings", p + " sets disableAllHooks: opening this repo turns provguard off"})
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

// versionRe reads the version out of `provguard version` ("provguard 0.5.1").
var versionRe = regexp.MustCompile(`(?m)^provguard\s+(\S+)`)

// hookVersionTimeout caps how long the installed binary may take to answer.
const hookVersionTimeout = 3 * time.Second

// HookBinaryVersion compares the provguard running this check with the one
// the hooks actually run. Nothing else reports that they differ, so an
// installed binary stayed behind a fixed build with no sign of it but the
// crashes it kept making. It runs the installed binary (`provguard
// version`), so it belongs to the doctor command, not to HookIntegrity.
func HookBinaryVersion(o Options) []Finding {
	if o.Version == "" || o.UserSettings == "" {
		return nil
	}
	s, err := install.Load(o.UserSettings)
	if err != nil {
		return nil // HookIntegrity reports an unreadable settings file
	}
	hooks, _ := s["hooks"].(map[string]any)
	cmd := provguardCommand(hooks, "PreToolUse")
	if cmd == "" {
		return nil // HookIntegrity reports a missing hook
	}
	bin := commandBinary(cmd)
	if sameBinary(bin) {
		return []Finding{{Info, "binary", "hooks run this binary, provguard " + o.Version}}
	}
	got, err := binaryVersion(bin)
	if err != nil {
		return []Finding{{Medium, "binary", "the hooks run " + bin +
			", which does not report its version (" + firstLine(err.Error(), 60) + ")"}}
	}
	return compareVersions(o.Version, got)
}

// compareVersions reports the installed hook binary's version against the
// version of the provguard running the check.
func compareVersions(running, installed string) []Finding {
	if installed == running {
		return []Finding{{Info, "binary", "hooks run provguard " + installed + ", the same version as this one"}}
	}
	return []Finding{{Medium, "binary", "the hooks run provguard " + installed + ", but this is provguard " + running +
		"; the hooks keep using the installed build until you run provguard init --yes"}}
}

// sameBinary reports whether p is the file running this check.
func sameBinary(p string) bool {
	self, err := os.Executable()
	if err != nil {
		return false
	}
	a, err := os.Stat(self)
	if err != nil {
		return false
	}
	b, err := os.Stat(p)
	return err == nil && os.SameFile(a, b)
}

// binaryVersion asks a provguard binary for its version.
func binaryVersion(bin string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), hookVersionTimeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, bin, "version").Output()
	if err != nil {
		return "", err
	}
	m := versionRe.FindSubmatch(out)
	if m == nil {
		return "", errors.New("unexpected output")
	}
	return string(m[1]), nil
}

// failClosedFindings reports when the installed PreToolUse hook does not
// match the profile. `provguard init` writes "onFailure": "block" only for
// strict, so switching the profile in config.json afterwards leaves the
// setting behind, and a hook that times out without it is a way through.
func failClosedFindings(o Options, hooks map[string]any) []Finding {
	if o.Home == "" {
		return nil
	}
	cfg, err := config.Load(o.Home)
	if err != nil {
		return nil // reported as a config finding elsewhere
	}
	blocks := provguardOnFailureBlock(hooks, "PreToolUse")
	switch cfg.ProfileName() {
	case config.Strict:
		if !blocks {
			return []Finding{{Medium, "hooks", `profile is strict but the PreToolUse hook has no "onFailure": "block", so a hook that times out lets the call through (run provguard init --yes)`}}
		}
	case config.Balanced:
		if !blocks {
			return []Finding{{Info, "hooks", "a PreToolUse hook that times out does not block the call in balanced; a check that crashes still blocks once the session has read untrusted content and secrets (strict blocks either way)"}}
		}
	}
	return nil
}

// provguardOnFailureBlock reports whether provguard's hook for ev is set to
// block when it fails.
func provguardOnFailureBlock(hooks map[string]any, ev string) bool {
	groups, _ := hooks[ev].([]any)
	for _, g := range groups {
		gm, _ := g.(map[string]any)
		inner, _ := gm["hooks"].([]any)
		for _, h := range inner {
			hm, _ := h.(map[string]any)
			if c, _ := hm["command"].(string); !install.IsProvguard(c) {
				continue
			}
			if f, _ := hm["onFailure"].(string); strings.EqualFold(f, "block") {
				return true
			}
		}
	}
	return false
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
	// A repository policy can only add checks, so it is reported, not feared.
	if p := config.FindRepoPolicy(repo); p != "" {
		if rp, err := config.LoadRepoPolicy(p); err != nil {
			out = append(out, Finding{Medium, "repo policy", redact.OneLine(err.Error(), 200) + " (not applied)"})
		} else {
			out = append(out, Finding{Info, "repo policy", fmt.Sprintf("%s adds %d rules, %d packs, %d sensitive paths and %d blocked hosts; mode %q (can only make provguard stricter)", p, len(rp.Rules), len(rp.Packs), len(rp.SensitivePaths), len(rp.BlockedHosts), rp.Mode)})
		}
	}
	for _, name := range instructionFiles {
		p := filepath.Join(repo, filepath.FromSlash(name))
		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		text := string(b)
		for _, s := range suspicious {
			if m := s.re.FindString(text); m != "" {
				out = append(out, Finding{s.sev, "instructions", name + ": " + s.what + ": " + redact.OneLine(m, 90)})
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
			out = append(out, Finding{Medium, "mcp", ".mcp.json defines server " + name + ": " + redact.OneLine(what, 90)})
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
	out = append(out, contentTrustFindings(cfg)...)
	if !cfg.ProfileKnown() {
		out = append(out, Finding{Medium, "config", "unknown profile " + strconvQuote(cfg.Profile) + "; provguard uses balanced (valid: audit, balanced, strict)"})
	}
	out = append(out, Finding{Info, "profile", "active profile: " + cfg.ProfileName()})
	return out
}

// publicContentHosts serve text and code that anyone can publish, so
// trusting their content turns the untrusted label off for the places
// injected instructions actually come from.
var publicContentHosts = map[string]bool{
	"github.com": true, "gist.github.com": true, "raw.githubusercontent.com": true,
	"gitlab.com": true, "bitbucket.org": true, "githubusercontent.com": true,
	"pastebin.com": true, "gitea.com": true, "codeberg.org": true,
	"npmjs.com": true, "pypi.org": true, "stackoverflow.com": true,
	"reddit.com": true, "medium.com": true, "x.com": true, "twitter.com": true,
}

// contentTrustFindings reports trusted_content_hosts entries that are too
// broad to mean anything, and entries that look like they were meant for
// allowed_hosts.
func contentTrustFindings(cfg config.Config) []Finding {
	var out []Finding
	for _, h := range cfg.TrustedContentHosts {
		n := strings.ToLower(strings.Trim(strings.TrimSpace(h), "."))
		switch {
		case n == "":
			continue
		case !strings.Contains(n, "."):
			out = append(out, Finding{Medium, "trust", "trusted_content_hosts has " + strconvQuote(h) +
				", which matches every host under it: content from anywhere there is treated as yours"})
		case publicContentHosts[n]:
			out = append(out, Finding{Medium, "trust", "trusted_content_hosts has " + strconvQuote(h) +
				", where anyone can publish: injected instructions fetched from it would not taint the session"})
		}
	}
	return out
}

func strconvQuote(s string) string { return `"` + s + `"` }

// firstLine keeps a message to one short line.
func firstLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
