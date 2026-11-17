package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
)

// Rule is an ask or deny rule for shell commands or tools. It matches when
// every part it sets matches:
//   - Command: words the shell command contains in this order, starting
//     with its name; flags and other words may come between them, and "*"
//     or other globs match one word ("kubectl apply", "aws create-*").
//   - Match: a regular expression on the whole command line.
//   - Tool: a glob on the tool name, for tools that are not shell commands
//     ("mcp__github__merge_*").
type Rule struct {
	Name    string `json:"name"`
	Command string `json:"command,omitempty"`
	Match   string `json:"match,omitempty"`
	Tool    string `json:"tool,omitempty"`
	Action  string `json:"action"` // "ask" or "deny"
	Reason  string `json:"reason,omitempty"`
}

// ValidateRules reports the first rule that cannot work.
func ValidateRules(rules []Rule) error {
	for i, r := range rules {
		name := r.Name
		if name == "" {
			name = fmt.Sprintf("rule %d", i+1)
		}
		if r.Action != "ask" && r.Action != "deny" {
			return fmt.Errorf("%s: action must be \"ask\" or \"deny\", not %q", name, r.Action)
		}
		if r.Command == "" && r.Match == "" && r.Tool == "" {
			return fmt.Errorf("%s: set command, match or tool", name)
		}
		if r.Match != "" {
			if _, err := regexp.Compile(r.Match); err != nil {
				return fmt.Errorf("%s: match: %v", name, err)
			}
		}
		for _, g := range append(strings.Fields(r.Command), r.Tool) {
			if _, err := path.Match(g, ""); err != nil {
				return fmt.Errorf("%s: bad pattern %q", name, g)
			}
		}
	}
	return nil
}

// SensitivePathMatch reports whether p matches one of SensitivePaths. A
// pattern with n path elements is matched against the last n elements of p.
func (c Config) SensitivePathMatch(p string) bool {
	segs := strings.Split(strings.ToLower(strings.ReplaceAll(p, `\`, "/")), "/")
	for _, pat := range c.SensitivePaths {
		ps := strings.Split(strings.ToLower(strings.Trim(strings.ReplaceAll(pat, `\`, "/"), "/")), "/")
		if len(ps) == 0 || len(ps) > len(segs) {
			continue
		}
		if ok, _ := path.Match(strings.Join(ps, "/"), strings.Join(segs[len(segs)-len(ps):], "/")); ok {
			return true
		}
	}
	return false
}

// HostBlocked reports whether host is in BlockedHosts, or a subdomain of one.
func (c Config) HostBlocked(host string) bool { return hostIn(host, c.BlockedHosts) }

// RepoPolicyPath is a repository's own provguard policy, relative to its root.
const RepoPolicyPath = ".provguard/policy.json"

// RepoPolicy is a team policy committed to a repository. It can only make
// provguard stricter: a cloned repository is untrusted, so nothing in it may
// turn a check off. Keys that would weaken a check are not read.
type RepoPolicy struct {
	Mode           string   `json:"mode,omitempty"` // raises the mode, never lowers it
	SensitivePaths []string `json:"sensitive_paths,omitempty"`
	BlockedHosts   []string `json:"blocked_hosts,omitempty"`
	Rules          []Rule   `json:"rules,omitempty"`
	Packs          []string `json:"packs,omitempty"`
}

// maxRepoPolicy bounds the policy file read on every hook call.
const maxRepoPolicy = 64 << 10

// FindRepoPolicy returns the path of the repository policy that applies to
// a command run in cwd: .provguard/policy.json in cwd or the nearest parent,
// up to the repository root (the folder holding .git). It returns "" when
// there is none.
func FindRepoPolicy(cwd string) string {
	if cwd == "" {
		return ""
	}
	home, _ := os.UserHomeDir()
	for d := filepath.Clean(cwd); ; d = filepath.Dir(d) {
		if home != "" && strings.EqualFold(d, filepath.Clean(home)) {
			return "" // the user's own folder holds provguard's data, not a policy
		}
		p := filepath.Join(d, filepath.FromSlash(RepoPolicyPath))
		if fi, err := os.Stat(p); err == nil && fi.Mode().IsRegular() {
			return p
		}
		if _, err := os.Stat(filepath.Join(d, ".git")); err == nil || filepath.Dir(d) == d {
			return ""
		}
	}
}

// LoadRepoPolicy reads a repository policy. Unknown keys are ignored.
func LoadRepoPolicy(p string) (RepoPolicy, error) {
	var rp RepoPolicy
	f, err := os.Open(p)
	if err != nil {
		return rp, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, maxRepoPolicy+1))
	if err != nil {
		return rp, err
	}
	if len(b) > maxRepoPolicy {
		return rp, errors.New(p + " is larger than 64 KB")
	}
	if err := json.Unmarshal(b, &rp); err != nil {
		return rp, fmt.Errorf("parse %s: %w", p, err)
	}
	if err := ValidateRules(rp.Rules); err != nil {
		return rp, fmt.Errorf("%s: %w", p, err)
	}
	return rp, nil
}

// strictness orders the modes.
var strictness = map[string]int{Audit: 0, Balanced: 1, Strict: 2}

// Tighten returns c with a repository policy added: a stricter mode, and
// its sensitive paths, blocked hosts, rules and packs. Nothing is removed.
func (c Config) Tighten(rp RepoPolicy) Config {
	if m := strings.ToLower(strings.TrimSpace(rp.Mode)); strictness[m] > strictness[c.ProfileName()] {
		c.Profile = m
	}
	c.SensitivePaths = append(append([]string{}, c.SensitivePaths...), rp.SensitivePaths...)
	c.BlockedHosts = append(append([]string{}, c.BlockedHosts...), rp.BlockedHosts...)
	c.Rules = append(append([]Rule{}, c.Rules...), rp.Rules...)
	c.Packs = append(append([]string{}, c.Packs...), rp.Packs...)
	return c
}

// WithRepoPolicy applies the repository policy for cwd, if any. A policy
// that cannot be read is reported and not applied.
func (c Config) WithRepoPolicy(cwd string) (Config, error) {
	p := FindRepoPolicy(cwd)
	if p == "" {
		return c, nil
	}
	rp, err := LoadRepoPolicy(p)
	if err != nil {
		return c, err
	}
	return c.Tighten(rp), nil
}
