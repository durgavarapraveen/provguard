// Package config loads provguard's user configuration.
//
// The file is JSON (not YAML) to avoid a third-party dependency.
// Location: <provguard home>/config.json. A missing file means defaults.
package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

type Config struct {
	// Profile is "audit" (log only, default), "balanced" or "strict".
	Profile string `json:"profile,omitempty"`

	// SelfProtect denies agent writes to hook settings and provguard files.
	// Pointer so that a missing key means the default (true).
	SelfProtect *bool `json:"self_protect,omitempty"`

	// TrustedRepoOwners: files in git repos whose origin owner is in this list
	// are trusted. Empty list turns the repo-owner check off.
	TrustedRepoOwners []string `json:"trusted_repo_owners,omitempty"`

	// TrustedMCPServers: output from these MCP servers is trusted.
	TrustedMCPServers []string `json:"trusted_mcp_servers,omitempty"`

	// TrustSDKMCPServers trusts in-process MCP servers that the host app
	// provides (mcp_server.source == "sdk"). Default true.
	TrustSDKMCPServers *bool `json:"trust_sdk_mcp_servers,omitempty"`

	// AllowedHosts: data sent to these hosts does not count as egress.
	// Review finding (MED): this used to mean trust in both directions, so
	// listing a host to allow uploads to it also made everything fetched
	// from it trusted. Content trust is now its own list.
	AllowedHosts []string `json:"allowed_hosts,omitempty"`

	// TrustedContentHosts: content fetched from these hosts does not taint
	// the session. Hosts that carry anyone's writing (github.com,
	// gist.github.com, raw.githubusercontent.com, pastebin) do not belong
	// here; provguard doctor reports them.
	TrustedContentHosts []string `json:"trusted_content_hosts,omitempty"`

	// BlockMode is "deny" (default) or "ask". In the balanced profile, "ask"
	// turns policy denies (secret in call, lethal trifecta) into Claude Code's
	// approval prompt. Self-protection always denies; strict ignores this.
	BlockMode string `json:"block_mode,omitempty"`

	// SessionTitleIcon puts the trust icon (🔴 🟡 🟠) in front of the session
	// title, so untrusted sessions stand out in the app's session list.
	// Default true.
	SessionTitleIcon *bool `json:"session_title_icon,omitempty"`

	// AuditRetentionDays: daily audit logs older than this are deleted at
	// session start. 0 = default (30); negative = keep forever.
	AuditRetentionDays int `json:"audit_retention_days,omitempty"`

	// LocalhostIsExternal treats localhost as a third party. Only the live
	// benchmark needs it, because its fake attacker runs on 127.0.0.1.
	LocalhostIsExternal bool `json:"localhost_is_external,omitempty"`
}

func (c Config) SelfProtectOn() bool { return c.SelfProtect == nil || *c.SelfProtect }

// Profiles.
const (
	Audit    = "audit"
	Balanced = "balanced"
	Strict   = "strict"
)

// ProfileName returns the active profile. An empty profile means audit (the
// default). Review finding (MED): a typo such as " balanced" or "balancd"
// used to fall back silently to audit, which blocks nothing; an unknown
// value now means balanced, and `provguard doctor` reports it.
func (c Config) ProfileName() string {
	switch strings.ToLower(strings.TrimSpace(c.Profile)) {
	case "", Audit:
		return Audit
	case Strict:
		return Strict
	}
	return Balanced
}

// ProfileKnown reports whether the configured profile is spelled correctly.
func (c Config) ProfileKnown() bool {
	switch strings.ToLower(strings.TrimSpace(c.Profile)) {
	case "", Audit, Balanced, Strict:
		return true
	}
	return false
}

// FailSafe is the configuration used when config.json cannot be parsed: the
// user meant to configure something, so provguard enforces balanced rather
// than silently doing nothing.
func FailSafe() Config { return Config{Profile: Balanced} }

// HostAllowed reports whether host is an allowed egress destination: in
// AllowedHosts, or a subdomain of one.
func (c Config) HostAllowed(host string) bool { return hostIn(host, c.AllowedHosts) }

// ContentTrusted reports whether content fetched from host is trusted:
// host is in TrustedContentHosts, or a subdomain of one.
func (c Config) ContentTrusted(host string) bool { return hostIn(host, c.TrustedContentHosts) }

func hostIn(host string, list []string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range list {
		a = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(a), "."))
		if a == "" {
			continue
		}
		if h == a || strings.HasSuffix(h, "."+a) {
			return true
		}
	}
	return false
}

func (c Config) TrustSDK() bool { return c.TrustSDKMCPServers == nil || *c.TrustSDKMCPServers }

func (c Config) TitleIconOn() bool { return c.SessionTitleIcon == nil || *c.SessionTitleIcon }

// BlockAsks reports block_mode "ask" (any other value means deny).
func (c Config) BlockAsks() bool { return strings.EqualFold(strings.TrimSpace(c.BlockMode), "ask") }

func (c Config) RepoOwnerTrusted(owner string) bool {
	return contains(c.TrustedRepoOwners, owner)
}

func (c Config) MCPServerTrusted(name string) bool {
	return contains(c.TrustedMCPServers, name)
}

func contains(list []string, v string) bool {
	for _, x := range list {
		if strings.EqualFold(x, v) {
			return true
		}
	}
	return false
}

// Path returns the config file path under home.
func Path(home string) string { return filepath.Join(home, "config.json") }

// Load reads the config. A missing file returns defaults.
func Load(home string) (Config, error) {
	var c Config
	b, err := os.ReadFile(Path(home))
	if errors.Is(err, os.ErrNotExist) {
		return c, nil
	}
	if err != nil {
		return c, err
	}
	if err := json.Unmarshal(b, &c); err != nil {
		return Config{}, fmt.Errorf("parse %s: %w", Path(home), err)
	}
	return c, nil
}
