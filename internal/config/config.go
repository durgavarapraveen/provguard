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

	// AllowedHosts: fetched content from these hosts is trusted (used from week 4).
	AllowedHosts []string `json:"allowed_hosts,omitempty"`

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

// ProfileName returns the active profile. Unknown values fall back to audit.
func (c Config) ProfileName() string {
	switch strings.ToLower(c.Profile) {
	case Balanced:
		return Balanced
	case Strict:
		return Strict
	}
	return Audit
}

// HostAllowed reports whether host is in AllowedHosts or a subdomain of one.
func (c Config) HostAllowed(host string) bool {
	h := strings.ToLower(strings.TrimSuffix(host, "."))
	for _, a := range c.AllowedHosts {
		a = strings.ToLower(a)
		if h == a || strings.HasSuffix(h, "."+a) {
			return true
		}
	}
	return false
}

func (c Config) TrustSDK() bool { return c.TrustSDKMCPServers == nil || *c.TrustSDKMCPServers }

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
