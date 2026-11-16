package config

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"slices"
	"strings"
)

// Describe returns a one-line, plain-language meaning of a profile.
func Describe(profile string) string {
	switch profile {
	case Audit:
		return "watch only: logs what it would stop, blocks nothing"
	case Strict:
		return "lockdown: stops every risky step"
	}
	return "protect: stops leaks, asks before risky steps"
}

// Update applies fn to the config file under home and writes it back.
//
// Keys that this version does not know are kept, so an older binary does not
// erase settings written by a newer one. A file that cannot be parsed is not
// touched: the user must fix it first, so no setting is lost silently.
func Update(home string, fn func(*Config) error) (Config, error) {
	path := Path(home)
	raw := map[string]json.RawMessage{}
	b, err := os.ReadFile(path)
	switch {
	case errors.Is(err, os.ErrNotExist):
	case err != nil:
		return Config{}, err
	default:
		if err := json.Unmarshal(b, &raw); err != nil {
			return Config{}, fmt.Errorf("%s is not valid JSON (%v); fix or delete it first", path, err)
		}
	}
	var c Config
	if len(b) > 0 {
		if err := json.Unmarshal(b, &c); err != nil {
			return Config{}, fmt.Errorf("%s has a wrong value (%v); fix or delete it first", path, err)
		}
	}
	if err := fn(&c); err != nil {
		return Config{}, err
	}

	// Replace the known keys; keep the rest.
	for _, k := range knownKeys() {
		delete(raw, k)
	}
	known, err := json.Marshal(c)
	if err != nil {
		return Config{}, err
	}
	if err := json.Unmarshal(known, &raw); err != nil {
		return Config{}, err
	}
	out, err := json.MarshalIndent(raw, "", "  ")
	if err != nil {
		return Config{}, err
	}
	return c, writeAtomic(path, append(out, '\n'))
}

func knownKeys() []string {
	var keys []string
	t := reflect.TypeOf(Config{})
	for i := range t.NumField() {
		if name, _, _ := strings.Cut(t.Field(i).Tag.Get("json"), ","); name != "" && name != "-" {
			keys = append(keys, name)
		}
	}
	return keys
}

func writeAtomic(path string, b []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".config-*.tmp")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name()) // no-op after a successful rename
	if _, err := tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), path)
}

// SetProfile sets a profile after checking its name.
func (c *Config) SetProfile(p string) error {
	p = strings.ToLower(strings.TrimSpace(p))
	switch p {
	case Audit, Balanced, Strict:
		c.Profile = p
		return nil
	}
	return fmt.Errorf("unknown mode %q: use audit, balanced or strict", p)
}

// SetBlockMode sets what happens when policy stops a call: "deny" or "ask".
func (c *Config) SetBlockMode(m string) error {
	m = strings.ToLower(strings.TrimSpace(m))
	switch m {
	case "deny":
		c.BlockMode = "" // the default; keep the file short
		return nil
	case "ask":
		c.BlockMode = m
		return nil
	}
	return fmt.Errorf("unknown value %q: use deny or ask", m)
}

var (
	ownerRe = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9-]{0,38})$`)
	hostRe  = regexp.MustCompile(`^(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z][a-z0-9-]{0,62}$`)
	mcpRe   = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,100}$`)
)

// NormalizeOwner checks a GitHub user or organization name.
func NormalizeOwner(s string) (string, error) {
	s = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(s), "@"))
	if !ownerRe.MatchString(s) {
		return "", fmt.Errorf("%q is not a GitHub user or organization name", s)
	}
	return s, nil
}

// NormalizeHost accepts "api.example.com" (a URL is reduced to its host) and
// rejects anything that is not a dotted host name. Single-label names and IP
// addresses are refused on purpose: allowed hosts must be specific.
func NormalizeHost(s string) (string, error) {
	h := strings.ToLower(strings.TrimSpace(s))
	if _, rest, ok := strings.Cut(h, "://"); ok {
		h = rest
	}
	h, _, _ = strings.Cut(h, "/")
	if at := strings.LastIndex(h, "@"); at >= 0 {
		h = h[at+1:]
	}
	if i := strings.LastIndex(h, ":"); i >= 0 {
		h = h[:i]
	}
	h = strings.TrimSuffix(h, ".")
	if !hostRe.MatchString(h) {
		return "", fmt.Errorf("%q is not a host name such as api.example.com", s)
	}
	return h, nil
}

// NormalizeMCPServer checks an MCP server name.
func NormalizeMCPServer(s string) (string, error) {
	s = strings.TrimSpace(s)
	if !mcpRe.MatchString(s) {
		return "", fmt.Errorf("%q is not an MCP server name", s)
	}
	return s, nil
}

// AddTo adds v to list (case-insensitive) and reports whether it was new.
func AddTo(list *[]string, v string) bool {
	if contains(*list, v) {
		return false
	}
	*list = append(*list, v)
	return true
}

// RemoveFrom removes v from list (case-insensitive) and reports whether it was there.
func RemoveFrom(list *[]string, v string) bool {
	n := len(*list)
	*list = slices.DeleteFunc(*list, func(x string) bool { return strings.EqualFold(x, v) })
	return len(*list) != n
}
