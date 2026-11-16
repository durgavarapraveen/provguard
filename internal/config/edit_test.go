package config

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
)

func TestUpdateKeepsUnknownKeys(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(Path(home), []byte(`{"profile":"audit","future_key":{"a":1},"allowed_hosts":["x.test"]}`), 0o600)
	c, err := Update(home, func(c *Config) error {
		AddTo(&c.AllowedHosts, "y.test")
		return c.SetProfile("Balanced")
	})
	if err != nil {
		t.Fatal(err)
	}
	if c.ProfileName() != Balanced || len(c.AllowedHosts) != 2 {
		t.Fatalf("got %+v", c)
	}
	var raw map[string]any
	b, _ := os.ReadFile(Path(home))
	if err := json.Unmarshal(b, &raw); err != nil {
		t.Fatal(err)
	}
	if raw["future_key"] == nil {
		t.Error("unknown key was dropped")
	}
	if raw["profile"] != "balanced" {
		t.Errorf("profile = %v", raw["profile"])
	}
}

func TestUpdateRemovesClearedKeys(t *testing.T) {
	home := t.TempDir()
	os.WriteFile(Path(home), []byte(`{"block_mode":"ask","allowed_hosts":["x.test"]}`), 0o600)
	if _, err := Update(home, func(c *Config) error {
		RemoveFrom(&c.AllowedHosts, "X.TEST")
		return c.SetBlockMode("deny")
	}); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(Path(home))
	if s := string(b); strings.Contains(s, "block_mode") || strings.Contains(s, "allowed_hosts") {
		t.Errorf("cleared keys left in file: %s", s)
	}
}

func TestUpdateRefusesBrokenFile(t *testing.T) {
	home := t.TempDir()
	broken := []byte(`{"profile": "balanced",`)
	os.WriteFile(Path(home), broken, 0o600)
	if _, err := Update(home, func(c *Config) error { return c.SetProfile("audit") }); err == nil {
		t.Fatal("broken file accepted")
	}
	if b, _ := os.ReadFile(Path(home)); string(b) != string(broken) {
		t.Error("broken file was changed")
	}
}

func TestUpdateCreatesFileAndFailedEditWritesNothing(t *testing.T) {
	home := t.TempDir()
	if _, err := Update(home, func(c *Config) error { return c.SetProfile("nope") }); err == nil {
		t.Fatal("bad profile accepted")
	}
	if _, err := os.Stat(Path(home)); !os.IsNotExist(err) {
		t.Fatal("failed edit wrote a file")
	}
	if _, err := Update(home, func(c *Config) error { return c.SetProfile("strict") }); err != nil {
		t.Fatal(err)
	}
	if c, _ := Load(home); c.ProfileName() != Strict {
		t.Fatal("new file not written")
	}
}

func TestNormalizeHost(t *testing.T) {
	ok := map[string]string{
		"api.example.com":               "api.example.com",
		"HTTPS://Api.Example.com/x?y=1": "api.example.com",
		"user@git.example.com:22":       "git.example.com",
		"example.com.":                  "example.com",
	}
	for in, want := range ok {
		if got, err := NormalizeHost(in); err != nil || got != want {
			t.Errorf("NormalizeHost(%q) = %q, %v; want %q", in, got, err, want)
		}
	}
	for _, in := range []string{"", "localhost", "com", "10.0.0.1", "*.example.com", "exa mple.com", "-x.com", "a..com"} {
		if got, err := NormalizeHost(in); err == nil {
			t.Errorf("NormalizeHost(%q) = %q, want error", in, got)
		}
	}
}

func TestNormalizeOwner(t *testing.T) {
	for _, in := range []string{"durgavarapraveen", "@my-org", "A1"} {
		if _, err := NormalizeOwner(in); err != nil {
			t.Errorf("%q: %v", in, err)
		}
	}
	for _, in := range []string{"", "-x", "a/b", "a b", strings.Repeat("a", 40)} {
		if _, err := NormalizeOwner(in); err == nil {
			t.Errorf("%q accepted", in)
		}
	}
}
