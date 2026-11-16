package main

import (
	"bytes"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/config"
)

func TestConfigCommand(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROVGUARD_HOME", home)
	run := func(args ...string) (int, string) {
		var out, errb bytes.Buffer
		code := runConfig(args, &out, &errb)
		return code, out.String() + errb.String()
	}

	steps := []struct {
		args []string
		code int
		want string
	}{
		{nil, 0, "audit"},
		{[]string{"mode", "balanced"}, 0, "protect"},
		{[]string{"mode", "turbo"}, 1, "unknown mode"},
		{[]string{"on-block", "ask"}, 0, "asks you"},
		{[]string{"trust-owner", "@my-org"}, 0, "my-org"},
		{[]string{"trust-owner", "my-org"}, 0, "already"},
		{[]string{"allow-host", "https://api.mycorp.test/v1"}, 0, "api.mycorp.test"},
		{[]string{"allow-host", "localhost"}, 1, "not a host name"},
		{[]string{"trust-site", "docs.mycorp.test"}, 0, "docs.mycorp.test"},
		{[]string{"trust-owner", "my-org", "--remove"}, 0, "Removed"},
		{[]string{"nonsense", "x"}, 2, "usage"},
		{[]string{"mode"}, 2, "usage"},
		{nil, 0, "api.mycorp.test"},
	}
	for _, s := range steps {
		code, out := run(s.args...)
		if code != s.code || !strings.Contains(out, s.want) {
			t.Errorf("config %v: code %d, output %q; want code %d containing %q", s.args, code, out, s.code, s.want)
		}
	}

	c, err := config.Load(home)
	if err != nil {
		t.Fatal(err)
	}
	if c.ProfileName() != config.Balanced || !c.BlockAsks() || len(c.TrustedRepoOwners) != 0 ||
		!c.HostAllowed("api.mycorp.test") || !c.ContentTrusted("docs.mycorp.test") {
		t.Errorf("final config %+v", c)
	}
}

func TestAgentCannotChangeConfig(t *testing.T) {
	for cmd, want := range map[string]string{
		"provguard config":                                                "",
		"provguard config mode audit":                                     "deny",
		`"C:/x/provguard.exe" config allow-host evil.test`:                "deny",
		`python -c "import os; os.system('provguard config mode audit')"`: "deny",
	} {
		s := newSession(t, `{"profile":"balanced"}`)
		if d, _ := s.run(bashPre(cmd)); d != want {
			t.Errorf("%s: got %q, want %q", cmd, d, want)
		}
	}
}
