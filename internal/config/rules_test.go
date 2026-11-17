package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestValidateRules(t *testing.T) {
	bad := []Rule{
		{Name: "a", Command: "x", Action: "allow"},
		{Name: "b", Action: "ask"},
		{Name: "c", Match: "(", Action: "deny"},
		{Name: "d", Tool: "[", Action: "ask"},
	}
	for _, r := range bad {
		if ValidateRules([]Rule{r}) == nil {
			t.Errorf("%+v: no error", r)
		}
	}
	if err := ValidateRules([]Rule{{Name: "ok", Command: "kubectl apply", Action: "ask"}, {Tool: "mcp__x__*", Action: "deny"}}); err != nil {
		t.Error(err)
	}
}

func TestSensitivePathMatch(t *testing.T) {
	c := Config{SensitivePaths: []string{"*.tfvars", "secrets/*", "deploy/prod.yaml"}}
	for p, want := range map[string]bool{
		"/w/infra/prod.tfvars":     true,
		`C:\w\secrets\db.json`:     true,
		"/w/deploy/prod.yaml":      true,
		"/w/other/deploy/prod.yml": false,
		"/w/main.go":               false,
		"/w/secrets":               false,
	} {
		if got := c.SensitivePathMatch(p); got != want {
			t.Errorf("%s: %v, want %v", p, got, want)
		}
	}
}

// A repository policy adds checks and raises the mode; it never lowers it.
func TestTightenOnlyAdds(t *testing.T) {
	user := Config{Profile: Strict, Rules: []Rule{{Name: "u", Command: "x", Action: "ask"}}}
	got := user.Tighten(RepoPolicy{Mode: Audit, Rules: []Rule{{Name: "r", Command: "y", Action: "deny"}}, BlockedHosts: []string{"paste.test"}})
	if got.ProfileName() != Strict || len(got.Rules) != 2 || !got.HostBlocked("a.paste.test") {
		t.Errorf("%+v", got)
	}
	if got := (Config{}).Tighten(RepoPolicy{Mode: "balanced"}); got.ProfileName() != Balanced {
		t.Errorf("mode not raised: %q", got.Profile)
	}
	if len(user.Rules) != 1 {
		t.Error("Tighten changed the user's config")
	}
}

func TestRepoPolicyLookup(t *testing.T) {
	repo := t.TempDir()
	sub := filepath.Join(repo, "svc", "api")
	os.MkdirAll(sub, 0o700)
	os.Mkdir(filepath.Join(repo, ".git"), 0o700)
	if p := FindRepoPolicy(sub); p != "" {
		t.Fatalf("found %s without a policy", p)
	}
	pol := filepath.Join(repo, ".provguard", "policy.json")
	os.MkdirAll(filepath.Dir(pol), 0o700)
	// allowed_hosts is not a repository key: it would weaken a check.
	os.WriteFile(pol, []byte(`{"mode":"strict","allowed_hosts":["evil.test"],"rules":[{"name":"deploy","command":"make deploy","action":"ask"}]}`), 0o600)
	if p := FindRepoPolicy(sub); p != pol {
		t.Fatalf("FindRepoPolicy = %q, want %q", p, pol)
	}
	c, err := Config{}.WithRepoPolicy(sub)
	if err != nil || c.ProfileName() != Strict || len(c.Rules) != 1 || c.HostAllowed("evil.test") {
		t.Errorf("%+v %v", c, err)
	}

	// A policy above the repository root does not apply.
	outer := t.TempDir()
	os.MkdirAll(filepath.Join(outer, ".provguard"), 0o700)
	os.WriteFile(filepath.Join(outer, ".provguard", "policy.json"), []byte(`{"mode":"strict"}`), 0o600)
	inner := filepath.Join(outer, "repo")
	os.MkdirAll(filepath.Join(inner, ".git"), 0o700)
	if p := FindRepoPolicy(inner); p != "" {
		t.Errorf("crossed the repository root: %s", p)
	}

	os.WriteFile(pol, []byte(`{"rules":[{"name":"bad","command":"x","action":"allow"}]}`), 0o600)
	if _, err := (Config{}).WithRepoPolicy(sub); err == nil || !strings.Contains(err.Error(), "bad") {
		t.Errorf("invalid policy: %v", err)
	}
}
