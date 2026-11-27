package policy

import (
	"strings"
	"testing"
	"time"

	"github.com/durgavarapraveen/provguard/internal/config"
	"github.com/durgavarapraveen/provguard/internal/registry"
	"github.com/durgavarapraveen/provguard/internal/shell"
	"github.com/durgavarapraveen/provguard/internal/store"
)

var pkgNow = time.Date(2026, 11, 27, 0, 0, 0, 0, time.UTC)

// fakePackages: "old-pkg" and "esbuild" are old, "fresh-pkg" is 3 days old
// with install scripts, "flaky" fails to look up, the rest do not exist.
func fakePackages(asked *[]string) func(registry.Pkg, bool) (registry.Info, bool) {
	return func(p registry.Pkg, remote bool) (registry.Info, bool) {
		*asked = append(*asked, string(p.Eco)+":"+p.Name)
		switch p.Name {
		case "old-pkg", "esbuild", "requests", "serde":
			return registry.Info{Found: true, Created: pkgNow.AddDate(-5, 0, 0), Checked: pkgNow}, true
		case "busy-pkg":
			return registry.Info{Found: true, Checked: pkgNow}, true // date unknown
		case "fresh-pkg":
			return registry.Info{Found: true, Created: pkgNow.AddDate(0, 0, -3), InstallScripts: true, Checked: pkgNow}, true
		case "flaky", "reqeusts":
			return registry.Info{}, false
		case "lodahs": // a live typosquat with few users
			return registry.Info{Found: true, Created: pkgNow.AddDate(-1, 0, 0), WeeklyDownloads: 30, Checked: pkgNow}, true
		case "axioss": // a real neighbour that many people use
			return registry.Info{Found: true, Created: pkgNow.AddDate(-4, 0, 0), WeeklyDownloads: 50_000, Checked: pkgNow}, true
		}
		return registry.Info{Found: false, Checked: pkgNow}, true
	}
}

func judgePkg(cmd string, s *store.Session, cfg config.Config, asked *[]string) Result {
	a := shell.Analyze(cmd, shell.Bash)
	return Evaluate(Input{Tool: "Bash", Sinks: a.Sinks, Text: cmd, Session: s, Key: key, Config: cfg,
		Cwd: "/work/proj", PackageInfo: fakePackages(asked)})
}

func TestDependencyGate(t *testing.T) {
	cases := []struct {
		cmd, rule, decision string
		asked               []string
	}{
		{`npm install old-pkg`, "", None, []string{"npm:old-pkg"}},
		{`npm install busy-pkg`, "", None, []string{"npm:busy-pkg"}},
		{`npm install reakt-dom-helpers`, "unknown_package", Deny, []string{"npm:reakt-dom-helpers"}},
		{`npm i old-pkg fresh-pkg`, "new_package", Ask, []string{"npm:old-pkg", "npm:fresh-pkg"}},
		{`npm i fresh-pkg made-up-x`, "unknown_package", Deny, []string{"npm:fresh-pkg", "npm:made-up-x"}},
		{`pip install Requests==2.31`, "", None, []string{"pypi:requests"}},
		{`pip install huggingface-cli-tools`, "unknown_package", Deny, []string{"pypi:huggingface-cli-tools"}},
		{`cargo add serde`, "", None, []string{"crates:serde"}},
		{`npx fresh-pkg`, "new_package", Ask, []string{"npm:fresh-pkg"}},
		{`npm install flaky`, "", None, []string{"npm:flaky"}},
		{`npm install lodahs`, "lookalike_package", Ask, []string{"npm:lodahs"}},
		{`npm install axioss`, "", None, []string{"npm:axioss"}},
		{`npm install expres`, "unknown_package", Deny, []string{"npm:expres"}},
		{`pip install reqeusts`, "lookalike_package", Ask, []string{"pypi:reqeusts"}}, // no answer: the name alone is enough to ask
		{`npm install`, "", None, nil},
		{`npm install ./local github:u/r`, "", None, nil},
		{`go install example.com/x@latest`, "", None, nil},
		{`echo npm install made-up`, "", None, nil},
	}
	for _, c := range cases {
		var asked []string
		r := judgePkg(c.cmd, nil, bal(), &asked)
		if r.Rule != c.rule || r.Decision != c.decision || strings.Join(asked, ",") != strings.Join(c.asked, ",") {
			t.Errorf("%q: rule %q decision %q asked %v; want %q %q %v", c.cmd, r.Rule, r.Decision, asked, c.rule, c.decision, c.asked)
		}
	}
}

func TestDependencyGateMessages(t *testing.T) {
	var asked []string
	r := judgePkg(`npm i fresh-pkg`, nil, bal(), &asked)
	if !strings.Contains(r.Summary, "fresh-pkg") || !strings.Contains(r.Summary, "3 days") || !strings.Contains(r.Summary, "install scripts") {
		t.Errorf("new_package summary: %q", r.Summary)
	}
	r = judgePkg(`npm i expres`, nil, bal(), &asked)
	if !strings.Contains(r.Summary, "did you mean express?") {
		t.Errorf("unknown lookalike summary: %q", r.Summary)
	}
	r = judgePkg(`npm i lodahs`, nil, bal(), &asked)
	if !strings.Contains(r.Summary, "looks like the popular package lodash") {
		t.Errorf("lookalike summary: %q", r.Summary)
	}
	r = judgePkg(`pip install made-up-x`, nil, bal(), &asked)
	if !strings.Contains(r.Summary, "PyPI has no package named made-up-x") {
		t.Errorf("unknown_package summary: %q", r.Summary)
	}
}

func TestDependencyGateProfiles(t *testing.T) {
	var asked []string
	if r := judgePkg(`npm i fresh-pkg`, nil, config.Config{Profile: "strict"}, &asked); r.Decision != Deny {
		t.Errorf("strict new_package: %q", r.Decision)
	}
	if r := judgePkg(`npm i made-up-x`, nil, config.Config{}, &asked); r.Decision != None || r.Would != Deny {
		t.Errorf("audit unknown_package: decision %q would %q", r.Decision, r.Would)
	}
	// Off: no lookup at all.
	a := shell.Analyze(`npm i made-up-x`, shell.Bash)
	if r := Evaluate(Input{Tool: "Bash", Sinks: a.Sinks, Config: bal()}); r.Rule != "" {
		t.Errorf("gate off: %q", r.Rule)
	}
}

// In a tainted session the deny for a made-up name beats rule 4's ask.
func TestDependencyGateTainted(t *testing.T) {
	s := &store.Session{}
	s.MarkTainted(store.Source{Tool: "WebFetch", Reason: "web"})
	var asked []string
	if r := judgePkg(`npm i made-up-x`, s, bal(), &asked); r.Rule != "unknown_package" || r.Decision != Deny {
		t.Errorf("tainted made-up: %q %q", r.Rule, r.Decision)
	}
	if r := judgePkg(`npm i old-pkg`, s, bal(), &asked); r.Rule != "tainted_exec_remote" {
		t.Errorf("tainted old: %q", r.Rule)
	}
}
