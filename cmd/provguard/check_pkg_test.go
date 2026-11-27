package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/registry"
)

// #42: check runs the same package check as the hook.
func TestCheckRunsPackageCheck(t *testing.T) {
	defer startBenchRegistry()()
	home := t.TempDir()
	t.Setenv("PROVGUARD_HOME", home)
	if err := writeConfig(home, "balanced", map[string]any{"package_check": true}); err != nil {
		t.Fatal(err)
	}
	run := func(cmd string) (int, checkResult) {
		var out bytes.Buffer
		code := runCheck([]string{"--json", "--shell", "bash", "--cwd", t.TempDir(), cmd}, &out, io.Discard)
		var r checkResult
		if err := json.Unmarshal(out.Bytes(), &r); err != nil {
			t.Fatalf("%s: %v\n%s", cmd, err, out.String())
		}
		return code, r
	}
	if code, r := run("npm install react-codeshift-helpers"); code != 1 || r.Decision != "deny" || r.Rule != "unknown_package" {
		t.Errorf("made-up package: exit %d %+v", code, r)
	}
	if code, r := run("npm install lodahs"); code != 1 || r.Decision != "ask" || r.Rule != "lookalike_package" {
		t.Errorf("lookalike: exit %d %+v", code, r)
	}
	if code, r := run("npm install left-pad"); code != 0 || r.Decision != "allow" {
		t.Errorf("known package: exit %d %+v", code, r)
	}

	// The registry does not answer: allowed, with a note that says so.
	dead := httptest.NewServer(nil)
	dead.Close()
	old := registryBase
	registryBase = map[registry.Eco]string{registry.NPM: dead.URL, registry.NPMDownloads: dead.URL}
	defer func() { registryBase = old }()
	var out bytes.Buffer
	code := runCheck([]string{"--shell", "bash", "--cwd", t.TempDir(), "npm install never-cached-pkg"}, &out, io.Discard)
	if code != 0 || !strings.Contains(out.String(), "Note:    package lookup failed") {
		t.Errorf("registry down: exit %d\n%s", code, out.String())
	}
}

// With package_check off (the default), check makes no lookup.
func TestCheckPackageCheckOff(t *testing.T) {
	code, out := checkRun(t, "--shell", "bash", "--profile", "balanced", "npm install react-codeshift-helpers")
	if code != 0 || strings.Contains(out, "unknown_package") || strings.Contains(out, "Note:") {
		t.Errorf("exit %d\n%s", code, out)
	}
}
