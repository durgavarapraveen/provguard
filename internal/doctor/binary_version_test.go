package doctor

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// Nothing told the user that the binary the hooks run is older than the one
// they just built, so a fixed build sat uninstalled while the old one kept
// crashing.
func TestCompareVersions(t *testing.T) {
	same := compareVersions("0.5.1", "0.5.1")
	if len(same) != 1 || same[0].Severity != Info {
		t.Fatalf("same version: %+v, want one INFO", same)
	}
	drift := compareVersions("dev", "0.5.1")
	if len(drift) != 1 || drift[0].Severity != Medium {
		t.Fatalf("drift: %+v, want one MEDIUM", drift)
	}
	for _, want := range []string{"0.5.1", "dev", "provguard init --yes"} {
		if !strings.Contains(drift[0].Message, want) {
			t.Errorf("drift message lacks %q: %q", want, drift[0].Message)
		}
	}
}

func TestVersionRe(t *testing.T) {
	for out, want := range map[string]string{
		"provguard 0.5.1\n":             "0.5.1",
		"provguard dev\n":               "dev",
		"provguard 0.6.0-rc1\r\n":       "0.6.0-rc1",
		"provguard 0.5.1\nextra line\n": "0.5.1",
		"go version go1.26.0 windows":   "",
		"":                              "",
		"not provguard 1.2.3":           "",
		"PROVGUARD 1.2.3":               "", // the binary prints lower case
	} {
		got := ""
		if m := versionRe.FindStringSubmatch(out); m != nil {
			got = m[1]
		}
		if got != want {
			t.Errorf("%q: got %q, want %q", out, got, want)
		}
	}
}

func TestBinaryVersionErrors(t *testing.T) {
	if _, err := binaryVersion(filepath.Join(t.TempDir(), "nope.exe")); err == nil {
		t.Error("a missing binary must fail")
	}
}

// The check is skipped unless it has both a version to compare and a
// settings file to read, and it says nothing that HookIntegrity reports.
func TestHookBinaryVersionGuards(t *testing.T) {
	dir := t.TempDir()
	settings := filepath.Join(dir, "settings.json")
	write := func(v any) {
		b, _ := json.Marshal(v)
		if err := os.WriteFile(settings, b, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	write(map[string]any{"hooks": map[string]any{"PreToolUse": []any{
		map[string]any{"hooks": []any{map[string]any{"command": `"C:/u/.provguard/bin/provguard.exe" hook PreToolUse`}}},
	}}})

	if f := HookBinaryVersion(Options{UserSettings: settings}); f != nil {
		t.Errorf("no version to compare: %+v", f)
	}
	if f := HookBinaryVersion(Options{Version: "dev"}); f != nil {
		t.Errorf("no settings file: %+v", f)
	}
	if f := HookBinaryVersion(Options{Version: "dev", UserSettings: filepath.Join(dir, "missing.json")}); f != nil {
		t.Errorf("unreadable settings: %+v", f)
	}
	// A settings file with no provguard hook: HookIntegrity reports that.
	write(map[string]any{"hooks": map[string]any{}})
	if f := HookBinaryVersion(Options{Version: "dev", UserSettings: settings}); f != nil {
		t.Errorf("no provguard hook: %+v", f)
	}
}
