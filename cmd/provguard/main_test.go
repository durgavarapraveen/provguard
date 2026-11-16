package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/audit"
)

func readLog(t *testing.T, home string) []audit.Record {
	t.Helper()
	files, _ := filepath.Glob(filepath.Join(home, "audit", "*.jsonl"))
	var out []audit.Record
	for _, f := range files {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		sc := bufio.NewScanner(bytes.NewReader(b))
		for sc.Scan() {
			var r audit.Record
			if err := json.Unmarshal(sc.Bytes(), &r); err != nil {
				t.Fatalf("bad log line %q: %v", sc.Text(), err)
			}
			out = append(out, r)
		}
	}
	return out
}

func TestHookFixturesLogOnlyAndRedact(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROVGUARD_HOME", home)

	fixtures, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "claudecode", "*.json"))
	if len(fixtures) == 0 {
		t.Fatal("no fixtures")
	}
	for _, f := range fixtures {
		in, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		var stdout bytes.Buffer
		if code := runHook(bytes.NewReader(in), &stdout, ""); code != 0 {
			t.Fatalf("%s: exit %d", f, code)
		}
		if stdout.Len() != 0 {
			t.Fatalf("%s: log-only mode must not print a decision, got %q", f, stdout.String())
		}
	}

	recs := readLog(t, home)
	if len(recs) != len(fixtures) {
		t.Fatalf("want %d log lines, got %d", len(fixtures), len(recs))
	}
	raw, _ := os.ReadFile(filepath.Join(home, "audit", recs[0].Time.UTC().Format("2006-01-02")+".jsonl"))
	if strings.Contains(string(raw), "sup3rS3cret") {
		t.Fatal("secret from tool_response reached the audit log")
	}
	for _, r := range recs {
		if r.Error != "" || r.SessionID == "" {
			t.Fatalf("bad record: %+v", r)
		}
		if r.Event == "PostToolUse" && (r.OutputBytes == 0 || r.OutputSHA256 == "") {
			t.Fatalf("post record lacks output hash: %+v", r)
		}
	}
}

func TestNoRawSecretAnywhereAndSessionLabeled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROVGUARD_HOME", home)
	in, err := os.ReadFile(filepath.Join("..", "..", "testdata", "claudecode", "post_read.json"))
	if err != nil {
		t.Fatal(err)
	}
	if code := runHook(bytes.NewReader(in), &bytes.Buffer{}, ""); code != 0 {
		t.Fatal("exit", code)
	}
	var sess map[string]any
	b, err := os.ReadFile(filepath.Join(home, "sessions", "abc123.json"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(b, &sess); err != nil {
		t.Fatal(err)
	}
	if sess["sensitive"] != true || sess["fingerprints"] == nil {
		t.Fatalf("session not marked sensitive with fingerprints: %s", b)
	}
	_ = filepath.Walk(home, func(p string, info os.FileInfo, err error) error {
		if err == nil && !info.IsDir() {
			if c, _ := os.ReadFile(p); strings.Contains(string(c), "sup3rS3cret") {
				t.Errorf("raw secret written to %s", p)
			}
		}
		return nil
	})
}

func TestHookDeniesSettingsTampering(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROVGUARD_HOME", home)
	settings := filepath.Join(t.TempDir(), ".claude", "settings.json")
	payload, _ := json.Marshal(map[string]any{
		"session_id": "s1", "hook_event_name": "PreToolUse", "tool_name": "Write", "tool_use_id": "t1",
		"tool_input": map[string]any{"file_path": settings, "content": `{"disableAllHooks": true}`},
	})
	var stdout bytes.Buffer
	if code := runHook(bytes.NewReader(payload), &stdout, ""); code != 0 {
		t.Fatal("exit", code)
	}
	var out struct {
		H struct {
			Decision string `json:"permissionDecision"`
			Reason   string `json:"permissionDecisionReason"`
		} `json:"hookSpecificOutput"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &out); err != nil || out.H.Decision != "deny" || out.H.Reason == "" {
		t.Fatalf("expected deny, got %q (%v)", stdout.String(), err)
	}
	recs := readLog(t, home)
	if len(recs) != 1 || recs[0].Decision != "deny" || recs[0].Rule != "self_protect_settings" {
		t.Fatalf("deny not logged: %+v", recs)
	}

	// self_protect=false turns it off.
	os.WriteFile(filepath.Join(home, "config.json"), []byte(`{"self_protect": false}`), 0o600)
	stdout.Reset()
	runHook(bytes.NewReader(payload), &stdout, "")
	if stdout.Len() != 0 {
		t.Fatal("self_protect=false still denied")
	}
}

func TestHookFailsOpenOnBadInput(t *testing.T) {
	home := t.TempDir()
	t.Setenv("PROVGUARD_HOME", home)
	var stdout bytes.Buffer
	if code := runHook(strings.NewReader("{not json"), &stdout, "PreToolUse"); code != 0 {
		t.Fatalf("exit %d, want 0", code)
	}
	if stdout.Len() != 0 {
		t.Fatal("printed output on bad input")
	}
	recs := readLog(t, home)
	if len(recs) != 1 || recs[0].Error == "" || recs[0].Event != "PreToolUse" {
		t.Fatalf("error not logged: %+v", recs)
	}
}
