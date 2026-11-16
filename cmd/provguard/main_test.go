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
