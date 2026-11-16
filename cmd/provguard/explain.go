package main

import (
	"bufio"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/doctor"
	"github.com/durgavarapraveen/provguard/internal/install"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// resolveSession turns "latest" (or "") into the most recently updated session id.
func resolveSession(home, id string) (string, error) {
	if id != "" && id != "latest" {
		return id, nil
	}
	files, _ := filepath.Glob(filepath.Join(home, "sessions", "*.json"))
	var best string
	var bestT time.Time
	for _, f := range files {
		if fi, err := os.Stat(f); err == nil && fi.ModTime().After(bestT) {
			best, bestT = f, fi.ModTime()
		}
	}
	if best == "" {
		return "", errors.New("no sessions recorded yet")
	}
	return strings.TrimSuffix(filepath.Base(best), ".json"), nil
}

func runExplain(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("explain", flag.ContinueOnError)
	all := fs.Bool("all", false, "list every policy hit, not only the last 20")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	id, err := resolveSession(home, fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	s, err := store.Get(home, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(w, "Session   %s\nUpdated   %s\n\n", s.ID, s.Updated.Local().Format(time.DateTime))
	fmt.Fprintf(w, "Untrusted %s\n", yesNo(s.Tainted))
	for _, src := range s.TaintSources {
		fmt.Fprintf(w, "  %s  %s: %s\n", src.At.Local().Format(time.TimeOnly), src.Tool, src.Reason)
	}
	fmt.Fprintf(w, "Sensitive %s\n", yesNo(s.Sensitive))
	for _, src := range s.SensitiveSources {
		fmt.Fprintf(w, "  %s  %s: %s\n", src.At.Local().Format(time.TimeOnly), src.Tool, src.Reason)
	}
	fmt.Fprintf(w, "Secrets fingerprinted: %d\n", len(s.Fingerprints))
	if n := len(s.UntrustedValues); n > 0 {
		show := s.UntrustedValues
		if n > 10 {
			show = show[n-10:]
		}
		fmt.Fprintf(w, "Untrusted URLs/hosts: %d (latest: %s)\n", n, strings.Join(show, ", "))
	}

	hits := policyHits(home, id)
	fmt.Fprintf(w, "\nPolicy hits: %d\n", len(hits))
	if !*all && len(hits) > 20 {
		hits = hits[len(hits)-20:]
	}
	for _, r := range hits {
		d := r.Decision
		if d == "none" {
			d = "would " + r.Would
		}
		fmt.Fprintf(w, "  %s  %-10s %-14s %s\n", r.Time.Local().Format(time.TimeOnly), r.ToolName, d, r.Rule)
		if len(r.Sinks) > 0 {
			fmt.Fprintf(w, "      sinks: %s\n", strings.Join(r.Sinks, ", "))
		}
		if cmd, ok := r.ToolInput["command"].(string); ok {
			fmt.Fprintf(w, "      cmd:   %s\n", oneLine(cmd, 120))
		}
	}
	return 0
}

// policyHits reads the audit logs of the last 7 days for decisions in a session.
func policyHits(home, id string) []audit.Record {
	files, _ := filepath.Glob(filepath.Join(home, "audit", "*.jsonl"))
	sort.Strings(files)
	if len(files) > 7 {
		files = files[len(files)-7:]
	}
	var out []audit.Record
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			continue
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 8<<20)
		for sc.Scan() {
			line := sc.Bytes()
			if !strings.Contains(string(line), id) {
				continue
			}
			var r audit.Record
			if json.Unmarshal(line, &r) != nil || r.SessionID != id {
				continue
			}
			if r.Would != "" || r.Decision == "deny" || r.Decision == "ask" {
				out = append(out, r)
			}
		}
		fh.Close()
	}
	return out
}

func runReset(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "clear the untrusted label (without it, only show what would change)")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	id, err := resolveSession(home, fs.Arg(0))
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	s, err := store.Get(home, id)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	fmt.Fprintf(w, "Session %s: untrusted=%s (%d sources, %d URLs/hosts)\n", id, yesNo(s.Tainted), len(s.TaintSources), len(s.UntrustedValues))
	fmt.Fprintln(w, "Reset clears the untrusted label only. Secret fingerprints stay, so secrets are still protected.")
	if !*yes {
		fmt.Fprintln(w, "No change written. Run again with --yes to apply.")
		return 0
	}
	err = store.Update(home, id, func(s *store.Session) error {
		s.Tainted = false
		s.TaintSources, s.UntrustedValues, s.TaintedAgents = nil, nil, nil
		s.AddStep(store.Step{At: time.Now().UTC(), Event: "Reset", Labels: []string{"untrusted_cleared_by_user"}})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	_ = audit.Write(home, audit.Record{Time: time.Now(), Agent: "user", Event: "Reset", SessionID: id, Decision: "none"})
	fmt.Fprintln(w, "Untrusted label cleared.")
	return 0
}

// runDoctor checks hook integrity and scans a repo before you open it.
func runDoctor(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print findings as JSON")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	repo := fs.Arg(0)
	if repo == "" {
		repo, _ = os.Getwd()
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	settings, err := install.DefaultSettingsPath()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	f := doctor.Run(doctor.Options{Home: home, UserSettings: settings, Repo: repo, Events: claudecode.Events})
	if *asJSON {
		b, _ := json.MarshalIndent(f, "", "  ")
		fmt.Fprintln(w, string(b))
	} else {
		fmt.Fprintf(w, "provguard doctor — %s\n\n", repo)
		for _, x := range f {
			fmt.Fprintf(w, "%-7s %-14s %s\n", x.Severity, x.Area, x.Message)
		}
		if !doctor.HasHigh(f) {
			fmt.Fprintln(w, "\nNo HIGH findings.")
		}
	}
	if doctor.HasHigh(f) {
		return 1
	}
	return 0
}

func yesNo(b bool) string {
	if b {
		return "YES"
	}
	return "no"
}

func oneLine(s string, max int) string {
	s = strings.Join(strings.Fields(s), " ")
	if len(s) > max {
		return s[:max] + "…"
	}
	return s
}
