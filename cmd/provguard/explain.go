package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/durgavarapraveen/provguard/internal/redact"
	"io"
	"os"
	"path/filepath"
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
	// Flags may also follow the session id (reset latest --source 2 --yes).
	arg := fs.Arg(0)
	if fs.NArg() > 1 {
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	id, err := resolveSession(home, arg)
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
			fmt.Fprintf(w, "      cmd:   %s\n", redact.OneLine(cmd, 120))
		}
	}
	return 0
}

// policyHits reads the audit logs of the last 7 days for decisions in a session.
func policyHits(home, id string) []audit.Record {
	recs, _ := audit.Read(home, time.Now().AddDate(0, 0, -7), func(r *audit.Record) bool {
		return r.SessionID == id && (r.Would != "" || r.Decision == "deny" || r.Decision == "ask")
	})
	return recs
}

func runReset(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("reset", flag.ContinueOnError)
	yes := fs.Bool("yes", false, "clear the untrusted label (without it, only show what would change)")
	source := fs.Int("source", 0, "clear only this untrusted source (its number in the list); the label stays while other sources remain")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	// Flags may also follow the session id (reset latest --source 2 --yes).
	arg := fs.Arg(0)
	if fs.NArg() > 1 {
		if err := fs.Parse(fs.Args()[1:]); err != nil {
			return 2
		}
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	id, err := resolveSession(home, arg)
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
	for i, src := range s.TaintSources {
		fmt.Fprintf(w, "  %d. %s  %s: %s\n", i+1, src.At.Local().Format("2006-01-02 15:04"), src.Tool, src.Reason)
	}
	fmt.Fprintln(w, "Reset clears the untrusted label only. Secret fingerprints stay, so secrets are still protected.")
	if *source < 0 || *source > len(s.TaintSources) {
		if len(s.TaintSources) == 0 {
			fmt.Fprintln(os.Stderr, "error: this session has no untrusted sources to clear")
		} else {
			fmt.Fprintf(os.Stderr, "error: --source must be a number from the list (1 to %d)\n", len(s.TaintSources))
		}
		return 2
	}
	if *source > 0 {
		fmt.Fprintf(w, "--source %d clears only that source. The label stays while other sources remain.\n", *source)
	}
	if !*yes {
		fmt.Fprintln(w, "No change written. Run again with --yes to apply.")
		return 0
	}
	var cleared bool
	err = store.Update(home, id, func(s *store.Session) error {
		now := time.Now().UTC()
		if *source > 0 {
			cleared = s.ClearTaintSource(*source - 1)
			s.AddStep(store.Step{At: now, Event: "Reset", Labels: []string{fmt.Sprintf("untrusted_source_cleared_by_user:%d", *source)}})
			return nil
		}
		s.ClearTaint()
		cleared = true
		s.AddStep(store.Step{At: now, Event: "Reset", Labels: []string{"untrusted_cleared_by_user"}})
		return nil
	})
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	_ = audit.Write(home, audit.Record{Time: time.Now(), Agent: "user", Event: "Reset", SessionID: id, Decision: "none"})
	switch {
	case cleared:
		fmt.Fprintln(w, "Untrusted label cleared.")
	case *source > 0:
		fmt.Fprintln(w, "Source cleared. The session stays untrusted: other sources remain, or older sources were dropped from the list. Run provguard reset --yes to clear all.")
	}
	return 0
}

// runDoctor checks hook integrity and scans a repo before you open it.
// stalePathFinding explains the commonest reason the provguard command is
// "not recognized": the folder is on the saved PATH, but this terminal
// started before it was added, so it is missing from this process. Found
// live, more than once.
func stalePathFinding(bin string) []doctor.Finding {
	if !userPath.has(bin) || processPathHas(bin) {
		return nil
	}
	return []doctor.Finding{{Severity: doctor.Info, Area: "path",
		Message: bin + " is on your saved PATH but not in this terminal's: a terminal keeps the PATH it started with " +
			"(a terminal inside an editor keeps the editor's). Open a new one to use the provguard command."}}
}

func runDoctor(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("doctor", flag.ContinueOnError)
	asJSON := fs.Bool("json", false, "print findings as JSON")
	live := fs.Bool("live", false, "send a test call through each installed agent's hook")
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
	if *live {
		return runDoctorLive(w, settings, home)
	}
	f := doctor.Run(doctor.Options{Home: home, UserSettings: settings, Repo: repo,
		Events: claudecode.Events, Version: version})
	f = append(f, stalePathFinding(filepath.Join(home, "bin"))...)
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
