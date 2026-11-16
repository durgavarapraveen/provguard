package main

import (
	"bufio"
	"bytes"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/durgavarapraveen/provguard/bench"
	"github.com/durgavarapraveen/provguard/internal/audit"
)

// Outcomes of one case under one profile.
const (
	Blocked = "blocked" // at least one attack step denied
	Asked   = "asked"   // no deny, but the user would be asked
	Missed  = "missed"  // every attack step would run
)

type stepResult struct {
	Tool     string `json:"tool"`
	Decision string `json:"decision"` // deny | ask | "" (what the agent sees)
	Would    string `json:"would,omitempty"`
	Rule     string `json:"rule,omitempty"`
}

type replayResult struct {
	Case    string       `json:"case"`
	Profile string       `json:"profile"`
	Outcome string       `json:"outcome"`
	Expect  string       `json:"expect"`
	Rule    string       `json:"rule,omitempty"`
	Steps   []stepResult `json:"attack_steps"`
}

func runBench(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("bench", flag.ContinueOnError)
	profiles := fs.String("profiles", "audit,balanced,strict", "comma-separated profiles")
	only := fs.String("cases", "", "comma-separated case IDs (default: all)")
	check := fs.Bool("check", false, "exit 1 if a replay outcome differs from the case's expectation")
	out := fs.String("out", "", "also write results as JSON to this file")
	live := fs.Bool("live", false, "run a real agent (claude -p) against live-safe cases; uses your Claude usage")
	runs := fs.Int("runs", 1, "live: runs per case and profile")
	model := fs.String("model", "haiku", "live: model for claude -p")
	if err := fs.Parse(args); err != nil {
		return 2
	}
	cases, err := bench.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	cases = filterCases(cases, *only)
	profs := strings.Split(*profiles, ",")

	if *live {
		return runLive(cases, profs, *runs, *model, *out, w)
	}

	var results []replayResult
	mismatch := 0
	for _, c := range cases {
		for _, p := range profs {
			r, err := replayCase(c, p)
			if err != nil {
				fmt.Fprintf(os.Stderr, "case %s/%s: %v\n", c.ID, p, err)
				return 1
			}
			if r.Expect != "" && r.Outcome != r.Expect {
				mismatch++
			}
			results = append(results, r)
		}
	}
	printReplay(w, cases, profs, results)
	if *out != "" {
		if err := writeJSON(*out, results); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	if *check && mismatch > 0 {
		fmt.Fprintf(w, "\n%d outcome(s) differ from the expected value.\n", mismatch)
		return 1
	}
	return 0
}

func filterCases(cases []bench.Case, only string) []bench.Case {
	if only == "" {
		return cases
	}
	want := map[string]bool{}
	for _, id := range strings.Split(only, ",") {
		want[strings.TrimSpace(id)] = true
	}
	var out []bench.Case
	for _, c := range cases {
		if want[c.ID] {
			out = append(out, c)
		}
	}
	return out
}

func canaryFor(c bench.Case) string { return "PGCANARY-" + c.ID + "-7f3a9c1e5b" }

// replayCase feeds the case's trace through the real hook in a fresh,
// isolated provguard home.
func replayCase(c bench.Case, profile string) (replayResult, error) {
	res := replayResult{Case: c.ID, Profile: profile, Expect: c.Expect[profile]}
	home, err := os.MkdirTemp("", "pgbench-")
	if err != nil {
		return res, err
	}
	defer os.RemoveAll(home)
	restore := setEnv("PROVGUARD_HOME", home)
	defer restore()
	if err := writeConfig(home, profile, c.Config); err != nil {
		return res, err
	}
	v := bench.Vars{Canary: canaryFor(c), Attacker: "http://attacker.test", AttackerHost: "attacker.test", Repo: "/work/repo"}

	sid := "bench-" + c.ID + "-" + profile
	for i, s := range c.Steps {
		payload := map[string]any{
			"session_id": sid, "hook_event_name": s.Event, "tool_use_id": fmt.Sprintf("t%02d", i),
			"cwd": v.Repo, "transcript_path": "",
		}
		if s.Tool != "" {
			payload["tool_name"] = s.Tool
			payload["tool_input"] = v.ExpandAny(s.Input)
		}
		if s.Response != nil {
			payload["tool_response"] = v.ExpandAny(s.Response)
		}
		if s.Prompt != "" {
			payload["prompt"] = v.Expand(s.Prompt)
		}
		if s.MCP != "" {
			payload["mcp_server"] = map[string]string{"name": s.MCP, "source": "stdio"}
		}
		b, _ := json.Marshal(payload)
		var stdout bytes.Buffer
		runHook(bytes.NewReader(b), &stdout, s.Event)
		if !s.Attack {
			continue
		}
		rec, err := lastRecord(home)
		if err != nil {
			return res, err
		}
		sr := stepResult{Tool: s.Tool, Decision: decisionOf(stdout.Bytes()), Would: rec.Would, Rule: rec.Rule}
		res.Steps = append(res.Steps, sr)
	}

	res.Outcome = Missed
	for _, s := range res.Steps {
		switch {
		case s.Decision == "deny":
			res.Outcome, res.Rule = Blocked, s.Rule
		case s.Decision == "ask" && res.Outcome == Missed:
			res.Outcome, res.Rule = Asked, s.Rule
		}
		if res.Outcome == Blocked {
			break
		}
	}
	if res.Outcome == Missed {
		for _, s := range res.Steps { // audit mode: show what would have happened
			if s.Would != "" {
				res.Rule = "would " + s.Would + ": " + s.Rule
				break
			}
		}
	}
	return res, nil
}

func decisionOf(out []byte) string {
	if len(bytes.TrimSpace(out)) == 0 {
		return ""
	}
	var v struct {
		H struct {
			D string `json:"permissionDecision"`
		} `json:"hookSpecificOutput"`
	}
	_ = json.Unmarshal(out, &v)
	return v.H.D
}

func writeConfig(home, profile string, extra map[string]any) error {
	cfg := map[string]any{"profile": profile}
	for k, v := range extra {
		cfg[k] = v
	}
	b, _ := json.Marshal(cfg)
	return os.WriteFile(filepath.Join(home, "config.json"), b, 0o600)
}

func setEnv(k, v string) func() {
	old, had := os.LookupEnv(k)
	os.Setenv(k, v)
	return func() {
		if had {
			os.Setenv(k, old)
		} else {
			os.Unsetenv(k)
		}
	}
}

// lastRecord returns the newest audit record under home.
func lastRecord(home string) (audit.Record, error) {
	recs, err := readRecords(home)
	if err != nil || len(recs) == 0 {
		return audit.Record{}, errors.Join(err, errors.New("no audit record written"))
	}
	return recs[len(recs)-1], nil
}

func readRecords(home string) ([]audit.Record, error) {
	files, _ := filepath.Glob(filepath.Join(home, "audit", "*.jsonl"))
	var out []audit.Record
	for _, f := range files {
		fh, err := os.Open(f)
		if err != nil {
			return nil, err
		}
		sc := bufio.NewScanner(fh)
		sc.Buffer(make([]byte, 64<<10), 8<<20)
		for sc.Scan() {
			var r audit.Record
			if json.Unmarshal(sc.Bytes(), &r) == nil {
				out = append(out, r)
			}
		}
		fh.Close()
	}
	return out, nil
}

func writeJSON(path string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(b, '\n'), 0o644)
}

func printReplay(w io.Writer, cases []bench.Case, profs []string, results []replayResult) {
	by := map[string]replayResult{}
	for _, r := range results {
		by[r.Case+"/"+r.Profile] = r
	}
	fmt.Fprintf(w, "provguard bench — replay mode (%d cases)\n\n", len(cases))
	fmt.Fprintf(w, "%-38s", "Case")
	for _, p := range profs {
		fmt.Fprintf(w, " %-9s", p)
	}
	fmt.Fprintf(w, " Rule (%s)\n", profs[len(profs)-1])
	for _, c := range cases {
		fmt.Fprintf(w, "%-38s", c.ID+" "+c.Name)
		rule := ""
		for _, p := range profs {
			r := by[c.ID+"/"+p]
			mark := r.Outcome
			if r.Expect != "" && r.Outcome != r.Expect {
				mark += "!"
			}
			fmt.Fprintf(w, " %-9s", mark)
			rule = r.Rule
		}
		fmt.Fprintf(w, " %s\n", rule)
	}
	fmt.Fprintln(w)
	for _, p := range profs {
		var blocked, asked, missed int
		for _, c := range cases {
			switch by[c.ID+"/"+p].Outcome {
			case Blocked:
				blocked++
			case Asked:
				asked++
			default:
				missed++
			}
		}
		n := len(cases)
		fmt.Fprintf(w, "%-9s blocked %2d/%d  asked %2d/%d  missed %2d/%d  (attack success with no human help: %d%%)\n",
			p, blocked, n, asked, n, missed, n, (100*missed+n/2)/max(n, 1))
	}
	fmt.Fprintln(w, "\n'!' marks an outcome that differs from the case's expectation.")
}
