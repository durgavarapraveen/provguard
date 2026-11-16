package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/durgavarapraveen/provguard/bench"
	"github.com/durgavarapraveen/provguard/internal/policy"
	"github.com/durgavarapraveen/provguard/internal/store"
)

// runDemo plays one normal task and two attacks through the real hook, in a
// throwaway provguard home with the balanced profile, and narrates each step.
// It touches nothing outside a temp folder.
func runDemo(w io.Writer) int {
	attacks, err := bench.Load()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	benign, err := bench.LoadBenign()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	pick := func(cs []bench.Case, id string) bench.Case {
		for _, c := range cs {
			if c.ID == id {
				return c
			}
		}
		return bench.Case{}
	}
	fmt.Fprintln(w, "provguard demo — profile: balanced, everything runs in a temp folder")
	fmt.Fprintln(w, "Each line is one hook call that a coding agent would make.")
	for _, c := range []bench.Case{pick(benign, "b01"), pick(attacks, "01"), pick(attacks, "11")} {
		if c.ID == "" {
			continue
		}
		if err := demoCase(w, c); err != nil {
			fmt.Fprintln(os.Stderr, "error:", err)
			return 1
		}
	}
	fmt.Fprintf(w, "\nRun `provguard bench` for all %d attacks and %d normal tasks.\n", len(attacks), len(benign))
	return 0
}

func demoCase(w io.Writer, c bench.Case) error {
	home, err := os.MkdirTemp("", "pgdemo-")
	if err != nil {
		return err
	}
	defer os.RemoveAll(home)
	restore := setEnv("PROVGUARD_HOME", home)
	defer restore()
	if err := writeConfig(home, "balanced", c.Config); err != nil {
		return err
	}
	v := bench.Vars{Canary: canaryFor(c), Attacker: "http://attacker.test", AttackerHost: "attacker.test", Repo: "/work/repo"}
	if c.Origin != "" {
		repo, err := makeRepo(c.Origin)
		if err != nil {
			return err
		}
		defer os.RemoveAll(repo)
		v.Repo = filepath.ToSlash(repo)
	}

	kind := "ATTACK"
	if strings.HasPrefix(c.ID, "b") {
		kind = "NORMAL WORK"
	}
	fmt.Fprintf(w, "\n== %s: %s ==\n", kind, c.Name)
	if c.Description != "" {
		fmt.Fprintf(w, "   %s\n", oneLine(c.Description, 110))
	}
	for i, s := range c.Steps {
		payload := map[string]any{"session_id": "demo-" + c.ID, "hook_event_name": s.Event, "tool_use_id": fmt.Sprintf("t%02d", i), "cwd": v.Repo}
		if s.Tool != "" {
			payload["tool_name"], payload["tool_input"] = s.Tool, v.ExpandAny(s.Input)
		}
		if s.Response != nil {
			payload["tool_response"] = v.ExpandAny(s.Response)
		}
		if s.Prompt != "" {
			payload["prompt"] = v.Expand(s.Prompt)
		}
		b, _ := json.Marshal(payload)
		var out bytes.Buffer
		runHook(bytes.NewReader(b), &out, s.Event)
		rec, err := lastRecord(home)
		if err != nil {
			return err
		}
		// Show workspace paths as repo/… (the temp path contains the user name).
		call := oneLine(strings.ReplaceAll(callText(v.ExpandAny(s.Input)), v.Repo, "repo"), 60)
		switch s.Event {
		case "PostToolUse":
			result := "trusted"
			if len(rec.Labels) > 0 {
				var ls []string
				for _, l := range rec.Labels {
					kind, why, _ := strings.Cut(l, ":") // "untrusted:web_fetch"
					ls = append(ls, kind+" ("+policy.SourceText(store.Source{Reason: why})+")")
				}
				result = strings.Join(ls, ", ")
			}
			fmt.Fprintf(w, "   read   %-10s %-60s → %s\n", s.Tool, call, result)
		case "PreToolUse":
			d, msg := hookDecision(out.Bytes())
			outcome := map[string]string{"deny": "BLOCKED", "ask": "ASKS YOU"}[d]
			if outcome == "" {
				fmt.Fprintf(w, "   run    %-10s %-60s → allowed\n", s.Tool, call)
				continue
			}
			fmt.Fprintf(w, "   run    %-10s %-60s → %s\n", s.Tool, call, outcome)
			// What the user sees, minus the note addressed to the agent.
			for _, l := range strings.Split(msg, "\n") {
				if !strings.HasPrefix(l, "Agent:") {
					fmt.Fprintf(w, "          %s\n", oneLine(strings.ReplaceAll(l, v.Repo, "repo"), 200))
				}
			}
		}
	}
	return nil
}
