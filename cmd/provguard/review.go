package main

import (
	"flag"
	"fmt"
	"github.com/durgavarapraveen/provguard/internal/redact"
	"io"
	"os"
	"sort"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
)

// ruleTitle names each rule in plain words for review.
func ruleTitle(rule string) string {
	switch {
	case rule == "secret_in_sink":
		return "a secret inside the call"
	case rule == "secret_in_push":
		return "a secret in the commits to push"
	case rule == "lethal_trifecta":
		return "data could leave after untrusted content and secrets"
	case rule == "untrusted_destination":
		return "data sent to an address from untrusted content"
	case strings.HasPrefix(rule, "tainted_"):
		return "a risky step after untrusted content"
	case rule == "remote_shell":
		return "a reverse shell"
	case rule == "destroy":
		return "deleting data or history"
	case strings.HasPrefix(rule, "self_protect"):
		return "an attempt to change provguard or hook settings"
	case rule == "fail_closed":
		return "a call the check could not run on"
	}
	return rule
}

// reviewGroup is one rule's hits.
type reviewGroup struct {
	rule     string
	deny     int
	ask      int
	examples []audit.Record
}

// review is the summary of a period of audit logs.
type review struct {
	days     int
	sessions int
	stopped  int // deny
	asked    int
	allowed  int // let through with provguard allow
	groups   []*reviewGroup

	// Sessions by trust state at the end of the period.
	untrusted, sensitive, both int
}

func buildReview(recs []audit.Record, days int) review {
	rv := review{days: days}
	sessions := map[string]bool{}
	type state struct{ tainted, sensitive bool }
	states := map[string]state{} // labels only grow, except after provguard reset
	by := map[string]*reviewGroup{}
	for i := range recs {
		r := &recs[i]
		if r.SessionID != "" {
			sessions[r.SessionID] = true
			st := states[r.SessionID]
			states[r.SessionID] = state{st.tainted || r.SessionTainted, st.sensitive || r.SessionSensitive}
		}
		if r.Override != "" {
			rv.allowed++
			continue
		}
		if !r.Stopped() {
			continue
		}
		g := by[r.Rule]
		if g == nil {
			g = &reviewGroup{rule: r.Rule}
			by[r.Rule] = g
			rv.groups = append(rv.groups, g)
		}
		if r.Outcome() == "deny" {
			g.deny++
			rv.stopped++
		} else {
			g.ask++
			rv.asked++
		}
		if len(g.examples) < 3 {
			g.examples = append(g.examples, *r)
		}
	}
	rv.sessions = len(sessions)
	for _, st := range states {
		switch {
		case st.tainted && st.sensitive:
			rv.both++
		case st.tainted:
			rv.untrusted++
		case st.sensitive:
			rv.sensitive++
		}
	}
	sort.SliceStable(rv.groups, func(i, j int) bool {
		a, b := rv.groups[i], rv.groups[j]
		return a.deny+a.ask > b.deny+b.ask
	})
	return rv
}

func runReview(args []string, w io.Writer) int {
	fs := flag.NewFlagSet("review", flag.ContinueOnError)
	days := fs.Int("days", 7, "how many days of logs to read")
	if err := fs.Parse(args); err != nil || *days < 1 {
		return 2
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	recs, err := audit.Read(home, time.Now().AddDate(0, 0, -*days+1), nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		return 1
	}
	cfg, cfgErr := config.Load(home)
	profile := cfg.ProfileName()
	if cfgErr != nil {
		profile = config.Balanced
	}
	printReview(w, buildReview(recs, *days), profile)
	return 0
}

func printReview(w io.Writer, rv review, profile string) {
	verb := map[bool][2]string{true: {"would have stopped", "would have asked about"}, false: {"stopped", "asked you about"}}[profile == config.Audit]
	fmt.Fprintf(w, "provguard review: last %d days. Mode: %s (%s).\n\n", rv.days, profile, config.Describe(profile))
	if rv.sessions == 0 {
		fmt.Fprintln(w, "No sessions logged yet. Use your coding agent as usual, then run this again.")
		return
	}
	fmt.Fprintf(w, "In %s, provguard %s %s and %s %d.\n", plural(rv.sessions, "session"), verb[0], plural(rv.stopped, "call"), verb[1], rv.asked)
	if rv.allowed > 0 {
		fmt.Fprintf(w, "You let %s through with provguard allow.\n", plural(rv.allowed, "blocked call"))
	}
	if rv.untrusted+rv.sensitive+rv.both > 0 {
		// The Claude desktop app and most agents do not show provguard's
		// notice when a session's state changes, so the reason is here.
		fmt.Fprintf(w, "Session states: %d 🟡 untrusted, %d 🟠 sensitive, %d 🔴 both.\n", rv.untrusted, rv.sensitive, rv.both)
		fmt.Fprintln(w, "Many agents do not show provguard's notice when a state changes. To see why: provguard explain latest")
	}
	for _, g := range rv.groups {
		fmt.Fprintf(w, "\n  %s (%s): %d stopped, %d asked\n", ruleTitle(g.rule), g.rule, g.deny, g.ask)
		for _, e := range g.examples {
			fmt.Fprintf(w, "    %s  %-8s %s\n", e.Time.Local().Format("Jan 02 15:04"), e.ToolName, redact.OneLine(callText(e.ToolInput), 90))
		}
	}
	fmt.Fprintln(w)
	fmt.Fprintln(w, reviewAdvice(rv, profile))
}

// reviewAdvice is the one next step for the user.
func reviewAdvice(rv review, profile string) string {
	fix := "If a hit is a false alarm, trust its source: provguard config trust-owner NAME | trust-site HOST | allow-host HOST."
	switch {
	case profile == config.Audit && rv.stopped+rv.asked == 0:
		return "Next step: nothing risky was seen. Turn protection on:\n  provguard config mode balanced"
	case profile == config.Audit:
		return "Next step: check the examples above. If they look like real risks, turn protection on:\n" +
			"  provguard config mode balanced\n  provguard config on-block ask   (be asked instead of blocked)\n" + fix
	case rv.stopped+rv.asked == 0:
		return "Nothing was stopped. provguard is on and quiet."
	}
	return fix + "\nDetails of one session: provguard explain latest"
}
