package main

import (
	"bufio"
	"context"
	"fmt"
	"io"
	"os/exec"
	"slices"
	"strconv"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/config"
)

// guide asks the setup questions. At end of input every question takes its
// default, so a closed stdin never loops.
type guide struct {
	r *bufio.Reader
	w io.Writer
}

func newGuide(in io.Reader, out io.Writer) guide { return guide{bufio.NewReader(in), out} }

// line prints the question and returns the trimmed answer, or def when the
// answer is empty or input has ended.
func (g guide) line(q, def string) string {
	if def != "" {
		fmt.Fprintf(g.w, "%s [%s]: ", q, def)
	} else {
		fmt.Fprintf(g.w, "%s: ", q)
	}
	s, err := g.r.ReadString('\n')
	s = strings.TrimSpace(s)
	if err != nil && s == "" {
		fmt.Fprintln(g.w)
		return def
	}
	if s == "" {
		return def
	}
	return s
}

func (g guide) confirm(q string, def bool) bool {
	hint := map[bool]string{true: "Y/n", false: "y/N"}[def]
	for range 3 {
		switch strings.ToLower(g.line(q+" ("+hint+")", "")) {
		case "":
			return def
		case "y", "yes":
			return true
		case "n", "no":
			return false
		}
		fmt.Fprintln(g.w, "  Please answer y or n.")
	}
	return def
}

// askAgents asks which coding agents to protect. Claude Code is option 1
// (Cursor and Devin run its hooks); the others follow in otherAgents order.
// The default, "all", is Claude Code plus every agent found on this computer.
func askAgents(g guide, agents []otherAgent) (claude bool, chosen []otherAgent) {
	found := func(ok bool) string {
		if ok {
			return "  (found)"
		}
		return ""
	}
	fmt.Fprintln(g.w, "Which coding agents should provguard protect?")
	fmt.Fprintln(g.w, "  all) Claude Code and every agent found below")
	fmt.Fprintf(g.w, "  1) Claude Code (also Cursor and Devin)%s\n", found(true))
	for i, a := range agents {
		fmt.Fprintf(g.w, "  %d) %s%s\n", i+2, a.name, found(a.present()))
	}
	for range 3 {
		ans := strings.ToLower(g.line("Type all, or numbers separated by commas", "all"))
		if ans == "all" {
			for _, a := range agents {
				if a.present() {
					chosen = append(chosen, a)
				}
			}
			return true, chosen
		}
		claude, chosen = false, nil
		ok := true
		for _, f := range strings.FieldsFunc(ans, func(r rune) bool { return r == ',' || r == ' ' }) {
			n, err := strconv.Atoi(f)
			switch {
			case err != nil || n < 1 || n > len(agents)+1:
				ok = false
			case n == 1:
				claude = true
			case !slices.ContainsFunc(chosen, func(a otherAgent) bool { return a.name == agents[n-2].name }):
				chosen = append(chosen, agents[n-2])
			}
		}
		if ok && (claude || len(chosen) > 0) {
			return claude, chosen
		}
		fmt.Fprintf(g.w, "  Please type all, or numbers from 1 to %d (for example 1,3).\n", len(agents)+1)
	}
	return false, nil
}

// choose shows numbered options and returns the index picked (0-based).
func (g guide) choose(q string, options []string, def int) int {
	fmt.Fprintln(g.w, q)
	for i, o := range options {
		fmt.Fprintf(g.w, "  %d) %s\n", i+1, o)
	}
	for range 3 {
		a := g.line("Choose", strconv.Itoa(def+1))
		if n, err := strconv.Atoi(a); err == nil && n >= 1 && n <= len(options) {
			return n - 1
		}
		fmt.Fprintf(g.w, "  Please type a number from 1 to %d.\n", len(options))
	}
	return def
}

// setupChoice is what the guided setup writes to config.json.
type setupChoice struct {
	owners    []string // added to trusted_repo_owners
	profile   string
	blockMode string // "ask" or "deny"; "" leaves it unchanged
}

func (c setupChoice) apply(cfg *config.Config) error {
	for _, o := range c.owners {
		config.AddTo(&cfg.TrustedRepoOwners, o)
	}
	if err := cfg.SetProfile(c.profile); err != nil {
		return err
	}
	if c.blockMode != "" {
		return cfg.SetBlockMode(c.blockMode)
	}
	return nil
}

var modes = []struct{ profile, text string }{
	{config.Balanced, "Protect: stop leaks, ask before risky steps (recommended)"},
	{config.Audit, "Watch only: log what it would stop, block nothing"},
	{config.Strict, "Lockdown: stop every risky step"},
}

// askSetup asks at most three questions. Settings the user already has are
// offered as the defaults, so running init again changes nothing by accident.
func askSetup(g guide, cur config.Config, detectUser func() string) setupChoice {
	var c setupChoice
	fmt.Fprintln(g.w, "provguard setup: 3 short questions. Press Enter to take the default.")
	fmt.Fprintln(g.w)

	if len(cur.TrustedRepoOwners) > 0 {
		fmt.Fprintf(g.w, "1. Repos owned by %s count as yours (change later: provguard config trust-owner).\n\n", strings.Join(cur.TrustedRepoOwners, ", "))
	} else {
		fmt.Fprintln(g.w, "1. Which GitHub users or organizations own the repos you trust?")
		fmt.Fprintln(g.w, "   Files in other people's repos mark a session untrusted. Separate names with commas.")
		c.owners = askOwners(g, detectUser())
		fmt.Fprintln(g.w)
	}

	def := 0
	if strings.TrimSpace(cur.Profile) != "" {
		for i, m := range modes {
			if m.profile == cur.ProfileName() {
				def = i
			}
		}
	}
	texts := make([]string, len(modes))
	for i, m := range modes {
		texts[i] = m.text
	}
	c.profile = modes[g.choose("2. How much should provguard do?", texts, def)].profile
	fmt.Fprintln(g.w)

	if c.profile == config.Balanced {
		askDef := 0 // new users: ask, so nothing is blocked without a choice
		if strings.TrimSpace(cur.Profile) != "" && !cur.BlockAsks() {
			askDef = 1
		}
		pick := g.choose("3. When provguard stops a possible leak of your secrets:",
			[]string{"Ask me each time (recommended)", "Block it"}, askDef)
		c.blockMode = []string{"ask", "deny"}[pick]
	} else {
		fmt.Fprintln(g.w, "3. (Only for Protect mode; skipped.)")
	}
	return c
}

func askOwners(g guide, detected string) []string {
	for range 3 {
		a := g.line("   Owners", detected)
		if a == "" || strings.EqualFold(a, "none") || a == "-" {
			return nil
		}
		var out []string
		bad := ""
		for _, f := range strings.FieldsFunc(a, func(r rune) bool { return r == ',' || r == ' ' }) {
			o, err := config.NormalizeOwner(f)
			if err != nil {
				bad = f
				break
			}
			out = append(out, o)
		}
		if bad == "" {
			return out
		}
		fmt.Fprintf(g.w, "   %q is not a GitHub name. Type names like my-user, my-org, or none.\n", bad)
	}
	return nil
}

// detectGitHubUser asks the GitHub CLI, then git config, for the user's
// GitHub name. Any failure means "unknown"; the user can type it.
func detectGitHubUser() string {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	for _, args := range [][]string{
		{"gh", "api", "user", "--jq", ".login"},
		{"git", "config", "--global", "github.user"},
	} {
		out, err := exec.CommandContext(ctx, args[0], args[1:]...).Output()
		if err != nil {
			continue
		}
		if o, err := config.NormalizeOwner(strings.TrimSpace(string(out))); err == nil {
			return o
		}
	}
	return ""
}
