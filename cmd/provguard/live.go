package main

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/adapter"
	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/adapter/cursor"
	"github.com/durgavarapraveen/provguard/internal/adapter/devin"
	"github.com/durgavarapraveen/provguard/internal/install"
	"github.com/durgavarapraveen/provguard/internal/redact"
)

// liveTarget is one agent whose installed hook doctor --live tests.
type liveTarget struct {
	name     string // shown to the user
	agent    string // adapter name
	agentArg string // the hook's --agent value; "" for the Claude Code hooks
	file     string // where the hook is configured
	bin      string // the provguard binary the hook runs
	err      string // why the hook cannot be tested, if it cannot
	after    string
}

// liveReason marks the reason in an adapter's expected deny reply.
const liveReason = "provguard-live-reason"

// runDoctorLive sends a test call through each installed agent's hook: a
// write to a file in a provguard data folder, which self-protection blocks
// in every mode. It runs the hook binary the way the agent does, with the
// agent's own payload, and checks that the answer is a block in that
// agent's reply format. The calls use a temporary provguard home, so they
// leave nothing in the audit log or the session store.
func runDoctorLive(w io.Writer, settings, home string) int {
	tmp, err := os.MkdirTemp("", "provguard-live-")
	if err != nil {
		fmt.Fprintln(w, "provguard:", err)
		return 1
	}
	defer os.RemoveAll(tmp)
	probe := filepath.Join(tmp, "doctor-live-probe")

	fmt.Fprintln(w, "provguard doctor --live: sends a test write to a protected file through each agent's hook.")
	fmt.Fprintln(w)
	targets := liveTargets(settings, home)
	width := 0
	for _, t := range targets {
		width = max(width, len([]rune(t.name)))
	}
	failed := false
	for _, t := range targets {
		if t.err != "" {
			if t.err != "-" {
				fmt.Fprintf(w, "✘ %-*s  %s\n", width, t.name, t.err)
				failed = true
			}
			continue
		}
		if why := runProbe(t, probe, tmp); why != "" {
			fmt.Fprintf(w, "✘ %-*s  %s\n", width, t.name, why)
			failed = true
			continue
		}
		fmt.Fprintf(w, "✔ %-*s  blocked, in its own reply format\n", width, t.name)
		if t.after != "" {
			fmt.Fprintf(w, "  %-*s  %s\n", width, "", t.after)
		}
	}
	fmt.Fprintln(w, `
This runs each hook command the way the agent does and checks provguard's
answer. It cannot make the agent call the hook. To see that, ask the agent to
write a file in ~/.provguard: provguard should block it.`)
	if failed {
		return 1
	}
	return 0
}

// liveTargets lists the agents to test: the Claude Code hooks (also run by
// Cursor and Devin), and each other agent found on this computer.
func liveTargets(settings, home string) []liveTarget {
	var out []liveTarget
	claude := liveTarget{name: "Claude Code", agent: claudecode.Agent, file: settings}
	if s, err := install.Load(settings); err != nil {
		claude.err = err.Error()
	} else if claude.bin = install.HookBinary(s); claude.bin == "" {
		claude.err = "provguard's hooks are not in " + settings + ". Run provguard init."
	}
	out = append(out, claude)
	for _, a := range []struct{ name, agent string }{{"Cursor (Claude Code hooks)", cursor.Agent}, {"Devin (Claude Code hooks)", devin.Agent}} {
		t := claude
		t.name, t.agent = a.name, a.agent
		if t.err != "" {
			t.err = "-" // reported once, on the Claude Code line
		}
		out = append(out, t)
	}

	bin := filepath.Join(home, "bin", "provguard"+exeSuffix())
	for _, a := range otherAgents {
		if !a.present() {
			continue
		}
		t := liveTarget{name: a.name, agent: a.agent, agentArg: a.agent, bin: bin, after: a.after}
		file, err := a.hookFile()
		t.file = file
		switch b, rerr := os.ReadFile(file); {
		case err != nil:
			t.err = err.Error()
		case rerr != nil:
			t.err = "provguard's hooks are not installed (" + file + "). Run provguard init."
		case !hookNamesAgent(string(b), a.agent):
			t.err = "provguard's hooks are not in " + file + ". Run provguard init."
		}
		if t.err == "" {
			if _, err := os.Stat(bin); err != nil {
				t.err = "the hook runs " + bin + ", which does not exist. Run provguard init."
			}
		}
		out = append(out, t)
	}
	return out
}

// hookNamesAgent reports whether a hook file runs provguard for agent: as a
// command line (`hook --agent NAME`) or as the arguments of the OpenCode
// plugin (`"--agent", "NAME"`).
func hookNamesAgent(text, agent string) bool {
	re := regexp.MustCompile(`--agent"?,?\s*"?` + regexp.QuoteMeta(agent) + `\b`)
	return strings.Contains(strings.ToLower(text), "provguard") && re.MatchString(text)
}

// runProbe runs the hook with the agent's probe and returns why the answer
// is not a block, or "".
func runProbe(t liveTarget, probe, tmpHome string) string {
	ad, ok := adapter.ByName(t.agent)
	if !ok {
		return "unknown agent " + t.agent
	}
	ev, payload := ad.Probe(probe)
	args := []string{"hook"}
	if t.agentArg != "" {
		args = append(args, "--agent", t.agentArg)
	}
	args = append(args, ev)

	stdout, code, err := runHookCommand(t.bin, args, tmpHome, payload)
	if err != nil {
		return "the hook could not run: " + redact.OneLine(err.Error(), 120)
	}

	want, err := ad.Reply(core.Deny, liveReason)
	if err != nil {
		return err.Error()
	}
	if blockedLike(want, core.Response{Stdout: stdout, ExitCode: code}) {
		return ""
	}
	return fmt.Sprintf("the hook answered without a block (exit %d, output %q)", code, redact.OneLine(string(stdout), 100))
}

// runHookCommand runs the hook binary with provguard's home set to home and
// returns its stdout and exit code. Tests replace it with an in-process call.
var runHookCommand = realRun

func realRun(bin string, args []string, home string, stdin []byte) ([]byte, int, error) {
	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(install.HookTimeoutSeconds)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, bin, args...)
	cmd.Stdin = bytes.NewReader(stdin)
	cmd.Env = append(os.Environ(), "PROVGUARD_HOME="+home)
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	err := cmd.Run()
	if ee, ok := err.(*exec.ExitError); ok {
		return stdout.Bytes(), ee.ExitCode(), nil
	}
	return stdout.Bytes(), 0, err
}

// blockedLike reports whether got is a block in the same format as want:
// the same non-zero exit code, or the same JSON with any reason text.
func blockedLike(want, got core.Response) bool {
	if want.ExitCode != 0 {
		return got.ExitCode == want.ExitCode
	}
	var w, g any
	if json.Unmarshal(want.Stdout, &w) != nil || json.Unmarshal(got.Stdout, &g) != nil {
		return false
	}
	return jsonLike(w, g)
}

func jsonLike(want, got any) bool {
	switch wv := want.(type) {
	case map[string]any:
		gv, ok := got.(map[string]any)
		if !ok {
			return false
		}
		for k, x := range wv {
			if !jsonLike(x, gv[k]) {
				return false
			}
		}
		return true
	case string:
		if wv == liveReason {
			_, ok := got.(string)
			return ok
		}
	}
	return want == got
}

func exeSuffix() string {
	if os.PathSeparator == '\\' {
		return ".exe"
	}
	return ""
}
