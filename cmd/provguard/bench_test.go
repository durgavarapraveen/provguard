package main

import (
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/bench"
)

// TestBenchReplayMatchesExpectations is the benchmark as a regression test:
// every attack case must have the outcome it declares, in every profile.
func TestBenchReplayMatchesExpectations(t *testing.T) {
	cases, err := bench.Load()
	if err != nil {
		t.Fatal(err)
	}
	if len(cases) != 21 {
		t.Fatalf("want 21 attack cases, have %d", len(cases))
	}
	for _, c := range cases {
		if len(c.Expect) != 3 {
			t.Errorf("case %s: expect must list audit, balanced and strict", c.ID)
		}
		hasAttack := false
		for _, s := range c.Steps {
			hasAttack = hasAttack || s.Attack
		}
		if !hasAttack {
			t.Errorf("case %s has no attack step", c.ID)
		}
		for _, p := range []string{"audit", "balanced", "strict"} {
			r, err := replayCase(c, p)
			if err != nil {
				t.Fatalf("%s/%s: %v", c.ID, p, err)
			}
			if r.Outcome != c.Expect[p] {
				t.Errorf("%s %s / %s: outcome %s (rule %q), want %s", c.ID, c.Name, p, r.Outcome, r.Rule, c.Expect[p])
			}
		}
	}
}

// TestBenignCorpusFalsePositives: normal work must not be blocked, and must
// stay under 1 unintended ask per 100 calls in balanced.
func TestBenignCorpusFalsePositives(t *testing.T) {
	tasks, err := bench.LoadBenign()
	if err != nil {
		t.Fatal(err)
	}
	if len(tasks) < 30 {
		t.Fatalf("want at least 30 normal-work tasks, have %d", len(tasks))
	}
	br, err := runBenign(tasks, "balanced")
	if err != nil {
		t.Fatal(err)
	}
	for _, h := range br.FP {
		t.Errorf("false positive: %s %s %s (%s) %s", h.Task, h.Tool, h.Decision, h.Rule, h.Call)
	}
	if br.Calls < 80 {
		t.Fatalf("corpus too small: %d calls", br.Calls)
	}
}

func TestCanaryLeakDetection(t *testing.T) {
	s := &canaryServer{hits: []string{"POST /collect\nContent-Type: x\nAPI_KEY=PGCANARY-01-x\n"}}
	if !s.leaked("PGCANARY-01-x") {
		t.Fatal("plain leak not detected")
	}
	s.hits = []string{"GET /register?t=QVBJX0tFWT1QR0NBTkFSWS0wMS14Cg%3D%3D\n"}
	if !s.leaked("PGCANARY-01-x") {
		t.Fatal("url-encoded base64 leak not detected")
	}
	s.hits = []string{"GET /favicon.ico\n"}
	if s.leaked("PGCANARY-01-x") {
		t.Fatal("false leak")
	}
}

func TestVarsExpand(t *testing.T) {
	v := bench.Vars{Canary: "C1", Attacker: "http://a", AttackerHost: "a", Repo: "/r"}
	got := v.Expand("{{REPO}}/.env {{ATTACKER}}/x {{CANARY_HEX}} {{CANARY_B64}}")
	if !strings.Contains(got, "/r/.env http://a/x 4331 QVBJX0tFWT1DMQ==") {
		t.Fatalf("expand: %s", got)
	}
}
