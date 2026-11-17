// Package core defines what every coding-agent adapter provides.
//
// provguard's checks (labels, shell analysis, policy, self-protection) work
// on the agent-neutral event.Event. An adapter is the only agent-specific
// part: it recognizes the agent's hook payload, converts it to an Event, and
// writes the agent's own reply format. Each agent lives in its own package
// under internal/adapter and implements Adapter; internal/adapter keeps the
// list.
package core

import (
	"encoding/json"

	"github.com/durgavarapraveen/provguard/internal/event"
)

// Decision is provguard's answer to a tool call. provguard never answers
// "allow": that would skip the agent's own permission prompts.
type Decision string

const (
	Deny Decision = "deny"
	Ask  Decision = "ask"
)

// Adapter connects provguard to one coding agent's hooks.
type Adapter interface {
	// Name identifies the agent in events and audit logs ("claude-code").
	Name() string

	// Detect reports whether a hook payload came from this agent.
	Detect(raw []byte) bool

	// Parse converts the payload to an Event. eventArg is the event name
	// from the hook command line; the payload's own name wins.
	Parse(raw []byte, eventArg string) (event.Event, error)

	// Reply encodes a decision on a tool call in the agent's format: most
	// agents read JSON on stdout, some (Kiro) an exit code and stderr.
	Reply(d Decision, reason string) (Response, error)

	// Feedback encodes what provguard tells the user outside a decision:
	// a notice when the session's trust state changed, and a new session
	// title. It returns nil when there is nothing to send or the agent
	// cannot show it.
	Feedback(e event.Event, notice, title string) []byte

	// CanAsk reports whether the agent acts on an Ask decision by asking
	// the user. When it does not, provguard denies instead, because an
	// ignored Ask lets the call run.
	CanAsk() bool
}

// Response is what the hook process writes and how it exits.
type Response struct {
	Stdout   []byte
	Stderr   string
	ExitCode int
}

// JSONResponse is a reply made of one JSON object on stdout, exit code 0.
func JSONResponse(v any) (Response, error) {
	b, err := json.Marshal(v)
	return Response{Stdout: b}, err
}
