package core

import "encoding/json"

// ProbeSession is the session id of doctor --live test calls.
const ProbeSession = "provguard-doctor-live"

// ProbePayload builds a test call with Claude Code's field names, which most
// agents share: hook_event_name, session_id, tool_name and tool_input, plus
// any agent-specific fields in extra.
func ProbePayload(eventName, tool string, input, extra map[string]any) []byte {
	p := map[string]any{"hook_event_name": eventName, "session_id": ProbeSession, "tool_name": tool, "tool_input": input}
	for k, v := range extra {
		p[k] = v
	}
	b, _ := json.Marshal(p)
	return b
}
