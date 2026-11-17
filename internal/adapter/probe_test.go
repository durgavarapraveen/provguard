package adapter

import (
	"testing"

	"github.com/durgavarapraveen/provguard/internal/event"
)

// Every adapter's Probe must parse back, through the same adapter selection
// the hook uses, as a PreToolUse write to the probe path. doctor --live
// relies on it.
func TestProbesRoundTrip(t *testing.T) {
	const path = "/home/u/.provguard/doctor-live-probe"
	for _, a := range adapters {
		ev, raw := a.Probe(path)
		name := a.Name()
		if a.Detect(raw) {
			name = "" // detected agents run the Claude Code hooks, without --agent
		}
		got, raw := Select(name, raw)
		if got.Name() != a.Name() {
			t.Errorf("%s: probe selected %s", a.Name(), got.Name())
			continue
		}
		e, err := got.Parse(raw, ev)
		if err != nil || e.Kind != event.PreTool {
			t.Errorf("%s: %+v %v", a.Name(), e, err)
			continue
		}
		paths := []any{e.ToolInput["file_path"]}
		if files, ok := e.ToolInput["path"].([]any); ok { // apply_patch (core.AddPatchPaths)
			paths = append(paths, files...)
		}
		found := false
		for _, p := range paths {
			found = found || p == path
		}
		if !found || e.ToolName != "Write" && e.ToolName != "apply_patch" {
			t.Errorf("%s: tool %q input %v, want a write to %s", a.Name(), e.ToolName, e.ToolInput, path)
		}
	}
}
