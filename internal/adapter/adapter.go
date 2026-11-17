// Package adapter keeps the list of supported coding agents and picks the
// one that sent a hook payload.
//
// One installed `provguard hook` command can receive payloads from more than
// one agent: Cursor, for example, also runs the Claude Code hooks in
// ~/.claude/settings.json. Each agent's package implements core.Adapter;
// adding an agent means adding its package and one line to adapters.
package adapter

import (
	"bytes"

	"github.com/durgavarapraveen/provguard/internal/adapter/claudecode"
	"github.com/durgavarapraveen/provguard/internal/adapter/codex"
	"github.com/durgavarapraveen/provguard/internal/adapter/copilot"
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/adapter/cursor"
)

// adapters in detection order: agents with a distinctive payload first,
// Claude Code (which accepts any JSON object) last.
var adapters = []core.Adapter{
	cursor.Adapter{},
	copilot.Adapter{}, // never detected; named by its hooks (--agent copilot)
	codex.Adapter{},   // never detected; named by its hooks (--agent codex)
	claudecode.Adapter{},
}

// ByName returns the adapter called name, for hooks that name their agent
// on the command line (`provguard hook --agent copilot PreToolUse`).
func ByName(name string) (core.Adapter, bool) {
	for _, a := range adapters {
		if a.Name() == name {
			return a, true
		}
	}
	return nil, false
}

// Default is the adapter used before a payload is read, for example to
// answer when stdin could not be read at all.
func Default() core.Adapter { return claudecode.Adapter{} }

// Select returns the adapter named by the hook command (--agent), or else
// the one that recognizes raw; and raw without a UTF-8 BOM.
func Select(name string, raw []byte) (core.Adapter, []byte) {
	if a, ok := ByName(name); ok {
		return a, trimBOM(raw)
	}
	return ForPayload(raw)
}

// trimBOM drops a UTF-8 byte-order mark: some shells, for example
// PowerShell pipes, prepend one.
func trimBOM(raw []byte) []byte { return bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf")) }

// ForPayload returns the adapter that recognizes raw, and raw without a
// UTF-8 BOM.
func ForPayload(raw []byte) (core.Adapter, []byte) {
	raw = trimBOM(raw)
	for _, a := range adapters {
		if a.Detect(raw) {
			return a, raw
		}
	}
	return Default(), raw
}
