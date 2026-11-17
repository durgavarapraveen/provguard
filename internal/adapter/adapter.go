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
	"github.com/durgavarapraveen/provguard/internal/adapter/core"
	"github.com/durgavarapraveen/provguard/internal/adapter/cursor"
)

// adapters in detection order: agents with a distinctive payload first,
// Claude Code (which accepts any JSON object) last.
var adapters = []core.Adapter{
	cursor.Adapter{},
	claudecode.Adapter{},
}

// Default is the adapter used before a payload is read, for example to
// answer when stdin could not be read at all.
func Default() core.Adapter { return claudecode.Adapter{} }

// ForPayload returns the adapter for raw, and raw without a UTF-8 BOM (some
// shells, for example PowerShell pipes, prepend one).
func ForPayload(raw []byte) (core.Adapter, []byte) {
	raw = bytes.TrimPrefix(raw, []byte("\xef\xbb\xbf"))
	for _, a := range adapters {
		if a.Detect(raw) {
			return a, raw
		}
	}
	return Default(), raw
}
