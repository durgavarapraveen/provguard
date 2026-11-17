package core

import (
	"runtime"
	"testing"
)

func TestHookCommand(t *testing.T) {
	p, w := HookCommand("/home/me/.provguard/bin/provguard", "kiro", "PreToolUse")
	if p != `"/home/me/.provguard/bin/provguard" hook --agent kiro PreToolUse` || w != `/home/me/.provguard/bin/provguard hook --agent kiro PreToolUse` {
		t.Errorf("unix path: %q %q", p, w)
	}
	if runtime.GOOS != "windows" {
		return // backslashes are path separators only on Windows
	}
	p, w = HookCommand(`C:\Users\me\.provguard\bin\provguard.exe`, "kiro", "PreToolUse")
	if p != `"C:/Users/me/.provguard/bin/provguard.exe" hook --agent kiro PreToolUse` ||
		w != `C:/Users/me/.provguard/bin/provguard.exe hook --agent kiro PreToolUse` {
		t.Errorf("no space: %q %q", p, w)
	}
	_, w = HookCommand(`C:/Program Files/pg/provguard.exe`, "kiro", "PreToolUse")
	if w != `& "C:/Program Files/pg/provguard.exe" hook --agent kiro PreToolUse` {
		t.Errorf("space: %q", w)
	}
}

func TestPatchFiles(t *testing.T) {
	got := PatchFiles("*** Begin Patch\n*** Update File: a.go\n*** Move to: b.go\n*** Delete File: c.go\n*** End Patch")
	if len(got) != 3 || got[0] != "a.go" || got[1] != "b.go" || got[2] != "c.go" {
		t.Errorf("got %v", got)
	}
}
