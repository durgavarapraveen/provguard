package policy

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/shell"
)

func TestInTemp(t *testing.T) {
	tmp := `C:\Users\me\AppData\Local\Temp`
	for p, want := range map[string]bool{
		`C:\Users\me\AppData\Local\Temp\pg-test`:      true,
		`/c/Users/me/AppData/Local/Temp/scratch/pg`:   true,
		`$env:TEMP\pg-lat7`:                           true,
		`C:\Users\me\AppData\Local\Temp`:              false, // the folder itself
		`C:\Users\me\AppData\Local\Temp\..\Documents`: false,
		`C:\Users\me\AppData\Local\Temp\*`:            false,
		`$env:TEMP\$name`:                             false,
		`$TEMP/pghome`:                                false, // may be a variable the command set
		`$tmp`:                                        false,
		`C:\Users\me\AppData\Local\TempX\a`:           false,
	} {
		if got := inTemp(p, tmp); got != want {
			t.Errorf("%s: got %v, want %v", p, got, want)
		}
	}
}

func TestTempDeleteIsNotRisky(t *testing.T) {
	dir := filepath.ToSlash(filepath.Join(os.TempDir(), "pg-scratch"))
	for cmd, want := range map[string]string{
		"rm -rf " + dir:                  None,
		"rm -rf " + dir + " ~/Documents": Ask,
		"rm -rf ~/Documents":             Ask,
	} {
		if got := judge(cmd, sess(true, false), bal()).Decision; got != want {
			t.Errorf("%s: got %q, want %q", cmd, got, want)
		}
	}
	// $env:TEMP pointed elsewhere first.
	cmd := `$env:TEMP = $HOME; Remove-Item -Recurse -Force $env:TEMP\Documents`
	a := shell.Analyze(cmd, shell.PowerShell)
	r := Evaluate(Input{Tool: "PowerShell", Sinks: a.Sinks, Text: cmd, Session: sess(true, false), Config: bal(), Cwd: "/work/proj"})
	if r.Decision != Ask {
		t.Errorf("redefined TEMP: got %q, want ask (%v)", r.Decision, a.Sinks)
	}
}
