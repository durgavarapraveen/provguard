package shell

import "testing"

func TestScriptFilesNoExec(t *testing.T) {
	for cmd, runs := range map[string]bool{
		"bash x.sh":                     true,
		"bash -n x.sh":                  false,
		"sh -n x.sh":                    false,
		"zsh -xn x.sh":                  false,
		"bash -o noexec x.sh":           false,
		"bash -o pipefail -n x.sh":      false,
		"bash -n +n x.sh":               true, // turned off again
		"bash -o noexec +o noexec x.sh": true,
		"bash x.sh -n":                  true, // -n after the script is the script's argument
		"bash -e x.sh":                  true, // errexit, not inline code
		"bash -eo pipefail x.sh":        true, // -o takes "pipefail"; x.sh is the script
		"bash -euo pipefail x.sh":       true,
		"bash -eo noexec x.sh":          false,
		"bash -eux x.sh":                true,
		"bash +e x.sh":                  true,
		"bash -O extglob x.sh":          true,
		"bash --norc x.sh":              true,
		"bash -- x.sh":                  true,
		"bash -c 'echo hi'":             false, // inline code: checked elsewhere
		"bash -s < x.sh":                false, // stdin
		"bash":                          false,
		"python -n x.py":                true, // not a shell's noexec
	} {
		a := Analyze(cmd, Bash)
		got := len(a.Cmds) > 0 && len(ScriptFiles(a.Cmds[0])) > 0
		if got != runs {
			t.Errorf("%s: script runs = %v, want %v", cmd, got, runs)
		}
	}
}
