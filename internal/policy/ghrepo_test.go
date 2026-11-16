package policy

import (
	"testing"

	"github.com/durgavarapraveen/provguard/internal/shell"
)

// A gh write to the user's own repository is not data leaving, even in a
// 🔴 session; to anyone else's, it is. A secret in the call is still denied.
func TestGHWriteToOwnRepo(t *testing.T) {
	trusted := map[string]bool{".": true, "me/app": true}
	var asked []string
	judgeGH := func(cmd string) Result {
		a := shell.Analyze(cmd, shell.Bash)
		return Evaluate(Input{
			Tool: "Bash", Sinks: a.Sinks, Text: cmd, Session: sess(true, true), Key: key, Config: bal(), Cwd: "/work/proj",
			GHRepoTrusted: func(repo string) bool { asked = append(asked, repo); return trusted[repo] },
		})
	}
	for cmd, want := range map[string]string{
		`gh pr create --title "fix" --body "fixes the parser"`: None,
		`gh issue comment 4 --body "done"`:                     None,
		`gh pr create -R me/app --fill`:                        None,
		`gh pr create --repo=stranger/app --fill`:              Deny,
		`gh pr create -R "$REPO" --fill`:                       Deny,
		`gh gist create notes.txt`:                             Deny, // not a repository
		`gh repo create new-thing --public`:                    Deny, // a new place
		`gh pr create --body "` + secret + `"`:                 Deny, // rule 1 still applies
	} {
		if got := judgeGH(cmd).Decision; got != want {
			t.Errorf("%s: got %q, want %q", cmd, got, want)
		}
	}

	// A clean session never asks GitHub.
	asked = nil
	a := shell.Analyze("gh pr create --fill", shell.Bash)
	Evaluate(Input{Tool: "Bash", Sinks: a.Sinks, Session: sess(false, false), Config: bal(),
		GHRepoTrusted: func(repo string) bool { asked = append(asked, repo); return true }})
	if len(asked) != 0 {
		t.Errorf("clean session checked the repository: %v", asked)
	}
}
