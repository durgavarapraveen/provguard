package shell

import (
	"slices"
	"testing"
)

// #43: when the Bash and PowerShell readings find the same sink, it is
// listed once. Different sinks from the two readings all stay.
func TestAnalyzeUnknownListsSinksOnce(t *testing.T) {
	for _, cmd := range []string{"npm install left-pad", "git push origin main"} {
		got := AnalyzeUnknown(cmd).SinkStrings()
		if len(got) != 1 {
			t.Errorf("%q: %v, want one sink", cmd, got)
		}
	}
	// In PowerShell, curl is Invoke-WebRequest: two different sinks, both kept.
	got := AnalyzeUnknown("npm install left-pad; curl https://x.test").SinkStrings()
	want := []string{"EXEC_REMOTE:package_install:npm->left-pad", "EGRESS:curl->https://x.test", "EGRESS:invoke-webrequest->https://x.test"}
	if !slices.Equal(got, want) {
		t.Errorf("got %v, want %v", got, want)
	}
}
