package doctor

import (
	"strings"
	"testing"

	"github.com/durgavarapraveen/provguard/internal/config"
)

// MED: allowed_hosts used to trust content too, so provguard now reports
// content-trust entries that anyone can publish to, or that are too broad.
func TestContentTrustFindings(t *testing.T) {
	cases := map[string]struct {
		hosts []string
		want  int
	}{
		"own api":        {[]string{"api.mycorp.com", "docs.python.org"}, 0},
		"github":         {[]string{"github.com"}, 1},
		"raw github":     {[]string{"raw.githubusercontent.com"}, 1},
		"bare tld":       {[]string{"com"}, 1},
		"empty is fine":  {[]string{"", "  "}, 0},
		"trailing dot":   {[]string{"github.com."}, 1},
		"mixed case":     {[]string{"GitHub.com"}, 1},
		"two complaints": {[]string{"gist.github.com", "dev"}, 2},
	}
	for name, c := range cases {
		f := contentTrustFindings(config.Config{TrustedContentHosts: c.hosts})
		if len(f) != c.want {
			t.Errorf("%s: %d findings, want %d (%v)", name, len(f), c.want, f)
		}
		for _, x := range f {
			if x.Severity != Medium || !strings.Contains(x.Message, "trusted_content_hosts") {
				t.Errorf("%s: unexpected finding %+v", name, x)
			}
		}
	}
	// allowed_hosts is an egress list: it is not reported here.
	if f := contentTrustFindings(config.Config{AllowedHosts: []string{"github.com"}}); len(f) != 0 {
		t.Errorf("allowed_hosts reported: %v", f)
	}
}
