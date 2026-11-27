package registry

import "testing"

func TestLookalike(t *testing.T) {
	cases := []struct {
		eco        Eco
		name, want string // want "" = not a lookalike
	}{
		{NPM, "expres", "express"},
		{NPM, "exprses", "express"},
		{NPM, "lodahs", "lodash"},
		{NPM, "reactdom", "react-dom"},
		{NPM, "react_dom", "react-dom"},
		{NPM, "axioss", "axios"},
		{NPM, "express", ""},
		{NPM, "react", ""},
		{NPM, "left-pad", ""},
		{NPM, "@types/expres", ""},
		{NPM, "vue", ""},
		{NPM, "vuex", ""},
		{PyPI, "reqeusts", "requests"},
		{PyPI, "request", "requests"},
		{PyPI, "beautifulsoup", "beautifulsoup4"}, // old Python 2 package: asking is right
		{PyPI, "python-dotenv", ""},
		{PyPI, "pythondotenv", "python-dotenv"},
		{Crates, "serde-json", "serde_json"},
		{Crates, "tokoi", "tokio"},
		{Crates, "serde", ""},
	}
	for _, c := range cases {
		got, ok := Lookalike(c.eco, c.name)
		if got != c.want || ok != (c.want != "") {
			t.Errorf("Lookalike(%s, %q) = %q, %v; want %q", c.eco, c.name, got, ok, c.want)
		}
	}
}

// No popular name may look like another one, or installing it would ask.
func TestPopularNoLookalikes(t *testing.T) {
	for eco, names := range popular {
		for _, n := range names {
			if p, ok := Lookalike(eco, n); ok {
				t.Errorf("%s: popular %q looks like %q", eco, n, p)
			}
		}
	}
}
