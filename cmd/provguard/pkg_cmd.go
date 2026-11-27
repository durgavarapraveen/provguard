package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/policy"
	"github.com/durgavarapraveen/provguard/internal/registry"
)

const pkgUsage = `usage: provguard pkg npm|pypi|cargo <name>...
  Asks the registry whether each package exists and when it was first
  published. Names like "left-pad@1.3", "requests==2.31" and "serde@1" work.
  Exit code: 0 all fine, 1 a name is unknown or new, 2 bad usage, 3 the
  registry did not answer.
`

// runPkg is the dependency gate by hand: the same lookup and the same
// limits the hook uses, whether or not package_check is on.
func runPkg(args []string, stdout, stderr io.Writer) int {
	if len(args) < 2 {
		fmt.Fprint(stderr, pkgUsage)
		return 2
	}
	eco, ok := map[string]registry.Eco{
		"npm": registry.NPM, "pypi": registry.PyPI, "pip": registry.PyPI,
		"cargo": registry.Crates, "crates": registry.Crates,
	}[args[0]]
	if !ok {
		fmt.Fprint(stderr, pkgUsage)
		return 2
	}
	home, err := audit.Home()
	if err != nil {
		home = "" // no cache
	}
	return checkPackages(&registry.Client{Dir: home, HTTP: &http.Client{Timeout: 5 * time.Second}}, eco, args[1:], stdout, stderr)
}

func checkPackages(c *registry.Client, eco registry.Eco, names []string, stdout, stderr io.Writer) int {
	code := 0
	worse := func(n int) {
		if n > code {
			code = n
		}
	}
	for _, spec := range names {
		p, ok := registry.Parse(eco, spec)
		if !ok {
			fmt.Fprintf(stdout, "%-24s skipped: not a registry name (a path, URL or git spec)\n", spec)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
		info, err := c.Lookup(ctx, eco, p.Name)
		cancel()
		switch {
		case err != nil:
			fmt.Fprintf(stderr, "%-24s no answer: %v\n", p.Name, err)
			worse(3)
		case !info.Found:
			fmt.Fprintf(stdout, "%-24s NOT FOUND: the name may be made up; anyone can register it\n", p.Name)
			worse(1)
		default:
			line := "exists"
			if !info.Created.IsZero() {
				days := int(info.Checked.Sub(info.Created).Hours() / 24)
				line += fmt.Sprintf(", first published %s (%d days ago)", info.Created.Format("2006-01-02"), days)
				if info.Checked.Sub(info.Created) < policy.NewPackageAge {
					line = "NEW: " + line
					worse(1)
				}
			}
			if info.Downloads >= 0 {
				line += fmt.Sprintf(", %d downloads", info.Downloads)
			}
			if info.InstallScripts {
				line += ", runs install scripts"
			}
			fmt.Fprintf(stdout, "%-24s %s\n", p.Name, line)
		}
	}
	return code
}
