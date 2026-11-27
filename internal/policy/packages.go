package policy

import (
	"fmt"
	"strings"
	"time"

	"github.com/durgavarapraveen/provguard/internal/registry"
	"github.com/durgavarapraveen/provguard/internal/shell"
)

// NewPackageAge: a package first published less than this long ago is new.
// Most malicious packages are found and removed within days.
const NewPackageAge = 30 * 24 * time.Hour

// unverifiedPackage is the dependency gate. It runs in clean sessions too:
// an agent can make a package name up (slopsquatting) without reading any
// untrusted content.
//   - unknown_package (deny): the registry has no package by that name.
//   - new_package (ask): the package was first published days ago.
//
// A lookup that failed or was skipped (private registry, local binary)
// counts as no answer; the other rules still apply.
func unverifiedPackage(in Input) (Result, bool) {
	if in.PackageInfo == nil {
		return Result{}, false
	}
	var ask Result
	for _, x := range filter(in.Sinks, shell.ExecRemote) {
		kind, tool, ok := strings.Cut(x.Detail, ":")
		if !ok || kind != "package_install" && kind != "run_remote_package" {
			continue
		}
		eco, ok := registry.ToolEco(tool)
		if !ok {
			continue
		}
		for _, w := range strings.Fields(x.Target) {
			p, ok := registry.Parse(eco, w)
			if !ok {
				continue
			}
			like, isLike := registry.Lookalike(eco, p.Name)
			info, ok := in.PackageInfo(p, kind == "run_remote_package")
			if ok && !info.Found {
				hint := ""
				if isLike {
					hint = fmt.Sprintf(" (did you mean %s?)", like)
				}
				r := result(Deny, "unknown_package", fmt.Sprintf(
					"%s has no package named %q%s; the name may be made up, and anyone can register it with malicious code", ecoName(eco), p.Name, hint), []shell.Sink{x})
				r.say = fmt.Sprintf("%s has no package named %s%s, so the agent may have made the name up (an attacker can register such a name)", ecoName(eco), p.Name, hint)
				return r, true
			}
			// A name one typo away from a popular package. A package that is
			// popular itself (many downloads) is a real neighbour, not a copy.
			if isLike && ask.Rule == "" && !(ok && WidelyUsed(info)) {
				ask = result(Ask, "lookalike_package", fmt.Sprintf(
					"%s %s looks like the popular package %s", ecoName(eco), p.Name, like), []shell.Sink{x})
				ask.say = fmt.Sprintf("the package %s looks like the popular package %s; typosquats copy popular names with one letter changed", p.Name, like)
			}
			if !ok {
				continue
			}
			if age := info.Checked.Sub(info.Created); ask.Rule == "" && !info.Created.IsZero() && age < NewPackageAge {
				days := int(age.Hours() / 24)
				extra := ""
				if info.InstallScripts {
					extra = ", and it runs install scripts"
				}
				ask = result(Ask, "new_package", fmt.Sprintf(
					"%s %s was first published %d days ago%s", ecoName(eco), p.Name, days, extra), []shell.Sink{x})
				ask.say = fmt.Sprintf("the package %s was first published on %s only %s ago%s; new packages are a common way to spread malware",
					p.Name, ecoName(eco), plural(days, "day"), extra)
			}
		}
	}
	return ask, ask.Rule != ""
}

// WidelyUsed: download counts show a package many people use. Unknown
// counts (PyPI) never count as widely used.
func WidelyUsed(i registry.Info) bool {
	return i.WeeklyDownloads >= 10_000 || i.Downloads >= 1_000_000
}

func ecoName(e registry.Eco) string {
	switch e {
	case registry.NPM:
		return "npm"
	case registry.PyPI:
		return "PyPI"
	}
	return "crates.io"
}

func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
