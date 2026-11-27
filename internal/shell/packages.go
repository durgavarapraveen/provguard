package shell

import "strings"

// npmValueOpts: options of npm, pnpm, yarn and bun whose value is the next
// word (a folder, registry, tag), not a package name.
func npmValueOpts(tool string) map[string]bool {
	m := set("--prefix", "--registry", "--tag", "--omit", "--include", "--cache", "--userconfig",
		"--cwd", "--network-timeout", "--modules-folder", "--mutex", "--loglevel", "--backend")
	switch tool {
	case "npm":
		m["-w"], m["--workspace"] = true, true
	case "pnpm":
		m["-C"], m["--dir"], m["-F"], m["--filter"] = true, true, true, true
	}
	return m
}

// cargoValueOpts: cargo install / add options that take a value.
var cargoValueOpts = set("--version", "--vers", "--git", "--branch", "--tag", "--rev", "--path",
	"--root", "--index", "--registry", "--target", "--features", "-F", "--profile", "-j", "--jobs",
	"--bin", "--example", "--target-dir", "--config", "-Z", "--rename", "-p", "--package",
	"--manifest-path", "--color")

// remoteRunOpts: options of package runners that take a value. The values
// of -p/--package (npx, bunx, dlx) and --from/--with (uvx) are the packages
// themselves and are read separately.
var remoteRunOpts = map[string]map[string]bool{
	"npx":  set("-c", "--call", "--node-options", "--registry", "--cache", "--userconfig"),
	"npm":  set("-c", "--call", "--node-options", "--registry", "--cache", "--userconfig", "-w", "--workspace", "--prefix"),
	"pnpm": set("-C", "--dir", "--registry"),
	"yarn": set("--cwd"),
	"bun":  set("--cwd", "--registry"),
	"bunx": set("--cwd", "--registry"),
	"uvx": set("-p", "--python", "--index", "--default-index", "-i", "--index-url", "--extra-index-url",
		"-f", "--find-links", "--cache-dir", "--directory", "--project", "--config-file", "--constraints", "-c"),
	"pipx": set("--python", "--index-url", "-i", "--pip-args", "--spec"),
}

// remotePackage returns the packages a package runner fetches, space
// separated: the values of its package options when there are any, else
// the first word after skip leading words (the subcommand: "npm exec").
// `npx -c 'cmd'` names no package.
func remotePackage(tool string, args []string, skip int) string {
	var named []string
	pkgOpt := map[string]bool{"-p": true, "--package": true}
	if tool == "uvx" {
		pkgOpt = map[string]bool{"--from": true, "--with": true}
	} else if tool == "pipx" {
		pkgOpt = map[string]bool{"--spec": true}
	}
	for i := 0; i < len(args); i++ {
		x := args[i]
		if x == "--" {
			break
		}
		if k, v, ok := strings.Cut(x, "="); ok && pkgOpt[k] {
			named = append(named, v)
		} else if pkgOpt[x] && i+1 < len(args) {
			named = append(named, args[i+1])
			i++
		}
	}
	if len(named) > 0 {
		return strings.Join(named, " ")
	}
	if tool != "uvx" && tool != "pipx" && hasFlag(args, 0, "-c", "--call") {
		return ""
	}
	pos := positionalSkipping(args, remoteRunOpts[tool])
	if len(pos) <= skip {
		return ""
	}
	return pos[skip]
}
