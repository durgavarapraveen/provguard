package shell

import (
	"regexp"
	"strings"
)

var (
	shells       = set("sh", "bash", "zsh", "dash", "ksh", "fish", "busybox")
	psShells     = set("pwsh", "powershell")
	interpreters = set("python", "python3", "python2", "py", "node", "nodejs", "deno", "bun",
		"ruby", "perl", "php", "osascript", "lua", "tclsh")
	httpClients = set("curl", "wget", "http", "https", "xh", "aria2c", "invoke-webrequest",
		"invoke-restmethod", "iwr", "irm", "start-bitstransfer")
	rawSockets = set("nc", "ncat", "netcat", "socat", "telnet")
	sshTools   = set("ssh", "scp", "sftp")
	dnsTools   = set("nslookup", "dig", "host", "ping", "ping6", "resolve-dnsname", "drill")
	decoders   = set("base64", "base32", "xxd", "openssl", "uudecode", "gzip", "gunzip", "zcat")
	// prefix wrappers: the real command follows (after their own options)
	prefixes = set("sudo", "doas", "env", "nohup", "time", "command", "exec", "nice", "ionice",
		"timeout", "stdbuf", "setsid", "chronic", "unbuffer", "xargs", "builtin", "caffeinate", "watch")
	// options of prefix wrappers that take a separate value
	prefixValueOpts = map[string]map[string]bool{
		"sudo":    set("-u", "-g", "-h", "-p", "-c", "-r", "-t", "-C", "-D", "-U"),
		"doas":    set("-u", "-c"),
		"env":     set("-u", "-c", "--unset", "--chdir", "-C", "-S", "--split-string"),
		"nice":    set("-n", "--adjustment"),
		"ionice":  set("-c", "-n", "-p"),
		"timeout": set("-s", "--signal", "-k", "--kill-after"),
		"xargs":   set("-I", "-n", "-P", "-L", "-s", "-d", "-E", "-a", "--arg-file", "--delimiter", "--max-args", "--max-procs"),
		"watch":   set("-n", "--interval", "-d"),
		"stdbuf":  set("-i", "-o", "-e"),
	}
	codeFlags = map[string]map[string]bool{
		"python": set("-c"), "python3": set("-c"), "python2": set("-c"), "py": set("-c"),
		"node": set("-e", "--eval", "-p", "--print"), "nodejs": set("-e", "--eval", "-p", "--print"),
		"deno": set("eval"), "bun": set("-e", "--eval"), "ruby": set("-e"),
		"perl": set("-e", "-E"), "php": set("-r"), "osascript": set("-e"), "lua": set("-e"),
	}
	netCode   = regexp.MustCompile(`(?i)\b(?:socket|urllib|requests\.|http\.client|httpx|aiohttp|fetch\(|https?\.(?:get|request)|net\.connect|XMLHttpRequest|LWP::|IO::Socket|Net::HTTP|open-uri|curl_exec|file_get_contents\(\s*['"]https?:|smtplib|ftplib|websocket|dns\.resolver|getaddrinfo)`)
	writeCode = regexp.MustCompile(`(?i)(?:open\([^)]*['"][wa]b?\+?['"]|write_text|write_bytes|writeFileSync|writeFile\(|appendFile|fs\.rm|unlink|shutil\.(?:rmtree|move|copy)|os\.remove|File\.write|File\.open\([^)]*['"]w|IO\.write|rmtree|rename\()`)
)

func set(xs ...string) map[string]bool {
	m := make(map[string]bool, len(xs))
	for _, x := range xs {
		m[x] = true
	}
	return m
}

// command classifies one program call. args[0] is the program.
func command(a *Analysis, args []string, dyn []bool, depth int, d Dialect) {
	if len(args) == 0 {
		return
	}
	name := baseName(args[0])
	a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args, Dynamic: dyn[0]})
	if dyn[0] {
		a.sink(Opaque, "dynamic_command", args[0])
		return
	}
	rest, rdyn := args[1:], dyn[1:]

	// Prefix wrappers: skip their options and classify the real command.
	if prefixes[name] {
		i := skipPrefixOpts(name, rest)
		if i < len(rest) {
			command(a, rest[i:], rdyn[i:], depth, d)
		}
		return
	}

	switch {
	case shells[name]:
		if code, cdyn, ok := flagValue(rest, rdyn, set("-c")); ok {
			nested(a, code, cdyn, depth, Bash)
		}
		return
	case psShells[name]:
		for i, x := range rest {
			lx := strings.ToLower(x)
			if lx == "-e" || lx == "-ec" || lx == "-en" || strings.HasPrefix(lx, "-enc") {
				a.sink(Opaque, "encoded_command", "")
				return
			}
			if lx == "-c" || lx == "-command" {
				code := strings.Join(rest[i+1:], " ")
				nested(a, code, anyTrue(rdyn[i+1:]), depth, PowerShell)
				return
			}
		}
		return
	case name == "cmd":
		for i, x := range rest {
			if lx := strings.ToLower(x); lx == "/c" || lx == "/k" {
				nested(a, strings.Join(rest[i+1:], " "), anyTrue(rdyn[i+1:]), depth, PowerShell)
				return
			}
		}
		return
	case interpreters[name]:
		if name == "python" || name == "python3" || name == "py" {
			if len(rest) >= 2 && rest[0] == "-m" {
				command(a, append([]string{rest[1]}, rest[2:]...), rdyn[1:], depth, d)
				return
			}
		}
		if code, cdyn, ok := flagValue(rest, rdyn, codeFlags[name]); ok {
			inlineCode(a, name, code, cdyn)
		}
		return
	case name == "eval" || name == "source" && anyTrue(rdyn) || name == "." && anyTrue(rdyn):
		a.sink(Opaque, name, "")
		a.Code = append(a.Code, strings.Join(rest, " "))
		return
	}
	classify(a, name, rest)
}

// nested re-parses a code string given to bash -c, pwsh -Command, cmd /c.
func nested(a *Analysis, code string, dyn bool, depth int, d Dialect) {
	if dyn || depth >= maxDepth {
		a.sink(Opaque, "dynamic_script", "")
		a.Code = append(a.Code, code)
		return
	}
	if d == PowerShell {
		analyzePS(a, code, depth+1)
	} else {
		analyzeBash(a, code, depth+1)
	}
}

func inlineCode(a *Analysis, name, code string, dyn bool) {
	a.Code = append(a.Code, code)
	if dyn {
		a.sink(Opaque, "dynamic_code:"+name, "")
	}
	if netCode.MatchString(code) {
		a.sink(Egress, "interpreter_network:"+name, firstURL([]string{code}))
	}
	if writeCode.MatchString(code) {
		a.sink(Opaque, "interpreter_write:"+name, "")
	}
}

func skipPrefixOpts(name string, args []string) int {
	vopts := prefixValueOpts[name]
	i := 0
	for i < len(args) {
		x := args[i]
		switch {
		case name == "env" && strings.Contains(x, "=") && !strings.HasPrefix(x, "-"):
			i++
		case name == "timeout" && i == 0 && len(x) > 0 && (x[0] >= '0' && x[0] <= '9'):
			i++
		case name == "timeout" && !strings.HasPrefix(x, "-") && i > 0 && looksDuration(args[i-1]):
			return i
		case strings.HasPrefix(x, "-"):
			if vopts[x] {
				i += 2
			} else {
				i++
			}
			if x == "--" {
				return i
			}
		default:
			if name == "timeout" && looksDuration(x) {
				i++
				continue
			}
			return i
		}
	}
	return i
}

func looksDuration(s string) bool {
	return len(s) > 0 && s[0] >= '0' && s[0] <= '9'
}

// flagValue returns the argument after the first flag in flags.
func flagValue(args []string, dyn []bool, flags map[string]bool) (string, bool, bool) {
	for i, x := range args {
		if flags[x] && i+1 < len(args) {
			return args[i+1], dyn[i+1], true
		}
	}
	return "", false, false
}

func anyTrue(b []bool) bool {
	for _, x := range b {
		if x {
			return true
		}
	}
	return false
}

func positional(args []string) []string {
	var out []string
	for i, x := range args {
		if x == "--" {
			return append(out, args[i+1:]...)
		}
		if !strings.HasPrefix(x, "-") || x == "-" {
			out = append(out, x)
		}
	}
	return out
}

func hasFlag(args []string, short byte, long ...string) bool {
	for _, x := range args {
		if x == "--" {
			return false
		}
		for _, l := range long {
			if x == l {
				return true
			}
		}
		if short != 0 && len(x) > 1 && x[0] == '-' && x[1] != '-' && strings.IndexByte(x[1:], short) >= 0 {
			return true
		}
	}
	return false
}

var urlLike = regexp.MustCompile(`(?i)\b(?:https?|ftp|s3|gs)://[^\s'"<>]+`)

func firstURL(args []string) string {
	for _, x := range args {
		if m := urlLike.FindString(x); m != "" {
			return m
		}
	}
	for _, x := range positional(args) {
		if strings.Contains(x, ".") && !strings.ContainsAny(x, "/\\") {
			return x
		}
	}
	return ""
}

// classify handles programs that are not wrappers. It is shared by both dialects.
func classify(a *Analysis, name string, args []string) {
	pos := positional(args)
	switch {
	case httpClients[name]:
		a.sink(Egress, name, firstURL(args))
		for i, x := range args {
			if (x == "-o" || x == "--output" || x == "-O" && name == "wget" || x == "-OutFile") && i+1 < len(args) {
				a.write(args[i+1], "write", false)
			}
		}
	case rawSockets[name]:
		a.sink(Egress, name, strings.Join(pos, " "))
	case sshTools[name]:
		a.sink(Egress, name, firstHost(pos))
	case name == "rsync":
		for _, p := range pos {
			if strings.Contains(p, ":") && !isWindowsDrive(p) || strings.HasPrefix(p, "rsync://") {
				a.sink(Egress, "rsync", p)
				break
			}
		}
	case name == "ftp" || name == "tftp" || name == "sendmail" || name == "mail":
		a.sink(Egress, name, firstHost(pos))
	case dnsTools[name]:
		if len(pos) > 0 {
			a.sink(Egress, "dns:"+name, pos[0])
		}
	case name == "git":
		gitCmd(a, args)
	case name == "gh":
		ghCmd(a, args)
	case name == "npm" || name == "pnpm" || name == "yarn" || name == "bun":
		if len(pos) > 0 {
			switch pos[0] {
			case "publish":
				a.sink(Egress, name+"_publish", "")
			case "install", "i", "add", "ci", "update", "upgrade":
				a.sink(ExecRemote, "package_install:"+name, strings.Join(pos[1:], " "))
			case "dlx", "exec", "x":
				a.sink(ExecRemote, "run_remote_package:"+name, strings.Join(pos[1:], " "))
			}
		}
	case name == "npx" || name == "bunx" || name == "uvx":
		a.sink(ExecRemote, "run_remote_package:"+name, strings.Join(pos, " "))
	case name == "pip" || name == "pip3" || name == "uv" || name == "pipx" || name == "poetry":
		for i, p := range pos {
			if p == "install" || p == "add" || (name == "pipx" && p == "run") {
				// Only named packages count as targets, not -r requirements.txt or -e .
				a.sink(ExecRemote, "package_install:"+name, strings.Join(namedPackages(args, pos[i+1:]), " "))
				break
			}
			if p == "publish" || p == "upload" {
				a.sink(Egress, name+"_publish", "")
				break
			}
		}
	case name == "twine":
		if len(pos) > 0 && pos[0] == "upload" {
			a.sink(Egress, "twine_upload", "")
		}
	case name == "go" || name == "cargo" || name == "gem":
		if len(pos) > 0 {
			switch pos[0] {
			case "install", "get":
				a.sink(ExecRemote, "package_install:"+name, strings.Join(pos[1:], " "))
			case "publish", "push":
				a.sink(Egress, name+"_publish", "")
			}
		}
	case name == "docker" || name == "podman":
		if len(pos) > 0 && pos[0] == "push" {
			a.sink(Egress, name+"_push", strings.Join(pos[1:], " "))
		}
	case name == "aws" || name == "gsutil" || name == "gcloud" || name == "az" || name == "rclone":
		for _, p := range pos {
			if strings.Contains(p, "://") || strings.Contains(p, "upload") {
				a.sink(Egress, "cloud_copy:"+name, p)
				break
			}
		}
	case name == "winget" || name == "choco" || name == "scoop" || name == "brew" || name == "apt" || name == "apt-get":
		if len(pos) > 0 && (pos[0] == "install" || pos[0] == "add") {
			a.sink(ExecRemote, "package_install:"+name, strings.Join(pos[1:], " "))
		}

	// --- file changes ---
	case name == "rm" || name == "unlink" || name == "rmdir" || name == "shred" || name == "del" || name == "erase" || name == "rd":
		for _, p := range pos {
			a.write(p, "delete", false)
		}
		if name == "shred" || hasFlag(args, 'r', "--recursive") || hasFlag(args, 'R') || hasFlag(args, 0, "/s", "/S") {
			a.sink(Destroy, name+"_recursive", strings.Join(pos, " "))
		}
	case name == "tee":
		for _, p := range pos {
			op := "write"
			if hasFlag(args, 'a', "--append") {
				op = "append"
			}
			a.write(p, op, false)
		}
	case name == "cp" || name == "install" || name == "ln" || name == "copy" || name == "xcopy" || name == "robocopy":
		if len(pos) >= 2 {
			a.write(pos[len(pos)-1], "write", false)
		}
	case name == "mv" || name == "move" || name == "ren" || name == "rename":
		for i, p := range pos {
			op := "delete"
			if i == len(pos)-1 {
				op = "write"
			}
			a.write(p, op, false)
		}
	case name == "touch" || name == "truncate":
		for _, p := range pos {
			a.write(p, "write", false)
		}
	case name == "chmod" || name == "chown" || name == "chattr" || name == "icacls" || name == "attrib":
		for _, p := range pos[min(1, len(pos)):] {
			a.write(p, "perm", false)
		}
	case name == "sed" || name == "perl":
		if hasFlag(args, 'i', "--in-place") || hasPrefixArg(args, "--in-place") {
			files := pos
			if !hasFlag(args, 'e', "--expression") && !hasFlag(args, 'f', "--file") && len(files) > 0 {
				files = files[1:] // first positional is the script
			}
			for _, p := range files {
				a.write(p, "write", false)
			}
		}
	case name == "dd":
		for _, x := range args {
			if v, ok := strings.CutPrefix(x, "of="); ok {
				a.write(v, "write", false)
			}
		}
	case strings.HasPrefix(name, "mkfs") || name == "format" || name == "diskpart" || name == "wipefs":
		a.sink(Destroy, name, strings.Join(pos, " "))
	case name == "find":
		if hasFlag(args, 0, "-delete") {
			a.sink(Destroy, "find_delete", strings.Join(pos, " "))
			for _, p := range pos {
				a.write(p, "delete", false)
			}
		}
		if hasFlag(args, 0, "-exec", "-execdir") {
			for i, x := range args {
				if (x == "-exec" || x == "-execdir") && i+1 < len(args) {
					end := i + 1
					for end < len(args) && args[end] != ";" && args[end] != `\;` && args[end] != "+" {
						end++
					}
					sub := args[i+1 : end]
					command(a, sub, make([]bool, len(sub)), maxDepth, Bash)
				}
			}
		}
	case name == "crontab":
		if !hasFlag(args, 'l') {
			a.sink(Persist, "crontab", "")
		}
	case name == "systemctl" || name == "launchctl":
		for _, p := range pos {
			if p == "enable" || p == "load" || p == "bootstrap" {
				a.sink(Persist, name+"_"+p, strings.Join(pos, " "))
				break
			}
		}
	case name == "schtasks":
		if hasFlag(args, 0, "/create", "/Create", "/CREATE") {
			a.sink(Persist, "schtasks", "")
		}
	case name == "reg":
		if len(pos) > 0 && (strings.EqualFold(pos[0], "add") || strings.EqualFold(pos[0], "import")) {
			a.sink(Persist, "registry", strings.Join(pos[1:min(2, len(pos))], ""))
		}
	case name == "cd" || name == "pushd":
		if len(pos) > 0 {
			a.Cds = append(a.Cds, pos[0])
		}
	case name == "provguard":
		// recorded in Cmds; self-protection decides.
	}
}

// pipValueFlags take a file, path or URL, not a package name.
var pipValueFlags = set("-r", "--requirement", "-c", "--constraint", "-e", "--editable",
	"-f", "--find-links", "-i", "--index-url", "--extra-index-url", "-t", "--target", "--python")

// namedPackages drops values of pipValueFlags and local paths from cands.
func namedPackages(args, cands []string) []string {
	skip := map[string]bool{}
	for i, x := range args {
		if pipValueFlags[x] && i+1 < len(args) {
			skip[args[i+1]] = true
		}
	}
	var out []string
	for _, c := range cands {
		if skip[c] || c == "." || strings.HasPrefix(c, "./") || strings.HasPrefix(c, "../") {
			continue
		}
		out = append(out, c)
	}
	return out
}

func hasPrefixArg(args []string, p string) bool {
	for _, x := range args {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

func isWindowsDrive(p string) bool {
	return len(p) >= 2 && p[1] == ':' && (p[0]|0x20) >= 'a' && (p[0]|0x20) <= 'z'
}

func firstHost(pos []string) string {
	for _, p := range pos {
		if strings.Contains(p, "@") || strings.Contains(p, ".") || strings.Contains(p, ":") {
			return p
		}
	}
	if len(pos) > 0 {
		return pos[0]
	}
	return ""
}

func gitCmd(a *Analysis, args []string) {
	// skip global options: -C <dir>, -c <k=v>, --git-dir=..., etc.
	i := 0
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		if args[i] == "-C" || args[i] == "-c" {
			i++
		}
		i++
	}
	if i >= len(args) {
		return
	}
	sub, rest := args[i], args[i+1:]
	pos := positional(rest)
	switch sub {
	case "push":
		a.sink(Egress, "git_push", strings.Join(pos, " "))
		if hasFlag(rest, 'f', "--force", "--force-with-lease", "--mirror", "--delete") || anyPrefix(pos, "+") || anyPrefix(pos, ":") {
			a.sink(Destroy, "git_force_push", strings.Join(pos, " "))
		}
	case "remote":
		if len(pos) > 0 && (pos[0] == "add" || pos[0] == "set-url") {
			a.sink(Persist, "git_remote_"+pos[0], strings.Join(pos[1:], " "))
		}
	case "config":
		if !hasFlag(rest, 'l', "--get", "--get-all", "--get-regexp", "--list", "--show-origin") && len(pos) >= 2 {
			a.sink(Persist, "git_config", pos[0])
		}
	case "reset":
		if hasFlag(rest, 0, "--hard") {
			a.sink(Destroy, "git_reset_hard", "")
		}
	case "clean":
		if hasFlag(rest, 'f', "--force") {
			a.sink(Destroy, "git_clean", "")
		}
	case "branch":
		if hasFlag(rest, 'D') {
			a.sink(Destroy, "git_branch_delete", strings.Join(pos, " "))
		}
	case "stash":
		if len(pos) > 0 && (pos[0] == "drop" || pos[0] == "clear") {
			a.sink(Destroy, "git_stash_"+pos[0], "")
		}
	case "filter-branch", "filter-repo":
		a.sink(Destroy, "git_"+sub, "")
	}
}

func anyPrefix(xs []string, p string) bool {
	for _, x := range xs {
		if strings.HasPrefix(x, p) {
			return true
		}
	}
	return false
}

// ghWrite: gh subcommands that send data to GitHub (EGRESS).
var ghWrite = map[string]map[string]bool{
	"issue":    set("create", "comment", "edit", "close", "reopen", "transfer"),
	"pr":       set("create", "comment", "edit", "review", "merge", "close"),
	"gist":     set("create", "edit"),
	"release":  set("create", "upload", "edit"),
	"repo":     set("create", "edit", "fork", "rename", "archive"),
	"secret":   set("set"),
	"variable": set("set"),
	"workflow": set("run", "enable"),
}

// ghDestroy: gh subcommands that delete data on GitHub (DESTROY).
// Found live: a loop of `gh repo delete` was classed as EGRESS, so the
// destroy rule did not see it.
var ghDestroy = map[string]map[string]bool{
	"repo":     set("delete"),
	"issue":    set("delete"),
	"gist":     set("delete"),
	"release":  set("delete", "delete-asset"),
	"secret":   set("delete", "remove"),
	"variable": set("delete"),
	"run":      set("delete"),
	"cache":    set("delete"),
	"label":    set("delete"),
	"ssh-key":  set("delete"),
	"gpg-key":  set("delete"),
	"project":  set("delete"),
}

func ghCmd(a *Analysis, args []string) {
	pos := positional(args)
	if len(pos) == 0 {
		return
	}
	if pos[0] == "api" {
		target := ""
		for _, p := range pos[1:] {
			if strings.Contains(p, "/") || strings.Contains(p, "graphql") {
				target = p // the endpoint, not the value of -X
				break
			}
		}
		switch m := apiMethod(args); {
		case m == "DELETE":
			a.sink(Destroy, "gh_api_delete", target)
		case m != "GET" || hasFlag(args, 'f', "--field", "--raw-field", "--input") || hasFlag(args, 'F'):
			a.sink(Egress, "gh_api_write", target)
		}
		return
	}
	if len(pos) < 2 {
		return
	}
	target := strings.Join(pos[2:], " ")
	if ghDestroy[pos[0]][pos[1]] {
		a.sink(Destroy, "gh_"+pos[0]+"_"+pos[1], target)
		return
	}
	if ghWrite[pos[0]][pos[1]] {
		a.sink(Egress, "gh_"+pos[0]+"_"+pos[1], "")
	}
}

// apiMethod returns the upper-case HTTP method of a `gh api` call (default GET).
func apiMethod(args []string) string {
	for i, x := range args {
		if (x == "-X" || x == "--method") && i+1 < len(args) {
			return strings.ToUpper(args[i+1])
		}
		if v, ok := strings.CutPrefix(x, "--method="); ok {
			return strings.ToUpper(v)
		}
	}
	return "GET"
}
