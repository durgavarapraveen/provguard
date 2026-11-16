package shell

import (
	"regexp"
	"strings"
)

// PowerShell has no Go parser, and starting PowerShell to parse costs ~300 ms
// per call. This is a tokenizer-level heuristic: quotes, $(...) subexpressions,
// statements, pipelines, redirects, aliases and named parameters.

var psAlias = map[string]string{
	"iwr": "invoke-webrequest", "irm": "invoke-restmethod", "iex": "invoke-expression",
	"icm": "invoke-command", "sc": "set-content", "ac": "add-content", "ni": "new-item",
	"rm": "remove-item", "ri": "remove-item", "del": "remove-item", "erase": "remove-item",
	"rmdir": "remove-item", "rd": "remove-item", "cp": "copy-item", "copy": "copy-item",
	"cpi": "copy-item", "mv": "move-item", "move": "move-item", "mi": "move-item",
	"ren": "rename-item", "rni": "rename-item", "saps": "start-process", "start": "start-process",
	"cd": "set-location", "sl": "set-location", "chdir": "set-location", "tee": "tee-object",
	"echo": "write-output", "write": "write-output", "sp": "set-itemproperty", "clc": "clear-content",
	// Windows PowerShell 5 aliases curl/wget to Invoke-WebRequest.
	"curl": "invoke-webrequest", "wget": "invoke-webrequest",
}

var (
	psDotNetNet  = regexp.MustCompile(`(?i)net\.webclient|system\.net\.http|net\.sockets|\[system\.net\.dns\]|net\.httpwebrequest`)
	psEncoded    = regexp.MustCompile(`(?i)frombase64string|\[scriptblock\]::create|-encodedcommand\b`)
	psFileMethod = regexp.MustCompile(`(?i)\[(?:system\.)?io\.file\]::(writealltext|writeallbytes|writealllines|appendalltext|appendalllines|delete|move|copy|create|openwrite)\(\s*['"]?([^'",)]+)`)
)

type psTok struct {
	s     string
	dyn   bool
	quote bool
	op    string // ";" "|" "&&" "||" ">" ">>"
}

func analyzePS(a *Analysis, src string, depth int) {
	if psDotNetNet.MatchString(src) {
		a.sink(Egress, "dotnet_network", firstURL([]string{src}))
	}
	if psEncoded.MatchString(src) {
		a.sink(Opaque, "encoded_or_scriptblock", "")
		a.Code = append(a.Code, src)
	}
	for _, m := range psFileMethod.FindAllStringSubmatch(src, -1) {
		op := "write"
		if strings.EqualFold(m[1], "delete") {
			op = "delete"
		}
		a.write(strings.TrimSpace(m[2]), op, strings.Contains(m[2], "$"))
	}

	toks := psTokenize(a, src, depth)
	var stage [][]psTok // current pipeline
	var cur []psTok
	flush := func(endPipeline bool) {
		if len(cur) > 0 {
			stage = append(stage, cur)
			cur = nil
		}
		if endPipeline && len(stage) > 0 {
			psPipeline(a, stage, depth)
			stage = nil
		}
	}
	for _, t := range toks {
		switch t.op {
		case ";", "&&", "||":
			flush(true)
		case "|":
			flush(false)
		default:
			cur = append(cur, t)
		}
	}
	flush(true)
}

func psPipeline(a *Analysis, stages [][]psTok, depth int) {
	fetch := false
	for i, st := range stages {
		name := psStatement(a, st, depth)
		// "Get-ChildItem X -Recurse | Remove-Item" deletes a whole tree.
		if name == "remove-item" && i > 0 && psHasRecurse(stages[i-1]) && !a.Has(Destroy) {
			a.sink(Destroy, "remove_item_recurse", psFirstPositional(stages[i-1]))
		}
		if name == "invoke-expression" && i > 0 {
			if fetch {
				a.sink(ExecRemote, "pipe_to_iex", "")
			} else {
				a.sink(Opaque, "stdin_to_iex", "")
			}
		}
		if httpClients[name] {
			fetch = true
		}
	}
}

// psStatement classifies one pipeline stage and returns its canonical name.
func psStatement(a *Analysis, toks []psTok, depth int) string {
	// redirects
	var words []psTok
	for i := 0; i < len(toks); i++ {
		t := toks[i]
		if t.op == ">" || t.op == ">>" {
			if i+1 < len(toks) {
				op := "write"
				if t.op == ">>" {
					op = "append"
				}
				a.write(toks[i+1].s, op, toks[i+1].dyn)
				i++
			}
			continue
		}
		words = append(words, t)
	}
	if len(words) == 0 {
		return ""
	}
	// call operators: & cmd / . script
	callOp := false
	if (words[0].s == "&" || words[0].s == ".") && !words[0].quote && len(words) > 1 {
		words, callOp = words[1:], true
	}
	first := words[0]
	// "$x = <pipeline>" runs the pipeline. Review finding (CRIT): assignments
	// were skipped as expressions, so `$null = Set-Content …` and
	// `$r = iwr … -InFile .env` were never checked.
	if !callOp {
		if rhs, ok := psAssignmentRHS(words); ok {
			if len(rhs) == 0 {
				return ""
			}
			return psStatement(a, rhs, depth)
		}
	}
	// Without & or ., PowerShell never runs a computed name: a statement that
	// starts with $x, "…", (…), @(…) or [type] is an expression. Their insides
	// were already analyzed by the tokenizer. (Found live: @(…) and
	// ([datetime]$x) were read as unknown commands.)
	if !callOp && (first.dyn || first.quote || strings.HasPrefix(first.s, "$") || strings.HasPrefix(first.s, "[")) {
		return ""
	}
	if psKeywords[strings.ToLower(first.s)] {
		return "" // control flow; its blocks are separate statements
	}
	known := knownProgramPath(first.s)
	if known {
		// & "$env:USERPROFILE\tools\x.exe": the program is x.
		first.dyn, words[0].dyn = false, false
	}
	if first.dyn || callOp && strings.HasPrefix(first.s, "$") && !known {
		a.sink(Opaque, "dynamic_command", first.s)
		a.Cmds = append(a.Cmds, Cmd{Name: first.s, Dynamic: true})
		return ""
	}
	if strings.HasPrefix(first.s, "[") || strings.HasPrefix(first.s, "(") {
		return "" // .NET call or expression; handled by text regexes
	}
	raw := first.s
	name := baseName(raw)
	if c, ok := psAlias[name]; ok && !strings.HasSuffix(strings.ToLower(raw), ".exe") {
		name = c
	}
	args := make([]string, len(words))
	dyn := make([]bool, len(words))
	for i, w := range words {
		args[i], dyn[i] = w.s, w.dyn
	}
	args[0] = name

	params, posArgs := psParams(words[1:])
	get := func(names ...string) (string, bool) {
		if v, ok := psLookup(params, names...); ok {
			return v.s, v.dyn
		}
		return "", false
	}
	pathArg := func(names ...string) (string, bool) {
		if v, d := get(names...); v != "" {
			return v, d
		}
		if len(posArgs) > 0 {
			return posArgs[0].s, posArgs[0].dyn
		}
		return "", false
	}

	switch name {
	case "invoke-webrequest", "invoke-restmethod", "start-bitstransfer":
		a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args})
		u, _ := get("-uri", "-source")
		if u == "" && len(posArgs) > 0 {
			u = posArgs[0].s
		}
		a.sink(Egress, name, u)
		if o, d := get("-outfile", "-destination"); o != "" {
			a.write(o, "write", d)
		}
	case "send-mailmessage":
		a.sink(Egress, name, "")
	case "invoke-expression":
		a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args})
		code, d := pathArg("-command")
		a.Code = append(a.Code, code)
		if code != "" && !d && depth < maxDepth {
			analyzePS(a, code, depth+1)
		} else if code != "" {
			a.sink(Opaque, "invoke_expression", "")
		}
	case "invoke-command":
		a.sink(Opaque, "invoke_command", "")
		a.Code = append(a.Code, strings.Join(args[1:], " "))
	case "start-process":
		a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args})
		fp, d := pathArg("-filepath")
		al, ad := get("-argumentlist")
		// -ArgumentList 'uninstall','--yes' arrives as one token "uninstall,--yes".
		sub := []string{fp}
		for _, x := range strings.FieldsFunc(al, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' }) {
			if x = strings.Trim(x, `'"`); x != "" {
				sub = append(sub, x)
			}
		}
		subd := make([]bool, len(sub))
		subd[0] = d
		for i := 1; i < len(subd); i++ {
			subd[i] = ad
		}
		if fp != "" {
			command(a, sub, subd, depth, PowerShell)
		}
	case "set-location", "push-location":
		if p, _ := pathArg("-path", "-literalpath"); p != "" {
			a.Cds = append(a.Cds, p)
		}
	case "remove-item", "clear-content", "clear-item":
		a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args})
		targets := psAll(params, posArgs, "-path", "-literalpath")
		for _, t := range targets {
			a.write(t.s, "delete", t.dyn)
		}
		if _, ok := psLookup(params, "-recurse"); ok {
			a.sink(Destroy, "remove_item_recurse", joinToks(targets))
		}
	case "set-content", "add-content", "out-file", "new-item", "tee-object", "export-csv", "export-clixml", "set-acl":
		a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args})
		p, d := pathArg("-path", "-filepath", "-literalpath")
		if n, nd := get("-name"); n != "" {
			if p != "" && p != n {
				p, d = joinPath(p, n), d || nd // New-Item -Path DIR -Name FILE
			} else {
				p, d = n, nd
			}
		}
		op := "write"
		if name == "add-content" || hasParam(params, "-append") {
			op = "append"
		}
		a.write(p, op, d)
		if name == "new-item" {
			if t, _ := get("-itemtype", "-type"); strings.Contains(strings.ToLower(t), "link") || strings.EqualFold(t, "junction") {
				tgt, td := get("-target", "-value")
				a.write(tgt, "link", td) // a write through the link reaches the target
			}
		}
	case "expand-archive":
		a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args})
		dst, _ := get("-destinationpath")
		if dst == "" && len(posArgs) > 1 {
			dst = posArgs[1].s
		}
		bulkWrite(a, name, dst)
	case "copy-item", "move-item", "rename-item":
		a.Cmds = append(a.Cmds, Cmd{Name: name, Args: args})
		src, sd := pathArg("-path", "-literalpath")
		dst, dd := get("-destination", "-newname")
		if dst == "" && len(posArgs) > 1 {
			dst, dd = posArgs[1].s, posArgs[1].dyn
		}
		if name != "copy-item" {
			a.write(src, "delete", sd)
		}
		a.write(dst, "write", dd)
	case "register-scheduledtask", "new-scheduledtask", "new-service":
		a.sink(Persist, name, "")
	case "set-itemproperty", "new-itemproperty":
		if p, _ := pathArg("-path", "-literalpath"); strings.Contains(strings.ToLower(p), `\run`) {
			a.sink(Persist, "registry_run", p)
		}
	case "install-module", "install-package", "install-script", "save-module":
		a.sink(ExecRemote, "package_install:"+name, joinToks(posArgs))
	default:
		// Native programs and anything else: shared classifier with wrappers.
		command(a, args, dyn, depth, PowerShell)
		return name
	}
	return name
}

func hasParam(p map[string]psTok, n string) bool { _, ok := p[n]; return ok }

func psHasRecurse(toks []psTok) bool {
	for _, t := range toks {
		if n := strings.ToLower(t.s); !t.quote && len(n) >= 2 && strings.HasPrefix("-recurse", n) {
			return true
		}
	}
	return false
}

func psFirstPositional(toks []psTok) string {
	if len(toks) < 2 {
		return ""
	}
	_, pos := psParams(toks[1:])
	if len(pos) > 0 {
		return pos[0].s
	}
	return ""
}

func joinToks(ts []psTok) string {
	var s []string
	for _, t := range ts {
		s = append(s, t.s)
	}
	return strings.Join(s, " ")
}

var psKeywords = set("if", "elseif", "else", "foreach", "for", "while", "do", "until", "switch",
	"try", "catch", "finally", "function", "filter", "param", "begin", "process", "end",
	"return", "exit", "throw", "break", "continue", "trap", "class", "enum")

// psSwitches never take a value.
var psSwitches = set("-recurse", "-force", "-append", "-nonewline", "-passthru", "-usebasicparsing",
	"-whatif", "-confirm", "-noprofile", "-noninteractive", "-erroraction", "-verbose", "-raw")

var paramName = regexp.MustCompile(`^-[A-Za-z][A-Za-z0-9]*:`)

// psAssignmentRHS returns the tokens after "=" in "$x = …", "$x += …",
// "[type]$x = …" or "$x=…" (no spaces).
func psAssignmentRHS(words []psTok) ([]psTok, bool) {
	first := words[0]
	if first.quote || !(strings.HasPrefix(first.s, "$") || strings.HasPrefix(first.s, "[")) {
		return nil, false
	}
	if len(words) > 1 && !words[1].quote {
		switch words[1].s {
		case "=", "+=", "-=", "*=", "/=", "%=", "??=":
			return words[2:], true
		}
	}
	if i := strings.Index(first.s, "="); i > 0 && strings.HasPrefix(first.s, "$") {
		rest := first.s[i+1:]
		out := append([]psTok{}, words[1:]...)
		if rest != "" {
			out = append([]psTok{{s: rest, dyn: strings.Contains(rest, "$")}}, out...)
		}
		return out, true
	}
	return nil, false
}

// psLookup finds a parameter by full name or by an unambiguous abbreviation
// (PowerShell accepts -Pa for -Path, -Dest for -Destination). Review
// finding: abbreviations hid write targets.
func psLookup(params map[string]psTok, names ...string) (psTok, bool) {
	for _, n := range names {
		if v, ok := params[n]; ok {
			return v, true
		}
	}
	for k, v := range params {
		for _, n := range names {
			if len(k) >= 3 && strings.HasPrefix(n, k) {
				return v, true
			}
			if n == "-recurse" && (k == "-r" || k == "-re") {
				return v, true
			}
		}
	}
	return psTok{}, false
}

// psIsSwitch: a known switch, or an abbreviation of one (-fo for -Force).
func psIsSwitch(n string) bool {
	if psSwitches[n] {
		return true
	}
	if len(n) < 2 {
		return false
	}
	for s := range psSwitches {
		if strings.HasPrefix(s, n) {
			return true
		}
	}
	return false
}

// psParams splits "-Name value" pairs from positional arguments.
func psParams(ts []psTok) (map[string]psTok, []psTok) {
	params := map[string]psTok{}
	var pos []psTok
	for i := 0; i < len(ts); i++ {
		t := ts[i]
		// -Name:value binds even when the value was quoted (-Path:'x').
		if m := paramName.FindString(t.s); m != "" {
			k := strings.ToLower(strings.TrimSuffix(m, ":"))
			params[k] = psTok{s: t.s[len(m):], dyn: t.dyn}
			continue
		}
		if !t.quote && strings.HasPrefix(t.s, "-") && len(t.s) > 1 {
			n := strings.ToLower(t.s)
			if psIsSwitch(n) || i+1 >= len(ts) || (!ts[i+1].quote && strings.HasPrefix(ts[i+1].s, "-")) {
				params[n] = psTok{}
				continue
			}
			params[n] = ts[i+1]
			i++
			continue
		}
		pos = append(pos, t)
	}
	return params, pos
}

func psAll(params map[string]psTok, pos []psTok, names ...string) []psTok {
	var out []psTok
	for _, n := range names {
		if v, ok := psLookup(params, n); ok && v.s != "" {
			for _, part := range strings.Split(v.s, ",") {
				out = append(out, psTok{s: strings.Trim(strings.TrimSpace(part), `'"`), dyn: v.dyn})
			}
		}
	}
	if len(out) == 0 {
		out = append(out, pos...)
	}
	return out
}

// psTokenize splits PowerShell source into words and operators. Quoted text
// stays in one token. $(...) subexpressions are analyzed and marked dynamic.
func psTokenize(a *Analysis, s string, depth int) []psTok {
	var toks []psTok
	var cur strings.Builder
	dyn, quote, has := false, false, false
	emit := func() {
		if has {
			toks = append(toks, psTok{s: cur.String(), dyn: dyn, quote: quote})
		}
		cur.Reset()
		dyn, quote, has = false, false, false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '\'':
			quote, has = true, true
			for i++; i < len(s); i++ {
				if s[i] == '\'' {
					if i+1 < len(s) && s[i+1] == '\'' {
						cur.WriteByte('\'')
						i++
						continue
					}
					break
				}
				cur.WriteByte(s[i])
			}
		case c == '"':
			quote, has = true, true
			for i++; i < len(s) && s[i] != '"'; i++ {
				switch {
				case s[i] == '`' && i+1 < len(s):
					i++
					cur.WriteByte(s[i])
				case s[i] == '$' && i+1 < len(s) && s[i+1] == '(':
					end := matchParen(s, i+1)
					psSubexpr(a, s[i+2:end], depth)
					cur.WriteString("$(...)")
					dyn = true
					i = end
				case s[i] == '$' && i+1 < len(s) && isVarChar(s[i+1]):
					j := i + 1
					for j < len(s) && (isVarChar(s[j]) || s[j] == ':') {
						j++
					}
					cur.WriteString(s[i:j])
					dyn = true
					i = j - 1
				default:
					cur.WriteByte(s[i])
				}
			}
		case c == '`' && i+1 < len(s):
			i++
			if s[i] != '\n' {
				cur.WriteByte(s[i])
				has = true
			}
		case c == '$' && i+1 < len(s) && s[i+1] == '(':
			end := matchParen(s, i+1)
			psSubexpr(a, s[i+2:end], depth)
			cur.WriteString("$(...)")
			dyn, has = true, true
			i = end
		case c == '(' && !has:
			// Grouping expression, e.g. (iwr https://x).Content: analyze inside.
			end := matchParen(s, i)
			psSubexpr(a, s[i+1:end], depth)
			cur.WriteString("(...)")
			dyn, has = true, true
			i = end
		case c == '@' && !has && i+2 < len(s) && (s[i+1] == '\'' || s[i+1] == '"') && (s[i+2] == '\n' || s[i+2] == '\r'):
			// Here-string: @'<newline>…<newline>'@ (or @"…"@). The body is
			// one string, even if it contains quotes or apostrophes.
			q := s[i+1]
			start := i + 2
			if start < len(s) && s[start] == '\r' {
				start++
			}
			if start < len(s) && s[start] == '\n' {
				start++
			}
			end := strings.Index(s[start:], "\n"+string(q)+"@")
			body := ""
			if end < 0 {
				body, i = s[start:], len(s)
			} else {
				body, i = s[start:start+end], start+end+2
			}
			body = strings.TrimSuffix(body, "\r")
			cur.WriteString(body)
			quote, has = true, true
			if q == '"' && strings.Contains(body, "$") {
				dyn = true
			}
		case c == '@' && !has && i+1 < len(s) && s[i+1] == '(':
			// Array subexpression @(...): an expression, not a command.
			// Found live: it was read as an unknown command (OPAQUE).
			end := matchParen(s, i+1)
			psSubexpr(a, s[i+2:end], depth)
			cur.WriteString("(...)")
			dyn, has = true, true
			i = end
		case c == '$' && i+1 < len(s) && isVarChar(s[i+1]):
			j := i + 1
			for j < len(s) && (isVarChar(s[j]) || s[j] == ':') {
				j++
			}
			cur.WriteString(s[i:j])
			dyn, has = true, true
			i = j - 1
		case c == ' ' || c == '\t' || c == '\r':
			emit()
		case c == '\n' || c == ';' || c == '{' || c == '}':
			// Script blocks become separate statements, so commands inside
			// if/foreach/ForEach-Object blocks are analyzed too.
			emit()
			toks = append(toks, psTok{op: ";"})
		case c == '|' && i+1 < len(s) && s[i+1] == '|':
			emit()
			toks = append(toks, psTok{op: "||"})
			i++
		case c == '|':
			emit()
			toks = append(toks, psTok{op: "|"})
		case c == '&' && i+1 < len(s) && s[i+1] == '&':
			emit()
			toks = append(toks, psTok{op: "&&"})
			i++
		case c == '>' || (c >= '1' && c <= '6' || c == '*') && i+1 < len(s) && s[i+1] == '>' && !has:
			emit()
			if c != '>' {
				i++ // n> or *>
			}
			op := ">"
			if i+1 < len(s) && s[i+1] == '>' {
				op = ">>"
				i++
			}
			if i+1 < len(s) && s[i+1] == '&' { // 2>&1
				i += 2
				continue
			}
			toks = append(toks, psTok{op: op})
		case c == '#' && !has:
			for i < len(s) && s[i] != '\n' {
				i++
			}
			i--
		default:
			cur.WriteByte(c)
			has = true
		}
	}
	emit()
	return toks
}

func isVarChar(c byte) bool {
	return c == '_' || c == '{' || c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9'
}

func psSubexpr(a *Analysis, inner string, depth int) {
	if depth < maxDepth {
		analyzePS(a, inner, depth+1)
	}
}

// matchParen returns the index of the ')' matching the '(' at open.
func matchParen(s string, open int) int {
	n := 0
	for i := open; i < len(s); i++ {
		switch s[i] {
		case '(':
			n++
		case ')':
			n--
			if n == 0 {
				return i
			}
		}
	}
	return len(s) - 1
}
