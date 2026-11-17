package shell

import (
	"strconv"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

type bashAn struct {
	a     *Analysis
	vars  map[string]string // variables assigned earlier in the same command line
	depth int
	piped map[*syntax.BinaryCmd]bool
}

func analyzeBash(a *Analysis, src string, depth int) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(strings.NewReader(src), "")
	if err != nil {
		if a.ParseError == "" {
			a.ParseError = err.Error()
		}
		a.sink(Opaque, "parse_error", "")
		a.Code = append(a.Code, src)
		return
	}
	b := &bashAn{a: a, vars: map[string]string{}, depth: depth, piped: map[*syntax.BinaryCmd]bool{}}
	syntax.Walk(f, b.visit)
}

func (b *bashAn) visit(n syntax.Node) bool {
	switch x := n.(type) {
	case *syntax.Stmt:
		b.stmt(x)
	case *syntax.CallExpr:
		b.call(x)
	case *syntax.DeclClause:
		for _, as := range x.Args {
			b.assign(as)
		}
	case *syntax.BinaryCmd:
		if (x.Op == syntax.Pipe || x.Op == syntax.PipeAll) && !b.piped[x] {
			b.pipeline(x)
		}
	}
	return true
}

func (b *bashAn) assign(as *syntax.Assign) {
	b.a.Assigns++
	if as == nil || as.Name == nil || as.Value == nil {
		return
	}
	if v, dyn := b.word(as.Value); !dyn {
		b.vars[as.Name.Value] = v
	} else {
		delete(b.vars, as.Name.Value)
	}
}

// stmt handles redirects and here-documents fed to a shell.
func (b *bashAn) stmt(s *syntax.Stmt) {
	for _, r := range s.Redirs {
		// bash opens a network socket for /dev/tcp/HOST/PORT and /dev/udp/...
		// (reverse shells, raw exfil). That is EGRESS, not a file write.
		if r.Word != nil {
			if v, _ := b.word(r.Word); strings.HasPrefix(v, "/dev/tcp/") || strings.HasPrefix(v, "/dev/udp/") {
				target := strings.TrimPrefix(strings.TrimPrefix(v, "/dev/tcp/"), "/dev/udp/")
				b.a.sink(Egress, "dev_tcp", target)
				// A shell or interpreter wired to a socket, or a socket read
				// as input, is a reverse shell: remote code execution.
				if p, _ := b.effective(s); shells[p] || interpreters[p] ||
					r.Op == syntax.RdrIn || r.Op == syntax.RdrInOut || r.Op == syntax.DplIn {
					b.a.sink(ExecRemote, "reverse_shell", target)
				}
				continue
			}
		}
		switch r.Op {
		case syntax.RdrOut, syntax.RdrClob, syntax.RdrAll, syntax.RdrInOut:
			if r.Word != nil {
				v, dyn := b.word(r.Word)
				b.a.write(v, "write", dyn)
			}
		case syntax.DplOut:
			// ">& file" writes stdout and stderr to file; ">&2" is fd duplication.
			if r.Word != nil {
				if v, dyn := b.word(r.Word); v != "-" && strings.Trim(v, "0123456789") != "" {
					b.a.write(v, "write", dyn)
				}
			}
		case syntax.AppOut, syntax.AppAll, syntax.AppClob:
			if r.Word != nil {
				v, dyn := b.word(r.Word)
				b.a.write(v, "append", dyn)
			}
		case syntax.Hdoc, syntax.DashHdoc, syntax.WordHdoc:
			body := r.Hdoc
			if r.Op == syntax.WordHdoc {
				body = r.Word
			}
			if body == nil || !b.stdinShell(s) {
				continue
			}
			// A shell reads the heredoc as bash; an interpreter (python -,
			// node, perl…) reads it as its own code.
			if name, _ := b.effective(s); interpreters[name] {
				v, dyn := b.word(body)
				inlineCode(b.a, name, v, dyn)
			} else {
				b.script(body)
			}
		}
	}
}

// effective returns the program that s really runs and its arguments, after
// resolving quotes and removing prefix wrappers, so `sudo bash <<EOF`,
// `curl … | sudo bash` and `"bash" <<EOF` all resolve to bash.
func (b *bashAn) effective(s *syntax.Stmt) (string, []string) {
	c, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(c.Args) == 0 {
		return "", nil
	}
	args := make([]string, len(c.Args))
	for i, w := range c.Args {
		args[i], _ = b.word(w)
	}
	for len(args) > 0 {
		name := baseName(args[0])
		if !prefixes[name] {
			return name, args[1:]
		}
		args = args[1+skipPrefixOpts(name, args[1:]):]
	}
	return "", nil
}

// stdinShell reports whether s runs a shell or interpreter that reads its
// script from stdin (no script file and no inline code).
func (b *bashAn) stdinShell(s *syntax.Stmt) bool {
	name, rest := b.effective(s)
	if !shells[name] && !interpreters[name] {
		return false
	}
	for _, x := range rest {
		if x == "-" {
			continue
		}
		if !strings.HasPrefix(x, "-") || x == "-c" || x == "-e" || x == "--eval" {
			return false
		}
	}
	return true
}

func (b *bashAn) script(w *syntax.Word) {
	v, dyn := b.word(w)
	if dyn || b.depth >= maxDepth {
		b.a.sink(Opaque, "dynamic_script", "")
		b.a.Code = append(b.a.Code, v)
		return
	}
	analyzeBash(b.a, v, b.depth+1)
}

func (b *bashAn) call(c *syntax.CallExpr) {
	for _, as := range c.Assigns {
		b.assign(as)
	}
	if len(c.Args) == 0 {
		return
	}
	args := make([]string, len(c.Args))
	dyn := make([]bool, len(c.Args))
	for i, w := range c.Args {
		args[i], dyn[i] = b.word(w)
	}
	command(b.a, args, dyn, b.depth, Bash)
}

// pipeline detects "something | sh" style pipes.
func (b *bashAn) pipeline(x *syntax.BinaryCmd) {
	var stages []*syntax.Stmt
	var flatten func(*syntax.BinaryCmd)
	flatten = func(p *syntax.BinaryCmd) {
		b.piped[p] = true
		if l, ok := p.X.Cmd.(*syntax.BinaryCmd); ok && (l.Op == syntax.Pipe || l.Op == syntax.PipeAll) {
			flatten(l)
		} else {
			stages = append(stages, p.X)
		}
		stages = append(stages, p.Y)
	}
	flatten(x)

	fetch, decode := false, false
	for i, st := range stages {
		name, _ := b.effective(st)
		if name == "" {
			continue
		}
		if i > 0 && b.stdinShell(st) {
			switch {
			case fetch:
				b.a.sink(ExecRemote, "pipe_to_"+name, "")
			case decode:
				b.a.sink(Opaque, "decoded_to_"+name, "")
			default:
				b.a.sink(Opaque, "stdin_to_"+name, "")
			}
		}
		if httpClients[name] || rawSockets[name] {
			fetch = true
		}
		if decoders[name] {
			decode = true
		}
	}
}

// word resolves a shell word to a string. dyn is true when part of it is
// only known at run time; such parts appear as "$NAME" or "$(...)".
func (b *bashAn) word(w *syntax.Word) (string, bool) {
	var sb strings.Builder
	dyn := false
	var parts func([]syntax.WordPart, bool)
	parts = func(ps []syntax.WordPart, quoted bool) {
		for _, p := range ps {
			switch x := p.(type) {
			case *syntax.Lit:
				if quoted {
					sb.WriteString(unescapeDq(x.Value))
				} else {
					sb.WriteString(unescape(x.Value))
					// An unquoted glob expands at run time (.cla?de, settings.jso[n]).
					// Keep the pattern text (callers can match it) but mark it dynamic.
					if strings.ContainsAny(x.Value, "*?[") {
						dyn = true
					}
				}
			case *syntax.SglQuoted:
				if x.Dollar {
					sb.WriteString(decodeANSIC(x.Value)) // $'\x61' → "a"
				} else {
					sb.WriteString(x.Value)
				}
			case *syntax.DblQuoted:
				parts(x.Parts, true)
			case *syntax.ParamExp:
				name := ""
				if x.Param != nil {
					name = x.Param.Value
				}
				simple := x.Exp == nil && x.Repl == nil && x.Slice == nil && x.Index == nil && !x.Length && !x.Excl
				if v, ok := b.vars[name]; ok && simple {
					sb.WriteString(v)
				} else {
					sb.WriteString("$" + name)
					dyn = true
				}
			case *syntax.CmdSubst:
				sb.WriteString("$(...)")
				dyn = true
			case *syntax.ProcSubst:
				sb.WriteString("<(...)")
				dyn = true
			default: // arithmetic, globs, brace expansion
				dyn = true
				sb.WriteString("$?")
			}
		}
	}
	parts(w.Parts, false)
	return sb.String(), dyn
}

// decodeANSIC decodes bash $'...' escapes, so $'.cl\x61ude' reads as ".claude".
func decodeANSIC(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	simple := map[byte]string{'a': "\a", 'b': "\b", 'e': "\x1b", 'E': "\x1b", 'f': "\f", 'n': "\n",
		'r': "\r", 't': "\t", 'v': "\v", '\\': `\`, '\'': "'", '"': `"`, '?': "?"}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] != '\\' || i+1 >= len(s) {
			sb.WriteByte(s[i])
			continue
		}
		c := s[i+1]
		if r, ok := simple[c]; ok {
			sb.WriteString(r)
			i++
			continue
		}
		hexN := map[byte]int{'x': 2, 'u': 4, 'U': 8}[c]
		if hexN > 0 {
			j := i + 2
			for j < len(s) && j < i+2+hexN && isHex(s[j]) {
				j++
			}
			if j > i+2 {
				if v, err := strconv.ParseUint(s[i+2:j], 16, 32); err == nil {
					sb.WriteRune(rune(v))
					i = j - 1
					continue
				}
			}
		}
		if c >= '0' && c <= '7' { // octal \nnn
			j := i + 1
			for j < len(s) && j < i+4 && s[j] >= '0' && s[j] <= '7' {
				j++
			}
			if v, err := strconv.ParseUint(s[i+1:j], 8, 8); err == nil {
				sb.WriteByte(byte(v))
				i = j - 1
				continue
			}
		}
		if c == 'c' && i+2 < len(s) { // \cX control character
			sb.WriteByte(s[i+2] & 0x1f)
			i += 2
			continue
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func isHex(c byte) bool {
	return c >= '0' && c <= '9' || c >= 'a' && c <= 'f' || c >= 'A' && c <= 'F'
}

// unescape removes backslash escapes from an unquoted word.
func unescape(s string) string { return unescapeOnly(s, "") }

// unescapeDq removes the backslash escapes that work inside double quotes.
func unescapeDq(s string) string { return unescapeOnly(s, "$`\"\\\n") }

// unescapeOnly removes a backslash before any character in only (before
// every character when only is ""); a backslash-newline is removed whole.
func unescapeOnly(s, only string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && (only == "" || strings.IndexByte(only, s[i+1]) >= 0) {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}
