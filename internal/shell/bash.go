package shell

import (
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
				if p := stdinProgram(s); shells[p] || interpreters[p] ||
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
			if body == nil || !isShellStdin(s) {
				continue
			}
			// A shell reads the heredoc as bash; an interpreter (python -,
			// node, perl…) reads it as its own code. Found in review: python
			// heredocs were parsed as bash.
			if name := stdinProgram(s); interpreters[name] {
				v, dyn := b.word(body)
				inlineCode(b.a, name, v, dyn)
			} else {
				b.script(body)
			}
		}
	}
}

// stdinProgram returns the base name of the program that s runs.
func stdinProgram(s *syntax.Stmt) string {
	c, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(c.Args) == 0 {
		return ""
	}
	return baseName(c.Args[0].Lit())
}

// isShellStdin reports whether s runs a shell or interpreter that reads its script from stdin.
func isShellStdin(s *syntax.Stmt) bool {
	c, ok := s.Cmd.(*syntax.CallExpr)
	if !ok || len(c.Args) == 0 {
		return false
	}
	name := baseName(c.Args[0].Lit())
	if !shells[name] && !interpreters[name] {
		return false
	}
	for _, w := range c.Args[1:] {
		l := w.Lit()
		if l == "" || !strings.HasPrefix(l, "-") || l == "-c" || l == "-e" {
			return false // has a script file or inline code
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
		c, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(c.Args) == 0 {
			continue
		}
		name, _ := b.word(c.Args[0])
		name = baseName(name)
		if i > 0 && isShellStdin(st) {
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
				}
			case *syntax.SglQuoted:
				sb.WriteString(x.Value)
				if x.Dollar && strings.Contains(x.Value, `\`) {
					dyn = true // $'..' escapes such as \x41
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

func unescape(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}

func unescapeDq(s string) string {
	if !strings.Contains(s, `\`) {
		return s
	}
	var sb strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' && i+1 < len(s) && strings.IndexByte("$`\"\\\n", s[i+1]) >= 0 {
			i++
			if s[i] == '\n' {
				continue
			}
		}
		sb.WriteByte(s[i])
	}
	return sb.String()
}
