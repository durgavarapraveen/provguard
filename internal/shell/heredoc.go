package shell

import (
	"bytes"
	"strings"

	"mvdan.cc/sh/v3/syntax"
)

// WithoutDataHeredocs returns a shell script with the bodies of its data
// heredocs blanked out, for text scans that look for commands. A heredoc
// is data when:
//   - it feeds cat or tee, and their output goes to a file (cat > f <<EOF);
//   - its body runs nothing: no $(…), `…` or <(…);
//   - the script does not use the target file as a word anywhere else, so
//     it does not run what it wrote (cat > b.sh <<EOF … EOF; bash b.sh).
//
// ok is false when the script does not parse; the caller then scans all of
// it. Line breaks are kept, so offsets and line numbers stay the same.
func WithoutDataHeredocs(src []byte) (out []byte, ok bool) {
	f, err := syntax.NewParser(syntax.Variant(syntax.LangBash)).Parse(bytes.NewReader(src), "")
	if err != nil {
		return nil, false
	}
	// The words of the script as source text, without the words that echo
	// and printf only print. A target file named in any of them (b.sh,
	// ./b.sh, f=b.sh) may be run.
	printed := map[*syntax.Word]bool{}
	syntax.Walk(f, func(n syntax.Node) bool {
		if c, ok := n.(*syntax.CallExpr); ok && len(c.Args) > 0 && (c.Args[0].Lit() == "echo" || c.Args[0].Lit() == "printf") {
			for _, a := range c.Args[1:] {
				printed[a] = true
			}
		}
		return true
	})
	var words []*syntax.Word
	syntax.Walk(f, func(n syntax.Node) bool {
		if w, ok := n.(*syntax.Word); ok && !printed[w] {
			words = append(words, w)
		}
		return true
	})
	text := func(w *syntax.Word) string { return string(src[w.Pos().Offset():w.End().Offset()]) }
	usedElsewhere := func(target *syntax.Word) bool {
		base := strings.Trim(text(target), `"'`)
		if i := strings.LastIndexAny(base, `/\`); i >= 0 {
			base = base[i+1:]
		}
		if base == "" {
			return true
		}
		for _, w := range words {
			if w != target && w.Pos().Offset() != target.Pos().Offset() && strings.Contains(text(w), base) {
				return true
			}
		}
		return false
	}
	out = bytes.Clone(src)
	syntax.Walk(f, func(n syntax.Node) bool {
		st, ok := n.(*syntax.Stmt)
		if !ok {
			return true
		}
		call, ok := st.Cmd.(*syntax.CallExpr)
		if !ok || len(call.Args) == 0 {
			return true
		}
		name := call.Args[0].Lit()
		if name != "cat" && name != "tee" {
			return true
		}
		var target *syntax.Word
		var docs []*syntax.Redirect
		for _, r := range st.Redirs {
			switch r.Op {
			case syntax.RdrOut, syntax.AppOut, syntax.ClbOut:
				target = r.Word
			case syntax.Hdoc, syntax.DashHdoc:
				docs = append(docs, r)
			}
		}
		if name == "tee" && target == nil && len(call.Args) > 1 {
			target = call.Args[len(call.Args)-1]
		}
		if target == nil {
			return true // output goes on, to a pipe or the terminal
		}
		if usedElsewhere(target) {
			return true // the file is used again: it may be run
		}
		for _, r := range docs {
			if r.Hdoc == nil || runsCode(r.Hdoc) {
				continue
			}
			for i := r.Hdoc.Pos().Offset(); i < r.Hdoc.End().Offset() && i < uint(len(out)); i++ {
				if out[i] != '\n' && out[i] != '\r' {
					out[i] = ' '
				}
			}
		}
		return true
	})
	return out, true
}

// runsCode: the word holds a command substitution or process substitution.
func runsCode(w *syntax.Word) bool {
	found := false
	syntax.Walk(w, func(n syntax.Node) bool {
		switch n.(type) {
		case *syntax.CmdSubst, *syntax.ProcSubst:
			found = true
		}
		return !found
	})
	return found
}
