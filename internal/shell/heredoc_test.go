package shell

import (
	"strings"
	"testing"
)

func TestWithoutDataHeredocs(t *testing.T) {
	cases := []struct {
		name, src string
		kept      bool // the marker text "SECRET_TEXT" is still scanned
	}{
		{"data to a file", "cat > out.rb <<EOF\nSECRET_TEXT\nEOF\n", false},
		{"quoted data", "cat > out.txt <<'EOF'\nSECRET_TEXT\nEOF\n", false},
		{"append", "cat >> notes.md <<-EOF\n\tSECRET_TEXT\n\tEOF\n", false},
		{"tee to a file", "tee out.yaml >/dev/null <<EOF\nSECRET_TEXT\nEOF\n", false},
		{"variable target", "cat > \"$w/$id.yaml\" <<YAML\nSECRET_TEXT $id\nYAML\n", false},
		{"command substitution runs", "cat > out <<EOF\n$(SECRET_TEXT)\nEOF\n", true},
		{"backticks run", "cat > out <<EOF\n`SECRET_TEXT`\nEOF\n", true},
		{"written then run", "cat > b.sh <<EOF\nSECRET_TEXT\nEOF\nbash b.sh\n", true},
		{"written then run by path", "cat > b.sh <<EOF\nSECRET_TEXT\nEOF\n./b.sh\n", true},
		{"written then run by variable", "cat > \"$d/b.sh\" <<EOF\nSECRET_TEXT\nEOF\nf=$d/b.sh\nsh \"$f\"\n", true},
		{"written, only named by echo", "cat > out.rb <<EOF\nSECRET_TEXT\nEOF\necho \"wrote out.rb\"\n", false},
		{"to a shell", "bash <<EOF\nSECRET_TEXT\nEOF\n", true},
		{"cat to the terminal", "cat <<EOF\nSECRET_TEXT\nEOF\n", true},
		{"cat into a pipe", "cat <<EOF | sh\nSECRET_TEXT\nEOF\n", true},
		{"plain command", "SECRET_TEXT --yes\n", true},
	}
	for _, c := range cases {
		out, ok := WithoutDataHeredocs([]byte(c.src))
		if !ok {
			t.Errorf("%s: did not parse", c.name)
			continue
		}
		if got := strings.Contains(string(out), "SECRET_TEXT"); got != c.kept {
			t.Errorf("%s: kept = %v, want %v\n%s", c.name, got, c.kept, out)
		}
		if len(out) != len(c.src) || strings.Count(string(out), "\n") != strings.Count(c.src, "\n") {
			t.Errorf("%s: length or lines changed", c.name)
		}
	}
	if _, ok := WithoutDataHeredocs([]byte("if then fi ((")); ok {
		t.Error("broken script: want ok = false")
	}
}
