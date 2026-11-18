//go:build !windows

package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// On macOS and Linux the PATH comes from the shell's start-up file. provguard
// adds one line, tagged so that uninstall removes exactly that line. fish
// gets a file of its own in conf.d.

const pathTag = "# added by provguard"

// userPathFoldCase: PATH entries are case-sensitive on macOS and Linux.
const userPathFoldCase = false

// shellStartFile returns the start-up file of the user's login shell and the
// line that puts dir on PATH there.
func shellStartFile(home, shell, dir string) (file, line string) {
	switch filepath.Base(shell) {
	case "fish":
		return filepath.Join(home, ".config", "fish", "conf.d", "provguard.fish"),
			"fish_add_path " + shellQuote(dir) + " " + pathTag
	case "zsh":
		file = filepath.Join(home, ".zshrc")
	case "bash":
		file = filepath.Join(home, ".bashrc")
		if runtime.GOOS == "darwin" {
			file = filepath.Join(home, ".bash_profile") // Terminal.app starts login shells
		}
	default:
		file = filepath.Join(home, ".profile")
	}
	return file, "export PATH=" + shellQuote(dir) + `:"$PATH" ` + pathTag
}

func shellQuote(s string) string { return "'" + strings.ReplaceAll(s, "'", `'\''`) + "'" }

func userHomeAndShell() (string, string) {
	h, _ := os.UserHomeDir()
	return h, os.Getenv("SHELL")
}

func userPathHas(dir string) bool {
	if pathListHas(os.Getenv("PATH"), dir, ":", false) {
		return true
	}
	home, shell := userHomeAndShell()
	file, _ := shellStartFile(home, shell, dir)
	b, err := os.ReadFile(file)
	return err == nil && strings.Contains(string(b), pathTag)
}

func userPathAdd(dir string) (string, error) {
	home, shell := userHomeAndShell()
	return addStartLine(home, shell, dir)
}

func userPathRemove(dir string) error {
	home, shell := userHomeAndShell()
	return removeStartLines(home, shell, dir)
}

// addStartLine appends the PATH line once and returns the file it changed.
func addStartLine(home, shell, dir string) (string, error) {
	file, line := shellStartFile(home, shell, dir)
	b, err := os.ReadFile(file)
	if err != nil && !os.IsNotExist(err) {
		return "", err
	}
	if strings.Contains(string(b), pathTag) {
		return file, nil
	}
	if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
		return "", err
	}
	text := string(b)
	if text != "" && !strings.HasSuffix(text, "\n") {
		text += "\n"
	}
	return file, os.WriteFile(file, []byte(text+line+"\n"), 0o644)
}

// removeStartLines removes provguard's tagged lines from the start-up files
// it may have written (all of them: the login shell may have changed).
func removeStartLines(home, shell, dir string) error {
	var errs []error
	for _, sh := range []string{shell, "zsh", "bash", "fish", "sh"} {
		file, _ := shellStartFile(home, sh, dir)
		b, err := os.ReadFile(file)
		if err != nil || !strings.Contains(string(b), pathTag) {
			continue
		}
		var keep []string
		for _, l := range strings.SplitAfter(string(b), "\n") {
			if !strings.Contains(l, pathTag) {
				keep = append(keep, l)
			}
		}
		rest := strings.Join(keep, "")
		if strings.TrimSpace(rest) == "" && filepath.Base(file) == "provguard.fish" {
			errs = append(errs, os.Remove(file))
			continue
		}
		errs = append(errs, os.WriteFile(file, []byte(rest), 0o644))
	}
	for _, e := range errs {
		if e != nil {
			return e
		}
	}
	return nil
}
