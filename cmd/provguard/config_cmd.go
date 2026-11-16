package main

import (
	"errors"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
)

const configUsage = `usage:
  provguard config                              show the settings
  provguard config mode audit|balanced|strict   how much provguard stops
  provguard config on-block deny|ask            balanced: block a leak, or ask you
  provguard config trust-owner NAME [--remove]  repos owned by NAME count as yours
  provguard config allow-host HOST [--remove]   never block data sent to HOST
  provguard config trust-site HOST [--remove]   pages from HOST do not make a session untrusted
  provguard config trust-mcp NAME [--remove]    output of MCP server NAME is trusted
`

// listSetting is a config key that holds a list of names.
type listSetting struct {
	field     func(*config.Config) *[]string
	normalize func(string) (string, error)
	added     string // message after adding, %s = value
}

var listSettings = map[string]listSetting{
	"trust-owner": {
		field:     func(c *config.Config) *[]string { return &c.TrustedRepoOwners },
		normalize: config.NormalizeOwner,
		added:     "Files in git repos owned by %s are now trusted.",
	},
	"allow-host": {
		field:     func(c *config.Config) *[]string { return &c.AllowedHosts },
		normalize: config.NormalizeHost,
		added:     "Data sent to %s (and its subdomains) is no longer blocked.",
	},
	"trust-site": {
		field:     func(c *config.Config) *[]string { return &c.TrustedContentHosts },
		normalize: config.NormalizeHost,
		added:     "Pages read from %s no longer mark a session untrusted. Add only sites where nobody else can publish.",
	},
	"trust-mcp": {
		field:     func(c *config.Config) *[]string { return &c.TrustedMCPServers },
		normalize: config.NormalizeMCPServer,
		added:     "Output from the MCP server %s is now trusted.",
	},
}

// runConfig shows or changes ~/.provguard/config.json. Agents cannot run the
// forms that change it: self-protection denies them in the hook.
func runConfig(args []string, stdout, stderr io.Writer) int {
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(stderr, "provguard:", err)
		return 1
	}
	if len(args) == 0 {
		return showConfig(home, stdout, stderr)
	}
	msg, err := changeConfig(home, args)
	if errors.Is(err, errUsage) {
		fmt.Fprint(stderr, configUsage)
		return 2
	}
	if err != nil {
		fmt.Fprintln(stderr, "provguard:", err)
		return 1
	}
	fmt.Fprintln(stdout, msg)
	return 0
}

var errUsage = errors.New("usage")

// changeConfig applies one change and returns the message for the user.
func changeConfig(home string, args []string) (string, error) {
	key, rest := args[0], args[1:]
	remove := false
	if n := len(rest); n > 0 && rest[n-1] == "--remove" {
		remove, rest = true, rest[:n-1]
	}
	if len(rest) != 1 {
		return "", errUsage
	}
	value := rest[0]

	var msg string
	_, err := config.Update(home, func(c *config.Config) error {
		switch key {
		case "mode":
			if remove {
				return errUsage
			}
			if err := c.SetProfile(value); err != nil {
				return err
			}
			msg = fmt.Sprintf("Mode: %s (%s).", c.ProfileName(), config.Describe(c.ProfileName()))
			return nil
		case "on-block":
			if remove {
				return errUsage
			}
			if err := c.SetBlockMode(value); err != nil {
				return err
			}
			msg = "When provguard stops a leak, it now " + map[bool]string{true: "asks you.", false: "blocks it."}[c.BlockAsks()]
			if c.ProfileName() != config.Balanced {
				msg += " (This applies in balanced mode; the mode is " + c.ProfileName() + ".)"
			}
			return nil
		}
		ls, ok := listSettings[key]
		if !ok {
			return errUsage
		}
		v, err := ls.normalize(value)
		if err != nil {
			return err
		}
		list := ls.field(c)
		switch {
		case remove && config.RemoveFrom(list, v):
			msg = "Removed " + v + "."
		case remove:
			msg = v + " was not in the list."
		case config.AddTo(list, v):
			msg = fmt.Sprintf(ls.added, v)
		default:
			msg = v + " is already in the list."
		}
		return nil
	})
	return msg, err
}

func showConfig(home string, w, stderr io.Writer) int {
	c, err := config.Load(home)
	if err != nil {
		fmt.Fprintln(stderr, "provguard:", err)
		fmt.Fprintln(stderr, "Until you fix it, provguard runs in balanced mode.")
		return 1
	}
	if !c.ProfileKnown() {
		fmt.Fprintf(w, "warning: unknown mode %q; provguard runs in balanced mode.\n\n", c.Profile)
	}
	p := c.ProfileName()
	onBlock := "block"
	if c.BlockAsks() {
		onBlock = "ask you"
	}
	rows := [][2]string{
		{"mode", p + "  (" + config.Describe(p) + ")"},
		{"on-block", onBlock + "  (balanced mode only)"},
		{"trust-owner", list(c.TrustedRepoOwners, "none: every repo you did not write counts as untrusted")},
		{"allow-host", list(c.AllowedHosts, "none: sending data out is checked for every host")},
		{"trust-site", list(c.TrustedContentHosts, "none: every web page counts as untrusted")},
		{"trust-mcp", list(c.TrustedMCPServers, "none")},
	}
	for _, r := range rows {
		fmt.Fprintf(w, "%-12s %s\n", r[0], r[1])
	}
	fmt.Fprintf(w, "\nFile: %s\nChange a setting: provguard config <setting> <value>\n", config.Path(home))
	if _, err := os.Stat(config.Path(home)); errors.Is(err, os.ErrNotExist) {
		fmt.Fprintln(w, "(The file does not exist yet; these are the defaults.)")
	}
	return 0
}

func list(xs []string, empty string) string {
	if len(xs) == 0 {
		return empty
	}
	return strings.Join(xs, ", ")
}
