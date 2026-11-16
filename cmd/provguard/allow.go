package main

import (
	"fmt"
	"io"
	"os"
	"time"

	"github.com/durgavarapraveen/provguard/internal/allowonce"
	"github.com/durgavarapraveen/provguard/internal/audit"
)

// runAllow grants one blocked call (provguard allow <token>). Agents cannot
// run it: self-protection denies it in the hook.
func runAllow(args []string, stdout io.Writer) int {
	if len(args) != 1 {
		fmt.Fprintln(os.Stderr, "usage: provguard allow <token>   (the token is in the block message)")
		return 2
	}
	home, err := audit.Home()
	if err != nil {
		fmt.Fprintln(os.Stderr, "provguard:", err)
		return 1
	}
	p, err := allowonce.Grant(home, args[0], time.Now())
	if err != nil {
		fmt.Fprintln(os.Stderr, "provguard:", err)
		return 1
	}
	fmt.Fprintf(stdout, "Allowed once (next 10 minutes):\n  session %s\n  tool    %s\n  rule    %s\n  call    %s\n",
		p.Session, p.Tool, p.Rule, p.Command)
	fmt.Fprintln(stdout, "Ask the agent to run the same call again.")
	return 0
}
