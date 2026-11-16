package main

import (
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/durgavarapraveen/provguard/internal/audit"
	"github.com/durgavarapraveen/provguard/internal/config"
)

// nudgeAfter is how long provguard watches in audit mode before it suggests
// a review, once.
const nudgeAfter = 3 * 24 * time.Hour

// auditNudge returns a one-time session-start notice for users who are
// still in audit (watch-only) mode after a few days, or "".
func auditNudge(home string, cfg config.Config, now time.Time) string {
	if cfg.ProfileName() != config.Audit {
		return ""
	}
	marker := filepath.Join(home, "review-nudged")
	if _, err := os.Stat(marker); err == nil {
		return ""
	}
	first, ok := audit.FirstDay(home)
	if !ok || now.Sub(first) < nudgeAfter {
		return ""
	}
	// O_EXCL: two sessions starting together show the notice once.
	f, err := os.OpenFile(marker, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return ""
	}
	f.Close()

	recs, _ := audit.Read(home, first, func(r *audit.Record) bool { return r.Stopped() })
	days := int(now.Sub(first).Hours() / 24)
	if len(recs) == 0 {
		return fmt.Sprintf("provguard has watched for %d days and saw nothing risky. Turn protection on: provguard config mode balanced", days)
	}
	return fmt.Sprintf("provguard has watched for %d days (log only) and would have stopped or asked about %s. See them: provguard review", days, plural(len(recs), "call"))
}

// plural returns "1 call", "2 calls".
func plural(n int, word string) string {
	if n == 1 {
		return "1 " + word
	}
	return fmt.Sprintf("%d %ss", n, word)
}
