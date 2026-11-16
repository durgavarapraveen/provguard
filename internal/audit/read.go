package audit

import (
	"bufio"
	"encoding/json"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const dayLayout = "2006-01-02"

// Read returns the records of the daily logs dated since or later (UTC
// days), oldest first, for which keep returns true (nil keeps all). Lines
// that do not parse are skipped: a log cut short by a crash must not hide
// the rest.
func Read(home string, since time.Time, keep func(*Record) bool) ([]Record, error) {
	files, err := filepath.Glob(filepath.Join(home, "audit", "*.jsonl"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files) // file names are dates, so this is time order
	first := since.UTC().Format(dayLayout)
	var out []Record
	for _, f := range files {
		if strings.TrimSuffix(filepath.Base(f), ".jsonl") < first {
			continue
		}
		recs, err := readFile(f, keep)
		if err != nil {
			return nil, err
		}
		out = append(out, recs...)
	}
	return out, nil
}

func readFile(name string, keep func(*Record) bool) ([]Record, error) {
	f, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	var out []Record
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 64<<10), 8<<20)
	for sc.Scan() {
		var r Record
		if json.Unmarshal(sc.Bytes(), &r) == nil && (keep == nil || keep(&r)) {
			out = append(out, r)
		}
	}
	return out, sc.Err()
}

// FirstDay returns the date of the oldest daily log, or false if there is none.
func FirstDay(home string) (time.Time, bool) {
	files, _ := filepath.Glob(filepath.Join(home, "audit", "*.jsonl"))
	var first time.Time
	for _, f := range files {
		d, err := time.Parse(dayLayout, strings.TrimSuffix(filepath.Base(f), ".jsonl"))
		if err == nil && (first.IsZero() || d.Before(first)) {
			first = d
		}
	}
	return first, !first.IsZero()
}

// Stopped reports whether a PreToolUse record was, or in audit mode would
// have been, stopped or asked about.
func (r *Record) Stopped() bool {
	return r.Event == "PreToolUse" &&
		(r.Would == "deny" || r.Would == "ask" || r.Decision == "deny" || r.Decision == "ask")
}

// Outcome is "deny", "ask" or "" for a PreToolUse record: what happened, or
// in audit mode what would have happened.
func (r *Record) Outcome() string {
	if r.Decision == "deny" || r.Decision == "ask" {
		return r.Decision
	}
	if r.Would == "deny" || r.Would == "ask" {
		return r.Would
	}
	return ""
}
