//go:build sot

package parity

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
)

// Env is what one line check gets: the repo root, the lane and the
// lane's verified SoT.
type Env struct {
	Root string
	Lane sot.Lane
	SoT  string
}

// LineCheck proves one parity line in one lane. It fails the test via
// t.Error when the module's behaviour differs from the lane's SoT.
type LineCheck struct {
	Name  string
	Check func(t *testing.T, env *Env)
}

// checks holds the done lines. Every checklist line adds its entry here;
// the same check runs in both lanes.
var checks = map[string]LineCheck{}

// TestParity walks every line of both lanes' fixture lists, subtests
// 32/<key> and 64/<key>. Each line is a pass or a fail in each lane, and
// the test prints "parity 32: N of M" and "parity 64: N of M" at the
// end, then the omitted, blocked and failing lines by name. Parity is
// M of M in both lanes. A line that a -run filter leaves out is not run
// and is neither counted nor a pass; the counts are only the scoreboard
// when the whole test runs.
func TestParity(t *testing.T) {
	root := repoRoot(t)
	type result struct {
		pass, total int
		failures    []string
		omitted     []string
		blocked     []string
		notRun      int
	}
	results := map[sot.Lane]*result{}
	for _, lane := range sot.Lanes {
		lane := lane
		r := &result{}
		results[lane] = r
		t.Run(lane.String(), func(t *testing.T) {
			entries := loadEntries(t, root, lane)
			bin, oerr := sot.Binary(root, lane)
			env := &Env{Root: root, Lane: lane, SoT: bin}

			// Fixture integrity: the committed fixtures must equal the
			// lane's live SoT output byte for byte, otherwise every
			// walked line is untrustworthy.
			if oerr == nil {
				inv, usage := Fixtures(lane)
				for _, fx := range []struct {
					file string
					args []string
				}{
					{inv, []string{"i"}},
					{usage, nil},
				} {
					got, err := sot.Run(root, lane, fx.args...)
					want, rerr := os.ReadFile(filepath.Join(root, "testdata", "parity", fx.file))
					if err != nil || rerr != nil || !bytes.Equal(got, want) {
						oerr = fmt.Errorf("fixture %s differs from live SoT output (runErr=%v readErr=%v)", fx.file, err, rerr)
						break
					}
				}
			}

			for _, e := range entries {
				if _, skip := Omitted[e.Key]; skip {
					r.omitted = append(r.omitted, e.Key)
					continue
				}
				ran := false
				ok := t.Run(e.Key, func(t *testing.T) {
					ran = true
					if oerr != nil {
						t.Errorf("SoT/fixture problem: %v", oerr)
						return
					}
					if reason, blocked := Blocked[e.Key]; blocked {
						t.Error(reason)
						return
					}
					ch, found := checks[e.Key]
					if !found {
						t.Errorf("not done")
						return
					}
					ch.Check(t, env)
				})
				if !ran {
					r.notRun++
					continue
				}
				r.total++
				if ok {
					r.pass++
				} else {
					r.failures = append(r.failures, e.Key)
					if _, blocked := Blocked[e.Key]; blocked {
						r.blocked = append(r.blocked, e.Key)
					}
				}
			}
		})
	}
	for _, lane := range sot.Lanes {
		r := results[lane]
		if r.notRun > 0 {
			t.Logf("parity %s: %d of %d run (%d lines filtered out by -run; not a scoreboard)", lane, r.pass, r.total, r.notRun)
			continue
		}
		t.Logf("parity %s: %d of %d", lane, r.pass, r.total)
	}
	for _, lane := range sot.Lanes {
		r := results[lane]
		if len(r.omitted) > 0 {
			t.Logf("lane %s omitted lines (not counted): %s", lane, strings.Join(r.omitted, ", "))
		}
		if len(r.blocked) > 0 {
			t.Logf("lane %s blocked lines (counted as failures): %s", lane, strings.Join(r.blocked, ", "))
		}
		if len(r.failures) > 0 {
			t.Logf("lane %s failing lines: %s", lane, strings.Join(r.failures, ", "))
		}
	}
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("os.Getwd: %v", err)
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
	}
	t.Fatalf("go.mod not found at or above %s", wd)
	return ""
}

func loadEntries(t *testing.T, root string, lane sot.Lane) []Entry {
	t.Helper()
	invFile, usageFile := Fixtures(lane)
	i, err := os.ReadFile(filepath.Join(root, "testdata", "parity", invFile))
	if err != nil {
		t.Fatalf("read %s: %v", invFile, err)
	}
	u, err := os.ReadFile(filepath.Join(root, "testdata", "parity", usageFile))
	if err != nil {
		t.Fatalf("read %s: %v", usageFile, err)
	}
	inv, err := ParseInventory(invFile, i)
	if err != nil {
		t.Fatalf("parse %s: %v", invFile, err)
	}
	usage, err := ParseUsage(usageFile, u)
	if err != nil {
		t.Fatalf("parse %s: %v", usageFile, err)
	}
	entries := append(inv, usage...)
	if len(entries) == 0 {
		t.Fatalf("no parity entries parsed")
	}
	return entries
}
