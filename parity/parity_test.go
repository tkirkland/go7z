//go:build oracle

package parity

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkirkland/go7z/internal/oracle"
)

// Env is what one line check gets: the repo root and the verified oracle.
type Env struct {
	Root   string
	Oracle string
}

// LineCheck proves one parity line. It fails the test via t.Error when the
// module's behaviour differs from the oracle's.
type LineCheck struct {
	Name  string
	Check func(t *testing.T, env *Env)
}

// checks holds the done lines. Every checklist line adds its entry here.
var checks = map[string]LineCheck{}

// TestParity walks every line of both fixture lists. Each line is a pass or
// a fail, and the test prints "parity: N of M" at the end. Parity is M of M.
func TestParity(t *testing.T) {
	root := repoRoot(t)
	entries := loadEntries(t, root)

	bin, oerr := oracle.Binary(root)
	env := &Env{Root: root, Oracle: bin}

	// Fixture integrity: the committed fixtures must equal the live oracle
	// output byte for byte, otherwise every walked line is untrustworthy.
	if oerr == nil {
		for _, fx := range []struct {
			file string
			args []string
		}{
			{"7zr-i.txt", []string{"i"}},
			{"7zr-usage.txt", nil},
		} {
			got, err := oracle.Run(root, fx.args...)
			want, rerr := os.ReadFile(filepath.Join(root, "testdata", "parity", fx.file))
			if err != nil || rerr != nil || !bytes.Equal(got, want) {
				oerr = fmt.Errorf("fixture %s differs from live oracle output (runErr=%v readErr=%v)", fx.file, err, rerr)
				break
			}
		}
	}

	pass := 0
	total := len(entries)
	var failures []string
	for _, e := range entries {
		ok := t.Run(e.Key, func(t *testing.T) {
			if oerr != nil {
				t.Errorf("oracle/fixture problem: %v", oerr)
				return
			}
			ch, found := checks[e.Key]
			if !found {
				t.Errorf("not done")
				return
			}
			ch.Check(t, env)
		})
		if ok {
			pass++
		} else {
			failures = append(failures, e.Key)
		}
	}
	t.Logf("parity: %d of %d", pass, total)
	if len(failures) > 0 {
		t.Logf("failing lines: %s", strings.Join(failures, ", "))
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

func loadEntries(t *testing.T, root string) []Entry {
	t.Helper()
	i, err := os.ReadFile(filepath.Join(root, "testdata", "parity", "7zr-i.txt"))
	if err != nil {
		t.Fatalf("read 7zr-i.txt: %v", err)
	}
	u, err := os.ReadFile(filepath.Join(root, "testdata", "parity", "7zr-usage.txt"))
	if err != nil {
		t.Fatalf("read 7zr-usage.txt: %v", err)
	}
	inv, err := ParseInventory(i)
	if err != nil {
		t.Fatalf("parse 7zr-i.txt: %v", err)
	}
	usage, err := ParseUsage(u)
	if err != nil {
		t.Fatalf("parse 7zr-usage.txt: %v", err)
	}
	entries := append(inv, usage...)
	if len(entries) == 0 {
		t.Fatalf("no parity entries parsed")
	}
	return entries
}
