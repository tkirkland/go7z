package oracletest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"hash/crc32"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/tkirkland/go7z/internal/oracle"
	"github.com/tkirkland/go7z/sevenzip"
)

// TreeFile describes one input item for a 7z container check.
type TreeFile struct {
	Name string // relative path with '/'; trailing '/' = directory
	Data []byte
}

// FixedMTime is the modification time given to every tree item so that
// both the oracle and the module see the same metadata.
var FixedMTime = time.Date(2024, 1, 2, 3, 4, 5, 0, time.UTC)

// MakeTree creates the files under dir. Directories are created for
// every parent and for entries ending in '/'. Modification times are
// set to FixedMTime, deepest items first so that directory mtimes stay.
func MakeTree(t testing.TB, dir string, files []TreeFile) {
	t.Helper()
	var paths []string
	for _, f := range files {
		p := filepath.Join(dir, filepath.FromSlash(strings.TrimSuffix(f.Name, "/")))
		if strings.HasSuffix(f.Name, "/") {
			if err := os.MkdirAll(p, 0o755); err != nil {
				t.Fatal(err)
			}
		} else {
			if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(p, f.Data, 0o644); err != nil {
				t.Fatal(err)
			}
		}
		paths = append(paths, p)
	}
	// Set times on everything under dir, children before parents.
	var all []string
	filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if p != dir {
			all = append(all, p)
		}
		return nil
	})
	for i := len(all) - 1; i >= 0; i-- {
		if err := os.Chtimes(all[i], FixedMTime, FixedMTime); err != nil {
			t.Fatal(err)
		}
	}
}

// SevenZCase is one container comparison.
type SevenZCase struct {
	Name   string
	Files  []TreeFile
	Inputs []string // path arguments, relative to the tree root
	Args   []string // extra oracle switches
	Opts   sevenzip.Options
}

// CheckSevenZ creates the tree in dir, writes the archive with the
// oracle and with the module, requires byte identity, and then reads
// the oracle's archive with the module and checks every entry against
// the tree.
func CheckSevenZ(t *testing.T, root, dir string, c SevenZCase) {
	t.Helper()
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	MakeTree(t, tree, c.Files)

	oraclePath := filepath.Join(dir, "oracle.7z")
	args := append([]string{"a", "-t7z"}, c.Args...)
	args = append(args, oraclePath)
	args = append(args, c.Inputs...)
	cmdOut, err := runOracleIn(root, tree, args...)
	if err != nil {
		t.Fatalf("oracle %v: %v\n%s", args, err, cmdOut)
	}
	want, err := os.ReadFile(oraclePath)
	if err != nil {
		t.Fatal(err)
	}

	modulePath := filepath.Join(dir, "module.7z")
	w := sevenzip.NewWriter(c.Opts)
	for _, in := range c.Inputs {
		if err := w.AddPathIn(tree, in); err != nil {
			t.Fatal(err)
		}
	}
	f, err := os.Create(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Write(f); err != nil {
		f.Close()
		t.Fatal(err)
	}
	f.Close()
	got, err := os.ReadFile(modulePath)
	if err != nil {
		t.Fatal(err)
	}
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("%s: archive differs from oracle at byte %d (got %d bytes, want %d)\n%s", c.Name, i, len(got), len(want), describeDiff(got, want, i))
	}

	// Read the oracle's archive with the module.
	a, err := sevenzip.Open(bytes.NewReader(want), int64(len(want)))
	if err != nil {
		t.Fatalf("%s: module cannot open the oracle's archive: %v", c.Name, err)
	}
	expect := map[string]TreeFile{}
	for _, tf := range c.Files {
		expect[strings.TrimSuffix(tf.Name, "/")] = tf
	}
	for i := range a.Entries {
		e := &a.Entries[i]
		data, err := a.Extract(i)
		if err != nil {
			t.Fatalf("%s: extract %s: %v", c.Name, e.Name, err)
		}
		if e.IsDir {
			continue
		}
		p := filepath.Join(tree, filepath.FromSlash(e.Name))
		disk, err := os.ReadFile(p)
		if err != nil {
			t.Fatalf("%s: entry %s not in tree: %v", c.Name, e.Name, err)
		}
		if !bytes.Equal(data, disk) {
			t.Fatalf("%s: entry %s: extracted %d bytes differ from the %d on disk", c.Name, e.Name, len(data), len(disk))
		}
		if e.Size != 0 && (!e.HasCRC || e.CRC != crc32.ChecksumIEEE(disk)) {
			t.Fatalf("%s: entry %s: CRC %08x defined=%v, want %08x", c.Name, e.Name, e.CRC, e.HasCRC, crc32.ChecksumIEEE(disk))
		}
	}
}

// runOracleIn runs the oracle with cwd set to dir (oracle.Run uses dir
// both to locate the binary and as the working directory; the binary is
// found by walking up from root, so pass root for lookup and dir to run).
func runOracleIn(root, dir string, args ...string) ([]byte, error) {
	bin, err := oracle.Binary(root)
	if err != nil {
		return nil, err
	}
	return oracle.RunBinary(bin, dir, args...)
}

// describeDiff shows the bytes around the first difference and, when it
// falls in the header, the two headers.
func describeDiff(got, want []byte, i int) string {
	var sb strings.Builder
	lo := i - 16
	if lo < 0 {
		lo = 0
	}
	hi := func(b []byte) int {
		if i+16 < len(b) {
			return i + 16
		}
		return len(b)
	}
	fmt.Fprintf(&sb, "got  [%d:]: % x\n", lo, got[lo:hi(got)])
	fmt.Fprintf(&sb, "want [%d:]: % x\n", lo, want[lo:hi(want)])
	for _, pair := range []struct {
		name string
		b    []byte
	}{{"got", got}, {"want", want}} {
		if len(pair.b) >= 32 {
			off := binary.LittleEndian.Uint64(pair.b[12:])
			size := binary.LittleEndian.Uint64(pair.b[20:])
			fmt.Fprintf(&sb, "%s: packed %d, next header at %d size %d", pair.name, off, 32+off, size)
			if 32+off+size <= uint64(len(pair.b)) {
				fmt.Fprintf(&sb, ": % x", pair.b[32+off:32+off+size])
			}
			sb.WriteString("\n")
		}
	}
	return sb.String()
}
