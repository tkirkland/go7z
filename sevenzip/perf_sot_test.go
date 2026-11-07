//go:build sot

package sevenzip_test

import (
	"fmt"
	"math/rand"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
	"github.com/tkirkland/go7z/sevenzip"
)

// TestPerfVsSoT times the module's writer against 7zr on the same
// input and prints both. It is a measurement, not a check.
func TestPerfVsSoT(t *testing.T) {
	root := sottest.RepoRoot(t)
	bin, err := sot.Binary(root)
	if err != nil {
		t.Fatal(err)
	}
	words := []string{"the", "quick", "brown", "fox", "jumps", "over", "lazy", "dog", "lorem", "ipsum", "dolor", "sit", "amet", "7zip", "golang", "archive"}
	gen := func(n int) []byte {
		r := rand.New(rand.NewSource(1))
		b := make([]byte, 0, n+16)
		for len(b) < n {
			b = append(b, words[r.Intn(len(words))]...)
			if r.Intn(9) == 0 {
				b = append(b, '\n')
			} else {
				b = append(b, ' ')
			}
			if r.Intn(50) == 0 {
				b = append(b, byte(r.Intn(256)))
			}
		}
		return b[:n]
	}
	type cfg struct {
		name string
		args []string
		opts sevenzip.Options
	}
	cfgs := []cfg{
		{"lzma2 default", nil, sevenzip.Options{}},
		{"lzma2 default -mmt1", []string{"-mmt1"}, sevenzip.Options{Threads: 1}},
		{"lzma2 -mx1", []string{"-mx1"}, sevenzip.Options{Level: 1}},
		{"lzma2 -mx1 -mmt1", []string{"-mx1", "-mmt1"}, sevenzip.Options{Level: 1, Threads: 1}},
		{"lzma2 -mx9", []string{"-mx9"}, sevenzip.Options{Level: 9}},
		{"lzma -mmt1", []string{"-m0=LZMA", "-mmt1"}, sevenzip.Options{Method: sevenzip.LZMA, Threads: 1}},
		{"copy", []string{"-m0=Copy"}, sevenzip.Options{Method: sevenzip.Copy}},
	}
	sizes := []int{1 << 20, 16 << 20, 64 << 20}
	fmt.Printf("%-22s %8s %10s %10s %7s\n", "config", "size", "7zr", "module", "ratio")
	for _, n := range sizes {
		data := gen(n)
		for _, c := range cfgs {
			dir := t.TempDir()
			in := filepath.Join(dir, "in.bin")
			if err := os.WriteFile(in, data, 0o644); err != nil {
				t.Fatal(err)
			}
			args := append([]string{"a", "-t7z"}, c.args...)
			args = append(args, filepath.Join(dir, "o.7z"), "in.bin")
			t0 := time.Now()
			if out, err := sot.RunBinary(bin, dir, args...); err != nil {
				t.Fatalf("%v: %v\n%s", args, err, out)
			}
			d7 := time.Since(t0)

			w := sevenzip.NewWriter(c.opts)
			if err := w.AddPathIn(dir, "in.bin"); err != nil {
				t.Fatal(err)
			}
			f, err := os.Create(filepath.Join(dir, "m.7z"))
			if err != nil {
				t.Fatal(err)
			}
			t1 := time.Now()
			if err := w.Write(f); err != nil {
				t.Fatal(err)
			}
			f.Close()
			dm := time.Since(t1)
			fmt.Printf("%-22s %6dMB %10s %10s %6.2fx\n", c.name, n>>20, d7.Round(time.Millisecond), dm.Round(time.Millisecond), float64(dm)/float64(d7))
		}
	}
}
