package sottest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkirkland/go7z/hasher"
	"github.com/tkirkland/go7z/internal/sot"
)

// HashCase is one `7za h` invocation: a tree, the arguments (relative
// to the tree's root directory, the SoT's working directory) and the
// -scrc switch (empty for the default, CRC32).
type HashCase struct {
	Name  string
	Files []TreeFile
	Args  []string
	Scrc  string // "", "SHA256", "*", ...
}

// CheckHash runs the SoT's h command on the case and requires the
// module's report (hasher.Scan + hasher.Render) to equal the SoT's
// output from the "Scanning" line on (the banner line before it names
// the build and is checked separately by sot.Binary).
func CheckHash(t *testing.T, root string, lane sot.Lane, dir string, c HashCase) {
	t.Helper()
	tree := filepath.Join(dir, "tree")
	if err := os.MkdirAll(tree, 0o755); err != nil {
		t.Fatal(err)
	}
	MakeTree(t, tree, c.Files)
	// -sccUTF-8 makes the SoT print names in UTF-8 instead of the
	// console code page (observed: "é" is byte 0x82 otherwise).
	args := []string{"h", "-sccUTF-8"}
	if c.Scrc != "" {
		args = append(args, "-scrc"+c.Scrc)
	}
	args = append(args, c.Args...)
	out, err := runSoTIn(root, lane, tree, args...)
	if err != nil {
		t.Fatalf("SoT %v: %v\n%s", args, err, out)
	}
	text := strings.ReplaceAll(string(out), "\r\n", "\n")
	i := strings.Index(text, "Scanning\n")
	if i < 0 {
		t.Fatalf("%s: no Scanning line in SoT output:\n%s", c.Name, text)
	}
	want := text[i:]

	var algs []hasher.Algorithm
	switch c.Scrc {
	case "":
		a, _ := hasher.Lookup("CRC32")
		algs = []hasher.Algorithm{a}
	case "*":
		algs = hasher.Algorithms
	default:
		a, ok := hasher.Lookup(c.Scrc)
		if !ok {
			t.Fatalf("unknown hasher %q", c.Scrc)
		}
		algs = []hasher.Algorithm{a}
	}
	b, err := hasher.Scan(tree, c.Args, algs)
	if err != nil {
		t.Fatalf("%s: module scan: %v", c.Name, err)
	}
	got := hasher.Render(b)
	if got != want {
		gl := strings.Split(got, "\n")
		wl := strings.Split(want, "\n")
		for j := 0; j < len(gl) || j < len(wl); j++ {
			var g, w string
			if j < len(gl) {
				g = gl[j]
			}
			if j < len(wl) {
				w = wl[j]
			}
			if g != w {
				t.Fatalf("%s: report differs at line %d:\n got %q\nwant %q\n--- got ---\n%s--- want ---\n%s", c.Name, j+1, g, w, got, want)
			}
		}
		t.Fatalf("%s: report differs", c.Name)
	}
}

// HashCases returns the report cases for one -scrc value: single
// files (including empty), several files in argument order, trees with
// nested directories, empty directories, names ordered by upper case,
// non-ASCII names, sizes at the KiB/MiB rounding boundaries, and a
// directory given with a trailing slash. exe is the lane's SoT binary.
func HashCases(scrc string, exe []byte) []HashCase {
	pre := "crc32"
	if scrc != "" {
		pre = strings.ToLower(strings.ReplaceAll(scrc, "*", "all"))
	}
	var cases []HashCase
	add := func(name string, files []TreeFile, args ...string) {
		cases = append(cases, HashCase{Name: pre + "_" + name, Files: files, Args: args, Scrc: scrc})
	}
	one := []TreeFile{{"d/a.txt", []byte("hello")}}
	add("one", one, "d/a.txt")
	add("one_abs_style", one, "d\\a.txt")
	add("empty_file", []TreeFile{{"e.bin", nil}}, "e.bin")
	add("exe", []TreeFile{{"x.exe", exe}}, "x.exe")
	add("exe_slice", []TreeFile{{"x.bin", exe[:300001]}}, "x.bin")
	two := []TreeFile{{"d/a.txt", []byte("hello")}, {"d/b.bin", exe[:100000]}}
	add("two", two, "d/a.txt", "d/b.bin")
	add("two_reversed", two, "d/b.bin", "d/a.txt")
	tree := []TreeFile{
		{"d/a.txt", []byte("hello")},
		{"d/b.bin", exe[:100000]},
		{"d/empty.bin", nil},
		{"d/sub/c.txt", []byte("xyz")},
		{"d/sub/deep/z.bin", DeterministicData(4097)},
		{"d/Sub2/y.bin", TextLike(1000)},
		{"d/_x.txt", []byte("c")},
		{"d/B.txt", []byte("A")},
		{"d/1", []byte("1")}, {"d/10", []byte("10")}, {"d/2", []byte("2")},
		{"d/a b", []byte("s")}, {"d/a-1", []byte("-")}, {"d/a.1", []byte(".")}, {"d/a1", []byte("1")}, {"d/ab", []byte("b")}, {"d/a_1", []byte("_")},
		{"d/[x", []byte("[")}, {"d/~y", []byte("~")},
		{"d/caf\u00e9.txt", []byte("g")},
		{"d/\u65e5\u672c\u8a9e.txt", []byte("j")},
		{"d/emptydir/", nil},
	}
	add("tree", tree, "d")
	add("tree_slash", tree, "d/")
	add("tree_backslash", tree, "d\\")
	add("tree_sub", tree, "d/sub")
	add("tree_files", tree, "d/a.txt", "d/b.bin", "d/empty.bin", "d/sub/c.txt")
	add("tree_mixed_args", tree, "d/sub", "d/a.txt", "d/Sub2")
	add("empty_dir", []TreeFile{{"ed/", nil}}, "ed")
	add("two_empty", []TreeFile{{"tf/e1", nil}, {"tf/e2", nil}}, "tf/e1", "tf/e2")
	add("kib_1023", []TreeFile{{"s.bin", DeterministicData(1023)}}, "s.bin")
	add("kib_1025", []TreeFile{{"s.bin", DeterministicData(1025)}}, "s.bin")
	add("kib_1048577", []TreeFile{{"s.bin", DeterministicData(1048577)}}, "s.bin")
	add("kib_10485759", []TreeFile{{"s.bin", DeterministicData(10485759)}}, "s.bin")
	add("mib_10485761", []TreeFile{{"s.bin", DeterministicData(10485761)}}, "s.bin")
	add("mib_tree", []TreeFile{{"m/a.bin", DeterministicData(6 << 20)}, {"m/b.bin", DeterministicData(5 << 20)}}, "m")
	return cases
}

// RunHashMatrix runs every report case for one -scrc value in one lane
// as parallel subtests.
func RunHashMatrix(t *testing.T, root string, lane sot.Lane, scrc string) {
	exe := SoTExe(t, root, lane)
	for _, c := range HashCases(scrc, exe) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			CheckHash(t, root, lane, t.TempDir(), c)
		})
	}
}

// hashLines is a helper for messages.
func hashLines(s string) []string { return strings.Split(strings.TrimRight(s, "\n"), "\n") }

var _ = hashLines
var _ = bytes.Equal
var _ = fmt.Sprintf
