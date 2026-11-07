package sottest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/copycoder"
)

// CheckCopy encodes input with the module's Copy coder and compares with
// the raw stream the SoT writes into .7z for the given arguments
// (either -m0=Copy at a level, or a bare -mx0, which selects Copy); then it
// decodes the SoT's stream with the module.
func CheckCopy(t *testing.T, root, dir string, input []byte, args ...string) {
	t.Helper()
	want := SevenZRawStream(t, root, dir, input, args...)
	got := copycoder.EncodeBytes(input)
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("%v: Copy stream differs from SoT: got %d bytes, want %d, first difference at %d", args, len(got), len(want), i)
	}
	dec := copycoder.DecodeBytes(want)
	if !bytes.Equal(dec, input) {
		t.Fatalf("%v: decoding the SoT's stream failed: %d bytes, want %d", args, len(dec), len(input))
	}
}

// RunCopyMatrix runs every Copy comparison as parallel subtests:
// -m0=Copy at -mx0/1/5/9 and bare -mx0 on binary and text-like input, and
// small inputs (1, 100, 4096 bytes).
func RunCopyMatrix(t *testing.T, root string) {
	bin := DeterministicData(300000)
	txt := TextLike(300000)
	type c struct {
		name  string
		args  []string
		input []byte
	}
	var cases []c
	for _, lvl := range []int{0, 1, 5, 9} {
		cases = append(cases, c{fmt.Sprintf("Copy_mx%d_bin", lvl), []string{"-m0=Copy", fmt.Sprintf("-mx=%d", lvl)}, bin})
		cases = append(cases, c{fmt.Sprintf("Copy_mx%d_txt", lvl), []string{"-m0=Copy", fmt.Sprintf("-mx=%d", lvl)}, txt})
	}
	cases = append(cases, c{"mx0_bin", []string{"-mx=0"}, bin})
	cases = append(cases, c{"mx0_txt", []string{"-mx=0"}, txt})
	for _, size := range []int{1, 100, 4096} {
		cases = append(cases, c{fmt.Sprintf("Copy_n%d", size), []string{"-m0=Copy"}, DeterministicData(size)})
	}
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckCopy(t, root, t.TempDir(), cs.input, cs.args...)
		})
	}
}
