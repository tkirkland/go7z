package oracletest

import (
	"bytes"
	"fmt"
	"os"
	"testing"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/internal/oracle"
)

// OracleExe returns the bytes of the pinned oracle binary itself: a real
// x86 PE image, used as filter input so that the branch converters see
// genuine CALL/JMP instructions and not only random bytes.
func OracleExe(t testing.TB, root string) []byte {
	t.Helper()
	bin, err := oracle.Binary(root)
	if err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(bin)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// BranchPattern returns n bytes drawn from a small alphabet rich in
// branch opcodes (E8, E9) and in the 0x00/0xFF operand bytes the x86
// converter keys on, so that every path of the state machine is hit and
// the 7-Zip filter coder's chunk boundaries fall inside instructions.
func BranchPattern(n int, seed uint32) []byte {
	alphabet := []byte{0xE8, 0xE8, 0xE9, 0x00, 0x00, 0xFF, 0xFF, 0x01, 0x80, 0x7F, 0xFE, 0x55}
	out := make([]byte, n)
	x := seed | 1
	for i := range out {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		out[i] = alphabet[x%uint32(len(alphabet))]
	}
	return out
}

// CheckBCJ encodes input with the module's x86 converter and compares it
// with the raw stream the oracle writes into a .7z for -m0=BCJ (the
// folder's only coder is BCJ, so the packed stream is the filter
// output); then it decodes the oracle's stream back to the input, with
// the whole-buffer functions and with the streaming readers.
func CheckBCJ(t *testing.T, root, dir string, input []byte, args ...string) {
	t.Helper()
	full := append([]string{"-m0=BCJ"}, args...)
	want := SevenZRawStream(t, root, dir, input, full...)
	got := bra.X86EncodeBytes(input)
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("%v: BCJ stream differs from oracle: got %d bytes, want %d, first difference at %d", full, len(got), len(want), i)
	}
	if dec := bra.X86DecodeBytes(want); !bytes.Equal(dec, input) {
		t.Fatalf("%v: decoding the oracle's stream does not give the input (%d bytes)", full, len(dec))
	}
	var sb bytes.Buffer
	if _, err := sb.ReadFrom(bra.NewX86EncodeReader(&oddReader{r: bytes.NewReader(input)})); err != nil {
		t.Fatal(err)
	}
	if i := FirstDifference(sb.Bytes(), want); i >= 0 {
		t.Fatalf("%v: streaming BCJ encoder differs from oracle at %d", full, i)
	}
	sb.Reset()
	if _, err := sb.ReadFrom(bra.NewX86DecodeReader(&oddReader{r: bytes.NewReader(want)})); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sb.Bytes(), input) {
		t.Fatalf("%v: streaming BCJ decoder does not give the input", full)
	}
}

// oddReader returns data in uneven chunks so that the streaming
// converters are exercised across chunk boundaries.
type oddReader struct {
	r *bytes.Reader
	i int
}

func (o *oddReader) Read(p []byte) (int, error) {
	sizes := []int{1, 7, 4, 3000, 5, 2, 65536, 13, 1}
	n := sizes[o.i%len(sizes)]
	o.i++
	if n > len(p) {
		n = len(p)
	}
	return o.r.Read(p[:n])
}

// RunBCJMatrix runs every BCJ comparison as parallel subtests: the
// oracle binary (a real PE), deterministic binary and text-like inputs
// across the filter coder's buffer boundaries, branch-opcode patterns,
// and the sizes where the converter has nothing to do (0..5 bytes).
func RunBCJMatrix(t *testing.T, root string) {
	type c struct {
		name  string
		input []byte
		args  []string
	}
	var cases []c
	exe := OracleExe(t, root)
	cases = append(cases, c{"exe", exe, nil})
	cases = append(cases, c{"exe_mx1", exe, []string{"-mx=1"}})
	cases = append(cases, c{"exe_mx9", exe, []string{"-mx=9"}})
	cases = append(cases, c{"exe_head_100k", exe[:100000], nil})
	cases = append(cases, c{"exe_mid_odd", exe[12345:300001], nil})
	for _, n := range []int{0, 1, 4, 5, 6, 9, 100, 4096, 65535, 65536, 65537, 300000, 3<<20 + 7} {
		cases = append(cases, c{fmt.Sprintf("bin_%d", n), DeterministicData(n), nil})
	}
	for _, n := range []int{5, 1000, 300000} {
		cases = append(cases, c{fmt.Sprintf("txt_%d", n), TextLike(n), nil})
	}
	for _, n := range []int{5, 6, 7, 8, 9, 16, 1000, 70000, 1 << 20} {
		cases = append(cases, c{fmt.Sprintf("branch_%d", n), BranchPattern(n, uint32(n)), nil})
	}
	all := func(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }
	cases = append(cases, c{"all_e8", all(0xE8, 70000), nil})
	cases = append(cases, c{"all_e9", all(0xE9, 70000), nil})
	cases = append(cases, c{"all_00", all(0x00, 70000), nil})
	cases = append(cases, c{"all_ff", all(0xFF, 70000), nil})
	cases = append(cases, c{"e8_00", bytes.Repeat([]byte{0xE8, 0x00}, 35000), nil})
	cases = append(cases, c{"e8_ff", bytes.Repeat([]byte{0xE8, 0xFF}, 35000), nil})
	cases = append(cases, c{"e8_x4", bytes.Repeat([]byte{0xE8, 0x10, 0x20, 0x30, 0x00}, 14000), nil})
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckBCJ(t, root, t.TempDir(), cs.input, cs.args...)
		})
	}
}
