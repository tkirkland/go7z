package sottest

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/internal/sot"
)

// ARMPattern returns n bytes of little-endian 32-bit words whose top
// byte is 0xEB (an ARM BL instruction) about one word in three, with
// random 24-bit offsets, so that the converter's add/subtract wraps
// inside the 24-bit field and the filter coder's chunk boundaries fall
// between instructions.
func ARMPattern(n int, seed uint32) []byte {
	out := make([]byte, n)
	x := seed | 1
	next := func() uint32 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		return x
	}
	for i := 0; i < n; i++ {
		v := next()
		if i&3 == 3 {
			switch v % 3 {
			case 0:
				out[i] = 0xEB
			case 1:
				out[i] = byte(v >> 8)
			default:
				out[i] = 0xEA
			}
			continue
		}
		out[i] = byte(v)
	}
	return out
}

// RiscCheck is the module side of one RISC branch converter: the
// whole-buffer encoder and decoder and the streaming readers.
type RiscCheck struct {
	Method      string // 7z method name for -m0=<Method>
	EncodeBytes func([]byte) []byte
	DecodeBytes func([]byte) []byte
	EncodeR     func(io.Reader) io.Reader
	DecodeR     func(io.Reader) io.Reader
}

// ARMCheck is the ARM converter (bra.ARMConvert).
var ARMCheck = RiscCheck{
	Method:      "ARM",
	EncodeBytes: bra.ARMEncodeBytes,
	DecodeBytes: bra.ARMDecodeBytes,
	EncodeR:     bra.NewARMEncodeReader,
	DecodeR:     bra.NewARMDecodeReader,
}

// CheckRisc encodes input with the module's converter and compares it
// with the raw stream the lane's SoT writes into a .7z for
// -m0=<Method> (the folder's only coder is the filter, so the packed
// stream is the filter output); then it decodes the SoT's stream back
// to the input, with the whole-buffer functions and with the streaming
// readers.
func CheckRisc(t *testing.T, root string, lane sot.Lane, dir string, rc RiscCheck, input []byte, args ...string) {
	t.Helper()
	full := append([]string{"-m0=" + rc.Method}, args...)
	want := SevenZRawStream(t, root, lane, dir, input, full...)
	got := rc.EncodeBytes(input)
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("%v: %s stream differs from SoT: got %d bytes, want %d, first difference at %d", full, rc.Method, len(got), len(want), i)
	}
	if dec := rc.DecodeBytes(want); !bytes.Equal(dec, input) {
		t.Fatalf("%v: decoding the SoT's stream does not give the input (%d bytes)", full, len(dec))
	}
	var sb bytes.Buffer
	if _, err := sb.ReadFrom(rc.EncodeR(&oddReader{r: bytes.NewReader(input)})); err != nil {
		t.Fatal(err)
	}
	if i := FirstDifference(sb.Bytes(), want); i >= 0 {
		t.Fatalf("%v: streaming %s encoder differs from SoT at %d", full, rc.Method, i)
	}
	sb.Reset()
	if _, err := sb.ReadFrom(rc.DecodeR(&oddReader{r: bytes.NewReader(want)})); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sb.Bytes(), input) {
		t.Fatalf("%v: streaming %s decoder does not give the input", full, rc.Method)
	}
}

// RunARMMatrix runs every ARM comparison for one lane as parallel
// subtests: the lane's SoT binary (as arbitrary data with occasional
// 0xEB top bytes), deterministic binary and text inputs across the
// filter coder's buffer boundaries, BL-instruction patterns, the
// sizes where the converter has nothing to do (0..3 bytes) and the
// tails it leaves (sizes not a multiple of 4).
func RunARMMatrix(t *testing.T, root string, lane sot.Lane) {
	type c struct {
		name  string
		input []byte
		args  []string
	}
	var cases []c
	exe := SoTExe(t, root, lane)
	cases = append(cases, c{"exe", exe, nil})
	cases = append(cases, c{"exe_mx1", exe, []string{"-mx=1"}})
	cases = append(cases, c{"exe_mx9", exe, []string{"-mx=9"}})
	cases = append(cases, c{"exe_head_100k", exe[:100000], nil})
	cases = append(cases, c{"exe_mid_odd", exe[12345:300001], nil})
	for _, n := range []int{0, 1, 3, 4, 5, 7, 8, 9, 100, 4096, 65535, 65536, 65537, 300000, 3<<20 + 7} {
		cases = append(cases, c{fmt.Sprintf("bin_%d", n), DeterministicData(n), nil})
	}
	for _, n := range []int{5, 1000, 300000} {
		cases = append(cases, c{fmt.Sprintf("txt_%d", n), TextLike(n), nil})
	}
	for _, n := range []int{4, 7, 8, 12, 16, 1000, 70000, 1 << 20} {
		cases = append(cases, c{fmt.Sprintf("bl_%d", n), ARMPattern(n, uint32(n)), nil})
	}
	all := func(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }
	cases = append(cases, c{"all_eb", all(0xEB, 70000), nil})
	cases = append(cases, c{"all_00", all(0x00, 70000), nil})
	cases = append(cases, c{"all_ff", all(0xFF, 70000), nil})
	cases = append(cases, c{"bl_zero", bytes.Repeat([]byte{0x00, 0x00, 0x00, 0xEB}, 17500), nil})
	cases = append(cases, c{"bl_max", bytes.Repeat([]byte{0xFF, 0xFF, 0xFF, 0xEB}, 17500), nil})
	cases = append(cases, c{"bl_wrap", bytes.Repeat([]byte{0xFE, 0xFF, 0xFF, 0xEB, 0x01, 0x00, 0x00, 0xEB}, 8750), nil})
	cases = append(cases, c{"bl_tail", append(bytes.Repeat([]byte{0x10, 0x20, 0x30, 0xEB}, 250), 0xEB, 0xEB, 0xEB), nil})
	cases = append(cases, c{"eb_misaligned", bytes.Repeat([]byte{0xEB, 0x00, 0x00, 0x00}, 17500), nil})
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckRisc(t, root, lane, t.TempDir(), ARMCheck, cs.input, cs.args...)
		})
	}
}
