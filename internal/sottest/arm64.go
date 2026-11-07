package sottest

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/internal/sot"
)

// ARM64Pattern returns n bytes of little-endian 32-bit words: about one
// in four an AArch64 BL (top six bits 100101) with a random 26-bit
// offset, one in four an ADRP (1 immlo 10000 immhi Rd) with the page
// offset half the time inside the converter's window and half the time
// outside it, and random data otherwise, so that both rewrites, the
// window check, the 26-bit wrap and the filter coder's chunk
// boundaries are all hit.
func ARM64Pattern(n int, seed uint32) []byte {
	out := make([]byte, n)
	x := seed | 1
	next := func() uint32 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		return x
	}
	for i := 0; i+3 < n; i += 4 {
		v := next()
		switch v >> 30 {
		case 0:
			v = 0x94000000 | v&0x03ffffff
		case 1:
			// ADRP: bit 31 set, immlo at bits 29..30, 10000 at 24..28,
			// immhi at 5..23, Rd at 0..4.
			immhi := v >> 5 & 0x7ffff
			if next()&1 == 0 {
				immhi &= 0x7fff // inside the window
				if next()&1 == 0 {
					immhi = (0x7ffff - immhi) & 0x7ffff // negative side
				}
			}
			v = 0x90000000 | v&0x60000000 | immhi<<5 | v&0x1f
		}
		binary.LittleEndian.PutUint32(out[i:], v)
	}
	for i := n &^ 3; i < n; i++ {
		out[i] = byte(next())
	}
	return out
}

// ARM64Check is the ARM64 converter (bra.ARM64Convert).
var ARM64Check = RiscCheck{
	Method:      "ARM64",
	EncodeBytes: bra.ARM64EncodeBytes,
	DecodeBytes: bra.ARM64DecodeBytes,
	EncodeR:     bra.NewARM64EncodeReader,
	DecodeR:     bra.NewARM64DecodeReader,
}

// RunARM64Matrix runs every ARM64 comparison for one lane as parallel
// subtests: the lane's SoT binary, deterministic binary and text
// inputs across the filter coder's buffer boundaries, BL and ADRP
// patterns, the sizes where the converter has nothing to do (0..3
// bytes), the tails it leaves (sizes not a multiple of 4), ADRP pages
// at the window edges and BL offsets that wrap.
func RunARM64Matrix(t *testing.T, root string, lane sot.Lane) {
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
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 4096, 65535, 65536, 65537, 300000, 3<<20 + 7} {
		cases = append(cases, c{fmt.Sprintf("bin_%d", n), DeterministicData(n), nil})
	}
	for _, n := range []int{5, 1000, 300000} {
		cases = append(cases, c{fmt.Sprintf("txt_%d", n), TextLike(n), nil})
	}
	for _, n := range []int{4, 5, 7, 8, 1000, 70000, 70001, 1 << 20, 4 << 20} {
		cases = append(cases, c{fmt.Sprintf("branch_%d", n), ARM64Pattern(n, uint32(n)), nil})
	}
	all := func(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }
	words := func(n int, w ...uint32) []byte {
		var one []byte
		for _, v := range w {
			one = binary.LittleEndian.AppendUint32(one, v)
		}
		return bytes.Repeat(one, n/len(one))
	}
	cases = append(cases, c{"all_94", all(0x94, 70000), nil})
	cases = append(cases, c{"all_97", all(0x97, 70000), nil})
	cases = append(cases, c{"all_90", all(0x90, 70000), nil})
	cases = append(cases, c{"all_ff", all(0xFF, 70000), nil})
	cases = append(cases, c{"all_00", all(0x00, 70000), nil})
	cases = append(cases, c{"bl_zero", words(70000, 0x94000000), nil})
	cases = append(cases, c{"bl_max", words(70000, 0x97ffffff), nil})
	cases = append(cases, c{"bl_wrap", words(70000, 0x97fffffe, 0x94000001), nil})
	cases = append(cases, c{"bl_shifted", append([]byte{1, 2, 3}, words(70000, 0x94000000)...), nil})
	cases = append(cases, c{"adrp_zero", words(70000, 0x90000000), nil})
	cases = append(cases, c{"adrp_rd_immlo", words(70000, 0xf000001f), nil})
	cases = append(cases, c{"adrp_window_edge", words(70000, 0x90000000|0x7fff<<5, 0x90000000|0x8000<<5, 0x90000000|0x78000<<5, 0x90000000|0x77fff<<5), nil})
	cases = append(cases, c{"adrp_out_of_window", words(70000, 0x90000000|0x40000<<5, 0x90000000|0x3ffff<<5), nil})
	cases = append(cases, c{"adrp_immhi_max", words(70000, 0x90000000|0x7ffff<<5), nil})
	cases = append(cases, c{"adrp_not", words(70000, 0x91000000, 0x98000000, 0x10000000), nil})
	cases = append(cases, c{"mixed_last", append(DeterministicData(1000), 0x00, 0x00, 0x00, 0x94), nil})
	cases = append(cases, c{"mixed_cut", append(DeterministicData(1000), 0x00, 0x00, 0x94), nil})
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckRisc(t, root, lane, t.TempDir(), ARM64Check, cs.input, cs.args...)
		})
	}
}
