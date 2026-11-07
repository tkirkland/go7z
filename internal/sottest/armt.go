package sottest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/internal/sot"
)

// ARMTPattern returns n bytes of little-endian 16-bit halfwords with
// Thumb BL pairs (0xF000..0xF7FF then 0xF800..0xFFFF) about one pair in
// four, lone halfwords of either half, and random data, so that the
// converter's pair matching, the 22-bit wrap and the look-ahead
// halfword at chunk boundaries are all hit.
func ARMTPattern(n int, seed uint32) []byte {
	out := make([]byte, n)
	x := seed | 1
	next := func() uint32 {
		x ^= x << 13
		x ^= x >> 17
		x ^= x << 5
		return x
	}
	for i := 0; i+1 < n; i += 2 {
		v := next()
		out[i] = byte(v)
		switch v >> 28 {
		case 0, 1, 2, 3:
			if i+3 < n {
				out[i+1] = 0xF0 | byte(v>>8)&7
				w := next()
				out[i+2] = byte(w)
				out[i+3] = 0xF8 | byte(w>>8)&7
				i += 2
				continue
			}
			out[i+1] = byte(v >> 8)
		case 4:
			out[i+1] = 0xF0 | byte(v>>8)&7
		case 5:
			out[i+1] = 0xF8 | byte(v>>8)&7
		default:
			out[i+1] = byte(v >> 8)
		}
	}
	if n&1 == 1 {
		out[n-1] = byte(next())
	}
	return out
}

// ARMTCheck is the ARMT (Thumb) converter (bra.ARMTConvert).
var ARMTCheck = RiscCheck{
	Method:      "ARMT",
	EncodeBytes: bra.ARMTEncodeBytes,
	DecodeBytes: bra.ARMTDecodeBytes,
	EncodeR:     bra.NewARMTEncodeReader,
	DecodeR:     bra.NewARMTDecodeReader,
}

// RunARMTMatrix runs every ARMT comparison for one lane as parallel
// subtests: the lane's SoT binary, deterministic binary and text
// inputs across the filter coder's buffer boundaries, Thumb BL
// patterns, the sizes where the converter has nothing to do (0..4
// bytes), odd sizes, and BL pairs at every offset including the last
// halfword.
func RunARMTMatrix(t *testing.T, root string, lane sot.Lane) {
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
	for _, n := range []int{4, 5, 6, 7, 8, 10, 1000, 70000, 70001, 1 << 20} {
		cases = append(cases, c{fmt.Sprintf("bl_%d", n), ARMTPattern(n, uint32(n)), nil})
	}
	all := func(b byte, n int) []byte { return bytes.Repeat([]byte{b}, n) }
	cases = append(cases, c{"all_f0", all(0xF0, 70000), nil})
	cases = append(cases, c{"all_f8", all(0xF8, 70000), nil})
	cases = append(cases, c{"all_ff", all(0xFF, 70000), nil})
	cases = append(cases, c{"all_00", all(0x00, 70000), nil})
	cases = append(cases, c{"bl_zero", bytes.Repeat([]byte{0x00, 0xF0, 0x00, 0xF8}, 17500), nil})
	cases = append(cases, c{"bl_max", bytes.Repeat([]byte{0xFF, 0xF7, 0xFF, 0xFF}, 17500), nil})
	cases = append(cases, c{"bl_wrap", bytes.Repeat([]byte{0xFF, 0xF7, 0xFE, 0xFF, 0x01, 0xF0, 0x00, 0xF8}, 8750), nil})
	cases = append(cases, c{"bl_shifted", append([]byte{0x12, 0x34}, bytes.Repeat([]byte{0x00, 0xF0, 0x00, 0xF8}, 17500)...), nil})
	cases = append(cases, c{"bl_odd_shift", append([]byte{0x12}, bytes.Repeat([]byte{0x00, 0xF0, 0x00, 0xF8}, 17500)...), nil})
	cases = append(cases, c{"f8_f0", bytes.Repeat([]byte{0x00, 0xF8, 0x00, 0xF0}, 17500), nil})
	cases = append(cases, c{"f0_f0_f8", bytes.Repeat([]byte{0x00, 0xF0, 0x00, 0xF0, 0x00, 0xF8}, 11000), nil})
	cases = append(cases, c{"bl_last", append(DeterministicData(1000), 0x10, 0xF0, 0x20, 0xF8), nil})
	cases = append(cases, c{"bl_cut", append(DeterministicData(1000), 0x10, 0xF0), nil})
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckRisc(t, root, lane, t.TempDir(), ARMTCheck, cs.input, cs.args...)
		})
	}
}
