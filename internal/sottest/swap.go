package sottest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/internal/sot"
)

// Swap2Check is the Swap2 byte-pair filter (bra.Swap2Convert).
var Swap2Check = RiscCheck{
	Method:      "Swap2",
	EncodeBytes: bra.Swap2EncodeBytes,
	DecodeBytes: bra.Swap2DecodeBytes,
	EncodeR:     bra.NewSwap2EncodeReader,
	DecodeR:     bra.NewSwap2DecodeReader,
}

// Swap4Check is the Swap4 four-byte-reverse filter (bra.Swap4Convert).
var Swap4Check = RiscCheck{
	Method:      "Swap4",
	EncodeBytes: bra.Swap4EncodeBytes,
	DecodeBytes: bra.Swap4DecodeBytes,
	EncodeR:     bra.NewSwap4EncodeReader,
	DecodeR:     bra.NewSwap4DecodeReader,
}

// RunSwapMatrix runs every Swap2 or Swap4 comparison for one lane as
// parallel subtests: the lane's SoT binary, deterministic binary and
// text inputs across the filter coder's buffer boundaries, every size
// 0..9 (the tails the filter leaves), sizes around 64 KB, and constant
// and short-period inputs.
func RunSwapMatrix(t *testing.T, root string, lane sot.Lane, rc RiscCheck) {
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
	for _, n := range []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 100, 4096, 65535, 65536, 65537, 65538, 65539, 300000, 3<<20 + 7} {
		cases = append(cases, c{fmt.Sprintf("bin_%d", n), DeterministicData(n), nil})
	}
	for _, n := range []int{5, 1000, 300000} {
		cases = append(cases, c{fmt.Sprintf("txt_%d", n), TextLike(n), nil})
	}
	cases = append(cases, c{"all_00", bytes.Repeat([]byte{0x00}, 70000), nil})
	cases = append(cases, c{"all_ff", bytes.Repeat([]byte{0xFF}, 70001), nil})
	cases = append(cases, c{"abcd", bytes.Repeat([]byte("ABCD"), 17501), nil})
	cases = append(cases, c{"abc", bytes.Repeat([]byte("ABC"), 23334), nil})
	cases = append(cases, c{"ab", bytes.Repeat([]byte("AB"), 35001), nil})
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckRisc(t, root, lane, t.TempDir(), rc, cs.input, cs.args...)
		})
	}
}
