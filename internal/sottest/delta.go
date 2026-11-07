package sottest

import (
	"bytes"
	"fmt"
	"io"
	"testing"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/internal/sot"
)

// DeltaCheck returns the RiscCheck for the Delta filter at one
// distance (-m0=Delta:<delta>; the bare -m0=Delta is delta 1).
func DeltaCheck(delta int) RiscCheck {
	method := "Delta"
	if delta != 1 {
		method = fmt.Sprintf("Delta:%d", delta)
	}
	return RiscCheck{
		Method:      method,
		EncodeBytes: func(d []byte) []byte { return bra.DeltaEncodeBytes(delta, d) },
		DecodeBytes: func(d []byte) []byte { return bra.DeltaDecodeBytes(delta, d) },
		EncodeR:     func(r io.Reader) io.Reader { return bra.NewDeltaEncodeReader(delta, r) },
		DecodeR:     func(r io.Reader) io.Reader { return bra.NewDeltaDecodeReader(delta, r) },
	}
}

// RunDeltaMatrix runs every Delta comparison for one lane as parallel
// subtests: distances 1 (the default, bare and explicit), 2, 3, 4, 5,
// 8, 16, 255 and 256 over the lane's SoT binary, deterministic binary
// and text inputs across the filter coder's buffer boundaries, sizes
// below, at and just above the distance (the size <= delta branch of
// Delta.c), odd and even sizes, and constant and short-period inputs.
func RunDeltaMatrix(t *testing.T, root string, lane sot.Lane) {
	type c struct {
		name  string
		delta int
		input []byte
		args  []string
	}
	var cases []c
	exe := SoTExe(t, root, lane)
	for _, d := range []int{1, 2, 3, 4, 5, 8, 16, 255, 256} {
		pre := fmt.Sprintf("d%d_", d)
		cases = append(cases, c{pre + "exe", d, exe, nil})
		cases = append(cases, c{pre + "exe_head_100k", d, exe[:100000], nil})
		cases = append(cases, c{pre + "exe_mid_odd", d, exe[12345:300001], nil})
		for _, n := range []int{0, 1, d - 1, d, d + 1, 2*d - 1, 2 * d, 2*d + 1, 100, 4096, 65535, 65536, 65537, 300000} {
			if n < 0 {
				continue
			}
			cases = append(cases, c{fmt.Sprintf("%sbin_%d", pre, n), d, DeterministicData(n), nil})
		}
		cases = append(cases, c{pre + "txt_300000", d, TextLike(300000), nil})
		cases = append(cases, c{pre + "all_00", d, bytes.Repeat([]byte{0x00}, 70000), nil})
		cases = append(cases, c{pre + "all_ff", d, bytes.Repeat([]byte{0xFF}, 70001), nil})
		cases = append(cases, c{pre + "abcd", d, bytes.Repeat([]byte("ABCD"), 17501), nil})
	}
	cases = append(cases, c{"d1_exe_mx1", 1, exe, []string{"-mx=1"}})
	cases = append(cases, c{"d1_exe_mx9", 1, exe, []string{"-mx=9"}})
	cases = append(cases, c{"d4_bin_3mb", 4, DeterministicData(3<<20 + 7), nil})
	cases = append(cases, c{"d256_bin_3mb", 256, DeterministicData(3<<20 + 7), nil})
	cases = append(cases, c{"d1_explicit", 1, DeterministicData(1000), nil})
	for _, cs := range cases {
		cs := cs
		rc := DeltaCheck(cs.delta)
		if cs.name == "d1_explicit" {
			rc.Method = "Delta:1"
		}
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckRisc(t, root, lane, t.TempDir(), rc, cs.input, cs.args...)
		})
	}
}
