package sottest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/lzma"
)

// LZMA2MethodCases are the 7z -m0=LZMA2 method strings covered against
// the SoT, including the LZMA2 block size (c) that splits the input
// into independently coded blocks.
var LZMA2MethodCases = []string{
	"LZMA2", "LZMA2:mf=bt2", "LZMA2:mf=hc4", "LZMA2:a=0", "LZMA2:fb=273:mc=1", "LZMA2:lc=4",
	"LZMA2:lc=0:lp=4", "LZMA2:d=4k", "LZMA2:c=8k", "LZMA2:d=64k:c=16k",
}

// CheckLZMA2 encodes input with the module for the given 7z method string
// and -mx level (mt1 adds -mmt1) and compares with the raw LZMA2 stream
// the SoT writes into .7z; then it decodes the SoT's stream.
func CheckLZMA2(t *testing.T, root, dir string, method string, level int, mt1 bool, input []byte) {
	t.Helper()
	args := []string{"-m0=" + method, fmt.Sprintf("-mx=%d", level)}
	if mt1 {
		args = append(args, "-mmt1")
	}
	want := SevenZRawStream(t, root, dir, input, args...)
	lzmaProps, blockSize, isLzma2 := ParseMethod(t, method, level, len(input))
	if !isLzma2 {
		t.Fatalf("not an LZMA2 method: %s", method)
	}
	var props lzma.Lzma2EncProps
	props.Init()
	props.LzmaProps = lzmaProps
	props.BlockSize = blockSize
	if mt1 {
		props.NumBlockThreadsMax = 1
	} else {
		props.NumBlockThreadsMax = 2
	}
	enc := lzma.NewLzma2Encoder()
	if err := enc.SetProps(&props); err != nil {
		t.Fatal(err)
	}
	enc.SetDataSize(uint64(len(input)))
	got, err := enc.EncodeBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("%s -mx%d mt1=%v: LZMA2 stream differs from SoT: got %d bytes, want %d, first difference at %d", method, level, mt1, len(got), len(want), i)
	}
	dst := make([]byte, len(input))
	written, _, _, err := lzma.Lzma2DecodeOneShot(dst, want, enc.WriteProperties(), lzma.FinishEnd)
	if err != nil || written != len(input) || !bytes.Equal(dst, input) {
		t.Fatalf("%s -mx%d: decoding the SoT's stream failed: written=%d err=%v", method, level, written, err)
	}
}

// CheckLZMA2Xz compares the module's LZMA2 stream with the payload of the
// single-block .xz the SoT writes for -mx level.
func CheckLZMA2Xz(t *testing.T, root, dir string, level int, input []byte) {
	t.Helper()
	data := SoTXz(t, root, dir, input, fmt.Sprintf("-mx=%d", level))
	want, prop, _ := XzSingleBlock(t, data)
	var props lzma.Lzma2EncProps
	props.Init()
	props.LzmaProps.Level = level
	props.LzmaProps.ReduceSize = uint64(len(input))
	enc := lzma.NewLzma2Encoder()
	if err := enc.SetProps(&props); err != nil {
		t.Fatal(err)
	}
	enc.SetDataSize(uint64(len(input)))
	if got := enc.WriteProperties(); got != prop {
		t.Fatalf("LZMA2 prop byte %d, SoT %d", got, prop)
	}
	got, err := enc.EncodeBytes(input)
	if err != nil {
		t.Fatal(err)
	}
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("xz -mx%d n=%d: LZMA2 stream differs from SoT: got %d bytes, want %d, first difference at %d", level, len(input), len(got), len(want), i)
	}
	dst := make([]byte, len(input))
	written, _, _, err := lzma.Lzma2DecodeOneShot(dst, want, prop, lzma.FinishEnd)
	if err != nil || written != len(input) || !bytes.Equal(dst, input) {
		t.Fatalf("decoding the SoT's stream failed: written=%d err=%v", written, err)
	}
}

// RunLZMA2Matrix runs every LZMA2 comparison as parallel subtests: the
// method matrix at -mx5, -mx1/3/7/9, multi-block inputs (block threads
// and -mmt1), and single-block .xz payloads at sizes 1 to 300000 bytes.
func RunLZMA2Matrix(t *testing.T, root string) {
	txt := TextLike(300000)
	big := TextLike(1500000)
	type c struct {
		method string
		level  int
		mt1    bool
		input  []byte
	}
	var cases []c
	for _, m := range LZMA2MethodCases {
		cases = append(cases, c{m, 5, false, txt})
	}
	for _, lvl := range []int{1, 3, 7, 9} {
		cases = append(cases, c{"LZMA2", lvl, false, txt})
	}
	cases = append(cases,
		c{"LZMA2:d=1m:c=1m", 5, false, big},
		c{"LZMA2:d=1m:c=1m", 5, true, big},
		c{"LZMA2:c=1m", 1, false, big},
	)
	for _, cs := range cases {
		cs := cs
		name := fmt.Sprintf("%s_mx%d_n%d", cs.method, cs.level, len(cs.input))
		if cs.mt1 {
			name += "_mt1"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			CheckLZMA2(t, root, t.TempDir(), cs.method, cs.level, cs.mt1, cs.input)
		})
	}
	for _, size := range []int{1, 100, 4096, 1 << 16, 300000} {
		for _, level := range []int{1, 3, 5, 7, 9} {
			size, level := size, level
			t.Run(fmt.Sprintf("xz_size%d_mx%d", size, level), func(t *testing.T) {
				t.Parallel()
				CheckLZMA2Xz(t, root, t.TempDir(), level, DeterministicData(size))
			})
		}
	}
}
