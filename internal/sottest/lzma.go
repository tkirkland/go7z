package sottest

import (
	"bytes"
	"fmt"
	"strings"
	"testing"

	"github.com/tkirkland/go7z/lzma"
)

// ParseMethod maps a 7-Zip method string (as given to -m0=) onto the SDK
// properties the SoT's C++ layer passes to the public-domain encoder.
// The mapping is observed behaviour; each name is a documented 7z method
// parameter. The dictionary is reduced to the input size as the SoT
// does (reduceSize). blockSize is the LZMA2 block size (c), 0 if not
// given; isLzma2 reports an LZMA2 method string.
func ParseMethod(t testing.TB, m string, level int, size int) (p lzma.EncProps, blockSize uint64, isLzma2 bool) {
	t.Helper()
	p.Init()
	p.Level = level
	p.ReduceSize = uint64(size)
	parts := strings.Split(m, ":")
	isLzma2 = parts[0] == "LZMA2"
	if parts[0] != "LZMA" && !isLzma2 {
		t.Fatalf("method %q", m)
	}
	sizeVal := func(v string) uint64 {
		mul := uint64(1)
		switch {
		case strings.HasSuffix(v, "k"):
			mul = 1 << 10
			v = strings.TrimSuffix(v, "k")
		case strings.HasSuffix(v, "m"):
			mul = 1 << 20
			v = strings.TrimSuffix(v, "m")
		}
		var n uint64
		fmt.Sscan(v, &n)
		return n * mul
	}
	for _, kv := range parts[1:] {
		k, v, _ := strings.Cut(kv, "=")
		var n int
		fmt.Sscan(v, &n)
		switch k {
		case "mf":
			switch v {
			case "bt2":
				p.BtMode, p.NumHashBytes = 1, 2
			case "bt3":
				p.BtMode, p.NumHashBytes = 1, 3
			case "bt4":
				p.BtMode, p.NumHashBytes = 1, 4
			case "bt5":
				p.BtMode, p.NumHashBytes = 1, 5
			case "hc4":
				p.BtMode, p.NumHashBytes = 0, 4
			case "hc5":
				p.BtMode, p.NumHashBytes = 0, 5
			default:
				t.Fatalf("mf=%s", v)
			}
		case "a":
			p.Algo = n
		case "fb":
			p.Fb = n
		case "mc":
			p.Mc = uint32(n)
		case "lc":
			p.Lc = n
		case "lp":
			p.Lp = n
		case "pb":
			p.Pb = n
		case "d":
			p.DictSize = uint32(sizeVal(v))
		case "c":
			blockSize = sizeVal(v)
		case "mt":
			p.NumThreads = n
		default:
			t.Fatalf("unknown param %s", k)
		}
	}
	return p, blockSize, isLzma2
}

// LZMAMethodCases are the 7z -m0=LZMA method strings covered against the
// SoT: every parameter the 7z -m switch exposes for the LZMA codec
// (mf, a, fb, mc, lc, lp, pb, d, mt).
var LZMAMethodCases = []string{
	"LZMA", "LZMA:mf=bt2", "LZMA:mf=bt3", "LZMA:mf=bt4", "LZMA:mf=bt5", "LZMA:mf=hc4", "LZMA:mf=hc5",
	"LZMA:a=0", "LZMA:a=0:mf=bt4", "LZMA:fb=5", "LZMA:fb=273", "LZMA:mc=1", "LZMA:mc=1000",
	"LZMA:lc=4:lp=0", "LZMA:lc=0:lp=4:pb=0", "LZMA:lc=8", "LZMA:d=4k", "LZMA:d=16k:fb=16", "LZMA:mt=1",
}

// CheckLZMA encodes input with the module for the given 7z method string
// and -mx level and compares with the raw stream the SoT writes into
// .7z; then it decodes the SoT's stream with the module.
func CheckLZMA(t *testing.T, root, dir string, method string, level int, input []byte) {
	t.Helper()
	want := SevenZRawStream(t, root, dir, input, "-m0="+method, fmt.Sprintf("-mx=%d", level))
	props, _, isLzma2 := ParseMethod(t, method, level, len(input))
	if isLzma2 {
		t.Fatalf("not an LZMA method: %s", method)
	}
	got, propsEncoded, err := lzma.EncodeBytes(input, &props, false)
	if err != nil {
		t.Fatal(err)
	}
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("%s -mx%d: LZMA stream differs from SoT: got %d bytes, want %d, first difference at %d", method, level, len(got), len(want), i)
	}
	dst := make([]byte, len(input))
	written, _, _, err := lzma.DecodeOneShot(dst, want, propsEncoded[:], lzma.FinishEnd)
	if err != nil || written != len(input) || !bytes.Equal(dst, input) {
		t.Fatalf("%s -mx%d: decoding the SoT's stream failed: written=%d err=%v", method, level, written, err)
	}
}

// RunLZMAMatrix runs every LZMA comparison as parallel subtests: the
// method matrix at -mx5 on text-like input, -mx1/3/7/9 on binary input,
// and small inputs (1, 100, 4096 bytes).
func RunLZMAMatrix(t *testing.T, root string) {
	bin := DeterministicData(300000)
	txt := TextLike(300000)
	type c struct {
		method string
		level  int
		input  []byte
	}
	var cases []c
	for _, m := range LZMAMethodCases {
		cases = append(cases, c{m, 5, txt})
	}
	for _, lvl := range []int{1, 3, 7, 9} {
		cases = append(cases, c{"LZMA", lvl, bin})
	}
	for _, size := range []int{1, 100, 4096} {
		cases = append(cases, c{"LZMA", 5, DeterministicData(size)})
	}
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_mx%d_n%d", cs.method, cs.level, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckLZMA(t, root, t.TempDir(), cs.method, cs.level, cs.input)
		})
	}
}
