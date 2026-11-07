package sottest

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/sevenzip"
)

// SevenZFolder writes a single-file .7z with the lane's SoT and returns
// the first folder's coder records and raw packed streams, read with
// the module's header parser.
func SevenZFolder(t testing.TB, root string, lane sot.Lane, dir string, input []byte, args ...string) ([]sevenzip.Coder, [][]byte, []uint64) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "in.bin"), input, 0o644); err != nil {
		t.Fatal(err)
	}
	full := append([]string{"a", "-t7z"}, args...)
	full = append(full, filepath.Join(dir, "out.7z"), filepath.Join(dir, "in.bin"))
	if out, err := sot.Run(root, lane, full...); err != nil {
		t.Fatalf("SoT %v: %v\n%s", full, err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.7z"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := sevenzip.Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("%v: module cannot open the SoT's archive: %v", full, err)
	}
	if a.NumFolders() != 1 {
		t.Fatalf("%v: %d folders, want 1", full, a.NumFolders())
	}
	packed, err := a.FolderPackStreams(0)
	if err != nil {
		t.Fatal(err)
	}
	return a.FolderCoders(0), packed, a.FolderUnpackSizes(0)
}

// CheckBCJ2 encodes input with the module's BCJ2 converter and compares
// the four streams with what the lane's SoT writes into a .7z for
// -m0=BCJ2 (observed: the folder's only coder is BCJ2 and its four
// pack streams are MAIN, CALL, JUMP, RC in that order); then it decodes
// the SoT's streams back to the input. Both the whole-buffer and the
// streaming encoder (uneven chunks) are checked.
func CheckBCJ2(t *testing.T, root string, lane sot.Lane, dir string, input []byte, args ...string) {
	t.Helper()
	full := append([]string{"-m0=BCJ2"}, args...)
	coders, packed, _ := SevenZFolder(t, root, lane, dir, input, full...)
	if len(coders) != 1 || coders[0].MethodID != sevenzip.MethodBCJ2 || coders[0].NumStreams != 4 || len(packed) != 4 {
		t.Fatalf("%v: unexpected folder layout: %+v, %d pack streams", full, coders, len(packed))
	}
	var want [bra.Bcj2NumStreams][]byte
	copy(want[:], packed)
	got := bra.Bcj2EncodeBytes(input)
	for s := range got {
		if i := FirstDifference(got[s], want[s]); i >= 0 {
			t.Fatalf("%v: BCJ2 stream %d differs from SoT: got %d bytes, want %d, first difference at %d", full, s, len(got[s]), len(want[s]), i)
		}
	}
	dec, err := bra.Bcj2DecodeBytes(want, len(input))
	if err != nil {
		t.Fatalf("%v: decoding the SoT's streams: %v", full, err)
	}
	if !bytes.Equal(dec, input) {
		t.Fatalf("%v: decoding the SoT's streams does not give the input (%d bytes)", full, len(dec))
	}
	var bufs [bra.Bcj2NumStreams]bytes.Buffer
	var outs [bra.Bcj2NumStreams]io.Writer
	for i := range bufs {
		outs[i] = &bufs[i]
	}
	enc := bra.Bcj2Encoder{FileSize: uint64(len(input))}
	if err := enc.Encode(outs, &oddReader{r: bytes.NewReader(input)}); err != nil {
		t.Fatal(err)
	}
	for s := range bufs {
		if i := FirstDifference(bufs[s].Bytes(), want[s]); i >= 0 {
			t.Fatalf("%v: streaming BCJ2 encoder stream %d differs from SoT at %d (got %d bytes, want %d)", full, s, i, bufs[s].Len(), len(want[s]))
		}
	}
}

// RunBCJ2Matrix runs every BCJ2 comparison for one lane as parallel
// subtests: the lane's SoT binary (a real PE), slices of it,
// deterministic binary and text inputs, branch-opcode patterns, the
// 0F 8x marker, and the sizes where a marker has no room for its operand.
func RunBCJ2Matrix(t *testing.T, root string, lane sot.Lane) {
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
	for _, n := range []int{1, 4, 5, 6, 9, 100, 4096, 65535, 65536, 65537, 300000, 3<<20 + 7} {
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
	cases = append(cases, c{"e9_x4", bytes.Repeat([]byte{0xE9, 0x10, 0x00, 0x00, 0x00}, 14000), nil})
	cases = append(cases, c{"jcc_x4", bytes.Repeat([]byte{0x0F, 0x84, 0x10, 0x00, 0x00, 0x00}, 12000), nil})
	cases = append(cases, c{"jcc_0f_run", bytes.Repeat([]byte{0x0F, 0x0F, 0x8F, 0x00, 0x00, 0x00, 0x00}, 10000), nil})
	cases = append(cases, c{"e8_tail", append(DeterministicData(1000), 0xE8, 0x01, 0x02), nil})
	cases = append(cases, c{"e8_last", append(DeterministicData(1000), 0xE8), nil})
	cases = append(cases, c{"big_offsets", bytes.Repeat([]byte{0xE8, 0x00, 0x00, 0x00, 0x10}, 14000), nil})
	// Targets 1 MB ahead in a 70 KB input: converted only when the
	// absolute-address limit (the file size) is not applied.
	cases = append(cases, c{"beyond_file", bytes.Repeat([]byte{0xE8, 0x00, 0x00, 0x10, 0x00}, 14000), nil})
	cases = append(cases, c{"beyond_file_neg", bytes.Repeat([]byte{0xE8, 0x00, 0x00, 0xF0, 0xFF}, 14000), nil})
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckBCJ2(t, root, lane, t.TempDir(), cs.input, cs.args...)
		})
	}
	// The SoT's other BCJ2 folder shapes: BCJ2 with only MAIN compressed
	// (-m0=BCJ2 -m1=<M>: two coders, CALL, JUMP and RC as pack streams)
	// and the four-coder folder; the module must read them back.
	for _, args := range [][]string{{"-m0=BCJ2", "-m1=LZMA2"}, {"-m0=BCJ2", "-m1=LZMA"}, {"-m0=BCJ2", "-m1=Copy"}, {"-mf=BCJ2"}, {"-mf=BCJ2", "-m0=LZMA"}, {"-mf=BCJ2", "-mx=0"}} {
		args := args
		t.Run("readback_"+strings.Join(args, "_"), func(t *testing.T) {
			t.Parallel()
			CheckBCJ2ReadBack(t, root, lane, t.TempDir(), exe, args...)
		})
	}
	// The release package the SoTs come from is LZMA + BCJ2 written by
	// 7-Zip itself: the module extracts the lane's binary from it and its
	// SHA-256 is the pinned one.
	t.Run("extra_package", func(t *testing.T) {
		t.Parallel()
		CheckExtraPackage(t, root, lane)
	})
}

// CheckBCJ2ReadBack writes a single-file archive with the SoT and the
// given switches and requires the module to extract the input from it.
func CheckBCJ2ReadBack(t *testing.T, root string, lane sot.Lane, dir string, input []byte, args ...string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "in.bin"), input, 0o644); err != nil {
		t.Fatal(err)
	}
	full := append([]string{"a", "-t7z"}, args...)
	full = append(full, filepath.Join(dir, "out.7z"), filepath.Join(dir, "in.bin"))
	if out, err := sot.Run(root, lane, full...); err != nil {
		t.Fatalf("SoT %v: %v\n%s", full, err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.7z"))
	if err != nil {
		t.Fatal(err)
	}
	a, err := sevenzip.Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("%v: open: %v", args, err)
	}
	if len(a.Entries) != 1 {
		t.Fatalf("%v: %d entries", args, len(a.Entries))
	}
	got, err := a.Extract(0)
	if err != nil {
		t.Fatalf("%v: extract: %v", args, err)
	}
	if !bytes.Equal(got, input) {
		t.Fatalf("%v: extracted %d bytes differ from the input (%d)", args, len(got), len(input))
	}
}

// CheckExtraPackage extracts the lane's 7za.exe from tools/tmp/7z2605-extra.7z
// (the release asset, LZMA + BCJ2 as 7-Zip packs its executables) with
// the module and compares its SHA-256 with the lane's pin. It is
// skipped when the package is not present.
func CheckExtraPackage(t *testing.T, root string, lane sot.Lane) {
	t.Helper()
	pkg := filepath.Join(root, "tools", "tmp", "7z2605-extra.7z")
	data, err := os.ReadFile(pkg)
	if err != nil {
		t.Skipf("package not present: %v", err)
	}
	a, err := sevenzip.Open(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("open %s: %v", pkg, err)
	}
	want := map[sot.Lane]string{sot.Lane32: "7za.exe", sot.Lane64: "x64/7za.exe"}[lane]
	for i := range a.Entries {
		if a.Entries[i].Name != want {
			continue
		}
		got, err := a.Extract(i)
		if err != nil {
			t.Fatalf("extract %s: %v", want, err)
		}
		sum := sha256.Sum256(got)
		if hex.EncodeToString(sum[:]) != lane.SHA256() {
			t.Fatalf("%s: SHA-256 %x, want %s", want, sum, lane.SHA256())
		}
		return
	}
	t.Fatalf("%s not in %s", want, pkg)
}
