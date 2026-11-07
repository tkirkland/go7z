package sottest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/ppmd"
	"github.com/tkirkland/go7z/sevenzip"
)

// CheckPPMD encodes input with the module's PPMd encoder at the order
// and memory the SoT records for the given -m0=PPMd arguments (the
// memory after the SoT's reduction, sevenzip.PPMdReducedMem) and
// compares it with the raw stream of the SoT's single-file .7z, then
// decodes the SoT's stream back.
func CheckPPMD(t *testing.T, root string, lane sot.Lane, dir string, input []byte, order, mem uint32, args ...string) {
	t.Helper()
	coders, packs, _ := SevenZFolder(t, root, lane, dir, input, args...)
	if len(coders) != 1 || coders[0].MethodID != sevenzip.MethodPPMD || len(coders[0].Props) != 5 || len(packs) != 1 {
		t.Fatalf("%v: SoT folder is not a single PPMD coder: %+v", args, coders)
	}
	want := packs[0]
	props := coders[0].Props
	gotOrder := uint32(props[0])
	gotMem := uint32(props[1]) | uint32(props[2])<<8 | uint32(props[3])<<16 | uint32(props[4])<<24
	wantMem := sevenzip.PPMdReducedMem(mem, uint64(len(input)))
	if gotOrder != order || gotMem != wantMem {
		t.Fatalf("%v: SoT props order %d mem %d; module expects order %d mem %d", args, gotOrder, gotMem, order, wantMem)
	}
	got, err := ppmd.EncodeBytes(input, order, wantMem)
	if err != nil {
		t.Fatal(err)
	}
	if i := FirstDifference(got, want); i >= 0 {
		t.Fatalf("%v: PPMd stream differs from SoT: got %d bytes, want %d, first difference at %d", args, len(got), len(want), i)
	}
	dec, err := ppmd.DecodeBytes(want, order, wantMem, len(input))
	if err != nil {
		t.Fatalf("%v: decoding the SoT's stream: %v", args, err)
	}
	if !bytes.Equal(dec, input) {
		t.Fatalf("%v: decoding the SoT's stream does not give the input", args)
	}
}

// RunPPMDMatrix runs every PPMd comparison for one lane as parallel
// subtests: levels 0..9 (order and memory per level, with the memory
// reduction at sizes around its boundaries), explicit orders 2, 3, 16,
// 32 and memories 64k, 96k, 2m, 1g, over the lane's SoT binary, text,
// deterministic binary, constant and tiny inputs including 1 and 2
// bytes, and a 3 MB input at mx9 (memory 2^26 after reduction, model
// restarts).
func RunPPMDMatrix(t *testing.T, root string, lane sot.Lane) {
	type c struct {
		name  string
		input []byte
		order uint32
		mem   uint32
		args  []string
	}
	var cases []c
	exe := SoTExe(t, root, lane)
	orders := [10]uint32{3, 4, 4, 5, 5, 6, 8, 16, 24, 32}
	level := func(name string, input []byte, mx int) {
		cases = append(cases, c{fmt.Sprintf("%s_mx%d", name, mx), input, orders[mx], 1 << (19 + uint(mx)), []string{"-m0=PPMd", fmt.Sprintf("-mx=%d", mx)}})
	}
	for mx := 0; mx <= 9; mx++ {
		level("exe300k", exe[:300000], mx)
		level("txt100k", TextLike(100000), mx)
	}
	for _, n := range []int{1, 2, 3, 100, 4096, 4097, 65536, 131072, 131073, 1048576, 1048577} {
		level(fmt.Sprintf("bin_%d", n), DeterministicData(n), 5)
	}
	level("exe_full", exe, 5)
	level("txt1m", TextLike(1<<20), 7)
	level("bin3m", DeterministicData(3<<20+7), 9)
	level("zeros70k", bytes.Repeat([]byte{0}, 70000), 5)
	level("ff70k", bytes.Repeat([]byte{0xFF}, 70001), 5)
	level("abcd", bytes.Repeat([]byte("ABCD"), 17501), 5)
	explicit := func(name string, input []byte, order uint32, mem uint32, param string) {
		cases = append(cases, c{name, input, order, mem, []string{"-m0=PPMd:" + param}})
	}
	explicit("o2", exe[:300000], 2, 1<<24, "o=2")
	explicit("o3", TextLike(300000), 3, 1<<24, "o=3")
	explicit("o16", exe[:300000], 16, 1<<24, "o=16")
	explicit("o32_mem1g", exe[:300000], 32, 1<<30, "o=32:mem=1g")
	explicit("mem64k", exe[:300000], 6, 1<<16, "mem=64k")
	explicit("mem96k", exe[:300000], 6, 96<<10, "mem=96k")
	explicit("mem2m", TextLike(1<<20), 6, 2<<20, "mem=2m")
	explicit("mem64k_3m", DeterministicData(3<<20), 6, 1<<16, "mem=64k")
	explicit("o32_mem64k_exe", exe, 32, 1<<16, "o=32:mem=64k")
	for _, cs := range cases {
		cs := cs
		t.Run(fmt.Sprintf("%s_n%d", cs.name, len(cs.input)), func(t *testing.T) {
			t.Parallel()
			CheckPPMD(t, root, lane, t.TempDir(), cs.input, cs.order, cs.mem, cs.args...)
		})
	}
}
