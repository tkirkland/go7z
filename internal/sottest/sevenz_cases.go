package sottest

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/sevenzip"
)

// SevenZCases is the container matrix compared with the SoT: single
// files at every method and level, empty files and directories,
// multi-file solid and non-solid archives, header compression on and
// off, nested directories, name ordering, CTime, and sizes that make the
// LZMA2 encoder split blocks, and the BCJ filter alone and in front of
// each method (exe is a real x86 image for the filter cases).
func SevenZCases(exe []byte) []SevenZCase {
	small := []TreeFile{{"in/a.txt", TextLike(85)}}
	mixed := []TreeFile{
		{"in/a.txt", TextLike(85)},
		{"in/b.bin", DeterministicData(4096)},
		{"in/empty.txt", nil},
		{"in/dir/c.txt", TextLike(12)},
		{"in/emptydir/", nil},
	}
	mixedInputs := []string{"in/a.txt", "in/b.bin", "in/empty.txt", "in/dir", "in/emptydir"}
	order := []TreeFile{
		{"srt/b.txt", []byte("x")}, {"srt/_x.txt", []byte("x")}, {"srt/B2.txt", []byte("x")},
		{"srt/a~.txt", []byte("x")}, {"srt/a-.txt", []byte("x")}, {"srt/a b.txt", []byte("x")},
		{"srt/A1.txt", []byte("x")}, {"srt/a1.txt", []byte("x")}, {"srt/1.txt", []byte("x")},
		{"srt/sub_x.txt", []byte("x")}, {"srt/subz.txt", []byte("x")}, {"srt/sub/q.txt", []byte("x")},
		{"srt/Sub2/", nil}, {"srt/emp/", nil}, {"srt/empty1.txt", nil}, {"srt/Empty0.txt", nil},
		{"srt/z.dat", DeterministicData(300)}, {"srt/m.bin", DeterministicData(200)},
	}
	var cases []SevenZCase
	add := func(name string, files []TreeFile, inputs []string, args []string, opts sevenzip.Options) {
		cases = append(cases, SevenZCase{Name: name, Files: files, Inputs: inputs, Args: args, Opts: opts})
	}
	// Single file, each method, levels.
	for _, m := range []struct {
		arg  string
		meth sevenzip.Method
	}{{"", sevenzip.LZMA2}, {"-m0=LZMA2", sevenzip.LZMA2}, {"-m0=LZMA", sevenzip.LZMA}, {"-m0=Copy", sevenzip.Copy}} {
		for _, lvl := range []int{1, 5, 9} {
			var args []string
			if m.arg != "" {
				args = append(args, m.arg)
			}
			args = append(args, fmt.Sprintf("-mx=%d", lvl))
			add(fmt.Sprintf("single_%s_mx%d", m.arg, lvl), small, []string{"in/a.txt"}, args, sevenzip.Options{Method: m.meth, Level: lvl})
		}
	}
	add("single_mx0", small, []string{"in/a.txt"}, []string{"-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	add("single_default", small, []string{"in/a.txt"}, nil, sevenzip.Options{})
	add("single_hc_off", small, []string{"in/a.txt"}, []string{"-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	// Sizes that cross dictionary and block boundaries.
	for _, n := range []int{1, 4097, 65537, 300000, 2097153} {
		files := []TreeFile{{"in/f.bin", DeterministicData(n)}}
		add(fmt.Sprintf("size_%d_lzma2", n), files, []string{"in/f.bin"}, nil, sevenzip.Options{})
		add(fmt.Sprintf("size_%d_lzma", n), files, []string{"in/f.bin"}, []string{"-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	}
	// Empty items only.
	add("empty_file", []TreeFile{{"in/empty.txt", nil}}, []string{"in/empty.txt"}, nil, sevenzip.Options{})
	add("empty_dir", []TreeFile{{"in/emptydir/", nil}}, []string{"in/emptydir"}, nil, sevenzip.Options{})
	add("empty_file_and_dir", []TreeFile{{"in/empty.txt", nil}, {"in/emptydir/", nil}}, []string{"in/empty.txt", "in/emptydir"}, nil, sevenzip.Options{})
	// Mixed trees.
	add("mixed_default", mixed, mixedInputs, nil, sevenzip.Options{})
	add("mixed_hc_off", mixed, mixedInputs, []string{"-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	add("mixed_ms_off", mixed, mixedInputs, []string{"-ms=off"}, sevenzip.Options{SolidOff: true})
	add("mixed_copy", mixed, mixedInputs, []string{"-m0=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	add("mixed_mx0", mixed, mixedInputs, []string{"-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	add("mixed_lzma", mixed, mixedInputs, []string{"-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	add("mixed_lzma_mx9", mixed, mixedInputs, []string{"-m0=LZMA", "-mx=9"}, sevenzip.Options{Method: sevenzip.LZMA, Level: 9})
	add("mixed_mx1", mixed, mixedInputs, []string{"-mx=1"}, sevenzip.Options{Level: 1})
	add("mixed_dir_arg", mixed, []string{"in"}, nil, sevenzip.Options{})
	add("mixed_ctime", mixed, mixedInputs, []string{"-mtc=on"}, sevenzip.Options{StoreCTime: true})
	add("mixed_no_mtime", mixed, mixedInputs, []string{"-mtm=off"}, sevenzip.Options{NoMTime: true})
	add("mixed_ctime_hc_off", mixed, mixedInputs, []string{"-mtc=on", "-mhc=off"}, sevenzip.Options{StoreCTime: true, NoHeaderCompression: true})
	// Ordering.
	add("order", order, []string{"srt"}, nil, sevenzip.Options{})
	add("order_hc_off", order, []string{"srt"}, []string{"-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	// Two files given in reverse name order.
	two := []TreeFile{{"in/z.txt", TextLike(100)}, {"in/a.txt", TextLike(200)}}
	add("two_reverse", two, []string{"in/z.txt", "in/a.txt"}, nil, sevenzip.Options{})
	add("two_copy", two, []string{"in/z.txt", "in/a.txt"}, []string{"-m0=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	// Many files: solid block with sub-stream sizes above 127 and a
	// names property above 127 bytes.
	var many []TreeFile
	var manyInputs []string
	for i := 0; i < 40; i++ {
		many = append(many, TreeFile{fmt.Sprintf("many/file%02d.bin", i), DeterministicData(100 + i*37)})
	}
	manyInputs = []string{"many"}
	add("many_default", many, manyInputs, nil, sevenzip.Options{})
	add("many_ms_off", many, manyInputs, []string{"-ms=off"}, sevenzip.Options{SolidOff: true})
	add("many_lzma", many, manyInputs, []string{"-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	// Solid limit: -ms=s forces a split at a small size.
	add("solid_limit", many, manyInputs, []string{"-ms=1k"}, sevenzip.Options{SolidSize: 1024})
	add("solid_limit_hc_off", many, manyInputs, []string{"-ms=1k", "-mhc=off"}, sevenzip.Options{SolidSize: 1024, NoHeaderCompression: true})
	// Dictionary reduction uses the total of all data files, not the folder.
	rs := []TreeFile{{"rs/a.bin", DeterministicData(100)}, {"rs/b.bin", DeterministicData(10000)}, {"rs/c.bin", DeterministicData(200)}, {"rs/d.bin", DeterministicData(5000)}}
	add("reduce_ms_off_lzma2", rs, []string{"rs/a.bin", "rs/b.bin"}, []string{"-ms=off"}, sevenzip.Options{SolidOff: true})
	add("reduce_ms_off_lzma", rs, []string{"rs/a.bin", "rs/b.bin"}, []string{"-ms=off", "-m0=LZMA"}, sevenzip.Options{SolidOff: true, Method: sevenzip.LZMA})
	add("reduce_ms_1k_lzma2", rs, []string{"rs/a.bin", "rs/c.bin", "rs/d.bin"}, []string{"-ms=1k"}, sevenzip.Options{SolidSize: 1024})
	add("reduce_ms_1k_lzma", rs, []string{"rs/a.bin", "rs/c.bin", "rs/d.bin"}, []string{"-ms=1k", "-m0=LZMA"}, sevenzip.Options{SolidSize: 1024, Method: sevenzip.LZMA})
	var tenMB []TreeFile
	for i := 0; i < 10; i++ {
		tenMB = append(tenMB, TreeFile{fmt.Sprintf("mb/z%d.bin", i), DeterministicData(1 << 20)})
	}
	add("reduce_ms_4m_lzma2", tenMB, []string{"mb"}, []string{"-ms=4m"}, sevenzip.Options{SolidSize: 4 << 20})
	add("reduce_ms_4m_lzma", tenMB, []string{"mb"}, []string{"-ms=4m", "-m0=LZMA"}, sevenzip.Options{SolidSize: 4 << 20, Method: sevenzip.LZMA})
	add("reduce_ms_off_1mb", tenMB, []string{"mb"}, []string{"-ms=off"}, sevenzip.Options{SolidOff: true})
	// Multi-block LZMA2 (input above the auto block size at mx1: 1 MB).
	big := []TreeFile{{"in/big.bin", DeterministicData(3 << 20)}}
	add("big_mx1", big, []string{"in/big.bin"}, []string{"-mx=1"}, sevenzip.Options{Level: 1})
	add("big_mx1_mt1", big, []string{"in/big.bin"}, []string{"-mx=1", "-mmt1"}, sevenzip.Options{Level: 1, Threads: 1})
	// BCJ filter: alone (-m0=BCJ), in front of each method (-m0=BCJ
	// -m1=<M>), and forced with -mf=BCJ; a real PE image, a tree of PE
	// slices with empty items, solid and non-solid, and header
	// compression off so the folder records are visible in the diff.
	pe := []TreeFile{{"in/exe.bin", exe}}
	peTree := []TreeFile{
		{"pe/a.bin", exe[:100000]},
		{"pe/b.bin", exe[100000:300000]},
		{"pe/c.bin", exe[300000:302000]},
		{"pe/empty.bin", nil},
		{"pe/dir/", nil},
	}
	bcj := func(name string, files []TreeFile, inputs []string, args []string, opts sevenzip.Options) {
		opts.Filter = sevenzip.BCJ
		add(name, files, inputs, args, opts)
	}
	bcj("bcj_only", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ"}, sevenzip.Options{Method: sevenzip.None})
	bcj("bcj_only_hc_off", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-mhc=off"}, sevenzip.Options{Method: sevenzip.None, NoHeaderCompression: true})
	bcj("bcj_only_mx1", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-mx=1"}, sevenzip.Options{Method: sevenzip.None, Level: 1})
	bcj("bcj_lzma2", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=LZMA2"}, sevenzip.Options{})
	bcj("bcj_lzma2_hc_off", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=LZMA2", "-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	bcj("bcj_lzma2_mx1", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=LZMA2", "-mx=1"}, sevenzip.Options{Level: 1})
	bcj("bcj_lzma2_mx9", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=LZMA2", "-mx=9"}, sevenzip.Options{Level: 9})
	bcj("bcj_lzma", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	bcj("bcj_lzma_hc_off", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=LZMA", "-mhc=off"}, sevenzip.Options{Method: sevenzip.LZMA, NoHeaderCompression: true})
	bcj("bcj_copy", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	bcj("bcj_copy_hc_off", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ", "-m1=Copy", "-mhc=off"}, sevenzip.Options{Method: sevenzip.Copy, NoHeaderCompression: true})
	bcj("mf_bcj", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ"}, sevenzip.Options{})
	bcj("mf_bcj_lzma", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ", "-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	bcj("mf_bcj_mx0", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ", "-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	bcj("mf_bcj_mt1", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ", "-mmt1"}, sevenzip.Options{Threads: 1})
	bcj("bcj_tree_only", peTree, []string{"pe"}, []string{"-m0=BCJ"}, sevenzip.Options{Method: sevenzip.None})
	bcj("bcj_tree_only_hc_off", peTree, []string{"pe"}, []string{"-m0=BCJ", "-mhc=off"}, sevenzip.Options{Method: sevenzip.None, NoHeaderCompression: true})
	bcj("bcj_tree_only_ms_off", peTree, []string{"pe"}, []string{"-m0=BCJ", "-ms=off"}, sevenzip.Options{Method: sevenzip.None, SolidOff: true})
	bcj("bcj_tree_only_ms_150k", peTree, []string{"pe"}, []string{"-m0=BCJ", "-ms=150k"}, sevenzip.Options{Method: sevenzip.None, SolidSize: 150 << 10})
	bcj("bcj_tree_lzma2", peTree, []string{"pe"}, []string{"-m0=BCJ", "-m1=LZMA2"}, sevenzip.Options{})
	bcj("bcj_tree_lzma2_hc_off", peTree, []string{"pe"}, []string{"-m0=BCJ", "-m1=LZMA2", "-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	bcj("bcj_tree_lzma2_ms_off", peTree, []string{"pe"}, []string{"-m0=BCJ", "-m1=LZMA2", "-ms=off"}, sevenzip.Options{SolidOff: true})
	bcj("bcj_tree_lzma2_ms_150k", peTree, []string{"pe"}, []string{"-m0=BCJ", "-m1=LZMA2", "-ms=150k"}, sevenzip.Options{SolidSize: 150 << 10})
	bcj("bcj_tree_lzma", peTree, []string{"pe"}, []string{"-m0=BCJ", "-m1=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	bcj("bcj_tree_copy", peTree, []string{"pe"}, []string{"-m0=BCJ", "-m1=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	bcj("bcj_tree_copy_ms_off", peTree, []string{"pe"}, []string{"-m0=BCJ", "-m1=Copy", "-ms=off"}, sevenzip.Options{Method: sevenzip.Copy, SolidOff: true})
	bcj("bcj_tree_mf_mx0", peTree, []string{"pe"}, []string{"-mf=BCJ", "-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	bcj("bcj_tree_many_mx1", tenMB, []string{"mb"}, []string{"-mf=BCJ", "-mx=1"}, sevenzip.Options{Level: 1})
	bcj("bcj_tree_many_ms_4m", tenMB, []string{"mb"}, []string{"-mf=BCJ", "-ms=4m"}, sevenzip.Options{SolidSize: 4 << 20})
	bcj("bcj_small", small, []string{"in/a.txt"}, []string{"-mf=BCJ"}, sevenzip.Options{})
	bcj("bcj_mixed", mixed, mixedInputs, []string{"-mf=BCJ"}, sevenzip.Options{})
	// ARM filter: the same shapes as BCJ (alone, in front of each
	// method, forced with -mf=ARM) over BL-instruction patterns and the
	// PE tree.
	armTree := []TreeFile{
		{"arm/a.bin", ARMPattern(100000, 1)},
		{"arm/b.bin", ARMPattern(200001, 2)},
		{"arm/c.bin", ARMPattern(2002, 3)},
		{"arm/empty.bin", nil},
		{"arm/dir/", nil},
	}
	armOne := []TreeFile{{"in/arm.bin", ARMPattern(300000, 7)}}
	arm := func(name string, files []TreeFile, inputs []string, args []string, opts sevenzip.Options) {
		opts.Filter = sevenzip.ARM
		add(name, files, inputs, args, opts)
	}
	arm("arm_only", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM"}, sevenzip.Options{Method: sevenzip.None})
	arm("arm_only_hc_off", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM", "-mhc=off"}, sevenzip.Options{Method: sevenzip.None, NoHeaderCompression: true})
	arm("arm_lzma2", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM", "-m1=LZMA2"}, sevenzip.Options{})
	arm("arm_lzma2_hc_off", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM", "-m1=LZMA2", "-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	arm("arm_lzma2_mx1", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM", "-m1=LZMA2", "-mx=1"}, sevenzip.Options{Level: 1})
	arm("arm_lzma2_mx9", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM", "-m1=LZMA2", "-mx=9"}, sevenzip.Options{Level: 9})
	arm("arm_lzma", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM", "-m1=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	arm("arm_copy", armOne, []string{"in/arm.bin"}, []string{"-m0=ARM", "-m1=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	arm("arm_mf", armOne, []string{"in/arm.bin"}, []string{"-mf=ARM"}, sevenzip.Options{})
	arm("arm_mf_mx0", armOne, []string{"in/arm.bin"}, []string{"-mf=ARM", "-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	arm("arm_tree_only", armTree, []string{"arm"}, []string{"-m0=ARM"}, sevenzip.Options{Method: sevenzip.None})
	arm("arm_tree_only_ms_off", armTree, []string{"arm"}, []string{"-m0=ARM", "-ms=off"}, sevenzip.Options{Method: sevenzip.None, SolidOff: true})
	arm("arm_tree_lzma2", armTree, []string{"arm"}, []string{"-m0=ARM", "-m1=LZMA2"}, sevenzip.Options{})
	arm("arm_tree_lzma2_hc_off", armTree, []string{"arm"}, []string{"-m0=ARM", "-m1=LZMA2", "-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	arm("arm_tree_lzma2_ms_off", armTree, []string{"arm"}, []string{"-m0=ARM", "-m1=LZMA2", "-ms=off"}, sevenzip.Options{SolidOff: true})
	arm("arm_tree_lzma2_ms_150k", armTree, []string{"arm"}, []string{"-m0=ARM", "-m1=LZMA2", "-ms=150k"}, sevenzip.Options{SolidSize: 150 << 10})
	arm("arm_tree_lzma", armTree, []string{"arm"}, []string{"-m0=ARM", "-m1=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	arm("arm_tree_copy_ms_off", armTree, []string{"arm"}, []string{"-m0=ARM", "-m1=Copy", "-ms=off"}, sevenzip.Options{Method: sevenzip.Copy, SolidOff: true})
	arm("arm_pe_tree_mf", peTree, []string{"pe"}, []string{"-mf=ARM"}, sevenzip.Options{})
	arm("arm_mixed", mixed, mixedInputs, []string{"-mf=ARM"}, sevenzip.Options{})
	// BCJ2: alone (-m0=BCJ2), forced with -mf=BCJ2 in front of each
	// method and level (the four-coder folder with the LZMA side
	// streams), the same trees as BCJ, and a tree whose files hold calls
	// that target beyond their own file but inside the solid block (the
	// converter's file size is the folder's).
	bcj2 := func(name string, files []TreeFile, inputs []string, args []string, opts sevenzip.Options) {
		opts.Filter = sevenzip.BCJ2
		add(name, files, inputs, args, opts)
	}
	bcj2("bcj2_only", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ2"}, sevenzip.Options{Method: sevenzip.None})
	bcj2("bcj2_only_hc_off", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ2", "-mhc=off"}, sevenzip.Options{Method: sevenzip.None, NoHeaderCompression: true})
	bcj2("bcj2_only_mx1", pe, []string{"in/exe.bin"}, []string{"-m0=BCJ2", "-mx=1"}, sevenzip.Options{Method: sevenzip.None, Level: 1})
	bcj2("mf_bcj2", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2"}, sevenzip.Options{})
	bcj2("mf_bcj2_hc_off", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	bcj2("mf_bcj2_mx1", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-mx=1"}, sevenzip.Options{Level: 1})
	bcj2("mf_bcj2_mx9", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-mx=9"}, sevenzip.Options{Level: 9})
	bcj2("mf_bcj2_lzma", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	bcj2("mf_bcj2_lzma_hc_off", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-m0=LZMA", "-mhc=off"}, sevenzip.Options{Method: sevenzip.LZMA, NoHeaderCompression: true})
	bcj2("mf_bcj2_copy", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-m0=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	bcj2("mf_bcj2_mx0", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	bcj2("mf_bcj2_mt1", pe, []string{"in/exe.bin"}, []string{"-mf=BCJ2", "-mmt1"}, sevenzip.Options{Threads: 1})
	bcj2("bcj2_tree_only", peTree, []string{"pe"}, []string{"-m0=BCJ2"}, sevenzip.Options{Method: sevenzip.None})
	bcj2("bcj2_tree_only_hc_off", peTree, []string{"pe"}, []string{"-m0=BCJ2", "-mhc=off"}, sevenzip.Options{Method: sevenzip.None, NoHeaderCompression: true})
	bcj2("bcj2_tree_only_ms_off", peTree, []string{"pe"}, []string{"-m0=BCJ2", "-ms=off"}, sevenzip.Options{Method: sevenzip.None, SolidOff: true})
	bcj2("bcj2_tree_only_ms_150k", peTree, []string{"pe"}, []string{"-m0=BCJ2", "-ms=150k"}, sevenzip.Options{Method: sevenzip.None, SolidSize: 150 << 10})
	bcj2("bcj2_tree_mf", peTree, []string{"pe"}, []string{"-mf=BCJ2"}, sevenzip.Options{})
	bcj2("bcj2_tree_mf_hc_off", peTree, []string{"pe"}, []string{"-mf=BCJ2", "-mhc=off"}, sevenzip.Options{NoHeaderCompression: true})
	bcj2("bcj2_tree_mf_ms_off", peTree, []string{"pe"}, []string{"-mf=BCJ2", "-ms=off"}, sevenzip.Options{SolidOff: true})
	bcj2("bcj2_tree_mf_ms_150k", peTree, []string{"pe"}, []string{"-mf=BCJ2", "-ms=150k"}, sevenzip.Options{SolidSize: 150 << 10})
	bcj2("bcj2_tree_mf_lzma", peTree, []string{"pe"}, []string{"-mf=BCJ2", "-m0=LZMA"}, sevenzip.Options{Method: sevenzip.LZMA})
	bcj2("bcj2_tree_mf_copy", peTree, []string{"pe"}, []string{"-mf=BCJ2", "-m0=Copy"}, sevenzip.Options{Method: sevenzip.Copy})
	bcj2("bcj2_tree_mf_copy_ms_off", peTree, []string{"pe"}, []string{"-mf=BCJ2", "-m0=Copy", "-ms=off"}, sevenzip.Options{Method: sevenzip.Copy, SolidOff: true})
	bcj2("bcj2_tree_mf_mx0", peTree, []string{"pe"}, []string{"-mf=BCJ2", "-mx=0"}, sevenzip.Options{Level: sevenzip.LevelStore})
	bcj2("bcj2_tree_many_mx1", tenMB, []string{"mb"}, []string{"-mf=BCJ2", "-mx=1"}, sevenzip.Options{Level: 1})
	bcj2("bcj2_tree_many_ms_4m", tenMB, []string{"mb"}, []string{"-mf=BCJ2", "-ms=4m"}, sevenzip.Options{SolidSize: 4 << 20})
	bcj2("bcj2_tree_many_only", tenMB, []string{"mb"}, []string{"-m0=BCJ2"}, sevenzip.Options{Method: sevenzip.None})
	bcj2("bcj2_small", small, []string{"in/a.txt"}, []string{"-mf=BCJ2"}, sevenzip.Options{})
	bcj2("bcj2_mixed", mixed, mixedInputs, []string{"-mf=BCJ2"}, sevenzip.Options{})
	// Each file is 70 KB of calls 100 KB ahead: converted only when the
	// target lies inside the data the converter is told about.
	ahead := bytes.Repeat([]byte{0xE8, 0x00, 0x90, 0x01, 0x00}, 14000)
	aheadTree := []TreeFile{{"ah/a.bin", ahead}, {"ah/b.bin", ahead}, {"ah/c.bin", ahead}}
	bcj2("bcj2_ahead_solid", aheadTree, []string{"ah"}, []string{"-mf=BCJ2"}, sevenzip.Options{})
	bcj2("bcj2_ahead_ms_off", aheadTree, []string{"ah"}, []string{"-mf=BCJ2", "-ms=off"}, sevenzip.Options{SolidOff: true})
	bcj2("bcj2_ahead_only", aheadTree, []string{"ah"}, []string{"-m0=BCJ2"}, sevenzip.Options{Method: sevenzip.None})
	return cases
}

// RunSevenZMatrix runs every container case for one lane as a parallel
// subtest, then the large single-file cases of LargeCases (default
// threads and -mmt1) one at a time.
func RunSevenZMatrix(t *testing.T, root string, lane sot.Lane) {
	for _, c := range SevenZCases(SoTExe(t, root, lane)) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			CheckSevenZ(t, root, lane, t.TempDir(), c)
		})
	}
	for _, lc := range LargeCases() {
		for _, mt1 := range []bool{false, true} {
			lc, mt1 := lc, mt1
			name := fmt.Sprintf("large_%s_mx%d", lc.Name, lc.Level)
			args := []string{fmt.Sprintf("-mx=%d", lc.Level)}
			opts := sevenzip.Options{Level: lc.Level}
			if mt1 {
				name += "_mt1"
				args = append(args, "-mmt1")
				opts.Threads = 1
			}
			t.Run(name, func(t *testing.T) {
				files := []TreeFile{{"in/large.bin", lc.Input()}}
				CheckSevenZ(t, root, lane, t.TempDir(), SevenZCase{Name: name, Files: files, Inputs: []string{"in/large.bin"}, Args: args, Opts: opts})
			})
		}
	}
}
