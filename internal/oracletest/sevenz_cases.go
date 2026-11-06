package oracletest

import (
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/sevenzip"
)

// SevenZCases is the container matrix compared with the oracle: single
// files at every method and level, empty files and directories,
// multi-file solid and non-solid archives, header compression on and
// off, nested directories, name ordering, CTime, and sizes that make the
// LZMA2 encoder split blocks.
func SevenZCases() []SevenZCase {
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
	return cases
}

// RunSevenZMatrix runs every container case as a parallel subtest.
func RunSevenZMatrix(t *testing.T, root string) {
	for _, c := range SevenZCases() {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			CheckSevenZ(t, root, t.TempDir(), c)
		})
	}
}
