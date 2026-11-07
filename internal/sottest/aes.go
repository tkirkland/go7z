package sottest

import (
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/sevenzip"
)

// AESCases returns the 7zAES container cases: -p with every folder
// shape the writer has (LZMA2 at levels, LZMA, Copy, -mx0, the branch
// filters alone and in front of LZMA2, BCJ2 alone and -mf=BCJ2, Delta),
// solid and non-solid trees (one 7zAES coder per folder), empty files,
// -mhc=off, -mhe with one file and with a tree, and passwords with
// non-ASCII characters. exe is the lane's SoT binary.
func AESCases(exe []byte) []SevenZCase {
	var cases []SevenZCase
	add := func(name string, files []TreeFile, inputs []string, args []string, opts sevenzip.Options) {
		cases = append(cases, SevenZCase{Name: "aes_" + name, Files: files, Inputs: inputs, Args: args, Opts: opts})
	}
	const pw = "Test"
	one := []TreeFile{{"in/a.bin", DeterministicData(300001)}}
	pe := []TreeFile{{"in/pe.exe", exe[:600000]}}
	small := []TreeFile{{"in/s.bin", DeterministicData(11)}}
	tree := []TreeFile{
		{"t/a.bin", DeterministicData(100001)},
		{"t/b.bin", exe[:50001]},
		{"t/c.txt", TextLike(2003)},
		{"t/empty.bin", nil},
		{"t/dir/", nil},
		{"t/dir/d.bin", DeterministicData(16)},
	}
	p := func(args ...string) []string { return append([]string{"-p" + pw}, args...) }
	o := func(opts sevenzip.Options) sevenzip.Options { opts.Password = pw; return opts }

	add("one", one, []string{"in/a.bin"}, p(), o(sevenzip.Options{}))
	add("one_hc_off", one, []string{"in/a.bin"}, p("-mhc=off"), o(sevenzip.Options{NoHeaderCompression: true}))
	add("small", small, []string{"in/s.bin"}, p(), o(sevenzip.Options{}))
	add("small_copy", small, []string{"in/s.bin"}, p("-m0=Copy"), o(sevenzip.Options{Method: sevenzip.Copy}))
	add("empty", []TreeFile{{"in/e.bin", nil}}, []string{"in/e.bin"}, p(), o(sevenzip.Options{}))
	add("one_mx1", one, []string{"in/a.bin"}, p("-mx=1"), o(sevenzip.Options{Level: 1}))
	add("one_mx9", one, []string{"in/a.bin"}, p("-mx=9"), o(sevenzip.Options{Level: 9}))
	add("one_mx0", one, []string{"in/a.bin"}, p("-mx=0"), o(sevenzip.Options{Level: sevenzip.LevelStore}))
	add("one_lzma", one, []string{"in/a.bin"}, p("-m0=LZMA"), o(sevenzip.Options{Method: sevenzip.LZMA}))
	add("one_copy", one, []string{"in/a.bin"}, p("-m0=Copy"), o(sevenzip.Options{Method: sevenzip.Copy}))
	add("one_mt1", one, []string{"in/a.bin"}, p("-mmt1"), o(sevenzip.Options{Threads: 1}))
	add("pe", pe, []string{"in/pe.exe"}, p("-mf=off"), o(sevenzip.Options{}))
	add("pe_bcj", pe, []string{"in/pe.exe"}, p("-mf=BCJ"), o(sevenzip.Options{Filter: sevenzip.BCJ}))
	add("pe_bcj_only", pe, []string{"in/pe.exe"}, p("-m0=BCJ"), o(sevenzip.Options{Filter: sevenzip.BCJ, Method: sevenzip.None}))
	add("pe_bcj_copy", pe, []string{"in/pe.exe"}, p("-mf=BCJ", "-mx=0"), o(sevenzip.Options{Filter: sevenzip.BCJ, Level: sevenzip.LevelStore}))
	add("pe_bcj2", pe, []string{"in/pe.exe"}, p("-mf=BCJ2"), o(sevenzip.Options{Filter: sevenzip.BCJ2}))
	add("pe_bcj2_lzma", pe, []string{"in/pe.exe"}, p("-mf=BCJ2", "-m0=LZMA"), o(sevenzip.Options{Filter: sevenzip.BCJ2, Method: sevenzip.LZMA}))
	add("pe_bcj2_mx0", pe, []string{"in/pe.exe"}, p("-mf=BCJ2", "-mx=0"), o(sevenzip.Options{Filter: sevenzip.BCJ2, Level: sevenzip.LevelStore}))
	add("pe_bcj2_only", pe, []string{"in/pe.exe"}, p("-m0=BCJ2"), o(sevenzip.Options{Filter: sevenzip.BCJ2, Method: sevenzip.None}))
	add("small_bcj2_only", small, []string{"in/s.bin"}, p("-m0=BCJ2"), o(sevenzip.Options{Filter: sevenzip.BCJ2, Method: sevenzip.None}))
	add("small_bcj2", small, []string{"in/s.bin"}, p("-mf=BCJ2"), o(sevenzip.Options{Filter: sevenzip.BCJ2}))
	add("one_arm", one, []string{"in/a.bin"}, p("-mf=ARM"), o(sevenzip.Options{Filter: sevenzip.ARM}))
	add("one_armt", one, []string{"in/a.bin"}, p("-mf=ARMT"), o(sevenzip.Options{Filter: sevenzip.ARMT}))
	add("one_arm64", one, []string{"in/a.bin"}, p("-mf=ARM64"), o(sevenzip.Options{Filter: sevenzip.ARM64}))
	add("one_swap2", one, []string{"in/a.bin"}, p("-mf=Swap2"), o(sevenzip.Options{Filter: sevenzip.Swap2}))
	add("one_swap4_only", one, []string{"in/a.bin"}, p("-m0=Swap4"), o(sevenzip.Options{Filter: sevenzip.Swap4, Method: sevenzip.None}))
	add("one_delta", one, []string{"in/a.bin"}, p("-mf=Delta:4"), o(sevenzip.Options{Filter: sevenzip.Delta, DeltaDistance: 4}))
	add("tree", tree, []string{"t"}, p(), o(sevenzip.Options{}))
	add("tree_ms_off", tree, []string{"t"}, p("-ms=off"), o(sevenzip.Options{SolidOff: true}))
	add("tree_ms_120k", tree, []string{"t"}, p("-ms=120k"), o(sevenzip.Options{SolidSize: 120 << 10}))
	add("tree_hc_off", tree, []string{"t"}, p("-mhc=off"), o(sevenzip.Options{NoHeaderCompression: true}))
	add("tree_copy_ms_off", tree, []string{"t"}, p("-m0=Copy", "-ms=off"), o(sevenzip.Options{Method: sevenzip.Copy, SolidOff: true}))
	add("tree_bcj2_ms_off", tree, []string{"t"}, p("-mf=BCJ2", "-ms=off"), o(sevenzip.Options{Filter: sevenzip.BCJ2, SolidOff: true}))
	add("tree_lzma", tree, []string{"t"}, p("-m0=LZMA"), o(sevenzip.Options{Method: sevenzip.LZMA}))
	add("tree_mtc", tree, []string{"t"}, p("-mtc=on", "-mtm=off"), o(sevenzip.Options{StoreCTime: true, NoMTime: true}))
	add("mhe_one", one, []string{"in/a.bin"}, p("-mhe"), o(sevenzip.Options{EncryptHeader: true}))
	add("mhe_small", small, []string{"in/s.bin"}, p("-mhe"), o(sevenzip.Options{EncryptHeader: true}))
	add("mhe_tree", tree, []string{"t"}, p("-mhe"), o(sevenzip.Options{EncryptHeader: true}))
	add("mhe_tree_ms_off", tree, []string{"t"}, p("-mhe", "-ms=off"), o(sevenzip.Options{EncryptHeader: true, SolidOff: true}))
	add("mhe_tree_hc_off", tree, []string{"t"}, p("-mhe", "-mhc=off"), o(sevenzip.Options{EncryptHeader: true, NoHeaderCompression: true}))
	add("mhe_pe_bcj2", pe, []string{"in/pe.exe"}, p("-mhe", "-mf=BCJ2"), o(sevenzip.Options{EncryptHeader: true, Filter: sevenzip.BCJ2}))
	passwords := []string{
		"a",
		"pässwörd€",
		"日本語のパスワード",
		"a very long password with spaces and symbols @#%^&*()_+ and more text to exceed sixty-four bytes in length",
	}
	for i, pwd := range passwords {
		opts := sevenzip.Options{Password: pwd}
		cases = append(cases, SevenZCase{Name: fmt.Sprintf("aes_pw%d", i), Files: small, Inputs: []string{"in/s.bin"}, Args: []string{"-p" + pwd}, Opts: opts})
		opts.EncryptHeader = true
		cases = append(cases, SevenZCase{Name: fmt.Sprintf("aes_pw%d_mhe", i), Files: tree, Inputs: []string{"t"}, Args: []string{"-p" + pwd, "-mhe"}, Opts: opts})
	}
	return cases
}

// RunAESMatrix runs every 7zAES container case for one lane as a
// parallel subtest (CheckSevenZ with the SoT's IVs injected).
func RunAESMatrix(t *testing.T, root string, lane sot.Lane) {
	for _, c := range AESCases(SoTExe(t, root, lane)) {
		c := c
		t.Run(c.Name, func(t *testing.T) {
			t.Parallel()
			CheckSevenZ(t, root, lane, t.TempDir(), c)
		})
	}
}
