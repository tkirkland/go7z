//go:build oracle

package sevenzip_test

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"os"
	"path/filepath"
	"testing"

	"go7z/internal/oracle"
	"go7z/internal/oracletest"
	"go7z/lzma"
	"go7z/sevenzip"
)

// oracleHeaders writes a multi-item archive with the oracle twice, with
// and without header compression, and returns the raw header and the
// packed header bytes.
func oracleHeaders(t *testing.T, root, dir string, files []oracletest.TreeFile, inputs []string) (raw, packed []byte) {
	t.Helper()
	tree := filepath.Join(dir, "tree")
	os.MkdirAll(tree, 0o755)
	oracletest.MakeTree(t, tree, files)
	bin, err := oracle.Binary(root)
	if err != nil {
		t.Fatal(err)
	}
	run := func(name string, extra ...string) []byte {
		args := append([]string{"a", "-t7z"}, extra...)
		args = append(args, filepath.Join(dir, name))
		args = append(args, inputs...)
		if out, err := oracle.RunBinary(bin, tree, args...); err != nil {
			t.Fatalf("oracle: %v\n%s", err, out)
		}
		b, err := os.ReadFile(filepath.Join(dir, name))
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	plain := run("plain.7z", "-mhc=off")
	off := binary.LittleEndian.Uint64(plain[12:])
	size := binary.LittleEndian.Uint64(plain[20:])
	raw = plain[32+off : 32+off+size]

	comp := run("comp.7z")
	off = binary.LittleEndian.Uint64(comp[12:])
	size = binary.LittleEndian.Uint64(comp[20:])
	info := comp[32+off : 32+off+size]
	if info[0] != 0x17 {
		t.Fatalf("oracle did not compress the header: % x", info)
	}
	// 17 06 <packPos> 01 09 <packedSize> ...
	rd := bytes.NewReader(info[2:])
	packPos := readNum(t, rd)
	if n := readNum(t, rd); n != 1 {
		t.Fatalf("numPackStreams %d", n)
	}
	if b, _ := rd.ReadByte(); b != 0x09 {
		t.Fatalf("expected kSize")
	}
	packedSize := readNum(t, rd)
	packed = comp[32+packPos : 32+packPos+packedSize]
	return raw, packed
}

// nameWord returns a deterministic pseudo-random lowercase word for
// file names, so that the names property has little repetition.
func nameWord(i int) string {
	seed := uint32(i*2654435761 + 12345)
	n := 3 + (i*31)%40
	b := make([]byte, n)
	for k := range b {
		seed = seed*1664525 + 1013904223
		b[k] = byte('a' + (seed>>24)%26)
	}
	return string(b)
}

func readNum(t *testing.T, r *bytes.Reader) uint64 {
	first, _ := r.ReadByte()
	if first&0x80 == 0 {
		return uint64(first)
	}
	mask := byte(0x80)
	n := 0
	for mask != 0 && first&mask != 0 {
		mask >>= 1
		n++
	}
	var v uint64
	for i := 0; i < n; i++ {
		b, _ := r.ReadByte()
		v |= uint64(b) << (8 * uint(i))
	}
	v |= uint64(first&(mask-1)) << (8 * uint(n))
	return v
}

// TestHeaderEncoderParams pins the LZMA parameters of the oracle's
// header coder: the parameters in use must reproduce the oracle's
// packed header byte for byte on several headers. On failure it
// searches the parameter space and reports every match.
func TestHeaderEncoderParams(t *testing.T) {
	root := oracletest.RepoRoot(t)
	mixed := []oracletest.TreeFile{
		{Name: "in/a.txt", Data: oracletest.TextLike(85)},
		{Name: "in/b.bin", Data: oracletest.DeterministicData(4096)},
		{Name: "in/empty.txt"},
		{Name: "in/dir/c.txt", Data: oracletest.TextLike(12)},
		{Name: "in/emptydir/"},
	}
	var many []oracletest.TreeFile
	for i := 0; i < 4000; i++ {
		many = append(many, oracletest.TreeFile{Name: fmt.Sprintf("many/d%d/e%d/f%04d_%s.bin", i%13, (i*7)%5, i, nameWord(i)), Data: oracletest.DeterministicData(10 + i%200)})
	}
	type hc struct {
		name   string
		files  []oracletest.TreeFile
		inputs []string
		raw    []byte
		packed []byte
	}
	headers := []hc{
		{name: "mixed", files: mixed, inputs: []string{"in/a.txt", "in/b.bin", "in/empty.txt", "in/dir", "in/emptydir"}},
		{name: "many", files: many, inputs: []string{"many"}},
	}
	for i := range headers {
		headers[i].raw, headers[i].packed = oracleHeaders(t, root, t.TempDir(), headers[i].files, headers[i].inputs)
	}
	props, sds := sevenzip.HeaderEncProps()
	ok := true
	for _, h := range headers {
		got, pr, err := sevenzip.EncodeHeaderWith(h.raw, props, sds)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(got, h.packed) {
			t.Errorf("%s: packed header differs (got %d bytes, want %d, props % x)", h.name, len(got), len(h.packed), pr)
			ok = false
		}
	}
	if ok {
		return
	}
	// Search.
	type mf struct {
		bt, nh int
		name   string
	}
	mfs := []mf{{1, 4, "bt4"}, {0, 4, "hc4"}, {1, 2, "bt2"}, {1, 3, "bt3"}, {1, 5, "bt5"}, {0, 5, "hc5"}}
	for _, level := range []int{5, 9, 1, 3, 7} {
		for _, algo := range []int{-1, 0, 1} {
			for _, fb := range []int{-1, 32, 64, 128, 273, 16, 96} {
				for _, m := range mfs {
					for _, mc := range []uint32{0, 1 << 30} {
						for _, sd := range []bool{false, true} {
							var p lzma.EncProps
							p.Init()
							p.Level = level
							p.DictSize = 1 << 20
							p.Algo = algo
							p.Fb = fb
							p.BtMode, p.NumHashBytes = m.bt, m.nh
							p.Mc = mc
							match := true
							for _, h := range headers {
								got, _, err := sevenzip.EncodeHeaderWith(h.raw, p, sd)
								if err != nil || !bytes.Equal(got, h.packed) {
									match = false
									break
								}
							}
							if match {
								t.Logf("MATCH: level=%d algo=%d fb=%d mf=%s mc=%d setDataSize=%v", level, algo, fb, m.name, mc, sd)
							}
						}
					}
				}
			}
		}
	}
}
