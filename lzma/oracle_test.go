//go:build oracle

package lzma

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"go7z/internal/oracle"
)

// TestDecodeOracleXz decodes .xz files written by the pinned 7zr (single
// block, LZMA2) and requires byte-identical output. The test uses a minimal
// xz parse to reach the raw LZMA2 chunk stream; the full xz container port
// is exercised by the xz format line of the parity test.
func TestDecodeOracleXz(t *testing.T) {
	root := repoRoot(t)
	for _, size := range []int{1, 100, 4096, 1 << 16} {
		for _, level := range []string{"1", "5", "9"} {
			size, level := size, level
			t.Run(t.Name(), func(t *testing.T) {
				t.Parallel()
				dir := t.TempDir()
				input := deterministicData(size)
				if err := os.WriteFile(filepath.Join(dir, "in.bin"), input, 0o644); err != nil {
					t.Fatal(err)
				}
				// oracle.Run searches for the repo root from its dir argument,
				// so run from the repo root with absolute paths in the temp dir.
				if _, err := oracle.Run(root, "a", "-txz", "-mx="+level, filepath.Join(dir, "out.xz"), filepath.Join(dir, "in.bin")); err != nil {
					t.Fatalf("oracle a -txz: %v", err)
				}
				data, err := os.ReadFile(filepath.Join(dir, "out.xz"))
				if err != nil {
					t.Fatal(err)
				}
				payload, prop, uncompressed := xzSingleBlock(t, data)
				if uncompressed != uint64(len(input)) {
					t.Fatalf("xz index uncompressed size %d, want %d", uncompressed, len(input))
				}
				dst := make([]byte, int(uncompressed))
				written, _, _, err := Lzma2DecodeOneShot(dst, payload, prop, FinishEnd)
				if err != nil {
					t.Fatalf("Lzma2DecodeOneShot: %v", err)
				}
				if written != len(input) {
					t.Fatalf("decoded %d bytes, want %d", written, len(input))
				}
				if !bytes.Equal(dst, input) {
					t.Fatalf("decoded bytes differ")
				}
			})
		}
	}
}

// xzSingleBlock parses a single-block xz stream written by the oracle and
// returns the block's compressed payload, its LZMA2 dictionary property and
// the uncompressed size from the index.
func xzSingleBlock(t *testing.T, data []byte) (payload []byte, prop byte, uncompressed uint64) {
	t.Helper()
	if len(data) < 24 || !bytes.Equal(data[:6], []byte{0xFD, '7', 'z', 'X', 'Z', 0x00}) {
		t.Fatalf("not an xz stream")
	}
	off := 12
	hdrSize := (int(data[off]&0xFF) + 1) * 4
	hdr := data[off : off+hdrSize]
	off += hdrSize
	flags := hdr[1]
	nfilters := int(flags&0x03) + 1
	p := 2
	filterID := uint64(0)
	var props []byte
	for i := 0; i < nfilters; i++ {
		id, n := readXzVLI(hdr[p:])
		p += n
		propsSize, n := readXzVLI(hdr[p:])
		p += n
		props = hdr[p : p+int(propsSize)]
		p += int(propsSize)
		if i == 0 {
			filterID = id
		}
	}
	if flags&0x40 != 0 {
		_, n := readXzVLI(hdr[p:])
		p += n
	}
	if flags&0x80 != 0 {
		_, n := readXzVLI(hdr[p:])
		p += n
	}
	if filterID != 0x21 || len(props) != 1 {
		t.Fatalf("unexpected filter id %#x props %x", filterID, props)
	}

	// Index at the end: footer is the last 12 bytes.
	backward := int(data[len(data)-8] & 0xFF)
	indexSize := (backward + 1) * 4
	idx := data[len(data)-12-indexSize : len(data)-12]
	if idx[0] != 0x00 {
		t.Fatalf("xz index indicator %#x", idx[0])
	}
	ip := 1
	count, n := readXzVLI(idx[ip:])
	ip += n
	if count != 1 {
		t.Fatalf("expected 1 index record, got %d", count)
	}
	unpadded, n := readXzVLI(idx[ip:])
	ip += n
	uncompressed, n = readXzVLI(idx[ip:])
	ip += n

	payloadLen := int(unpadded) - hdrSize
	if off+payloadLen > len(data) {
		t.Fatalf("payload %d exceeds stream", payloadLen)
	}
	return data[off : off+payloadLen], props[0], uncompressed
}

func readXzVLI(b []byte) (uint64, int) {
	var v uint64
	var shift uint
	for i, c := range b {
		v |= uint64(c&0x7F) << shift
		if c&0x80 == 0 {
			return v, i + 1
		}
		shift += 7
	}
	return v, len(b)
}

// deterministicData returns size bytes of deterministic data with enough
// repetition to exercise matches.
func deterministicData(size int) []byte {
	out := make([]byte, size)
	seed := uint32(1)
	for i := range out {
		seed = seed*1664525 + 1013904223
		out[i] = byte(seed >> 24)
	}
	if size > 4096 {
		n := size / 8
		if n > 4000 {
			n = 4000
		}
		copy(out[size/2:], out[:n])
	}
	return out
}

func repoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	for d := wd; ; d = filepath.Dir(d) {
		if _, err := os.Stat(filepath.Join(d, "go.mod")); err == nil {
			return d
		}
		parent := filepath.Dir(d)
		if parent == d {
			break
		}
	}
	t.Fatalf("go.mod not found above %s", wd)
	return ""
}
