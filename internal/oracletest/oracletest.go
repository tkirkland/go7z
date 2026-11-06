// Package oracletest holds helpers shared by the oracle-backed tests:
// deterministic inputs, and ways to get raw codec streams out of what the
// pinned 7zr writes (single-block .xz payloads and single-file .7z packed
// streams), so the module's bytes can be compared with the oracle's.
package oracletest

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"go7z/internal/oracle"
)

// RepoRoot finds the directory holding go.mod above the test's cwd.
func RepoRoot(t testing.TB) string {
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

// DeterministicData returns size bytes of deterministic data with enough
// repetition to exercise matches.
func DeterministicData(size int) []byte {
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

// TextLike returns n bytes of deterministic pseudo-text (words from a
// small vocabulary) so the match finders see realistic repetition.
func TextLike(n int) []byte {
	vocab := []string{"the", "lzma", "encoder", "range", "coder", "match", "finder", "binary", "tree",
		"hash", "chain", "price", "optimal", "parser", "dictionary", "window", "stream", "block",
		"chunk", "literal", "distance", "length", "state", "probability", "oracle", "parity", "\n"}
	out := make([]byte, 0, n)
	seed := uint32(7)
	for len(out) < n {
		seed = seed*1664525 + 1013904223
		w := vocab[(seed>>24)%uint32(len(vocab))]
		out = append(out, w...)
		if w != "\n" {
			out = append(out, ' ')
		}
	}
	return out[:n]
}

// XzSingleBlock parses a single-block xz stream written by the oracle and
// returns the block's compressed payload (without the check), its LZMA2
// dictionary property and the uncompressed size from the index.
func XzSingleBlock(t testing.TB, data []byte) (payload []byte, prop byte, uncompressed uint64) {
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

	// Unpadded size = block header + compressed data + check. The check
	// size follows from the stream flags (byte 7 of the stream header).
	checkSize := 0
	switch data[7] & 0x0F {
	case 0x00:
		checkSize = 0
	case 0x01:
		checkSize = 4
	case 0x04:
		checkSize = 8
	case 0x0A:
		checkSize = 32
	default:
		t.Fatalf("unexpected xz check type %#x", data[7]&0x0F)
	}
	payloadLen := int(unpadded) - hdrSize - checkSize
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

// OracleXz writes input to a file in dir and has the oracle pack it as
// .xz with the given extra switches; it returns the .xz bytes.
func OracleXz(t testing.TB, root, dir string, input []byte, args ...string) []byte {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "in.bin"), input, 0o644); err != nil {
		t.Fatal(err)
	}
	full := append([]string{"a", "-txz"}, args...)
	full = append(full, filepath.Join(dir, "out.xz"), filepath.Join(dir, "in.bin"))
	if out, err := oracle.Run(root, full...); err != nil {
		t.Fatalf("oracle %v: %v\n%s", full, err, out)
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.xz"))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

// SevenZRawStream writes a single-file .7z with the oracle and returns
// the raw packed stream: it starts right after the 32-byte signature
// header and its length is the "Packed Size" the oracle lists.
func SevenZRawStream(t testing.TB, root, dir string, input []byte, args ...string) []byte {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, "in.bin"), input, 0o644); err != nil {
		t.Fatal(err)
	}
	full := append([]string{"a", "-t7z"}, args...)
	full = append(full, filepath.Join(dir, "out.7z"), filepath.Join(dir, "in.bin"))
	if out, err := oracle.Run(root, full...); err != nil {
		t.Fatalf("oracle %v: %v\n%s", full, err, out)
	}
	list, err := oracle.Run(root, "l", "-slt", filepath.Join(dir, "out.7z"))
	if err != nil {
		t.Fatalf("oracle l -slt: %v", err)
	}
	packed := -1
	for _, line := range strings.Split(string(list), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "Packed Size = ") {
			fmt.Sscan(strings.TrimPrefix(line, "Packed Size = "), &packed)
			break
		}
	}
	if packed < 0 {
		t.Fatalf("no Packed Size in oracle listing")
	}
	data, err := os.ReadFile(filepath.Join(dir, "out.7z"))
	if err != nil {
		t.Fatal(err)
	}
	if 32+packed > len(data) {
		t.Fatalf("packed size %d beyond archive", packed)
	}
	return data[32 : 32+packed]
}

// FirstDifference returns the index of the first differing byte, or -1
// when the slices are equal.
func FirstDifference(a, b []byte) int {
	if bytes.Equal(a, b) {
		return -1
	}
	i := 0
	for i < len(a) && i < len(b) && a[i] == b[i] {
		i++
	}
	return i
}
