//go:build oracle

package lzma_test

import (
	"bytes"
	"testing"

	"go7z/internal/oracletest"
	"go7z/lzma"
)

// TestDecodeOracleXz decodes .xz files written by the pinned 7zr (single
// block, LZMA2) and requires byte-identical output.
func TestDecodeOracleXz(t *testing.T) {
	root := oracletest.RepoRoot(t)
	for _, size := range []int{1, 100, 4096, 1 << 16} {
		for _, level := range []string{"1", "5", "9"} {
			size, level := size, level
			t.Run(t.Name(), func(t *testing.T) {
				t.Parallel()
				input := oracletest.DeterministicData(size)
				data := oracletest.OracleXz(t, root, t.TempDir(), input, "-mx="+level)
				payload, prop, uncompressed := oracletest.XzSingleBlock(t, data)
				if uncompressed != uint64(len(input)) {
					t.Fatalf("xz index uncompressed size %d, want %d", uncompressed, len(input))
				}
				dst := make([]byte, int(uncompressed))
				written, _, _, err := lzma.Lzma2DecodeOneShot(dst, payload, prop, lzma.FinishEnd)
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
