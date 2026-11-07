//go:build sot

package lzma_test

import (
	"bytes"
	"fmt"
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
	"github.com/tkirkland/go7z/lzma"
)

// TestDecodeSoTXz decodes .xz files written by each lane's pinned 7za
// (single block, LZMA2) and requires byte-identical output.
func TestDecodeSoTXz(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		for _, size := range []int{1, 100, 4096, 1 << 16} {
			for _, level := range []string{"1", "5", "9"} {
				lane, size, level := lane, size, level
				t.Run(fmt.Sprintf("%s/size%d_mx%s", lane, size, level), func(t *testing.T) {
					t.Parallel()
					input := sottest.DeterministicData(size)
					data := sottest.SoTXz(t, root, lane, t.TempDir(), input, "-mx="+level)
					payload, prop, uncompressed := sottest.XzSingleBlock(t, data)
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
}
