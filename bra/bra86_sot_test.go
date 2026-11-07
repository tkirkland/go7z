//go:build sot

package bra_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTBCJ requires the module's x86 BCJ output (bra/bra86.go,
// ported from Bra86.c) to be byte-identical to the raw stream the pinned
// 7zr writes into .7z for -m0=BCJ, whole-buffer and streaming, and the
// module to decode the SoT's streams. The same matrix is the parity
// check for codec/BCJ.
func TestEncodeSoTBCJ(t *testing.T) {
	sottest.RunBCJMatrix(t, sottest.RepoRoot(t))
}
