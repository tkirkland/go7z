//go:build oracle

package bra_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/oracletest"
)

// TestEncodeOracleBCJ requires the module's x86 BCJ output (bra/bra86.go,
// ported from Bra86.c) to be byte-identical to the raw stream the pinned
// 7zr writes into .7z for -m0=BCJ, whole-buffer and streaming, and the
// module to decode the oracle's streams. The same matrix is the parity
// check for codec/BCJ.
func TestEncodeOracleBCJ(t *testing.T) {
	oracletest.RunBCJMatrix(t, oracletest.RepoRoot(t))
}
