//go:build oracle

package lzma_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/oracletest"
)

// TestEncodeOracleLZMA requires the module's LZMA streams to be
// byte-identical to the raw streams the pinned 7zr writes into .7z for
// every LZMA method parameter and level, and the module to decode the
// oracle's streams. The same matrix is the parity check for codec/LZMA.
func TestEncodeOracleLZMA(t *testing.T) {
	oracletest.RunLZMAMatrix(t, oracletest.RepoRoot(t))
}
