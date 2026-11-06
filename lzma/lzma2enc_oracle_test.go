//go:build oracle

package lzma_test

import (
	"testing"

	"go7z/internal/oracletest"
)

// TestEncodeOracleLZMA2 requires the module's LZMA2 streams to be
// byte-identical to the raw streams the pinned 7zr writes into .7z (every
// LZMA2 method parameter, block splitting) and to the payloads of its
// single-block .xz files, and the module to decode the oracle's streams.
// The same matrix is the parity check for codec/LZMA2.
func TestEncodeOracleLZMA2(t *testing.T) {
	oracletest.RunLZMA2Matrix(t, oracletest.RepoRoot(t))
}
