//go:build sot

package lzma_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTLZMA requires the module's LZMA streams to be
// byte-identical to the raw streams the pinned 7zr writes into .7z for
// every LZMA method parameter and level, and the module to decode the
// SoT's streams. The same matrix is the parity check for codec/LZMA.
func TestEncodeSoTLZMA(t *testing.T) {
	sottest.RunLZMAMatrix(t, sottest.RepoRoot(t))
}
