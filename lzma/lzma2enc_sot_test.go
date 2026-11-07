//go:build sot

package lzma_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTLZMA2 requires the module's LZMA2 streams to be
// byte-identical to the raw streams the pinned 7zr writes into .7z (every
// LZMA2 method parameter, block splitting) and to the payloads of its
// single-block .xz files, and the module to decode the SoT's streams.
// The same matrix is the parity check for codec/LZMA2.
func TestEncodeSoTLZMA2(t *testing.T) {
	sottest.RunLZMA2Matrix(t, sottest.RepoRoot(t))
}
