//go:build sot

package bra_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTARM requires the module's ARM output (bra/bra.go, ported
// from Bra.c) to be byte-identical to the raw stream each lane's
// pinned 7za writes into .7z for -m0=ARM, whole-buffer and streaming,
// and the module to decode the SoT's streams. The same matrix is the
// parity check for codec/ARM.
func TestEncodeSoTARM(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunARMMatrix(t, root, lane)
		})
	}
}

// TestEncodeSoTARMT is the same proof for the ARMT (Thumb) converter
// (-m0=ARMT); the matrix is the parity check for codec/ARMT.
func TestEncodeSoTARMT(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunARMTMatrix(t, root, lane)
		})
	}
}

// TestEncodeSoTARM64 is the same proof for the ARM64 converter
// (-m0=ARM64); the matrix is the parity check for codec/ARM64.
func TestEncodeSoTARM64(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunARM64Matrix(t, root, lane)
		})
	}
}

// TestEncodeSoTSwap2 is the same proof for the Swap2 byte-swap filter
// (-m0=Swap2); the matrix is the parity check for codec/Swap2.
func TestEncodeSoTSwap2(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunSwapMatrix(t, root, lane, sottest.Swap2Check)
		})
	}
}

// TestEncodeSoTSwap4 is the same proof for Swap4 (-m0=Swap4); the
// matrix is the parity check for codec/Swap4.
func TestEncodeSoTSwap4(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunSwapMatrix(t, root, lane, sottest.Swap4Check)
		})
	}
}

// TestEncodeSoTDelta is the same proof for the Delta filter
// (-m0=Delta:<N>, bra/delta.go ported from Delta.c); the matrix is the
// parity check for codec/Delta.
func TestEncodeSoTDelta(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunDeltaMatrix(t, root, lane)
		})
	}
}
