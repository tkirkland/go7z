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
