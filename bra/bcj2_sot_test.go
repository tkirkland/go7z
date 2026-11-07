//go:build sot

package bra_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTBCJ2 requires the module's BCJ2 streams (bra/bcj2.go,
// ported from Bcj2Enc.c) to be byte-identical to the four pack streams
// each lane's pinned 7za writes into .7z for -m0=BCJ2, whole-buffer and
// streaming, and the module (ported from Bcj2.c) to decode the SoT's
// streams. The same matrix is the parity check for codec/BCJ2.
func TestEncodeSoTBCJ2(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunBCJ2Matrix(t, root, lane)
		})
	}
}
