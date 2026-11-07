//go:build sot

package ppmd_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTPPMD requires the module's PPMd output (ppmd package,
// ported from Ppmd7.c and Ppmd7Enc.c) to be byte-identical to the raw
// stream each lane's pinned 7za writes into .7z for -m0=PPMd at every
// level and at explicit orders and memory sizes, and the module to
// decode the SoT's streams. The matrix is the parity check for
// codec/PPMD.
func TestEncodeSoTPPMD(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunPPMDMatrix(t, root, lane)
		})
	}
}
