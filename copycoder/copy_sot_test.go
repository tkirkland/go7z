//go:build sot

package copycoder_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTCopy requires the module's Copy streams to be
// byte-identical to the raw streams each lane's pinned 7za writes into
// .7z for -m0=Copy at every level and for bare -mx0, and the module to
// decode the SoT's streams. The same matrix is the parity check for
// codec/Copy.
func TestEncodeSoTCopy(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunCopyMatrix(t, root, lane)
		})
	}
}
