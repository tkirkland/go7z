//go:build sot

package sevenzip_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
)

// TestSoT7z requires the module's .7z archives to be byte-identical
// to each lane's SoT's for the container matrix (methods, levels, empty
// items, solid and non-solid, header compression, ordering, times, the
// large inputs where the builds differ), and the module to read the
// SoT's archives back. The same matrix is the parity check for
// format/7z.
func TestSoT7z(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunSevenZMatrix(t, root, lane)
		})
	}
}

// TestSoT7zAES is the proof for the 7zAES coder (-p, -mhe): with the
// SoT's IVs injected the module's archives are byte-identical to each
// lane's, the SoT tests them with the password, and the module reads
// the SoT's. The matrix is the parity check for codec/7zAES.
func TestSoT7zAES(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunAESMatrix(t, root, lane)
		})
	}
}
