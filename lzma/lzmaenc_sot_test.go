//go:build sot

package lzma_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTLZMA requires the module's LZMA streams to be
// byte-identical to the raw streams each lane's pinned 7za writes into
// .7z for every LZMA method parameter and level, including the large
// inputs where the x64 build's mx7..9 dictionaries differ, and the
// module to decode the SoT's streams. The same matrix is the parity
// check for codec/LZMA.
func TestEncodeSoTLZMA(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			sottest.RunLZMAMatrix(t, root, lane)
		})
	}
}
