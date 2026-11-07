//go:build sot

package copycoder_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// TestEncodeSoTCopy requires the module's Copy streams to be
// byte-identical to the raw streams the pinned 7zr writes into .7z for
// -m0=Copy at every level and for bare -mx0, and the module to decode the
// SoT's streams. The same matrix is the parity check for codec/Copy.
func TestEncodeSoTCopy(t *testing.T) {
	sottest.RunCopyMatrix(t, sottest.RepoRoot(t))
}
