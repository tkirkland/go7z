//go:build sot

package sevenzip_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// TestSoT7z requires the module's .7z archives to be byte-identical
// to the SoT's for the container matrix (methods, levels, empty
// items, solid and non-solid, header compression, ordering, times), and
// the module to read the SoT's archives back. The same matrix is the
// parity check for format/7z.
func TestSoT7z(t *testing.T) {
	sottest.RunSevenZMatrix(t, sottest.RepoRoot(t))
}
