//go:build oracle

package sevenzip_test

import (
	"testing"

	"go7z/internal/oracletest"
)

// TestOracle7z requires the module's .7z archives to be byte-identical
// to the oracle's for the container matrix (methods, levels, empty
// items, solid and non-solid, header compression, ordering, times), and
// the module to read the oracle's archives back. The same matrix is the
// parity check for format/7z.
func TestOracle7z(t *testing.T) {
	oracletest.RunSevenZMatrix(t, oracletest.RepoRoot(t))
}
