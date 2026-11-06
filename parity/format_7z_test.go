//go:build oracle

package parity

import (
	"testing"

	"go7z/internal/oracletest"
)

// format/7z: the module writes .7z archives byte-identical to the
// oracle's (sevenzip/writer.go, from DOC/7zFormat.txt and observation)
// and reads the oracle's archives (sevenzip/reader.go, ported from
// 7zArcIn.c and 7zDec.c) for the container matrix.
func init() {
	checks["format/7z"] = LineCheck{
		Name: "7z container identical to oracle",
		Check: func(t *testing.T, env *Env) {
			oracletest.RunSevenZMatrix(t, env.Root)
		},
	}
}
