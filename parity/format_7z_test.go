//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// format/7z: the module writes .7z archives byte-identical to the
// SoT's (sevenzip/writer.go, from DOC/7zFormat.txt and observation)
// and reads the SoT's archives (sevenzip/reader.go, ported from
// 7zArcIn.c and 7zDec.c) for the container matrix.
func init() {
	checks["format/7z"] = LineCheck{
		Name: "7z container identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunSevenZMatrix(t, env.Root)
		},
	}
}
