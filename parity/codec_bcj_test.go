//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/BCJ: the module's x86 branch converter (bra/bra86.go, ported
// from Bra86.c) writes byte-identical streams to the SoT's -m0=BCJ
// packed stream for a real PE image and for synthetic inputs, and
// decodes the SoT's streams.
func init() {
	checks["codec/BCJ"] = LineCheck{
		Name: "BCJ (x86) converter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunBCJMatrix(t, env.Root)
		},
	}
}
