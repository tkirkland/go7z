//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/ARMT: the module's Thumb branch converter (bra/bra.go, ported
// from Bra.c) writes byte-identical streams to the SoT's -m0=ARMT
// packed stream for a real binary and for synthetic BL patterns, and
// decodes the SoT's streams.
func init() {
	checks["codec/ARMT"] = LineCheck{
		Name: "ARMT (Thumb) converter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunARMTMatrix(t, env.Root, env.Lane)
		},
	}
}
