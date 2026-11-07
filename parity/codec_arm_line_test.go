//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/ARM: the module's ARM branch converter (bra/bra.go, ported from
// Bra.c) writes byte-identical streams to the SoT's -m0=ARM packed
// stream for a real binary and for synthetic BL patterns, and decodes
// the SoT's streams.
func init() {
	checks["codec/ARM"] = LineCheck{
		Name: "ARM converter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunARMMatrix(t, env.Root, env.Lane)
		},
	}
}
