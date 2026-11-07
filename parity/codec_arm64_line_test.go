//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/ARM64: the module's AArch64 branch converter (bra/bra64.go,
// ported from Bra.c) writes byte-identical streams to the SoT's
// -m0=ARM64 packed stream for a real binary and for synthetic BL and
// ADRP patterns, and decodes the SoT's streams.
func init() {
	checks["codec/ARM64"] = LineCheck{
		Name: "ARM64 converter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunARM64Matrix(t, env.Root, env.Lane)
		},
	}
}
