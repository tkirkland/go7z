//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/PPMD: the module's PPMd encoder (ppmd package, ported from
// Ppmd7.c and Ppmd7Enc.c) writes byte-identical streams to the SoT's
// -m0=PPMd packed stream at every level and at explicit orders and
// memory sizes, with the SoT's memory reduction, and decodes the SoT's
// streams (Ppmd7Dec.c).
func init() {
	checks["codec/PPMD"] = LineCheck{
		Name: "PPMd encoder identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunPPMDMatrix(t, env.Root, env.Lane)
		},
	}
}
