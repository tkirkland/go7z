//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/Delta: the module's Delta filter (bra/delta.go, ported from
// Delta.c) writes byte-identical streams to the SoT's -m0=Delta:<N>
// packed stream at distances 1..256 and decodes the SoT's streams.
func init() {
	checks["codec/Delta"] = LineCheck{
		Name: "Delta filter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunDeltaMatrix(t, env.Root, env.Lane)
		},
	}
}
