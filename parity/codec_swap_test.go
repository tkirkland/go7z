//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/Swap2 and codec/Swap4: the module's byte-swap filters
// (bra/swap.go, semantics observed from the SoT; no public-domain
// source) write byte-identical streams to the SoT's -m0=Swap2 and
// -m0=Swap4 packed streams and decode the SoT's streams.
func init() {
	checks["codec/Swap2"] = LineCheck{
		Name: "Swap2 filter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunSwapMatrix(t, env.Root, env.Lane, sottest.Swap2Check)
		},
	}
	checks["codec/Swap4"] = LineCheck{
		Name: "Swap4 filter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunSwapMatrix(t, env.Root, env.Lane, sottest.Swap4Check)
		},
	}
}
