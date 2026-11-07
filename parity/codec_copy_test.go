//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/Copy: the module's Copy coder (copycoder/) writes byte-identical
// streams to the SoT's for -m0=Copy at every level and for bare -mx0,
// and reads the SoT's streams.
func init() {
	checks["codec/Copy"] = LineCheck{
		Name: "Copy coder identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunCopyMatrix(t, env.Root, env.Lane)
		},
	}
}
