//go:build oracle

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/oracletest"
)

// codec/Copy: the module's Copy coder (copycoder/) writes byte-identical
// streams to the oracle's for -m0=Copy at every level and for bare -mx0,
// and reads the oracle's streams.
func init() {
	checks["codec/Copy"] = LineCheck{
		Name: "Copy coder identical to oracle",
		Check: func(t *testing.T, env *Env) {
			oracletest.RunCopyMatrix(t, env.Root)
		},
	}
}
