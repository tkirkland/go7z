//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/BCJ2: the module's BCJ2 converter (bra/bcj2.go, ported from
// Bcj2Enc.c and Bcj2.c) writes the four streams byte-identical to the
// SoT's -m0=BCJ2 pack streams for a real PE image and synthetic inputs,
// whole-buffer and streaming, decodes the SoT's streams, and reads the
// SoT's BCJ2 archives in every shape it writes. The container side
// (-mf=BCJ2 with LZMA2, LZMA and Copy, -m0=BCJ2 alone, solid trees)
// is in the format/7z matrix.
func init() {
	checks["codec/BCJ2"] = LineCheck{
		Name: "BCJ2 (x86, four streams) converter identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunBCJ2Matrix(t, env.Root, env.Lane)
		},
	}
}
