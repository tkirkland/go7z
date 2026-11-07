//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/LZMA2: the module's LZMA2 encoder (lzma/lzma2enc.go, ported from
// Lzma2Enc.c) writes byte-identical streams to the SoT's for every
// LZMA2 method parameter including block splitting (c), in .7z and .xz,
// and the module's decoder reads the SoT's streams.
func init() {
	checks["codec/LZMA2"] = LineCheck{
		Name: "LZMA2 encoder and decoder identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunLZMA2Matrix(t, env.Root, env.Lane)
		},
	}
}
