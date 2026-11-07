//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/LZMA: the module's LZMA encoder (lzma/lzfind.go, lzma/lzmaenc.go,
// ported from LzFind.c and LzmaEnc.c) writes byte-identical streams to the
// SoT's for every LZMA method parameter (mf, a, fb, mc, lc, lp, pb, d,
// mt) and level, and the module's decoder reads the SoT's streams.
func init() {
	checks["codec/LZMA"] = LineCheck{
		Name: "LZMA encoder and decoder identical to SoT",
		Check: func(t *testing.T, env *Env) {
			sottest.RunLZMAMatrix(t, env.Root, env.Lane)
		},
	}
}
