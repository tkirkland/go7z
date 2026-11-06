//go:build oracle

package parity

import (
	"testing"

	"go7z/internal/oracletest"
)

// codec/LZMA: the module's LZMA encoder (lzma/lzfind.go, lzma/lzmaenc.go,
// ported from LzFind.c and LzmaEnc.c) writes byte-identical streams to the
// oracle's for every LZMA method parameter (mf, a, fb, mc, lc, lp, pb, d,
// mt) and level, and the module's decoder reads the oracle's streams.
func init() {
	checks["codec/LZMA"] = LineCheck{
		Name: "LZMA encoder and decoder identical to oracle",
		Check: func(t *testing.T, env *Env) {
			oracletest.RunLZMAMatrix(t, env.Root)
		},
	}
}
