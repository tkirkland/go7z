//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/7zAES: byte identity is impossible by construction (the SoT
// draws a random IV per 7zAES coder), so the line passes when, with the
// SoT's IVs injected through Options.Random, the module's archive is
// byte-identical to the SoT's for every folder shape (-p with LZMA2,
// LZMA, Copy, every filter, BCJ2, solid and non-solid trees, -mhe), the
// SoT tests the module's archive with the password and rejects a wrong
// one, and the module extracts the SoT's archives with the password.
func init() {
	checks["codec/7zAES"] = LineCheck{
		Name: "7zAES: structure identical given the SoT's IVs, cross-extraction both ways",
		Check: func(t *testing.T, env *Env) {
			sottest.RunAESMatrix(t, env.Root, env.Lane)
		},
	}
}
