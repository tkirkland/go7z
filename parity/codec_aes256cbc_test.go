//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// codec/AES256CBC: the SoT lists the raw codec but refuses it (user
// ruling 2026-11-07: 1:1 parity, rejections included). The line passes
// when the SoT refuses every way to write it (7z and zip "Not
// implemented", xz "The parameter is incorrect.") and the module has no
// way to write it, and when a 7z folder holding it is listed by both
// and extracted by neither ("Unsupported Method" / ErrUnsupported, with
// or without a password), for the SoT's archive and the module's.
func init() {
	checks["codec/AES256CBC"] = LineCheck{
		Name: "AES256CBC: refused 1:1 with the SoT, written by neither, read by neither",
		Check: func(t *testing.T, env *Env) {
			sottest.RunAES256CBCMatrix(t, env.Root, env.Lane)
		},
	}
}
