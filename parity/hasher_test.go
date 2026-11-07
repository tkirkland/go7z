//go:build sot

package parity

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sottest"
)

// hasher/<Name>: the module's hasher (hasher package) reproduces the
// SoT's `7za h -scrc<Name>` report for single files, trees and
// directories: every per-file value, the summed "for data" and "for
// data and names" values with their carry counts, and the report's
// text from the Scanning line on. CRC32 is also the default (no
// -scrc) and -scrc* prints all five.
func init() {
	for _, name := range []string{"CRC32", "CRC64", "SHA256", "SHA1", "XXH64"} {
		name := name
		checks["hasher/"+name] = LineCheck{
			Name: name + " report identical to SoT",
			Check: func(t *testing.T, env *Env) {
				sottest.RunHashMatrix(t, env.Root, env.Lane, name)
				if name == "CRC32" {
					sottest.RunHashMatrix(t, env.Root, env.Lane, "")
					sottest.RunHashMatrix(t, env.Root, env.Lane, "*")
				}
			},
		}
	}
}
