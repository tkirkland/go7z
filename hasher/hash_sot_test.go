//go:build sot

package hasher_test

import (
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/internal/sottest"
)

// TestSoTHash requires the module's hash report (hasher.Scan,
// hasher.Render) to equal each lane's `7za h` output from the Scanning
// line on, for every hasher 7za lists (-scrcCRC32, CRC64, SHA256,
// SHA1, XXH64), the default (CRC32) and -scrc*. The per-hasher
// matrices are the parity checks for hasher/<Name>.
func TestSoTHash(t *testing.T) {
	root := sottest.RepoRoot(t)
	for _, lane := range sot.Lanes {
		lane := lane
		t.Run(lane.String(), func(t *testing.T) {
			for _, scrc := range []string{"", "CRC32", "CRC64", "SHA256", "SHA1", "XXH64", "*"} {
				scrc := scrc
				name := scrc
				if name == "" {
					name = "default"
				} else if name == "*" {
					name = "all"
				}
				t.Run(name, func(t *testing.T) {
					sottest.RunHashMatrix(t, root, lane, scrc)
				})
			}
		})
	}
}
