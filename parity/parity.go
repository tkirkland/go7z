// Package parity defines the parity checklist walked by TestParity.
//
// The checklist is the pair of fixture files generated from each lane's
// pinned SoT (testdata/parity/7za-x86-i.txt and 7za-x86-usage.txt for
// the 32-bit lane, 7za-x64-i.txt and 7za-x64-usage.txt for the 64-bit
// lane). Each entry line is one parity line in that lane: it passes when
// its registered check passes against that lane's SoT, and fails when
// the check fails or no check is registered yet. A line is done only
// when both lanes pass.
package parity

import (
	"strings"

	"github.com/tkirkland/go7z/internal/sot"
)

// Omitted lists the fixture lines the user removed from scope (2026-11-06:
// "omit ppc, ia64, sparc, riscv"). TestParity skips them and names them
// in its output; they are never counted as passes.
var Omitted = map[string]string{
	"codec/PPC":   "omitted by the user on 2026-11-06",
	"codec/IA64":  "omitted by the user on 2026-11-06",
	"codec/SPARC": "omitted by the user on 2026-11-06",
	"codec/RISCV": "omitted by the user on 2026-11-06",
}

// Blocked lists lines that fail for a reason other than missing work.
// Empty since 2026-11-07: the user ruled that all 12 lines 7za adds
// count ("all 12"), including Deflate, Deflate64, BZip2, Cab, gzip and
// bzip2, whose only 7-Zip source is the C++ layer; they are ordinary
// not-done lines.
var Blocked = map[string]string{}

// Fixtures returns the two fixture file names of a lane: the output of
// "7za i" and of "7za" with no arguments.
func Fixtures(lane sot.Lane) (inventory, usage string) {
	switch lane {
	case sot.Lane32:
		return "7za-x86-i.txt", "7za-x86-usage.txt"
	case sot.Lane64:
		return "7za-x64-i.txt", "7za-x64-usage.txt"
	}
	return "", ""
}

// Entry is one walked line from the parity fixtures.
type Entry struct {
	File    string // fixture file name
	Section string // "Formats", "Codecs", "Hashers", "Commands", "Switches"
	Key     string // registry key, e.g. "codec/Copy", "switch/-m"
	Name    string // display name, e.g. "Copy", "-m"
	Spec    string // full switch spec for Switches, otherwise empty
	Line    string // original fixture line
}

// ParseInventory parses the output of "7za i" (file is the fixture name
// recorded in the entries).
func ParseInventory(file string, data []byte) ([]Entry, error) {
	var out []Entry
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)
		switch trim {
		case "Formats:", "Codecs:", "Hashers:":
			section = strings.TrimSuffix(trim, ":")
			continue
		}
		if section == "" || trim == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		var name string
		switch section {
		case "Formats":
			name = fields[1]
		default: // Codecs, Hashers
			name = fields[len(fields)-1]
		}
		kind := strings.TrimSuffix(strings.ToLower(section), "s")
		out = append(out, Entry{
			File:    file,
			Section: section,
			Key:     kind + "/" + name,
			Name:    name,
			Line:    line,
		})
	}
	return out, nil
}

// ParseUsage parses the output of "7za" with no arguments (file is the
// fixture name recorded in the entries).
func ParseUsage(file string, data []byte) ([]Entry, error) {
	var out []Entry
	section := ""
	for _, raw := range strings.Split(string(data), "\n") {
		line := strings.TrimRight(raw, "\r")
		trim := strings.TrimSpace(line)
		switch trim {
		case "<Commands>", "<Switches>":
			section = strings.Trim(trim, "<>")
			continue
		}
		if section == "" || trim == "" {
			continue
		}
		idx := strings.Index(line, " : ")
		if idx < 0 {
			continue
		}
		spec := strings.TrimSpace(line[:idx])
		switch section {
		case "Commands":
			fields := strings.Fields(spec)
			if len(fields) == 0 {
				continue
			}
			name := fields[0]
			out = append(out, Entry{
				File:    file,
				Section: section,
				Key:     "command/" + name,
				Name:    name,
				Line:    line,
			})
		case "Switches":
			base := spec
			if i := strings.IndexAny(base, "[{"); i >= 0 {
				base = base[:i]
			}
			out = append(out, Entry{
				File:    file,
				Section: section,
				Key:     "switch/" + base,
				Name:    base,
				Spec:    spec,
				Line:    line,
			})
		}
	}
	return out, nil
}
