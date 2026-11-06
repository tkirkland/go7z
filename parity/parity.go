// Package parity defines the parity checklist walked by TestParity.
//
// The checklist is the two fixture files generated from the pinned oracle
// (testdata/parity/7zr-i.txt and testdata/parity/7zr-usage.txt). Each entry
// line is one parity line: it passes when its registered check passes, and
// fails when the check fails or no check is registered yet.
package parity

import (
	"strings"
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

// Entry is one walked line from the parity fixtures.
type Entry struct {
	File    string // "7zr-i.txt" or "7zr-usage.txt"
	Section string // "Formats", "Codecs", "Hashers", "Commands", "Switches"
	Key     string // registry key, e.g. "codec/Copy", "switch/-m"
	Name    string // display name, e.g. "Copy", "-m"
	Spec    string // full switch spec for Switches, otherwise empty
	Line    string // original fixture line
}

// ParseInventory parses the output of "7zr i" (testdata/parity/7zr-i.txt).
func ParseInventory(data []byte) ([]Entry, error) {
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
			File:    "7zr-i.txt",
			Section: section,
			Key:     kind + "/" + name,
			Name:    name,
			Line:    line,
		})
	}
	return out, nil
}

// ParseUsage parses the output of "7zr" with no arguments
// (testdata/parity/7zr-usage.txt).
func ParseUsage(data []byte) ([]Entry, error) {
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
				File:    "7zr-usage.txt",
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
				File:    "7zr-usage.txt",
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
