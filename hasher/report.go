package hasher

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode/utf16"
)

// report.go: scanning and the text of `7za h`, observed on both SoTs
// (2026-11-07, identical in both lanes but for the banner line):
//
//   - Arguments are processed in order. A file argument is printed as
//     given, with backslashes. A directory argument is printed with a
//     trailing backslash and its contents follow depth first; each
//     directory's entries are in ordinal order of their upper-cased
//     names (the NTFS enumeration order: "1", "10", "2", "a", "a b",
//     "a-1", "a.1", "a1", "ab", "a_1", "b", "Z", "[x", "~y").
//   - The scan line: "N folders, " when there are directories, then
//     "N file(s), N bytes", then " (N KiB)" rounded up when the total
//     is not 0, MiB from 10 MiB and GiB from 10 GiB.
//   - The table: one column per algorithm (digest width), " ", Size
//     right-aligned in 13, "  Name"; dashes of the same widths; a
//     directory row has blank digest and size columns; the total row
//     has the summed digests, with "-XXXXXXXX" (the carry count)
//     appended when the number of files is not 1, and an empty name.
//   - Then "Folders: N" when there are directories, "Files: N" when the
//     number of files is not 1, "Size: N"; then per algorithm "NAME
//     for data:" padded to column 30 and the value, plus "NAME for
//     data and names:" with the names sum (count appended when files
//     plus directories is not 1) unless the scan is exactly one file
//     and no directory; then "Everything is Ok".

// Scan hashes the paths (relative to dir, as the SoT's arguments are
// relative to its working directory) into a bundle.
func Scan(dir string, paths []string, algs []Algorithm) (*Bundle, error) {
	b := NewBundle(algs)
	for _, p := range paths {
		if err := b.scanPath(dir, p); err != nil {
			return nil, err
		}
	}
	return b, nil
}

// scanPath adds one argument: a file, or a directory and its contents.
func (b *Bundle) scanPath(dir, arg string) error {
	name := strings.ReplaceAll(arg, "/", "\\")
	full := filepath.Join(dir, filepath.FromSlash(arg))
	st, err := os.Stat(full)
	if err != nil {
		return err
	}
	if !st.IsDir() {
		return b.addFilePath(name, full)
	}
	if !strings.HasSuffix(name, "\\") {
		name += "\\"
	}
	return b.scanDir(name, full)
}

func (b *Bundle) scanDir(name, full string) error {
	b.AddDir(name)
	ents, err := os.ReadDir(full)
	if err != nil {
		return err
	}
	sort.Slice(ents, func(i, j int) bool { return lessUpper(ents[i].Name(), ents[j].Name()) })
	for _, e := range ents {
		child := filepath.Join(full, e.Name())
		if e.IsDir() {
			if err := b.scanDir(name+e.Name()+"\\", child); err != nil {
				return err
			}
			continue
		}
		if err := b.addFilePath(name+e.Name(), child); err != nil {
			return err
		}
	}
	return nil
}

// lessUpper orders names by the ordinal order of their upper-cased
// UTF-16 units (the NTFS order observed on the SoT).
func lessUpper(a, b string) bool {
	ua := utf16.Encode([]rune(strings.ToUpper(a)))
	ub := utf16.Encode([]rune(strings.ToUpper(b)))
	for i := 0; i < len(ua) && i < len(ub); i++ {
		if ua[i] != ub[i] {
			return ua[i] < ub[i]
		}
	}
	return len(ua) < len(ub)
}

func (b *Bundle) addFilePath(name, full string) error {
	f, err := os.Open(full)
	if err != nil {
		return err
	}
	defer f.Close()
	hs := make([]hashWriter, len(b.Algorithms))
	ws := make([]io.Writer, len(b.Algorithms))
	for i, a := range b.Algorithms {
		hs[i] = hashWriter{a.New()}
		ws[i] = hs[i]
	}
	n, err := io.Copy(io.MultiWriter(ws...), f)
	if err != nil {
		return err
	}
	digests := make([][]byte, len(b.Algorithms))
	for i := range hs {
		digests[i] = hs[i].Sum(nil)
	}
	b.AddFile(name, uint64(n), digests)
	return nil
}

type hashWriter struct {
	h interface {
		io.Writer
		Sum([]byte) []byte
	}
}

func (w hashWriter) Write(p []byte) (int, error) { return w.h.Write(p) }
func (w hashWriter) Sum(b []byte) []byte         { return w.h.Sum(b) }

// Render returns the report text from the "Scanning" line through
// "Everything is Ok" (the banner line before it carries the build).
func Render(b *Bundle) string {
	var sb strings.Builder
	sb.WriteString("Scanning\n")
	if b.NumDirs > 0 {
		fmt.Fprintf(&sb, "%d %s, ", b.NumDirs, plural(b.NumDirs, "folder"))
	}
	fmt.Fprintf(&sb, "%d %s, %d bytes", b.NumFiles, plural(b.NumFiles, "file"), b.TotalSize)
	if b.TotalSize != 0 {
		sb.WriteString(" (" + roundedSize(b.TotalSize) + ")")
	}
	sb.WriteString("\n\n")

	widths := make([]int, len(b.Algorithms))
	for i, a := range b.Algorithms {
		widths[i] = a.DigestSize * 2
		fmt.Fprintf(&sb, "%-*s ", widths[i], a.Name)
	}
	sb.WriteString("         Size  Name\n")
	dashes := func() {
		for _, w := range widths {
			sb.WriteString(strings.Repeat("-", w) + " ")
		}
		sb.WriteString("-------------  ------------\n")
	}
	dashes()
	for _, e := range b.Entries {
		for i, a := range b.Algorithms {
			if e.IsDir {
				sb.WriteString(strings.Repeat(" ", widths[i]) + " ")
			} else {
				sb.WriteString(a.FormatDigest(e.Digests[i]) + " ")
			}
		}
		if e.IsDir {
			sb.WriteString(strings.Repeat(" ", 13))
		} else {
			fmt.Fprintf(&sb, "%13d", e.Size)
		}
		sb.WriteString("  " + e.Name + "\n")
	}
	dashes()
	for i, a := range b.Algorithms {
		sb.WriteString(b.Data[i].Format(a, b.NumFiles != 1) + " ")
	}
	fmt.Fprintf(&sb, "%13d  \n\n", b.TotalSize)

	if b.NumDirs > 0 {
		fmt.Fprintf(&sb, "Folders: %d\n", b.NumDirs)
	}
	if b.NumFiles != 1 {
		fmt.Fprintf(&sb, "Files: %d\n", b.NumFiles)
	}
	fmt.Fprintf(&sb, "Size: %d\n", b.TotalSize)
	for i, a := range b.Algorithms {
		sb.WriteString("\n")
		fmt.Fprintf(&sb, "%-30s%s\n", fmt.Sprintf("%-6s for data:", a.Name), b.Data[i].Format(a, b.NumFiles != 1))
		if b.NumFiles != 1 || b.NumDirs != 0 {
			fmt.Fprintf(&sb, "%-30s%s\n", fmt.Sprintf("%-6s for data and names:", a.Name), b.DataNames[i].Format(a, b.NumFiles+b.NumDirs != 1))
		}
	}
	sb.WriteString("\nEverything is Ok\n")
	return sb.String()
}

func plural(n int, word string) string {
	if n == 1 {
		return word
	}
	return word + "s"
}

// roundedSize is the parenthesised size: KiB rounded up below 10 MiB,
// MiB rounded up below 10 GiB, then GiB.
func roundedSize(n uint64) string {
	switch {
	case n >= 10<<30:
		return fmt.Sprintf("%d GiB", (n+(1<<30)-1)>>30)
	case n >= 10<<20:
		return fmt.Sprintf("%d MiB", (n+(1<<20)-1)>>20)
	default:
		return fmt.Sprintf("%d KiB", (n+1023)>>10)
	}
}
