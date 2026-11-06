//go:build !windows

package sevenzip

import "os"

// fileMeta on non-Windows hosts. The oracle is a Windows binary, so this
// path is not covered by the parity checks; it mirrors what 7-Zip's
// POSIX build stores (Windows attribute bits with the Unix mode in the
// high 16 bits and bit 15 set).
func fileMeta(fi os.FileInfo) (attrib uint32, ctime, atime, mtime uint64) {
	return fallbackMeta(fi)
}
