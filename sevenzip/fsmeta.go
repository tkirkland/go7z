package sevenzip

import (
	"os"
	"time"
)

const (
	attrDirectory     = 0x10
	attrArchive       = 0x20
	attrUnixExtension = 0x8000
)

// fallbackMeta derives the stored metadata from the portable os.FileInfo
// (used when the host does not provide Win32 data).
func fallbackMeta(fi os.FileInfo) (attrib uint32, ctime, atime, mtime uint64) {
	if fi.IsDir() {
		attrib = attrDirectory
	} else {
		attrib = attrArchive
	}
	attrib |= attrUnixExtension | uint32(fi.Mode().Perm())<<16
	mtime = toFiletime(fi.ModTime())
	return attrib, mtime, mtime, mtime
}

// toFiletime converts t to a Windows FILETIME (100 ns units since
// 1601-01-01 UTC).
func toFiletime(t time.Time) uint64 {
	const epochDiff = 116444736000000000 // 1601 to 1970 in 100 ns
	return uint64(t.UnixNano()/100) + epochDiff
}
