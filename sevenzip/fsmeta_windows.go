package sevenzip

import (
	"os"
	"syscall"
)

// fileMeta returns the Windows attributes and the creation, access and
// write FILETIMEs of fi, exactly as the file system reports them (the
// SoT stores them unchanged).
func fileMeta(fi os.FileInfo) (attrib uint32, ctime, atime, mtime uint64) {
	if d, ok := fi.Sys().(*syscall.Win32FileAttributeData); ok {
		return d.FileAttributes, filetime(d.CreationTime), filetime(d.LastAccessTime), filetime(d.LastWriteTime)
	}
	return fallbackMeta(fi)
}

func filetime(t syscall.Filetime) uint64 {
	return uint64(t.HighDateTime)<<32 | uint64(t.LowDateTime)
}
