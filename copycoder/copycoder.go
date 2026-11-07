// Package copycoder implements the 7-Zip "Copy" coder (method ID 0x00).
//
// Copy stores data unchanged: the packed stream is byte-identical to the
// unpacked stream, in both directions. 7-Zip selects it for -mx0 and for
// -m0=Copy; the level and every other method parameter are ignored. There
// is no SDK C source for it (the C++ CopyCoder.cpp is the LGPL layer and is
// not ported); the behavior is the identity and is verified against the
// raw stream the pinned SoT writes into .7z.
package copycoder

import "io"

// Encode copies r to w unchanged and returns the number of bytes written.
func Encode(w io.Writer, r io.Reader) (int64, error) {
	return io.Copy(w, r)
}

// Decode copies r to w unchanged and returns the number of bytes written.
func Decode(w io.Writer, r io.Reader) (int64, error) {
	return io.Copy(w, r)
}

// EncodeBytes returns a copy of in: the Copy coder's packed stream.
func EncodeBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}

// DecodeBytes returns a copy of in: the Copy coder's unpacked stream.
func DecodeBytes(in []byte) []byte {
	out := make([]byte, len(in))
	copy(out, in)
	return out
}
