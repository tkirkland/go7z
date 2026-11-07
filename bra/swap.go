package bra

import "io"

// swap.go holds the Swap2 and Swap4 filters. 7-Zip has no public-domain
// source for them (the C++ ByteSwap.cpp is LGPL); their semantics are
// observed from the SoT's -m0=Swap2 and -m0=Swap4 packed streams
// (2026-11-07, both lanes identical): Swap2 exchanges the two bytes of
// every aligned pair, Swap4 reverses every aligned group of four, and
// the bytes after the last whole group stay as they are. They share the
// filter coder's chunked reader (convReader) with the branch converters;
// the stream position (pc) does not enter the conversion.

// Swap2Convert swaps every byte pair of data in place and returns the
// number of bytes processed (len(data) rounded down to a multiple of 2).
// The transform is its own inverse.
func Swap2Convert(data []byte) int {
	n := len(data) &^ 1
	for i := 0; i < n; i += 2 {
		data[i], data[i+1] = data[i+1], data[i]
	}
	return n
}

// Swap4Convert reverses every group of four bytes of data in place and
// returns the number of bytes processed (len(data) rounded down to a
// multiple of 4). The transform is its own inverse.
func Swap4Convert(data []byte) int {
	n := len(data) &^ 3
	for i := 0; i < n; i += 4 {
		data[i], data[i+1], data[i+2], data[i+3] = data[i+3], data[i+2], data[i+1], data[i]
	}
	return n
}

// Swap2Encode converts a whole buffer in place as the 7z Swap2 coder
// does; Swap2Decode is the same transform.
func Swap2Encode(data []byte) { Swap2Convert(data) }

// Swap2Decode is the inverse of Swap2Encode in place.
func Swap2Decode(data []byte) { Swap2Convert(data) }

// Swap4Encode converts a whole buffer in place as the 7z Swap4 coder
// does; Swap4Decode is the same transform.
func Swap4Encode(data []byte) { Swap4Convert(data) }

// Swap4Decode is the inverse of Swap4Encode in place.
func Swap4Decode(data []byte) { Swap4Convert(data) }

// Swap2EncodeBytes returns a converted copy of data.
func Swap2EncodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	Swap2Encode(out)
	return out
}

// Swap2DecodeBytes returns a decoded copy of data.
func Swap2DecodeBytes(data []byte) []byte { return Swap2EncodeBytes(data) }

// Swap4EncodeBytes returns a converted copy of data.
func Swap4EncodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	Swap4Encode(out)
	return out
}

// Swap4DecodeBytes returns a decoded copy of data.
func Swap4DecodeBytes(data []byte) []byte { return Swap4EncodeBytes(data) }

// NewSwap2EncodeReader returns a reader that yields r's bytes with
// every pair swapped, chunk by chunk as 7-Zip's filter coder does (the
// odd byte at a chunk end is carried to the next chunk).
func NewSwap2EncodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, _ uint32) int { return Swap2Convert(data) })
}

// NewSwap2DecodeReader is NewSwap2EncodeReader (the transform is its
// own inverse).
func NewSwap2DecodeReader(r io.Reader) io.Reader { return NewSwap2EncodeReader(r) }

// NewSwap4EncodeReader returns a reader that yields r's bytes with
// every group of four reversed, chunk by chunk.
func NewSwap4EncodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, _ uint32) int { return Swap4Convert(data) })
}

// NewSwap4DecodeReader is NewSwap4EncodeReader (the transform is its
// own inverse).
func NewSwap4DecodeReader(r io.Reader) io.Reader { return NewSwap4EncodeReader(r) }
