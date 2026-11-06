package lzma

import "encoding/binary"

// Lzma86HeaderSize is the size of the .lzma header: 5 property bytes plus
// an 8-byte uncompressed size.
const Lzma86HeaderSize = 13

// ParseLzma86Header parses the 13-byte .lzma header. A size of
// 0xFFFFFFFFFFFFFFFF means the stream carries an end marker.
func ParseLzma86Header(data []byte) (props []byte, size uint64, err error) {
	if len(data) < Lzma86HeaderSize {
		return nil, 0, ErrInputEOF
	}
	return data[0:5], binary.LittleEndian.Uint64(data[5:13]), nil
}

// DecodeLzma86 decodes a complete .lzma file (13-byte header plus stream).
func DecodeLzma86(data []byte) ([]byte, error) {
	props, size, err := ParseLzma86Header(data)
	if err != nil {
		return nil, err
	}
	src := data[Lzma86HeaderSize:]

	if size != 0xFFFFFFFFFFFFFFFF {
		dst := make([]byte, int(size))
		written, _, _, err := DecodeOneShot(dst, src, props, FinishEnd)
		if err != nil {
			return nil, err
		}
		if written != int(size) {
			return nil, ErrData
		}
		return dst, nil
	}

	// Stream with end marker: decode into a growing buffer.
	d, err := NewDecoder(props)
	if err != nil {
		return nil, err
	}
	var out []byte
	rest := src
	for {
		n, st, err := d.Decode(d.dicBufSize, rest, FinishAny)
		rest = rest[n:]
		if err != nil {
			return nil, err
		}
		progress := d.dicPos
		out = append(out, d.dic[:d.dicPos]...)
		d.dicPos = 0
		if st == StatusFinishedWithMark {
			return out, nil
		}
		if st == StatusNeedsMoreInput {
			return nil, ErrInputEOF
		}
		if n == 0 && progress == 0 {
			return nil, ErrData
		}
	}
}
