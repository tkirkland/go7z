package bra

import (
	"encoding/binary"
	"io"
)

// bra.go is the port of C/Bra.c, the branch converters for RISC code.
// Each converter rewrites the CALL instructions of its architecture in
// place and returns the number of bytes processed (a multiple of the
// instruction alignment); the caller feeds the unprocessed tail with
// the next chunk, pc advanced by the processed bytes (Bra.h, "Example
// code for conversion in loop"). The tail left at end of input stays
// unconverted.

// ARMConvert is z7_BranchConv_ARM (Bra.c): ARM (32-bit) BL
// instructions, little-endian, alignment 4, no look-ahead. pc is the
// virtual address of data[0].
func ARMConvert(data []byte, pc uint32, encoding bool) int {
	size := len(data) &^ 3
	lim := size
	// BR_PC_INIT with BR_CONV_USE_OPT_PC_PTR: BR_PC_GET at position p
	// is pc + p. In ARM the branch offset is relative to +2 instructions
	// from the current one, and p points to the next instruction.
	pc += 8 - 4
	p := 0
	for {
		for {
			if p >= lim {
				return p
			}
			p += 4
			if data[p-1] == 0xeb {
				break
			}
			if p >= lim {
				return p
			}
			p += 4
			if data[p-1] == 0xeb {
				break
			}
		}
		v := binary.LittleEndian.Uint32(data[p-4:])
		c := (pc + uint32(p)) >> 2
		if encoding {
			v += c
		} else {
			v -= c
		}
		v &= 0x00ffffff
		v |= 0xeb000000
		binary.LittleEndian.PutUint32(data[p-4:], v)
	}
}

// ARMEncode converts a whole buffer in place as the 7z ARM encoder does
// (pc 0): z7_BranchConv_ARM_Enc over the whole stream.
func ARMEncode(data []byte) { ARMConvert(data, 0, true) }

// ARMDecode is the inverse of ARMEncode in place (7zDec.c applies
// z7_BranchConv_ARM_Dec to the whole unpacked folder with pc 0).
func ARMDecode(data []byte) { ARMConvert(data, 0, false) }

// ARMEncodeBytes returns a converted copy of data.
func ARMEncodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	ARMEncode(out)
	return out
}

// ARMDecodeBytes returns a decoded copy of data.
func ARMDecodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	ARMDecode(out)
	return out
}

// NewARMEncodeReader returns a reader that yields r's bytes converted
// by the ARM encoder, chunk by chunk as 7-Zip's filter coder does.
func NewARMEncodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, pc uint32) int { return ARMConvert(data, pc, true) })
}

// NewARMDecodeReader returns a reader that yields r's bytes converted
// by the ARM decoder.
func NewARMDecodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, pc uint32) int { return ARMConvert(data, pc, false) })
}

// convReader applies a stateless RISC converter to a stream in chunks
// the way 7-Zip's filter coder does (the same loop as x86Reader, which
// carries the x86 state as well): each chunk is converted as far as the
// converter goes, the unprocessed tail is kept for the next chunk, and
// pc advances by the bytes passed on. The tail left at end of input is
// passed through unconverted.
type convReader struct {
	r      io.Reader
	conv   func(data []byte, pc uint32) int
	pc     uint32
	buf    []byte // buf[out:n] is ready to return; buf[n:end] is the unprocessed tail
	out, n int
	end    int
	eof    bool
	err    error
}

const convReaderChunk = 1 << 16

func newConvReader(r io.Reader, conv func(data []byte, pc uint32) int) *convReader {
	return &convReader{r: r, conv: conv, buf: make([]byte, convReaderChunk+16)}
}

func (x *convReader) Read(p []byte) (int, error) {
	for x.out == x.n {
		if x.err != nil {
			return 0, x.err
		}
		if x.eof {
			if x.n < x.end {
				x.out, x.n = x.n, x.end
				break
			}
			x.err = io.EOF
			return 0, io.EOF
		}
		tail := copy(x.buf, x.buf[x.n:x.end])
		x.out, x.n, x.end = 0, 0, tail
		for x.end < len(x.buf) && !x.eof {
			m, err := x.r.Read(x.buf[x.end:])
			x.end += m
			if err == io.EOF {
				x.eof = true
			} else if err != nil {
				x.err = err
				x.eof = true
			}
			if m > 0 || err != nil {
				break
			}
		}
		if x.err != nil && x.end == 0 {
			return 0, x.err
		}
		processed := x.conv(x.buf[:x.end], x.pc)
		x.pc += uint32(processed)
		x.n = processed
		if x.err != nil {
			x.n = x.end
			if x.n == 0 {
				return 0, x.err
			}
		}
	}
	m := copy(p, x.buf[x.out:x.n])
	x.out += m
	return m, nil
}

// ARMTConvert is z7_BranchConv_ARMT (Bra.c): Thumb BL instruction
// pairs (first halfword 0xF000..0xF7FF, second 0xF800..0xFFFF),
// little-endian, alignment 2, look-ahead 2: the last halfword is left
// for the next call. pc is the virtual address of data[0].
func ARMTConvert(data []byte, pc uint32, encoding bool) int {
	size := len(data) &^ 1
	if size <= 2 {
		return 0
	}
	size -= 2
	lim := size
	// BR_PC_INIT; pc += 4 - 4: in Thumb the branch offset is relative to
	// +2 instructions (4 bytes) from the current one, and p points there
	// once both halfwords are consumed.
	p := 0
	for {
		b1 := uint32(data[p+1])
		for {
			if p >= lim {
				return p
			}
			b3 := uint32(data[p+3])
			p += 2
			if (b3 & (b1 ^ 8)) >= 0xf8 {
				break
			}
			if p >= lim {
				return p
			}
			b1 = uint32(data[p+3])
			p += 2
			if (b1 & (b3 ^ 8)) >= 0xf8 {
				break
			}
		}
		v := uint32(binary.LittleEndian.Uint16(data[p-2:]))<<11 |
			uint32(binary.LittleEndian.Uint16(data[p:]))&0x7FF
		p += 2
		c := (pc + uint32(p)) >> 1
		if encoding {
			v += c
		} else {
			v -= c
		}
		binary.LittleEndian.PutUint16(data[p-4:], uint16(((v>>11)&0x7ff)|0xf000))
		binary.LittleEndian.PutUint16(data[p-2:], uint16(v|0xf800))
		if p >= lim {
			return p
		}
	}
}

// ARMTEncode converts a whole buffer in place as the 7z ARMT encoder
// does (pc 0).
func ARMTEncode(data []byte) { ARMTConvert(data, 0, true) }

// ARMTDecode is the inverse of ARMTEncode in place (7zDec.c applies
// z7_BranchConv_ARMT_Dec to the whole unpacked folder with pc 0).
func ARMTDecode(data []byte) { ARMTConvert(data, 0, false) }

// ARMTEncodeBytes returns a converted copy of data.
func ARMTEncodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	ARMTEncode(out)
	return out
}

// ARMTDecodeBytes returns a decoded copy of data.
func ARMTDecodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	ARMTDecode(out)
	return out
}

// NewARMTEncodeReader returns a reader that yields r's bytes converted
// by the ARMT encoder, chunk by chunk.
func NewARMTEncodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, pc uint32) int { return ARMTConvert(data, pc, true) })
}

// NewARMTDecodeReader returns a reader that yields r's bytes converted
// by the ARMT decoder.
func NewARMTDecodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, pc uint32) int { return ARMTConvert(data, pc, false) })
}
