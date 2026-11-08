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
		var found bool
		p, found = armFind(data, lim, p)
		if !found {
			return p
		}
		armBl(data, p, pc, encoding)
	}
}

// armFind is the BL scan of z7_BranchConv_ARM: it steps two instructions
// at a time looking for the 0xEB byte, and stops at lim (false: return
// p to the caller).
func armFind(data []byte, lim, p int) (int, bool) {
	for {
		if p >= lim {
			return p, false
		}
		p += 4
		if data[p-1] == 0xeb {
			return p, true
		}
		if p >= lim {
			return p, false
		}
		p += 4
		if data[p-1] == 0xeb {
			return p, true
		}
	}
}

// armBl rewrites the BL instruction at data[p-4:] with the (encoded or
// decoded) relative offset.
func armBl(data []byte, p int, pc uint32, encoding bool) {
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

// convReader applies a branch converter to a stream in chunks the way
// 7-Zip's filter coder does: each chunk is converted as far as the
// converter goes, the unprocessed tail is kept for the next chunk, and
// pc advances by the bytes passed on (Bra.h, "Example code for
// conversion in loop"). The tail left at end of input is passed through
// unconverted. conv is the converter closed over whatever it carries
// between calls (the x86 mask), which is what lets this one loop serve
// both the stateless RISC converters and the stateful x86 one.
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
		x.fillBuf()
		if x.err != nil && x.end == 0 {
			return 0, x.err
		}
		processed := x.conv(x.buf[:x.end], x.pc)
		x.pc += uint32(processed)
		x.n = processed
		if x.applyErr() {
			return 0, x.err
		}
	}
	m := copy(p, x.buf[x.out:x.n])
	x.out += m
	return m, nil
}

// fillBuf shifts the unprocessed tail down to the buffer start and
// reads more input until the buffer is full, EOF was seen or an error
// arrived.
func (x *convReader) fillBuf() {
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
}

// applyErr forces the whole buffer through the converter when the
// stream already ended: nothing may stay unconverted past EOF. It
// returns true when the buffer is empty and the error must be reported.
func (x *convReader) applyErr() bool {
	if x.err == nil {
		return false
	}
	x.n = x.end
	return x.n == 0
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
		var found bool
		p, found = armTFind(data, lim, p)
		if !found {
			return p
		}
		p = armTBl(data, p, pc, encoding)
		if p >= lim {
			return p
		}
	}
}

// armTFind is the halfword scan of z7_BranchConv_ARMT: it stops at a
// BL halfword pair (true) or at lim (false: return p to the caller).
func armTFind(data []byte, lim, p int) (int, bool) {
	b1 := uint32(data[p+1])
	for {
		if p >= lim {
			return p, false
		}
		b3 := uint32(data[p+3])
		p += 2
		if (b3 & (b1 ^ 8)) >= 0xf8 {
			return p, true
		}
		if p >= lim {
			return p, false
		}
		b1 = uint32(data[p+3])
		p += 2
		if (b1 & (b3 ^ 8)) >= 0xf8 {
			return p, true
		}
	}
}

// armTBl rewrites the BL instruction pair at data[p-2:] and data[p:]
// with the (encoded or decoded) relative offset.
func armTBl(data []byte, p int, pc uint32, encoding bool) int {
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
	return p
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
