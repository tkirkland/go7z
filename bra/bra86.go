// Package bra holds the branch converters (BCJ filters) for executable
// code, ported from the public-domain LZMA SDK sources in 7-Zip 26.05.
// A converter rewrites the relative targets of CALL (and, for x86, JMP)
// instructions as absolute addresses so that the data compresses better;
// decoding is the inverse. The data size never changes.
//
// bra86.go is the port of C/Bra86.c (x86, the 7z method "BCJ").
package bra

import (
	"encoding/binary"
	"io"
)

// X86StateInit is Z7_BRANCH_CONV_ST_X86_STATE_INIT_VAL, the initial value
// of the state carried between calls of X86Convert.
const X86StateInit uint32 = 0

// x86NeedConvForMSByte is BR86_NEED_CONV_FOR_MS_BYTE: the most
// significant operand byte is 0x00 or 0xFF.
func x86NeedConvForMSByte(b uint32) bool { return ((b + 1) & 0xfe) == 0 }

// X86Convert is z7_BranchConvSt_X86 (Bra86.c): it converts data in place
// and returns the number of bytes processed. pc is the virtual program
// counter of data[0]; *state carries the converter's mask between calls
// (start with X86StateInit). The caller feeds the unprocessed tail,
// data[processed:], at the start of the next call with pc advanced by
// processed. When no more input follows, the tail stays unconverted.
func X86Convert(data []byte, pc uint32, state *uint32, encoding bool) int {
	size := len(data)
	if size < 5 {
		return 0
	}
	lim := size - 4
	mask := *state
	// BR_CONV_USE_OPT_PC_PTR: the branch offset is relative to the next
	// instruction, so pc is adjusted for the 4 operand bytes once here;
	// BR_PC_GET at position p is then pc + p.
	pc += 4
	var (
		p int
		v uint32
		c uint32
	)
	goto start

cont:
	mask |= 4
start:
	if p >= lim {
		goto fin
	}
	v = binary.LittleEndian.Uint32(data[p:]) ^ 0xe8e8e8e8
	p += 4
	if v&0xfe == 0 {
		goto m0
	}
	mask >>= 1
	if v&(0xfe<<8) == 0 {
		goto m1
	}
	mask >>= 1
	if v&(0xfe<<16) == 0 {
		goto m2
	}
	mask = 0
	if v&(0xfe<<24) == 0 {
		goto a3
	}
	goto mainLoop

m0:
	p--
m1:
	p--
m2:
	p--
	if mask == 0 {
		goto a3
	}
	if p > lim {
		goto finP
	}
	if mask > 4 || mask == 3 {
		mask >>= 1
		goto cont
	}
	mask >>= 1
	if x86NeedConvForMSByte(uint32(data[p+int(mask)])) {
		goto cont
	}
	v = binary.LittleEndian.Uint32(data[p:])
	v += 1 << 24
	if v&0xfe000000 != 0 {
		goto cont
	}
	c = pc + uint32(p)
	if encoding {
		v += c
	} else {
		v -= c
	}
	mask <<= 3
	if x86NeedConvForMSByte(v >> mask) {
		v ^= (uint32(0x100) << mask) - 1
		if encoding {
			v += c
		} else {
			v -= c
		}
	}
	mask = 0
	v &= 1<<25 - 1
	v -= 1 << 24
	binary.LittleEndian.PutUint32(data[p:], v)
	p += 4
	goto mainLoop

mainLoop:
	if p >= lim {
		goto fin
	}
	for {
		v = binary.LittleEndian.Uint32(data[p:]) ^ 0xe8e8e8e8
		p += 4
		if v&0xfe == 0 {
			goto a0
		}
		if v&(0xfe<<8) == 0 {
			goto a1
		}
		if v&(0xfe<<16) == 0 {
			goto a2
		}
		if v&(0xfe<<24) == 0 {
			goto a3
		}
		if p >= lim {
			goto fin
		}
	}

a0:
	p--
a1:
	p--
a2:
	p--
a3:
	if p > lim {
		goto finP
	}
	v = binary.LittleEndian.Uint32(data[p:])
	v += 1 << 24
	if v&0xfe000000 != 0 {
		goto cont
	}
	c = pc + uint32(p)
	if encoding {
		v += c
	} else {
		v -= c
	}
	v &= 1<<25 - 1
	v -= 1 << 24
	binary.LittleEndian.PutUint32(data[p:], v)
	p += 4
	goto mainLoop

finP:
	p--
fin:
	*state = mask
	return p
}

// X86Encode converts a whole buffer in place as the 7z BCJ encoder does
// (pc 0, fresh state): z7_BranchConvSt_X86_Enc over the whole stream.
// The last bytes that no complete instruction covers stay as they are.
func X86Encode(data []byte) {
	state := X86StateInit
	X86Convert(data, 0, &state, true)
}

// X86Decode is the inverse of X86Encode in place (7zDec.c applies
// z7_BranchConvSt_X86_Dec to the whole unpacked folder with pc 0).
func X86Decode(data []byte) {
	state := X86StateInit
	X86Convert(data, 0, &state, false)
}

// X86EncodeBytes returns a converted copy of data.
func X86EncodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	X86Encode(out)
	return out
}

// X86DecodeBytes returns a decoded copy of data.
func X86DecodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	X86Decode(out)
	return out
}

// x86Reader applies the converter to a stream in chunks the way 7-Zip's
// filter coder does: each chunk is converted as far as the converter
// goes, the unprocessed tail is kept for the next chunk, and pc advances
// by the bytes passed on. The converter is defined so that this gives
// the same bytes as one call over the whole stream (Bra.h, "Example
// code for conversion in loop"); the tail left at end of input is
// passed through unconverted.
type x86Reader struct {
	r        io.Reader
	encoding bool
	pc       uint32
	state    uint32
	buf      []byte // buf[out:n] is ready to return; buf[n:end] is the unprocessed tail
	out, n   int
	end      int
	eof      bool
	err      error
}

const x86ReaderChunk = 1 << 16

// NewX86EncodeReader returns a reader that yields r's bytes converted
// by the x86 BCJ encoder.
func NewX86EncodeReader(r io.Reader) io.Reader {
	return &x86Reader{r: r, encoding: true, state: X86StateInit, buf: make([]byte, x86ReaderChunk+8)}
}

// NewX86DecodeReader returns a reader that yields r's bytes converted
// by the x86 BCJ decoder.
func NewX86DecodeReader(r io.Reader) io.Reader {
	return &x86Reader{r: r, encoding: false, state: X86StateInit, buf: make([]byte, x86ReaderChunk+8)}
}

func (x *x86Reader) Read(p []byte) (int, error) {
	for x.out == x.n {
		if x.err != nil {
			return 0, x.err
		}
		if x.eof {
			// Pass the unconverted tail through, then report EOF.
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
		x.convert()
		if x.applyErr() {
			return 0, x.err
		}
	}
	m := copy(p, x.buf[x.out:x.n])
	x.out += m
	return m, nil
}

// fillBuf shifts the unprocessed tail down to the buffer start and reads
// more input until the buffer is full, EOF was seen or an error arrived.
func (x *x86Reader) fillBuf() {
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

// convert runs the converter over the filled buffer and advances the
// virtual program counter by the number of bytes it processed.
func (x *x86Reader) convert() {
	processed := X86Convert(x.buf[:x.end], x.pc, &x.state, x.encoding)
	x.pc += uint32(processed)
	x.n = processed
}

// applyErr forces the whole buffer through the converter when the stream
// already ended: nothing may stay unconverted past the error. It returns
// true when the buffer is empty and the error must be reported now.
func (x *x86Reader) applyErr() bool {
	if x.err == nil {
		return false
	}
	x.n = x.end
	return x.n == 0
}
