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

// x86Conv returns X86Convert ready for one stream: it holds the mask
// the converter carries between calls (Bra86.c's state argument, started
// at X86StateInit), so bra.go's convReader can drive it as a plain
// converter. The chunking that closure allows is what 7-Zip's filter
// coder does, and the converter is defined so that it gives the same
// bytes as one call over the whole stream (Bra.h, "Example code for
// conversion in loop").
func x86Conv(encoding bool) func(data []byte, pc uint32) int {
	state := X86StateInit
	return func(data []byte, pc uint32) int { return X86Convert(data, pc, &state, encoding) }
}

// NewX86EncodeReader returns a reader that yields r's bytes converted
// by the x86 BCJ encoder, chunk by chunk as 7-Zip's filter coder does.
func NewX86EncodeReader(r io.Reader) io.Reader {
	return newConvReader(r, x86Conv(true))
}

// NewX86DecodeReader returns a reader that yields r's bytes converted
// by the x86 BCJ decoder.
func NewX86DecodeReader(r io.Reader) io.Reader {
	return newConvReader(r, x86Conv(false))
}
