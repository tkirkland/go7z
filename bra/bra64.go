package bra

import (
	"encoding/binary"
	"io"
)

// bra64.go holds the ARM64 converter of C/Bra.c (z7_BranchConv_ARM64).
// The file is not named with an _arm64 suffix because Go would read
// that as a GOARCH constraint and drop it on x86.

// ARM64Convert is z7_BranchConv_ARM64 (Bra.c): AArch64 BL instructions
// (top six bits 100101) and ADRP instructions (1 immlo 10000 immhi Rd)
// whose page offset lies within the converter's 20-bit window,
// little-endian, alignment 4, no look-ahead. pc is the virtual address
// of data[0]. It returns the number of bytes processed (len(data)
// rounded down to a multiple of 4).
func ARM64Convert(data []byte, pc uint32, encoding bool) int {
	const flag = uint32(1) << (24 - 4)
	const mask = (uint32(1) << 24) - (flag << 1)
	lim := len(data) &^ 3
	// BR_PC_INIT with BR_CONV_USE_OPT_PC_PTR: BR_PC_GET at position p
	// is pc + p; pc -= 4 because p points to the next instruction.
	pc -= 4
	p := 0
	for {
		if p == lim {
			return p
		}
		v := binary.LittleEndian.Uint32(data[p:])
		p += 4
		if (v-0x94000000)&0xfc000000 == 0 {
			c := (pc + uint32(p)) >> 2
			if encoding {
				v += c
			} else {
				v -= c
			}
			v &= 0x03ffffff
			v |= 0x94000000
			binary.LittleEndian.PutUint32(data[p-4:], v)
			continue
		}
		v -= 0x90000000
		if v&0x9f000000 == 0 {
			v += flag
			if v&mask != 0 {
				continue
			}
			z := (v & 0xffffffe0) | (v >> 26)
			c := ((pc + uint32(p)) >> (12 - 3)) &^ 7
			if encoding {
				z += c
			} else {
				z -= c
			}
			v &= 0x1f
			v |= 0x90000000
			v |= z << 26
			v |= 0x00ffffe0 & ((z & ((flag << 1) - 1)) - flag)
			binary.LittleEndian.PutUint32(data[p-4:], v)
		}
	}
}

// ARM64Encode converts a whole buffer in place as the 7z ARM64 encoder
// does (pc 0; the SoT rejects a pc parameter on -m0=ARM64).
func ARM64Encode(data []byte) { ARM64Convert(data, 0, true) }

// ARM64Decode is the inverse of ARM64Encode in place (7zDec.c applies
// z7_BranchConv_ARM64_Dec to the whole unpacked folder with the pc from
// the coder's 4-byte properties, 0 when there are none).
func ARM64Decode(data []byte) { ARM64Convert(data, 0, false) }

// ARM64EncodeBytes returns a converted copy of data.
func ARM64EncodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	ARM64Encode(out)
	return out
}

// ARM64DecodeBytes returns a decoded copy of data.
func ARM64DecodeBytes(data []byte) []byte {
	out := append([]byte(nil), data...)
	ARM64Decode(out)
	return out
}

// NewARM64EncodeReader returns a reader that yields r's bytes converted
// by the ARM64 encoder, chunk by chunk as 7-Zip's filter coder does.
func NewARM64EncodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, pc uint32) int { return ARM64Convert(data, pc, true) })
}

// NewARM64DecodeReader returns a reader that yields r's bytes converted
// by the ARM64 decoder.
func NewARM64DecodeReader(r io.Reader) io.Reader {
	return newConvReader(r, func(data []byte, pc uint32) int { return ARM64Convert(data, pc, false) })
}
