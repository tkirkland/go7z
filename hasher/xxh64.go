package hasher

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

// xxh64.go is the port of C/Xxh64.c (XXH64 by Yann Collet, BSD
// 2-Clause, as modified by Igor Pavlov; seed 0), the XXH64 hasher that
// 7za lists.

const (
	xxhPrime1 = 0x9E3779B185EBCA87
	xxhPrime2 = 0xC2B2AE3D27D4EB4F
	xxhPrime3 = 0x165667B19E3779F9
	xxhPrime4 = 0x85EBCA77C2B2AE63
	xxhPrime5 = 0x27D4EB2F165667C5
)

func xxhRound(acc, input uint64) uint64 {
	acc += input * xxhPrime2
	acc = bits.RotateLeft64(acc, 31)
	return acc * xxhPrime1
}

func xxhMerge(acc, val uint64) uint64 {
	acc ^= xxhRound(0, val)
	return acc*xxhPrime1 + xxhPrime4
}

// xxh64 is CXxh64: the four lanes, the byte count and the 32-byte
// buffer of the pending partial block.
type xxh64 struct {
	v     [4]uint64
	count uint64
	buf   [32]byte
}

// NewXXH64 returns a hash.Hash computing XXH64 with seed 0.
func NewXXH64() hash.Hash {
	x := &xxh64{}
	x.Reset()
	return x
}

func (x *xxh64) Reset() {
	var seed uint64 // 7-Zip uses seed 0
	p1, p2 := uint64(xxhPrime1), uint64(xxhPrime2)
	x.v[0] = seed + p1 + p2
	x.v[1] = seed + p2
	x.v[2] = seed
	x.v[3] = seed - p1
	x.count = 0
	x.buf = [32]byte{}
}

func (x *xxh64) Size() int      { return 8 }
func (x *xxh64) BlockSize() int { return 32 }

func (x *xxh64) updateBlocks(data []byte) {
	v0, v1, v2, v3 := x.v[0], x.v[1], x.v[2], x.v[3]
	for len(data) >= 32 {
		v0 = xxhRound(v0, binary.LittleEndian.Uint64(data))
		v1 = xxhRound(v1, binary.LittleEndian.Uint64(data[8:]))
		v2 = xxhRound(v2, binary.LittleEndian.Uint64(data[16:]))
		v3 = xxhRound(v3, binary.LittleEndian.Uint64(data[24:]))
		data = data[32:]
	}
	x.v[0], x.v[1], x.v[2], x.v[3] = v0, v1, v2, v3
}

// Write is Xxh64_Update.
func (x *xxh64) Write(p []byte) (int, error) {
	n := len(p)
	if n == 0 {
		return 0, nil
	}
	cnt := int(x.count & 31)
	x.count += uint64(n)
	if cnt != 0 {
		rem := 32 - cnt
		if rem > len(p) {
			rem = len(p)
		}
		copy(x.buf[cnt:], p[:rem])
		p = p[rem:]
		cnt += rem
		if cnt != 32 {
			return n, nil
		}
		x.updateBlocks(x.buf[:])
	}
	full := len(p) &^ 31
	if full > 0 {
		x.updateBlocks(p[:full])
		p = p[full:]
	}
	if len(p) > 0 {
		copy(x.buf[:], p)
	}
	return n, nil
}

// Sum64 is Xxh64_Digest.
func (x *xxh64) Sum64() uint64 {
	h := x.v[2]
	if x.count >= 32 {
		h = bits.RotateLeft64(x.v[0], 1) +
			bits.RotateLeft64(x.v[1], 7) +
			bits.RotateLeft64(h, 12) +
			bits.RotateLeft64(x.v[3], 18)
		h = xxhMerge(h, x.v[0])
		h = xxhMerge(h, x.v[1])
		h = xxhMerge(h, x.v[2])
		h = xxhMerge(h, x.v[3])
	} else {
		h += xxhPrime5
	}
	h += x.count
	cnt := int(x.count & 31)
	data := x.buf[:cnt]
	for len(data) >= 8 {
		h ^= xxhRound(0, binary.LittleEndian.Uint64(data))
		data = data[8:]
		h = bits.RotateLeft64(h, 27)
		h = h*xxhPrime1 + xxhPrime4
	}
	if len(data) >= 4 {
		v := uint64(binary.LittleEndian.Uint32(data))
		data = data[4:]
		h ^= v * xxhPrime1
		h = bits.RotateLeft64(h, 23)
		h = h*xxhPrime2 + xxhPrime3
	}
	for _, b := range data {
		h ^= uint64(b) * xxhPrime5
		h = bits.RotateLeft64(h, 11)
		h *= xxhPrime1
	}
	h ^= h >> 33
	h *= xxhPrime2
	h ^= h >> 29
	h *= xxhPrime3
	h ^= h >> 32
	return h
}

// Sum appends the digest in little-endian byte order (the 7-Zip hasher
// interface writes digests as little-endian values; the report prints
// the value in hex).
func (x *xxh64) Sum(b []byte) []byte {
	return binary.LittleEndian.AppendUint64(b, x.Sum64())
}
