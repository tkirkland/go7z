package sevenzip

// ppmd.go: the PPMD method's parameters as the SoT chooses them
// (observed on both SoTs, 2026-11-07; the C++ PpmdEncoder.cpp is LGPL
// and not ported):
//
//   - -mx level 0..9 gives order 3, 4, 4, 5, 5, 6, 8, 16, 24, 32 and
//     memory 2^(19+level) bytes; -m0=PPMd:o=N:mem=M override them
//     (o 2..32 accepted by the SoT, mem >= 64 KB).
//   - The memory is reduced for small inputs: with the data size n
//     (the solid total, or the largest file when not solid, like the
//     LZMA dictionary), m is the smallest power of two from 2^16 with
//     n <= m/16, and the memory becomes min(mem, m). Observed
//     boundaries: 4096 -> 2^16, 4097 -> 2^17, 131072 -> 2^21, 131073 ->
//     2^22, 1048576 -> 2^24, 1048577 -> 2^25.
//   - Properties: order (1 byte), memory (UInt32 little-endian).
//   - The solid block limit is the LZMA rule on the memory:
//     max(mem << 7, 16 MB) (observed: 40 x 1 MB files give 3 blocks at
//     mem 64k, 2 at 256k, 1 from 1m).

var ppmdOrderByLevel = [10]uint32{3, 4, 4, 5, 5, 6, 8, 16, 24, 32}

// ppmdParams returns the order and memory for the options and level.
func (w *Writer) ppmdParams() (order uint32, mem uint32) {
	level := w.level()
	order = ppmdOrderByLevel[level]
	mem = uint32(1) << (19 + uint(level))
	if w.opts.PPMdOrder != 0 {
		order = uint32(w.opts.PPMdOrder)
	}
	if w.opts.PPMdMem != 0 {
		mem = w.opts.PPMdMem
	}
	return order, mem
}

// PPMdReducedMem is the SoT's memory reduction for a data size.
func PPMdReducedMem(mem uint32, dataSize uint64) uint32 {
	if dataSize >= uint64(mem) {
		return mem
	}
	for i := uint(16); i <= 31; i++ {
		m := uint64(1) << i
		if dataSize <= m/16 {
			if uint64(mem) > m {
				return uint32(m)
			}
			return mem
		}
	}
	return mem
}

// ppmdProps is the coder's 5-byte property record.
func ppmdProps(order, mem uint32) []byte {
	return []byte{byte(order), byte(mem), byte(mem >> 8), byte(mem >> 16), byte(mem >> 24)}
}
