package sevenzip

import (
	"runtime"

	"github.com/tkirkland/go7z/lzma"
)

// x86DefaultSolidDict is the smallest LZMA2 dictionary at which the x86
// build's default thread count no longer splits the input into blocks.
// Observed with the 32-bit SoT on a 32-processor, 64 GB machine
// (2026-11-06), 300 MB and 600 MB of zeros: the default output equals
// -mmt4 (two or more block threads, blocks of 4 x dict) for -md=16m,
// 24m, 32m, 33m, 34m, 35m and -mx5, and equals -mmt1 (one solid block)
// for -md=36m, 40m, 44m, 48m, 64m, 128m and -mx6..9; an explicit -mmt4,
// -mmt8, -mmt16 or -mmt32 splits at every dictionary up to 64 MB on both
// builds, so only the default is reduced. The x64 build's default splits
// at every level and at -md up to 1024m. The reduction is the 32-bit
// build limiting its memory, which the LGPL archive layer does and the
// module reproduces from observation only; no public-domain C file
// holds the estimate.
const x86DefaultSolidDict = 36 << 20

// Threads returns the total thread count (Lzma2EncProps.NumTotalThreads)
// the 7-Zip build with the given word size passes to the LZMA2 encoder
// for -mmt threads, with 0 meaning the default: the number of logical
// processors, as 7-Zip uses. The encoder derives the block thread count
// from it as Lzma2EncProps_Normalize does (total / LZMA threads), so
// -mmt2 and -mmt3 give one block thread (a solid stream) at the levels
// whose match finder uses two threads, and -mmt4 gives two. The x86
// build's default is reduced to one block thread from
// x86DefaultSolidDict up (see there). p supplies the level and
// dictionary; it is not modified.
func Threads(wordSize, threads int, p *lzma.Lzma2EncProps) int {
	if threads > 0 {
		return threads
	}
	n := runtime.NumCPU()
	if wordSize == lzma.WordSize32 {
		q := p.LzmaProps
		q.ReduceSize = ^uint64(0)
		q.Normalize()
		if q.DictSize >= x86DefaultSolidDict {
			// One block thread: two threads in total at the levels with
			// a two-thread match finder, one otherwise.
			q2 := p.LzmaProps
			q2.Normalize()
			return q2.NumThreads
		}
	}
	return n
}
