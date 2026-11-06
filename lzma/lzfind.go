package lzma

// Port of reference/7zip/C/LzFind.c (26.05, public domain): the LZ match
// finder used by the LZMA encoder. The port is literal: the same hash
// functions, the same binary-tree / hash-chain walks, the same cyclic
// buffer, limits and normalization, so that the match sequence (and hence
// the encoded bytes) is identical to the oracle's single-threaded match
// finder. (The oracle's multithreaded match finder produces the same
// matches; this was verified against the pinned 7zr before porting.)
//
// Pointers into the window are integer offsets into mf.bufBase. The C
// code's negative pointer arithmetic (cur - delta) becomes index
// arithmetic on that slice.

import (
	"errors"
	"io"
)

// LzHash.h
const (
	kHash2Size      = 1 << 10
	kHash3Size      = 1 << 16
	kFix3HashSize   = kHash2Size
	kFix4HashSize   = kHash2Size + kHash3Size
	kFix5HashSize   = kFix4HashSize
	kLzHashCrcSh1   = 5
	kLzHashCrcSh2   = 10
	kEmptyHashValue = 0

	kBlockMoveAlign      = 1 << 7
	kBlockSizeAlign      = 1 << 16
	kBlockSizeReserveMin = 1 << 24
	kMaxValForNormalize  = uint32(0)
	kCrcPoly             = 0xEDB88320
	numRefsAlignMask     = 0xF
)

var errMatchFinderMem = errors.New("lzma: match finder: cannot allocate window")

// matchFinder is CMatchFinder.
type matchFinder struct {
	bufBase []byte // window (stream mode) or the whole input (direct mode)
	buffer  int    // offset of the current position in bufBase

	pos       uint32
	posLimit  uint32
	streamPos uint32 // wrap over zero is allowed (streamPos < pos)
	lenLimit  uint32

	cyclicBufferPos  uint32
	cyclicBufferSize uint32 // = historySize + 1

	streamEndWasReached bool
	btMode              bool
	bigHash             bool
	directInput         bool

	matchMaxLen uint32
	refs        []uint32 // hash followed by son, one allocation as in C
	hash        []uint32
	son         []uint32
	hashMask    uint32
	cutValue    uint32

	stream io.Reader

	blockSize      uint32
	keepSizeBefore uint32
	keepSizeAfter  uint32

	numHashBytes    uint32
	directInputRem  int
	historySize     uint32
	fixedHashSize   uint32
	numHashBytesMin byte
	numHashOutBits  byte
	result          error
	crc             [256]uint32
	numRefs         int

	expectedDataSize uint64
}

func (p *matchFinder) availBytes() uint32 { return p.streamPos - p.pos }

// setDirectInput is MatchFinder_SET_DIRECT_INPUT_BUF.
func (p *matchFinder) setDirectInput(src []byte) {
	p.stream = nil
	p.directInput = true
	p.bufBase = src
	p.buffer = 0
	p.directInputRem = len(src)
}

// setStream is MatchFinder_SET_STREAM.
func (p *matchFinder) setStream(r io.Reader) {
	p.stream = r
	p.directInput = false
}

func (p *matchFinder) lzInWindowCreate2(blockSize uint32) bool {
	if blockSize == 0 {
		return false
	}
	if p.bufBase == nil || p.blockSize != blockSize || p.directInput || len(p.bufBase) != int(blockSize) {
		p.bufBase = nil
		p.blockSize = blockSize
		p.bufBase = make([]byte, blockSize)
	}
	return p.bufBase != nil
}

// readBlock is MatchFinder_ReadBlock.
func (p *matchFinder) readBlock() {
	if p.streamEndWasReached || p.result != nil {
		return
	}
	if p.directInput {
		curSize := uint32(0xFFFFFFFF) - p.availBytes()
		if uint64(curSize) > uint64(p.directInputRem) {
			curSize = uint32(p.directInputRem)
		}
		p.streamPos += curSize
		p.directInputRem -= int(curSize)
		if p.directInputRem == 0 {
			p.streamEndWasReached = true
		}
		return
	}
	for {
		dest := p.buffer + int(p.availBytes())
		size := int(p.blockSize) - dest
		if size == 0 {
			return
		}
		n, err := readSome(p.stream, p.bufBase[dest:dest+size])
		if err != nil {
			p.result = err
			return
		}
		if n == 0 {
			p.streamEndWasReached = true
			return
		}
		p.streamPos += uint32(n)
		if p.availBytes() > p.keepSizeAfter {
			return
		}
	}
}

// readSome mirrors ISeqInStream_Read: a partial read is fine, 0 means end
// of stream, and any error other than io.EOF is a read failure.
func readSome(r io.Reader, buf []byte) (int, error) {
	for {
		n, err := r.Read(buf)
		if n > 0 {
			return n, nil
		}
		if err == io.EOF {
			return 0, nil
		}
		if err != nil {
			return 0, err
		}
	}
}

// moveBlock is MatchFinder_MoveBlock.
func (p *matchFinder) moveBlock() {
	offset := p.buffer - int(p.keepSizeBefore)
	keepBefore := (offset & (kBlockMoveAlign - 1)) + int(p.keepSizeBefore)
	p.buffer = keepBefore
	src := offset &^ (kBlockMoveAlign - 1)
	copy(p.bufBase[:keepBefore+int(p.availBytes())], p.bufBase[src:src+keepBefore+int(p.availBytes())])
}

func (p *matchFinder) needMove() bool {
	if p.directInput {
		return false
	}
	if p.streamEndWasReached || p.result != nil {
		return false
	}
	return int(p.blockSize)-p.buffer <= int(p.keepSizeAfter)
}

func (p *matchFinder) readIfRequired() {
	if p.keepSizeAfter >= p.availBytes() {
		p.readBlock()
	}
}

func (p *matchFinder) setDefaultSettings() {
	p.cutValue = 32
	p.btMode = true
	p.numHashBytes = 4
	p.numHashBytesMin = 2
	p.numHashOutBits = 0
	p.bigHash = false
}

// construct is MatchFinder_Construct.
func (p *matchFinder) construct() {
	p.bufBase = nil
	p.buffer = 0
	p.directInput = false
	p.stream = nil
	p.refs = nil
	p.hash = nil
	p.son = nil
	p.expectedDataSize = ^uint64(0)
	p.setDefaultSettings()
	for i := 0; i < 256; i++ {
		r := uint32(i)
		for j := 0; j < 8; j++ {
			r = (r >> 1) ^ (kCrcPoly & (uint32(0) - (r & 1)))
		}
		p.crc[i] = r
	}
}

func (p *matchFinder) free() {
	p.refs = nil
	p.hash = nil
	p.son = nil
	if !p.directInput {
		p.bufBase = nil
	}
}

func (p *matchFinder) getBlockSize(historySize uint32) uint32 {
	blockSize := p.keepSizeBefore + p.keepSizeAfter
	if p.keepSizeBefore < historySize || blockSize < p.keepSizeBefore {
		return 0
	}
	const kBlockSizeMax = ^uint32(kBlockSizeAlign - 1)
	rem := kBlockSizeMax - blockSize
	sh := uint(2)
	if blockSize < 1<<30 {
		sh = 1
	}
	reserve := (blockSize >> sh) + (1 << 12) + kBlockMoveAlign + kBlockSizeAlign
	if blockSize >= kBlockSizeMax || rem < kBlockSizeReserveMin {
		return 0
	}
	if reserve >= rem {
		blockSize = kBlockSizeMax
	} else {
		blockSize += reserve
		blockSize &^= uint32(kBlockSizeAlign - 1)
	}
	return blockSize
}

func (p *matchFinder) getHashMask2(hs uint32) uint32 {
	if p.numHashBytes == 2 {
		return (1 << 16) - 1
	}
	if hs != 0 {
		hs--
	}
	hs |= hs >> 1
	hs |= hs >> 2
	hs |= hs >> 4
	hs |= hs >> 8
	if hs >= 1<<24 {
		if p.numHashBytes == 3 {
			hs = (1 << 24) - 1
		}
	}
	hs |= (1 << 16) - 1
	if p.numHashBytes >= 5 {
		hs |= (256 << kLzHashCrcSh2) - 1
	}
	return hs
}

func (p *matchFinder) getHashMask(hs uint32) uint32 {
	if p.numHashBytes == 2 {
		return (1 << 16) - 1
	}
	if hs != 0 {
		hs--
	}
	hs |= hs >> 1
	hs |= hs >> 2
	hs |= hs >> 4
	hs |= hs >> 8
	hs >>= 1
	if hs >= 1<<24 {
		if p.numHashBytes == 3 {
			hs = (1 << 24) - 1
		} else {
			hs >>= 1
		}
	}
	hs |= (1 << 16) - 1
	if p.numHashBytes >= 5 {
		hs |= (256 << kLzHashCrcSh2) - 1
	}
	return hs
}

// create is MatchFinder_Create.
func (p *matchFinder) create(historySize, keepAddBufferBefore, matchMaxLen, keepAddBufferAfter uint32) bool {
	p.keepSizeBefore = historySize + keepAddBufferBefore + 1
	keepAddBufferAfter += matchMaxLen
	if keepAddBufferAfter < p.numHashBytes {
		keepAddBufferAfter = p.numHashBytes
	}
	p.keepSizeAfter = keepAddBufferAfter

	if p.directInput {
		p.blockSize = 0
	}
	if p.directInput || p.lzInWindowCreate2(p.getBlockSize(historySize)) {
		var hashSizeSum uint64
		{
			var hs, hsCur uint32
			if p.numHashOutBits != 0 {
				numBits := uint(p.numHashOutBits)
				nbMax := uint(32)
				if p.numHashBytes == 2 {
					nbMax = 16
				} else if p.numHashBytes == 3 {
					nbMax = 24
				}
				if numBits >= nbMax {
					numBits = nbMax
				}
				if numBits >= 32 {
					hs = 0xFFFFFFFF
				} else {
					hs = (uint32(1) << numBits) - 1
				}
				hs |= (1 << 16) - 1
				if p.numHashBytes >= 5 {
					hs |= (256 << kLzHashCrcSh2) - 1
				}
				if hs2 := p.getHashMask2(historySize); hs >= hs2 {
					hs = hs2
				}
				hsCur = hs
				if p.expectedDataSize < uint64(historySize) {
					if hs2 := p.getHashMask2(uint32(p.expectedDataSize)); hsCur >= hs2 {
						hsCur = hs2
					}
				}
			} else {
				hs = p.getHashMask(historySize)
				hsCur = hs
				if p.expectedDataSize < uint64(historySize) {
					hsCur = p.getHashMask(uint32(p.expectedDataSize))
					if hsCur >= hs {
						hsCur = hs
					}
				}
			}
			p.hashMask = hsCur
			hashSizeSum = uint64(hs) + 1
			fixedHashSize := uint32(0)
			if p.numHashBytes > 2 && p.numHashBytesMin <= 2 {
				fixedHashSize += kHash2Size
			}
			if p.numHashBytes > 3 && p.numHashBytesMin <= 3 {
				fixedHashSize += kHash3Size
			}
			hashSizeSum += uint64(fixedHashSize)
			p.fixedHashSize = fixedHashSize
		}
		p.matchMaxLen = matchMaxLen
		{
			newCyclicBufferSize := historySize + 1
			p.historySize = historySize
			p.cyclicBufferSize = newCyclicBufferSize
			numSons := uint64(newCyclicBufferSize)
			if p.btMode {
				numSons <<= 1
			}
			newSize := hashSizeSum + numSons
			newSize = (newSize + numRefsAlignMask) &^ uint64(numRefsAlignMask)
			// 22.02: the buffer is not reallocated if the old size is
			// enough. As in C, p->son is left where the previous create
			// put it (hash is the same base pointer either way).
			if p.refs != nil && uint64(p.numRefs) >= newSize {
				return true
			}
			p.refs = nil
			p.numRefs = int(newSize)
			p.refs = make([]uint32, newSize)
			p.hash = p.refs[:hashSizeSum]
			p.son = p.refs[hashSizeSum:]
			return true
		}
	}
	p.free()
	return false
}

// setLimits is MatchFinder_SetLimits.
func (p *matchFinder) setLimits() {
	n := kMaxValForNormalize - p.pos
	if n == 0 {
		n = 0xFFFFFFFF
	}
	k := p.cyclicBufferSize - p.cyclicBufferPos
	if k < n {
		n = k
	}
	k = p.availBytes()
	{
		ksa := p.keepSizeAfter
		mm := p.matchMaxLen
		if k > ksa {
			k -= ksa
		} else if k >= mm {
			k -= mm
			k++
		} else {
			mm = k
			if k != 0 {
				k = 1
			}
		}
		p.lenLimit = mm
	}
	if k < n {
		n = k
	}
	p.posLimit = p.pos + n
}

func (p *matchFinder) initLowHash() {
	for i := uint32(0); i < p.fixedHashSize; i++ {
		p.hash[i] = kEmptyHashValue
	}
}

func (p *matchFinder) initHighHash() {
	items := p.hash[p.fixedHashSize:]
	numItems := uint64(p.hashMask) + 1
	for i := uint64(0); i < numItems; i++ {
		items[i] = kEmptyHashValue
	}
}

func (p *matchFinder) init4() {
	if !p.directInput {
		p.buffer = 0
	}
	p.pos = 1
	p.streamPos = 1
	p.result = nil
	p.streamEndWasReached = false
}

// init is MatchFinder_Init.
func (p *matchFinder) init() {
	p.initHighHash()
	p.initLowHash()
	p.init4()
	p.readBlock()
	p.cyclicBufferPos = p.pos
	p.setLimits()
}

// normalize3 is MatchFinder_Normalize3 (saturating subtract; the SIMD
// variants in C compute the same values).
func normalize3(subValue uint32, items []uint32) {
	for i, v := range items {
		if v < subValue {
			v = subValue
		}
		items[i] = v - subValue
	}
}

// checkLimits is MatchFinder_CheckLimits; call only after pos++.
func (p *matchFinder) checkLimits() {
	if p.keepSizeAfter == p.availBytes() {
		if p.needMove() {
			p.moveBlock()
		}
		p.readBlock()
	}
	if p.pos == kMaxValForNormalize {
		if p.availBytes() >= p.numHashBytes {
			subValue := p.pos - p.historySize - 1
			p.pos -= subValue
			p.streamPos -= subValue
			normalize3(subValue, p.hash[:uint64(p.hashMask)+1+uint64(p.fixedHashSize)])
			numSonRefs := uint64(p.cyclicBufferSize)
			if p.btMode {
				numSonRefs <<= 1
			}
			normalize3(subValue, p.son[:numSonRefs])
		}
	}
	if p.cyclicBufferPos == p.cyclicBufferSize {
		p.cyclicBufferPos = 0
	}
	p.setLimits()
}

// hcGetMatchesSpec is Hc_GetMatchesSpec. cur is an index into buf.
// d receives (len, dist) pairs starting at di; the new di is returned.
func hcGetMatchesSpec(lenLimit uint32, curMatch, pos uint32, buf []byte, cur int, son []uint32,
	cyclicBufferPos, cyclicBufferSize, cutValue uint32, d []uint32, di int, maxLen uint32) int {
	lim := cur + int(lenLimit)
	son[cyclicBufferPos] = curMatch
	for {
		if curMatch == 0 {
			break
		}
		delta := pos - curMatch
		if delta >= cyclicBufferSize {
			break
		}
		{
			idx := cyclicBufferPos - delta
			if cyclicBufferPos < delta {
				idx += cyclicBufferSize
			}
			curMatch = son[idx]
			diff := -int(delta)
			if buf[cur+int(maxLen)] == buf[cur+int(maxLen)+diff] {
				c := cur
				for buf[c] == buf[c+diff] {
					c++
					if c == lim {
						d[di] = uint32(lim - cur)
						d[di+1] = delta - 1
						return di + 2
					}
				}
				l := uint32(c - cur)
				if maxLen < l {
					maxLen = l
					d[di] = l
					d[di+1] = delta - 1
					di += 2
				}
			}
		}
		cutValue--
		if cutValue == 0 {
			break
		}
	}
	return di
}

// getMatchesSpec1 is GetMatchesSpec1 (binary tree).
func getMatchesSpec1(lenLimit uint32, curMatch, pos uint32, buf []byte, cur int, son []uint32,
	cyclicBufferPos, cyclicBufferSize, cutValue uint32, d []uint32, di int, maxLen uint32) int {
	ptr0 := int(cyclicBufferPos<<1) + 1
	ptr1 := int(cyclicBufferPos << 1)
	var len0, len1 uint32

	cmCheck := pos - cyclicBufferSize
	if pos < cyclicBufferSize {
		cmCheck = 0
	}
	if cmCheck < curMatch {
		for {
			delta := pos - curMatch
			{
				idx := cyclicBufferPos - delta
				if cyclicBufferPos < delta {
					idx += cyclicBufferSize
				}
				pair := int(idx << 1)
				pb := cur - int(delta)
				l := len1
				if len0 < len1 {
					l = len0
				}
				pair0 := son[pair]
				if buf[pb+int(l)] == buf[cur+int(l)] {
					l++
					if l != lenLimit && buf[pb+int(l)] == buf[cur+int(l)] {
						for {
							l++
							if l == lenLimit {
								break
							}
							if buf[pb+int(l)] != buf[cur+int(l)] {
								break
							}
						}
					}
					if maxLen < l {
						maxLen = l
						d[di] = l
						d[di+1] = delta - 1
						di += 2
						if l == lenLimit {
							son[ptr1] = pair0
							son[ptr0] = son[pair+1]
							return di
						}
					}
				}
				if buf[pb+int(l)] < buf[cur+int(l)] {
					son[ptr1] = curMatch
					curMatch = son[pair+1]
					ptr1 = pair + 1
					len1 = l
				} else {
					son[ptr0] = curMatch
					curMatch = son[pair]
					ptr0 = pair
					len0 = l
				}
			}
			cutValue--
			if cutValue == 0 || cmCheck >= curMatch {
				break
			}
		}
	}
	son[ptr0] = kEmptyHashValue
	son[ptr1] = kEmptyHashValue
	return di
}

// skipMatchesSpec is SkipMatchesSpec.
func skipMatchesSpec(lenLimit uint32, curMatch, pos uint32, buf []byte, cur int, son []uint32,
	cyclicBufferPos, cyclicBufferSize, cutValue uint32) {
	ptr0 := int(cyclicBufferPos<<1) + 1
	ptr1 := int(cyclicBufferPos << 1)
	var len0, len1 uint32

	cmCheck := pos - cyclicBufferSize
	if pos < cyclicBufferSize {
		cmCheck = 0
	}
	if cmCheck < curMatch {
		for {
			delta := pos - curMatch
			{
				idx := cyclicBufferPos - delta
				if cyclicBufferPos < delta {
					idx += cyclicBufferSize
				}
				pair := int(idx << 1)
				pb := cur - int(delta)
				l := len1
				if len0 < len1 {
					l = len0
				}
				if buf[pb+int(l)] == buf[cur+int(l)] {
					for {
						l++
						if l == lenLimit {
							break
						}
						if buf[pb+int(l)] != buf[cur+int(l)] {
							break
						}
					}
					if l == lenLimit {
						son[ptr1] = son[pair]
						son[ptr0] = son[pair+1]
						return
					}
				}
				if buf[pb+int(l)] < buf[cur+int(l)] {
					son[ptr1] = curMatch
					curMatch = son[pair+1]
					ptr1 = pair + 1
					len1 = l
				} else {
					son[ptr0] = curMatch
					curMatch = son[pair]
					ptr0 = pair
					len0 = l
				}
			}
			cutValue--
			if cutValue == 0 || cmCheck >= curMatch {
				break
			}
		}
	}
	son[ptr0] = kEmptyHashValue
	son[ptr1] = kEmptyHashValue
}

// movePos is MOVE_POS.
func (p *matchFinder) movePos() {
	p.cyclicBufferPos++
	p.buffer++
	pos1 := p.pos + 1
	p.pos = pos1
	if pos1 == p.posLimit {
		p.checkLimits()
	}
}

func (p *matchFinder) hash2(cur int) (hv uint32) {
	b := p.bufBase
	return uint32(b[cur]) | uint32(b[cur+1])<<8
}

func (p *matchFinder) hash3(cur int) (h2, hv uint32) {
	b := p.bufBase
	temp := p.crc[b[cur]] ^ uint32(b[cur+1])
	h2 = temp & (kHash2Size - 1)
	hv = (temp ^ (uint32(b[cur+2]) << 8)) & p.hashMask
	return
}

func (p *matchFinder) hash4(cur int) (h2, h3, hv uint32) {
	b := p.bufBase
	temp := p.crc[b[cur]] ^ uint32(b[cur+1])
	h2 = temp & (kHash2Size - 1)
	temp ^= uint32(b[cur+2]) << 8
	h3 = temp & (kHash3Size - 1)
	hv = (temp ^ (p.crc[b[cur+3]] << kLzHashCrcSh1)) & p.hashMask
	return
}

func (p *matchFinder) hash5(cur int) (h2, h3, hv uint32) {
	b := p.bufBase
	temp := p.crc[b[cur]] ^ uint32(b[cur+1])
	h2 = temp & (kHash2Size - 1)
	temp ^= uint32(b[cur+2]) << 8
	h3 = temp & (kHash3Size - 1)
	temp ^= p.crc[b[cur+3]] << kLzHashCrcSh1
	hv = (temp ^ (p.crc[b[cur+4]] << kLzHashCrcSh2)) & p.hashMask
	return
}

// updateMaxLen is UPDATE_maxLen.
func (p *matchFinder) updateMaxLen(cur int, d2 uint32, maxLen, lenLimit uint32) uint32 {
	buf := p.bufBase
	diff := -int(d2)
	c := cur + int(maxLen)
	lim := cur + int(lenLimit)
	for ; c != lim; c++ {
		if buf[c+diff] != buf[c] {
			break
		}
	}
	return uint32(c - cur)
}

func (p *matchFinder) setMmm(pos uint32) uint32 {
	mmm := p.cyclicBufferSize
	if pos < mmm {
		mmm = pos
	}
	return mmm
}

// GetMatches implementations. Each returns the number of uint32 values
// written to distances (len, dist pairs).

func (p *matchFinder) bt2GetMatches(distances []uint32) int {
	lenLimit := p.lenLimit
	if lenLimit < 2 {
		p.movePos()
		return 0
	}
	cur := p.buffer
	hv := p.hash2(cur)
	curMatch := p.hash[hv]
	p.hash[hv] = p.pos
	n := getMatchesSpec1(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue, distances, 0, 1)
	p.movePos()
	return n
}

func (p *matchFinder) bt3GetMatches(distances []uint32) int {
	lenLimit := p.lenLimit
	if lenLimit < 3 {
		p.movePos()
		return 0
	}
	cur := p.buffer
	h2, hv := p.hash3(cur)
	hash := p.hash
	pos := p.pos
	d2 := pos - hash[h2]
	curMatch := hash[kFix3HashSize+hv]
	hash[h2] = pos
	hash[kFix3HashSize+hv] = pos
	mmm := p.setMmm(pos)
	maxLen := uint32(2)
	di := 0
	buf := p.bufBase
	if d2 < mmm && buf[cur-int(d2)] == buf[cur] {
		maxLen = p.updateMaxLen(cur, d2, maxLen, lenLimit)
		distances[0] = maxLen
		distances[1] = d2 - 1
		di = 2
		if maxLen == lenLimit {
			skipMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue)
			p.movePos()
			return di
		}
	}
	di = getMatchesSpec1(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue, distances, di, maxLen)
	p.movePos()
	return di
}

func (p *matchFinder) bt4GetMatches(distances []uint32) int {
	lenLimit := p.lenLimit
	if lenLimit < 4 {
		p.movePos()
		return 0
	}
	cur := p.buffer
	h2, h3, hv := p.hash4(cur)
	hash := p.hash
	pos := p.pos
	d2 := pos - hash[h2]
	d3 := pos - hash[kFix3HashSize+h3]
	curMatch := hash[kFix4HashSize+hv]
	hash[h2] = pos
	hash[kFix3HashSize+h3] = pos
	hash[kFix4HashSize+hv] = pos
	mmm := p.setMmm(pos)
	maxLen := uint32(3)
	di := 0
	buf := p.bufBase
	for {
		if d2 < mmm && buf[cur-int(d2)] == buf[cur] {
			distances[di] = 2
			distances[di+1] = d2 - 1
			di += 2
			if buf[cur-int(d2)+2] == buf[cur+2] {
				// distances[-2] = 3
			} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
				d2 = d3
				distances[di+1] = d3 - 1
				di += 2
			} else {
				break
			}
		} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
			d2 = d3
			distances[di+1] = d3 - 1
			di += 2
		} else {
			break
		}
		maxLen = p.updateMaxLen(cur, d2, maxLen, lenLimit)
		distances[di-2] = maxLen
		if maxLen == lenLimit {
			skipMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue)
			p.movePos()
			return di
		}
		break
	}
	di = getMatchesSpec1(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue, distances, di, maxLen)
	p.movePos()
	return di
}

func (p *matchFinder) bt5GetMatches(distances []uint32) int {
	lenLimit := p.lenLimit
	if lenLimit < 5 {
		p.movePos()
		return 0
	}
	cur := p.buffer
	h2, h3, hv := p.hash5(cur)
	hash := p.hash
	pos := p.pos
	d2 := pos - hash[h2]
	d3 := pos - hash[kFix3HashSize+h3]
	curMatch := hash[kFix5HashSize+hv]
	hash[h2] = pos
	hash[kFix3HashSize+h3] = pos
	hash[kFix5HashSize+hv] = pos
	mmm := p.setMmm(pos)
	maxLen := uint32(4)
	di := 0
	buf := p.bufBase
	for {
		if d2 < mmm && buf[cur-int(d2)] == buf[cur] {
			distances[di] = 2
			distances[di+1] = d2 - 1
			di += 2
			if buf[cur-int(d2)+2] == buf[cur+2] {
			} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
				distances[di+1] = d3 - 1
				di += 2
				d2 = d3
			} else {
				break
			}
		} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
			distances[di+1] = d3 - 1
			di += 2
			d2 = d3
		} else {
			break
		}
		distances[di-2] = 3
		if buf[cur-int(d2)+3] != buf[cur+3] {
			break
		}
		maxLen = p.updateMaxLen(cur, d2, maxLen, lenLimit)
		distances[di-2] = maxLen
		if maxLen == lenLimit {
			skipMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue)
			p.movePos()
			return di
		}
		break
	}
	di = getMatchesSpec1(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue, distances, di, maxLen)
	p.movePos()
	return di
}

func (p *matchFinder) hc4GetMatches(distances []uint32) int {
	lenLimit := p.lenLimit
	if lenLimit < 4 {
		p.movePos()
		return 0
	}
	cur := p.buffer
	h2, h3, hv := p.hash4(cur)
	hash := p.hash
	pos := p.pos
	d2 := pos - hash[h2]
	d3 := pos - hash[kFix3HashSize+h3]
	curMatch := hash[kFix4HashSize+hv]
	hash[h2] = pos
	hash[kFix3HashSize+h3] = pos
	hash[kFix4HashSize+hv] = pos
	mmm := p.setMmm(pos)
	maxLen := uint32(3)
	di := 0
	buf := p.bufBase
	for {
		if d2 < mmm && buf[cur-int(d2)] == buf[cur] {
			distances[di] = 2
			distances[di+1] = d2 - 1
			di += 2
			if buf[cur-int(d2)+2] == buf[cur+2] {
			} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
				d2 = d3
				distances[di+1] = d3 - 1
				di += 2
			} else {
				break
			}
		} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
			d2 = d3
			distances[di+1] = d3 - 1
			di += 2
		} else {
			break
		}
		maxLen = p.updateMaxLen(cur, d2, maxLen, lenLimit)
		distances[di-2] = maxLen
		if maxLen == lenLimit {
			p.son[p.cyclicBufferPos] = curMatch
			p.movePos()
			return di
		}
		break
	}
	di = hcGetMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue, distances, di, maxLen)
	p.movePos()
	return di
}

func (p *matchFinder) hc5GetMatches(distances []uint32) int {
	lenLimit := p.lenLimit
	if lenLimit < 5 {
		p.movePos()
		return 0
	}
	cur := p.buffer
	h2, h3, hv := p.hash5(cur)
	hash := p.hash
	pos := p.pos
	d2 := pos - hash[h2]
	d3 := pos - hash[kFix3HashSize+h3]
	curMatch := hash[kFix5HashSize+hv]
	hash[h2] = pos
	hash[kFix3HashSize+h3] = pos
	hash[kFix5HashSize+hv] = pos
	mmm := p.setMmm(pos)
	maxLen := uint32(4)
	di := 0
	buf := p.bufBase
	for {
		if d2 < mmm && buf[cur-int(d2)] == buf[cur] {
			distances[di] = 2
			distances[di+1] = d2 - 1
			di += 2
			if buf[cur-int(d2)+2] == buf[cur+2] {
			} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
				distances[di+1] = d3 - 1
				di += 2
				d2 = d3
			} else {
				break
			}
		} else if d3 < mmm && buf[cur-int(d3)] == buf[cur] {
			distances[di+1] = d3 - 1
			di += 2
			d2 = d3
		} else {
			break
		}
		distances[di-2] = 3
		if buf[cur-int(d2)+3] != buf[cur+3] {
			break
		}
		maxLen = p.updateMaxLen(cur, d2, maxLen, lenLimit)
		distances[di-2] = maxLen
		if maxLen == lenLimit {
			p.son[p.cyclicBufferPos] = curMatch
			p.movePos()
			return di
		}
		break
	}
	di = hcGetMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue, distances, di, maxLen)
	p.movePos()
	return di
}

// Skip implementations.

func (p *matchFinder) bt2Skip(num uint32) {
	for {
		lenLimit := p.lenLimit
		if lenLimit < 2 {
			p.movePos()
		} else {
			cur := p.buffer
			hv := p.hash2(cur)
			curMatch := p.hash[hv]
			p.hash[hv] = p.pos
			skipMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue)
			p.movePos()
		}
		num--
		if num == 0 {
			break
		}
	}
}

func (p *matchFinder) bt3Skip(num uint32) {
	for {
		lenLimit := p.lenLimit
		if lenLimit < 3 {
			p.movePos()
		} else {
			cur := p.buffer
			h2, hv := p.hash3(cur)
			hash := p.hash
			curMatch := hash[kFix3HashSize+hv]
			hash[h2] = p.pos
			hash[kFix3HashSize+hv] = p.pos
			skipMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue)
			p.movePos()
		}
		num--
		if num == 0 {
			break
		}
	}
}

func (p *matchFinder) bt4Skip(num uint32) {
	for {
		lenLimit := p.lenLimit
		if lenLimit < 4 {
			p.movePos()
		} else {
			cur := p.buffer
			h2, h3, hv := p.hash4(cur)
			hash := p.hash
			curMatch := hash[kFix4HashSize+hv]
			hash[h2] = p.pos
			hash[kFix3HashSize+h3] = p.pos
			hash[kFix4HashSize+hv] = p.pos
			skipMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue)
			p.movePos()
		}
		num--
		if num == 0 {
			break
		}
	}
}

func (p *matchFinder) bt5Skip(num uint32) {
	for {
		lenLimit := p.lenLimit
		if lenLimit < 5 {
			p.movePos()
		} else {
			cur := p.buffer
			h2, h3, hv := p.hash5(cur)
			hash := p.hash
			curMatch := hash[kFix5HashSize+hv]
			hash[h2] = p.pos
			hash[kFix3HashSize+h3] = p.pos
			hash[kFix5HashSize+hv] = p.pos
			skipMatchesSpec(lenLimit, curMatch, p.pos, p.bufBase, cur, p.son, p.cyclicBufferPos, p.cyclicBufferSize, p.cutValue)
			p.movePos()
		}
		num--
		if num == 0 {
			break
		}
	}
}

// hcSkip is HC_SKIP_HEADER / HC_SKIP_FOOTER with the hash update in the
// middle (Hc4_MatchFinder_Skip / Hc5_MatchFinder_Skip).
func (p *matchFinder) hcSkip(num uint32, minLen uint32, five bool) {
	for {
		if p.lenLimit < minLen {
			p.movePos()
			num--
			if num == 0 {
				return
			}
			continue
		}
		pos := p.pos
		num2 := num
		{
			rem := p.posLimit - pos
			if num2 >= rem {
				num2 = rem
			}
		}
		num -= num2
		son := int(p.cyclicBufferPos)
		p.cyclicBufferPos += num2
		cur := p.buffer
		hash := p.hash
		for {
			var curMatch uint32
			if five {
				h2, h3, hv := p.hash5(cur)
				curMatch = hash[kFix5HashSize+hv]
				hash[h2] = pos
				hash[kFix3HashSize+h3] = pos
				hash[kFix5HashSize+hv] = pos
			} else {
				h2, h3, hv := p.hash4(cur)
				curMatch = hash[kFix4HashSize+hv]
				hash[h2] = pos
				hash[kFix3HashSize+h3] = pos
				hash[kFix4HashSize+hv] = pos
			}
			cur++
			pos++
			p.son[son] = curMatch
			son++
			num2--
			if num2 == 0 {
				break
			}
		}
		p.buffer = cur
		p.pos = pos
		if pos == p.posLimit {
			p.checkLimits()
		}
		if num == 0 {
			return
		}
	}
}

func (p *matchFinder) hc4Skip(num uint32) { p.hcSkip(num, 4, false) }
func (p *matchFinder) hc5Skip(num uint32) { p.hcSkip(num, 5, true) }

// matchFinderVTable is IMatchFinder2.
type matchFinderVTable struct {
	getMatches func(distances []uint32) int
	skip       func(num uint32)
}

// createVTable is MatchFinder_CreateVTable.
func (p *matchFinder) createVTable() matchFinderVTable {
	if !p.btMode {
		if p.numHashBytes <= 4 {
			return matchFinderVTable{p.hc4GetMatches, p.hc4Skip}
		}
		return matchFinderVTable{p.hc5GetMatches, p.hc5Skip}
	}
	switch p.numHashBytes {
	case 2:
		return matchFinderVTable{p.bt2GetMatches, p.bt2Skip}
	case 3:
		return matchFinderVTable{p.bt3GetMatches, p.bt3Skip}
	case 4:
		return matchFinderVTable{p.bt4GetMatches, p.bt4Skip}
	default:
		return matchFinderVTable{p.bt5GetMatches, p.bt5Skip}
	}
}
