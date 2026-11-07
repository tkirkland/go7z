package lzma

// Port of reference/7zip/C/LzmaEnc.c (26.05, public domain): the LZMA
// encoder (range coder, price tables, optimal and fast parsers, block
// coding). The port is literal so that the packed bytes are identical to
// the SoT's for the same input and properties.
//
// The SoT is the 32-bit 7zr build. The two places where the C code
// depends on sizeof(size_t) — the default dictionary size per level and
// kNumLogBits (hence the largest accepted dictionary) — follow the 32-bit
// value, sotSizeT.

import (
	"errors"
	"io"
)

var (
	// ErrParam is SZ_ERROR_PARAM: a property outside the accepted range.
	ErrParam = errors.New("lzma: invalid encoder property")
	// ErrOutputEOF is SZ_ERROR_OUTPUT_EOF: the output buffer is too small.
	ErrOutputEOF = errors.New("lzma: output buffer overflow")
	// ErrWrite is SZ_ERROR_WRITE: the output stream failed.
	ErrWrite = errors.New("lzma: write error")
	// ErrFail is SZ_ERROR_FAIL: the encoder did not consume all input.
	ErrFail = errors.New("lzma: encoder failure")
)

// sotSizeT is sizeof(size_t) of the pinned SoT build (x86).
const sotSizeT = 4

const (
	kLzmaMaxHistorySize = uint32(15) << 28

	kProbInitValue        = kBitModelTotal >> 1
	kNumMoveReducingBits  = 4
	kNumBitPriceShiftBits = 4
	repLenCount           = 64

	kNumLogBits            = 11 + sotSizeT/8*3
	kDicLogSizeMaxCompress = (kNumLogBits-1)*2 + 7

	lzmaNumReps = 4

	kNumOpts     = 1 << 11
	kPackReserve = kNumOpts * 8

	kDicLogSizeMax    = 32
	kDistTableSizeMax = kDicLogSizeMax * 2
	kAlignMask        = kAlignTableSize - 1

	lzmaPbMax          = 4
	lzmaLcMax          = 8
	lzmaLpMax          = 4
	lzmaNumPbStatesMax = 1 << lzmaPbMax

	kLenNumSymbolsTotal = kLenNumLowSymbols*2 + kLenNumHighSymbols
	lzmaMatchLenMin     = 2
	lzmaMatchLenMax     = lzmaMatchLenMin + kLenNumSymbolsTotal - 1

	kStateStart         = 0
	kStateLitAfterMatch = 4
	kStateLitAfterRep   = 5
	kStateMatchAfterLit = 7
	kStateRepAfterLit   = 8

	kInfinityPrice = 1 << 30
	markLit        = uint32(0xFFFFFFFF)

	rcBufSize        = 1 << 16
	kBigHashDicLimit = uint32(1) << 24

	lzmaPropsSize = 5
)

var (
	kLiteralNextStates  = [kNumStates]byte{0, 0, 0, 0, 1, 2, 3, 4, 5, 6, 4, 5}
	kMatchNextStates    = [kNumStates]byte{7, 7, 7, 7, 7, 7, 7, 10, 10, 10, 10, 10}
	kRepNextStates      = [kNumStates]byte{8, 8, 8, 8, 8, 8, 8, 11, 11, 11, 11, 11}
	kShortRepNextStates = [kNumStates]byte{9, 9, 9, 9, 9, 9, 9, 11, 11, 11, 11, 11}
)

func isLitState(s uint32) bool { return s < 7 }

func getLenToPosState2(l uint32) uint32 {
	if l < kNumLenToPosStates-1 {
		return l
	}
	return kNumLenToPosStates - 1
}

func getLenToPosState(l uint32) uint32 {
	if l < kNumLenToPosStates+1 {
		return l - 2
	}
	return kNumLenToPosStates - 1
}

// EncProps is CLzmaEncProps. Negative values (and zero for DictSize and
// Mc) mean "default", resolved by Normalize exactly as the C code does.
type EncProps struct {
	Level          int    // 0..9
	DictSize       uint32 // 0 = by level
	Lc, Lp, Pb     int    // -1 = default (3, 0, 2)
	Algo           int    // 0 fast, 1 normal; -1 = by level
	Fb             int    // 5..273; -1 = by level
	BtMode         int    // 0 hash chain, 1 binary tree; -1 = by algo
	NumHashBytes   int    // 2..5; -1 = default
	NumHashOutBits uint   // 0 = default
	Mc             uint32 // 0 = default
	WriteEndMark   bool
	NumThreads     int    // 1 or 2; -1 = default (output is identical either way)
	ReduceSize     uint64 // expected input size; the dictionary is reduced to it
}

// Init is LzmaEncProps_Init.
func (p *EncProps) Init() {
	p.Level = 5
	p.DictSize = 0
	p.Mc = 0
	p.ReduceSize = ^uint64(0)
	p.Lc, p.Lp, p.Pb, p.Algo, p.Fb, p.BtMode, p.NumHashBytes, p.NumThreads = -1, -1, -1, -1, -1, -1, -1, -1
	p.NumHashOutBits = 0
	p.WriteEndMark = false
}

// Normalize is LzmaEncProps_Normalize.
func (p *EncProps) Normalize() {
	level := p.Level
	if level < 0 {
		level = 5
	}
	p.Level = level
	if p.DictSize == 0 {
		switch {
		case uint(level) <= 4:
			p.DictSize = uint32(1) << (uint(level)*2 + 16)
		case uint(level) <= sotSizeT/2+4:
			p.DictSize = uint32(1) << (uint(level) + 20)
		default:
			p.DictSize = uint32(1) << (sotSizeT/2 + 24)
		}
	}
	if uint64(p.DictSize) > p.ReduceSize {
		v := uint32(p.ReduceSize)
		const kReduceMin = uint32(1) << 12
		if v < kReduceMin {
			v = kReduceMin
		}
		if p.DictSize > v {
			p.DictSize = v
		}
	}
	if p.Lc < 0 {
		p.Lc = 3
	}
	if p.Lp < 0 {
		p.Lp = 0
	}
	if p.Pb < 0 {
		p.Pb = 2
	}
	if p.Algo < 0 {
		if uint(level) < 5 {
			p.Algo = 0
		} else {
			p.Algo = 1
		}
	}
	if p.Fb < 0 {
		if uint(level) < 7 {
			p.Fb = 32
		} else {
			p.Fb = 64
		}
	}
	if p.BtMode < 0 {
		if p.Algo == 0 {
			p.BtMode = 0
		} else {
			p.BtMode = 1
		}
	}
	if p.NumHashBytes < 0 {
		if p.BtMode != 0 {
			p.NumHashBytes = 4
		} else {
			p.NumHashBytes = 5
		}
	}
	if p.Mc == 0 {
		p.Mc = 16 + uint32(uint(p.Fb)>>1)
		if p.BtMode == 0 {
			p.Mc >>= 1
		}
	}
	if p.NumThreads < 0 {
		if p.BtMode != 0 && p.Algo != 0 {
			p.NumThreads = 2
		} else {
			p.NumThreads = 1
		}
	}
}

// GetDictSize is LzmaEncProps_GetDictSize.
func (p EncProps) GetDictSize() uint32 {
	p.Normalize()
	return p.DictSize
}

// optimal is COptimal.
type optimal struct {
	price uint32
	state uint16
	extra uint16 // 0 normal; 1 LIT:MATCH; >1 MATCH(extra-1):LIT:REP0(len)
	len   uint32
	dist  uint32
	reps  [lzmaNumReps]uint32
}

// lenEnc is CLenEnc.
type lenEnc struct {
	low  [lzmaNumPbStatesMax << (kLenNumLowBits + 1)]uint16
	high [kLenNumHighSymbols]uint16
}

// lenPriceEnc is CLenPriceEnc.
type lenPriceEnc struct {
	tableSize uint32
	prices    [lzmaNumPbStatesMax][kLenNumSymbolsTotal]uint32
}

func (p *lenPriceEnc) price(posState, l uint32) uint32 {
	return p.prices[posState][l-lzmaMatchLenMin]
}

// rangeEnc is CRangeEnc.
type rangeEnc struct {
	rng       uint32
	cache     uint32
	low       uint64
	cacheSize uint64
	buf       []byte
	bufPos    int
	out       io.Writer
	processed uint64
	res       error
}

func (p *rangeEnc) alloc() {
	if p.buf == nil {
		p.buf = make([]byte, rcBufSize)
	}
}

func (p *rangeEnc) init() {
	p.rng = 0xFFFFFFFF
	p.cache = 0
	p.low = 0
	p.cacheSize = 0
	p.bufPos = 0
	p.processed = 0
	p.res = nil
}

func (p *rangeEnc) getProcessed() uint64 {
	return p.processed + uint64(p.bufPos) + p.cacheSize
}

func (p *rangeEnc) flushStream() {
	num := p.bufPos
	if p.res == nil {
		n, err := p.out.Write(p.buf[:num])
		if err != nil || n != num {
			p.res = ErrWrite
		}
	}
	p.processed += uint64(num)
	p.bufPos = 0
}

// shiftLow is RangeEnc_ShiftLow.
func (p *rangeEnc) shiftLow() {
	low := uint32(p.low)
	high := uint32(p.low >> 32)
	p.low = uint64(low << 8)
	if low < 0xFF000000 || high != 0 {
		p.buf[p.bufPos] = byte(p.cache + high)
		p.bufPos++
		p.cache = low >> 24
		if p.bufPos == len(p.buf) {
			p.flushStream()
		}
		if p.cacheSize == 0 {
			return
		}
		high += 0xFF
		for {
			p.buf[p.bufPos] = byte(high)
			p.bufPos++
			if p.bufPos == len(p.buf) {
				p.flushStream()
			}
			p.cacheSize--
			if p.cacheSize == 0 {
				return
			}
		}
	}
	p.cacheSize++
}

func (p *rangeEnc) flushData() {
	for i := 0; i < 5; i++ {
		p.shiftLow()
	}
}

// bit is RC_BIT (the branch form; the branchless form in C computes the
// same range, low and probability).
func (p *rangeEnc) bit(prob *uint16, bit uint32) {
	ttt := uint32(*prob)
	newBound := (p.rng >> kNumBitModelTotalBits) * ttt
	if bit == 0 {
		p.rng = newBound
		ttt += (kBitModelTotal - ttt) >> kNumMoveBits
	} else {
		p.low += uint64(newBound)
		p.rng -= newBound
		ttt -= ttt >> kNumMoveBits
	}
	*prob = uint16(ttt)
	if p.rng < kTopValue {
		p.rng <<= 8
		p.shiftLow()
	}
}

func (p *rangeEnc) bit0(prob *uint16) { p.bit(prob, 0) }
func (p *rangeEnc) bit1(prob *uint16) { p.bit(prob, 1) }

// litEncode is LitEnc_Encode.
func (p *rangeEnc) litEncode(probs []uint16, sym uint32) {
	sym |= 0x100
	for {
		prob := &probs[sym>>8]
		bit := (sym >> 7) & 1
		sym <<= 1
		p.bit(prob, bit)
		if sym >= 0x10000 {
			break
		}
	}
}

// litEncodeMatched is LitEnc_EncodeMatched.
func (p *rangeEnc) litEncodeMatched(probs []uint16, sym, matchByte uint32) {
	offs := uint32(0x100)
	sym |= 0x100
	for {
		matchByte <<= 1
		prob := &probs[offs+(matchByte&offs)+(sym>>8)]
		bit := (sym >> 7) & 1
		sym <<= 1
		offs &^= matchByte ^ sym
		p.bit(prob, bit)
		if sym >= 0x10000 {
			break
		}
	}
}

// rcTreeReverseEncode is RcTree_ReverseEncode.
func (p *rangeEnc) rcTreeReverseEncode(probs []uint16, numBits uint32, sym uint32) {
	m := uint32(1)
	for {
		bit := sym & 1
		sym >>= 1
		p.bit(&probs[m], bit)
		m = (m << 1) | bit
		numBits--
		if numBits == 0 {
			break
		}
	}
}

func initPriceTables(probPrices *[kBitModelTotal >> kNumMoveReducingBits]uint32) {
	for i := uint32(0); i < kBitModelTotal>>kNumMoveReducingBits; i++ {
		const kCyclesBits = kNumBitPriceShiftBits
		w := (i << kNumMoveReducingBits) + (1 << (kNumMoveReducingBits - 1))
		bitCount := uint32(0)
		for j := 0; j < kCyclesBits; j++ {
			w = w * w
			bitCount <<= 1
			for w >= uint32(1)<<16 {
				w >>= 1
				bitCount++
			}
		}
		probPrices[i] = (uint32(kNumBitModelTotalBits) << kCyclesBits) - 15 - bitCount
	}
}

type probPrices = [kBitModelTotal >> kNumMoveReducingBits]uint32

func getPricea(pp *probPrices, prob uint32, bit uint32) uint32 {
	return pp[(prob^((-bit)&(kBitModelTotal-1)))>>kNumMoveReducingBits]
}
func getPricea0(pp *probPrices, prob uint32) uint32 {
	return pp[prob>>kNumMoveReducingBits]
}
func getPricea1(pp *probPrices, prob uint32) uint32 {
	return pp[(prob^(kBitModelTotal-1))>>kNumMoveReducingBits]
}

func litGetPrice(probs []uint16, sym uint32, pp *probPrices) uint32 {
	price := uint32(0)
	sym |= 0x100
	for {
		bit := sym & 1
		sym >>= 1
		price += getPricea(pp, uint32(probs[sym]), bit)
		if sym < 2 {
			break
		}
	}
	return price
}

func litMatchedGetPrice(probs []uint16, sym, matchByte uint32, pp *probPrices) uint32 {
	price := uint32(0)
	offs := uint32(0x100)
	sym |= 0x100
	for {
		matchByte <<= 1
		price += getPricea(pp, uint32(probs[offs+(matchByte&offs)+(sym>>8)]), (sym>>7)&1)
		sym <<= 1
		offs &^= matchByte ^ sym
		if sym >= 0x10000 {
			break
		}
	}
	return price
}

func (p *lenEnc) init() {
	for i := range p.low {
		p.low[i] = kProbInitValue
	}
	for i := range p.high {
		p.high[i] = kProbInitValue
	}
}

// encode is LenEnc_Encode.
func (p *lenEnc) encode(rc *rangeEnc, sym uint32, posState uint32) {
	probs := p.low[:]
	if sym >= kLenNumLowSymbols {
		rc.bit1(&probs[0])
		probs = probs[kLenNumLowSymbols:]
		if sym >= kLenNumLowSymbols*2 {
			rc.bit1(&probs[0])
			rc.litEncode(p.high[:], sym-kLenNumLowSymbols*2)
			return
		}
		sym -= kLenNumLowSymbols
	}
	rc.bit0(&probs[0])
	posState <<= 1 + kLenNumLowBits
	probs = probs[posState:]
	bit := sym >> 2
	rc.bit(&probs[1], bit)
	m := (1 << 1) + bit
	bit = (sym >> 1) & 1
	rc.bit(&probs[m], bit)
	m = (m << 1) + bit
	bit = sym & 1
	rc.bit(&probs[m], bit)
}

func setPrices3(probs []uint16, startPrice uint32, prices []uint32, pp *probPrices) {
	for i := uint32(0); i < 8; i += 2 {
		price := startPrice
		price += getPricea(pp, uint32(probs[1]), i>>2)
		price += getPricea(pp, uint32(probs[2+(i>>2)]), (i>>1)&1)
		prob := uint32(probs[4+(i>>1)])
		prices[i] = price + getPricea0(pp, prob)
		prices[i+1] = price + getPricea1(pp, prob)
	}
}

// updateTables is LenPriceEnc_UpdateTables.
func (p *lenPriceEnc) updateTables(numPosStates uint32, enc *lenEnc, pp *probPrices) {
	var b uint32
	{
		prob := uint32(enc.low[0])
		b = getPricea1(pp, prob)
		a := getPricea0(pp, prob)
		c := b + getPricea0(pp, uint32(enc.low[kLenNumLowSymbols]))
		for posState := uint32(0); posState < numPosStates; posState++ {
			prices := p.prices[posState][:]
			posState2 := posState << (1 + kLenNumLowBits)
			probs := enc.low[posState2:]
			setPrices3(probs, a, prices, pp)
			setPrices3(probs[kLenNumLowSymbols:], c, prices[kLenNumLowSymbols:], pp)
		}
	}
	{
		i := p.tableSize
		if i > kLenNumLowSymbols*2 {
			probs := enc.high[:]
			prices := p.prices[0][kLenNumLowSymbols*2:]
			i -= kLenNumLowSymbols*2 - 1
			i >>= 1
			b += getPricea1(pp, uint32(enc.low[kLenNumLowSymbols]))
			for {
				i--
				sym := i + (1 << (kLenNumHighBits - 1))
				price := b
				for {
					bit := sym & 1
					sym >>= 1
					price += getPricea(pp, uint32(probs[sym]), bit)
					if sym < 2 {
						break
					}
				}
				prob := uint32(probs[i+(1<<(kLenNumHighBits-1))])
				prices[i*2] = price + getPricea0(pp, prob)
				prices[i*2+1] = price + getPricea1(pp, prob)
				if i == 0 {
					break
				}
			}
			num := p.tableSize - kLenNumLowSymbols*2
			for posState := uint32(1); posState < numPosStates; posState++ {
				copy(p.prices[posState][kLenNumLowSymbols*2:kLenNumLowSymbols*2+num], p.prices[0][kLenNumLowSymbols*2:kLenNumLowSymbols*2+num])
			}
		}
	}
}

// saveState is CSaveState.
type saveState struct {
	litProbs []uint16
	state    uint32
	reps     [lzmaNumReps]uint32

	posAlignEncoder [1 << kNumAlignBits]uint16
	isRep           [kNumStates]uint16
	isRepG0         [kNumStates]uint16
	isRepG1         [kNumStates]uint16
	isRepG2         [kNumStates]uint16
	isMatch         [kNumStates][lzmaNumPbStatesMax]uint16
	isRep0Long      [kNumStates][lzmaNumPbStatesMax]uint16

	posSlotEncoder [kNumLenToPosStates][1 << kNumPosSlotBits]uint16
	posEncoders    [kNumFullDistances]uint16

	lenProbs    lenEnc
	repLenProbs lenEnc
}

// Encoder is CLzmaEnc.
type Encoder struct {
	mf matchFinder
	vt matchFinderVTable

	optCur uint32
	optEnd uint32

	longestMatchLen uint32
	numPairs        uint32
	numAvail        uint32

	state            uint32
	numFastBytes     uint32
	additionalOffset uint32
	reps             [lzmaNumReps]uint32
	lpMask, pbMask   uint32
	litProbs         []uint16
	rc               rangeEnc

	backRes uint32

	lc, lp, pb uint32
	lclp       uint32

	fastMode     bool
	writeEndMark bool
	finished     bool
	multiThread  bool
	needInit     bool

	nowPos64 uint64

	matchPriceCount  uint32
	repLenEncCounter int

	distTableSize uint32

	dictSize uint32
	result   error

	probPrices probPrices

	matches [lzmaMatchLenMax*2 + 2]uint32

	alignPrices     [kAlignTableSize]uint32
	posSlotPrices   [kNumLenToPosStates][kDistTableSizeMax]uint32
	distancesPrices [kNumLenToPosStates][kNumFullDistances]uint32

	posAlignEncoder [1 << kNumAlignBits]uint16
	isRep           [kNumStates]uint16
	isRepG0         [kNumStates]uint16
	isRepG1         [kNumStates]uint16
	isRepG2         [kNumStates]uint16
	isMatch         [kNumStates][lzmaNumPbStatesMax]uint16
	isRep0Long      [kNumStates][lzmaNumPbStatesMax]uint16
	posSlotEncoder  [kNumLenToPosStates][1 << kNumPosSlotBits]uint16
	posEncoders     [kNumFullDistances]uint16

	lenProbs    lenEnc
	repLenProbs lenEnc

	gFastPos [1 << kNumLogBits]byte

	lenEnc    lenPriceEnc
	repLenEnc lenPriceEnc

	opt [kNumOpts]optimal

	saveState saveState
}

func (p *Encoder) fastPosInit() {
	g := p.gFastPos[:]
	g[0] = 0
	g[1] = 1
	g = g[2:]
	for slot := uint32(2); slot < kNumLogBits*2; slot++ {
		k := 1 << ((slot >> 1) - 1)
		for j := 0; j < k; j++ {
			g[j] = byte(slot)
		}
		g = g[k:]
	}
}

// bsr2 is BSR2_RET (table form).
func (p *Encoder) bsr2(pos uint32) uint32 {
	zz := uint32(6)
	if pos >= 1<<(kNumLogBits+6) {
		zz = 6 + kNumLogBits - 1
	}
	return uint32(p.gFastPos[pos>>zz]) + zz*2
}

func (p *Encoder) getPosSlot1(pos uint32) uint32 { return uint32(p.gFastPos[pos]) }
func (p *Encoder) getPosSlot2(pos uint32) uint32 { return p.bsr2(pos) }
func (p *Encoder) getPosSlot(pos uint32) uint32 {
	if pos < kNumFullDistances {
		return uint32(p.gFastPos[pos&(kNumFullDistances-1)])
	}
	return p.bsr2(pos)
}

func (p *Encoder) saveStateNow() {
	v := &p.saveState
	v.state = p.state
	v.reps = p.reps
	v.posAlignEncoder = p.posAlignEncoder
	v.isRep = p.isRep
	v.isRepG0 = p.isRepG0
	v.isRepG1 = p.isRepG1
	v.isRepG2 = p.isRepG2
	v.isMatch = p.isMatch
	v.isRep0Long = p.isRep0Long
	v.posSlotEncoder = p.posSlotEncoder
	v.posEncoders = p.posEncoders
	v.lenProbs = p.lenProbs
	v.repLenProbs = p.repLenProbs
	copy(v.litProbs, p.litProbs[:0x300<<p.lclp])
}

func (p *Encoder) restoreState() {
	v := &p.saveState
	p.state = v.state
	p.reps = v.reps
	p.posAlignEncoder = v.posAlignEncoder
	p.isRep = v.isRep
	p.isRepG0 = v.isRepG0
	p.isRepG1 = v.isRepG1
	p.isRepG2 = v.isRepG2
	p.isMatch = v.isMatch
	p.isRep0Long = v.isRep0Long
	p.posSlotEncoder = v.posSlotEncoder
	p.posEncoders = v.posEncoders
	p.lenProbs = v.lenProbs
	p.repLenProbs = v.repLenProbs
	copy(p.litProbs, v.litProbs[:0x300<<p.lclp])
}

// SetProps is LzmaEnc_SetProps.
func (p *Encoder) SetProps(props2 *EncProps) error {
	props := *props2
	props.Normalize()
	if props.Lc > lzmaLcMax || props.Lp > lzmaLpMax || props.Pb > lzmaPbMax {
		return ErrParam
	}
	if props.DictSize > kLzmaMaxHistorySize {
		props.DictSize = kLzmaMaxHistorySize
	}
	if uint64(props.DictSize) > uint64(1)<<kDicLogSizeMaxCompress {
		return ErrParam
	}
	p.dictSize = props.DictSize
	{
		fb := uint32(props.Fb)
		if fb < 5 {
			fb = 5
		}
		if fb > lzmaMatchLenMax {
			fb = lzmaMatchLenMax
		}
		p.numFastBytes = fb
	}
	p.lc = uint32(props.Lc)
	p.lp = uint32(props.Lp)
	p.pb = uint32(props.Pb)
	p.fastMode = props.Algo == 0
	p.mf.btMode = props.BtMode != 0
	{
		numHashBytes := uint32(4)
		if props.BtMode != 0 {
			if props.NumHashBytes < 2 {
				numHashBytes = 2
			} else if props.NumHashBytes < 4 {
				numHashBytes = uint32(props.NumHashBytes)
			}
		}
		if props.NumHashBytes >= 5 {
			numHashBytes = 5
		}
		p.mf.numHashBytes = numHashBytes
		p.mf.numHashOutBits = byte(props.NumHashOutBits)
	}
	p.mf.cutValue = props.Mc
	p.writeEndMark = props.WriteEndMark
	p.multiThread = props.NumThreads > 1
	return nil
}

// SetDataSize is LzmaEnc_SetDataSize.
func (p *Encoder) SetDataSize(expectedDataSize uint64) {
	p.mf.expectedDataSize = expectedDataSize
}

// readMatchDistances is ReadMatchDistances. It returns the longest match
// length and sets numPairs.
func (p *Encoder) readMatchDistances(numPairsRes *uint32) uint32 {
	p.additionalOffset++
	p.numAvail = p.mf.availBytes()
	numPairs := uint32(p.vt.getMatches(p.matches[:]))
	*numPairsRes = numPairs
	if numPairs == 0 {
		return 0
	}
	l := p.matches[numPairs-2]
	if l != p.numFastBytes {
		return l
	}
	numAvail := p.numAvail
	if numAvail > lzmaMatchLenMax {
		numAvail = lzmaMatchLenMax
	}
	buf := p.mf.bufBase
	p1 := p.mf.buffer - 1
	p2 := p1 + int(l)
	dif := -1 - int(p.matches[numPairs-1])
	lim := p1 + int(numAvail)
	for p2 != lim && buf[p2] == buf[p2+dif] {
		p2++
	}
	return uint32(p2 - p1)
}

func (p *Encoder) getPrice(prob uint16, bit uint32) uint32 {
	return p.probPrices[(uint32(prob)^((-bit)&(kBitModelTotal-1)))>>kNumMoveReducingBits]
}
func (p *Encoder) getPrice0(prob uint16) uint32 {
	return p.probPrices[uint32(prob)>>kNumMoveReducingBits]
}
func (p *Encoder) getPrice1(prob uint16) uint32 {
	return p.probPrices[(uint32(prob)^(kBitModelTotal-1))>>kNumMoveReducingBits]
}

func (p *Encoder) getPriceShortRep(state, posState uint32) uint32 {
	return p.getPrice0(p.isRepG0[state]) + p.getPrice0(p.isRep0Long[state][posState])
}

func (p *Encoder) getPriceRep0(state, posState uint32) uint32 {
	return p.getPrice1(p.isMatch[state][posState]) +
		p.getPrice1(p.isRep0Long[state][posState]) +
		p.getPrice1(p.isRep[state]) +
		p.getPrice0(p.isRepG0[state])
}

func (p *Encoder) getPricePureRep(repIndex, state, posState uint32) uint32 {
	var price uint32
	prob := p.isRepG0[state]
	if repIndex == 0 {
		price = p.getPrice0(prob)
		price += p.getPrice1(p.isRep0Long[state][posState])
	} else {
		price = p.getPrice1(prob)
		prob = p.isRepG1[state]
		if repIndex == 1 {
			price += p.getPrice0(prob)
		} else {
			price += p.getPrice1(prob)
			price += p.getPrice(p.isRepG2[state], repIndex-2)
		}
	}
	return price
}

// backward is Backward.
func (p *Encoder) backward(cur uint32) uint32 {
	wr := cur + 1
	p.optEnd = wr
	for {
		dist := p.opt[cur].dist
		l := p.opt[cur].len
		extra := uint32(p.opt[cur].extra)
		cur -= l
		if extra != 0 {
			wr--
			p.opt[wr].len = l
			cur -= extra
			l = extra
			if extra == 1 {
				p.opt[wr].dist = dist
				dist = markLit
			} else {
				p.opt[wr].dist = 0
				l--
				wr--
				p.opt[wr].dist = markLit
				p.opt[wr].len = 1
			}
		}
		if cur == 0 {
			p.backRes = dist
			p.optCur = wr
			return l
		}
		wr--
		p.opt[wr].dist = dist
		p.opt[wr].len = l
	}
}

// litProbsAt is LIT_PROBS(pos, prevByte).
func (p *Encoder) litProbsAt(pos uint32, prevByte byte) []uint16 {
	return p.litProbs[3*((((pos<<8)+uint32(prevByte))&p.lpMask)<<p.lc):]
}

func (p *Encoder) movePosN(num uint32) {
	p.additionalOffset += num
	p.vt.skip(num)
}

// getOptimum is GetOptimum.
func (p *Encoder) getOptimum(position uint32) uint32 {
	var last, cur uint32
	var reps [lzmaNumReps]uint32
	var repLens [lzmaNumReps]uint32
	matches := p.matches[:]
	buf := p.mf.bufBase

	{
		var numPairs, mainLen, repMaxIndex, posState uint32
		p.optCur = 0
		p.optEnd = 0

		if p.additionalOffset == 0 {
			mainLen = p.readMatchDistances(&numPairs)
		} else {
			mainLen = p.longestMatchLen
			numPairs = p.numPairs
		}

		numAvail := p.numAvail
		if numAvail < 2 {
			p.backRes = markLit
			return 1
		}
		if numAvail > lzmaMatchLenMax {
			numAvail = lzmaMatchLenMax
		}

		data := p.mf.buffer - 1
		repMaxIndex = 0

		for i := uint32(0); i < lzmaNumReps; i++ {
			reps[i] = p.reps[i]
			data2 := data - int(reps[i])
			if buf[data] != buf[data2] || buf[data+1] != buf[data2+1] {
				repLens[i] = 0
				continue
			}
			l := uint32(2)
			for l < numAvail && buf[data+int(l)] == buf[data2+int(l)] {
				l++
			}
			repLens[i] = l
			if l > repLens[repMaxIndex] {
				repMaxIndex = i
			}
			if l == lzmaMatchLenMax {
				break
			}
		}

		if repLens[repMaxIndex] >= p.numFastBytes {
			p.backRes = repMaxIndex
			l := repLens[repMaxIndex]
			p.movePosN(l - 1)
			return l
		}

		if mainLen >= p.numFastBytes {
			p.backRes = matches[numPairs-1] + lzmaNumReps
			p.movePosN(mainLen - 1)
			return mainLen
		}

		curByte := uint32(buf[data])
		matchByte := uint32(buf[data-int(reps[0])])

		last = repLens[repMaxIndex]
		if last <= mainLen {
			last = mainLen
		}

		if last < 2 && curByte != matchByte {
			p.backRes = markLit
			return 1
		}

		p.opt[0].state = uint16(p.state)

		posState = position & p.pbMask

		{
			probs := p.litProbsAt(position, buf[data-1])
			var lp uint32
			if !isLitState(p.state) {
				lp = litMatchedGetPrice(probs, curByte, matchByte, &p.probPrices)
			} else {
				lp = litGetPrice(probs, curByte, &p.probPrices)
			}
			p.opt[1].price = p.getPrice0(p.isMatch[p.state][posState]) + lp
		}

		p.opt[1].dist = markLit
		p.opt[1].extra = 0

		matchPrice := p.getPrice1(p.isMatch[p.state][posState])
		repMatchPrice := matchPrice + p.getPrice1(p.isRep[p.state])

		if matchByte == curByte && repLens[0] == 0 {
			shortRepPrice := repMatchPrice + p.getPriceShortRep(p.state, posState)
			if shortRepPrice < p.opt[1].price {
				p.opt[1].price = shortRepPrice
				p.opt[1].dist = 0
				p.opt[1].extra = 0
			}
			if last < 2 {
				p.backRes = p.opt[1].dist
				return 1
			}
		}

		p.opt[1].len = 1

		p.opt[0].reps = reps

		// ---------- REP ----------
		for i := uint32(0); i < lzmaNumReps; i++ {
			repLen := repLens[i]
			if repLen < 2 {
				continue
			}
			price := repMatchPrice + p.getPricePureRep(i, p.state, posState)
			for {
				price2 := price + p.repLenEnc.price(posState, repLen)
				opt := &p.opt[repLen]
				if price2 < opt.price {
					opt.price = price2
					opt.len = repLen
					opt.dist = i
					opt.extra = 0
				}
				repLen--
				if repLen < 2 {
					break
				}
			}
		}

		// ---------- MATCH ----------
		{
			l := repLens[0] + 1
			if l <= mainLen {
				offs := uint32(0)
				normalMatchPrice := matchPrice + p.getPrice0(p.isRep[p.state])
				if l < 2 {
					l = 2
				} else {
					for l > matches[offs] {
						offs += 2
					}
				}
				for ; ; l++ {
					dist := matches[offs+1]
					price := normalMatchPrice + p.lenEnc.price(posState, l)
					lenToPosState := getLenToPosState(l)
					if dist < kNumFullDistances {
						price += p.distancesPrices[lenToPosState][dist&(kNumFullDistances-1)]
					} else {
						slot := p.getPosSlot2(dist)
						price += p.alignPrices[dist&kAlignMask]
						price += p.posSlotPrices[lenToPosState][slot]
					}
					opt := &p.opt[l]
					if price < opt.price {
						opt.price = price
						opt.len = l
						opt.dist = dist + lzmaNumReps
						opt.extra = 0
					}
					if l == matches[offs] {
						offs += 2
						if offs == numPairs {
							break
						}
					}
				}
			}
		}
		cur = 0
	}

	// ---------- Optimal Parsing ----------
	for {
		cur++
		if cur == last {
			break
		}

		if cur >= kNumOpts-64 {
			price := p.opt[cur].price
			best := cur
			for j := cur + 1; j <= last; j++ {
				price2 := p.opt[j].price
				if price >= price2 {
					price = price2
					best = j
				}
			}
			delta := best - cur
			if delta != 0 {
				p.movePosN(delta)
			}
			cur = best
			break
		}

		var numPairs uint32
		newLen := p.readMatchDistances(&numPairs)

		if newLen >= p.numFastBytes {
			p.numPairs = numPairs
			p.longestMatchLen = newLen
			break
		}

		curOpt := &p.opt[cur]
		position++

		prev := cur - curOpt.len
		var state uint32

		if curOpt.len == 1 {
			state = uint32(p.opt[prev].state)
			if curOpt.dist == 0 {
				state = uint32(kShortRepNextStates[state])
			} else {
				state = uint32(kLiteralNextStates[state])
			}
		} else {
			dist := curOpt.dist
			if curOpt.extra != 0 {
				prev -= uint32(curOpt.extra)
				state = kStateRepAfterLit
				if curOpt.extra == 1 {
					if dist < lzmaNumReps {
						state = kStateRepAfterLit
					} else {
						state = kStateMatchAfterLit
					}
				}
			} else {
				state = uint32(p.opt[prev].state)
				if dist < lzmaNumReps {
					state = uint32(kRepNextStates[state])
				} else {
					state = uint32(kMatchNextStates[state])
				}
			}
			prevOpt := &p.opt[prev]
			b0 := prevOpt.reps[0]
			if dist < lzmaNumReps {
				if dist == 0 {
					reps[0] = b0
					reps[1] = prevOpt.reps[1]
					reps[2] = prevOpt.reps[2]
					reps[3] = prevOpt.reps[3]
				} else {
					reps[1] = b0
					b0 = prevOpt.reps[1]
					if dist == 1 {
						reps[0] = b0
						reps[2] = prevOpt.reps[2]
						reps[3] = prevOpt.reps[3]
					} else {
						reps[2] = b0
						reps[0] = prevOpt.reps[dist]
						reps[3] = prevOpt.reps[dist^1]
					}
				}
			} else {
				reps[0] = dist - lzmaNumReps + 1
				reps[1] = b0
				reps[2] = prevOpt.reps[1]
				reps[3] = prevOpt.reps[2]
			}
		}

		curOpt.state = uint16(state)
		curOpt.reps = reps

		data := p.mf.buffer - 1
		curByte := uint32(buf[data])
		matchByte := uint32(buf[data-int(reps[0])])

		posState := position & p.pbMask

		var litPrice, matchPrice uint32
		{
			curPrice := curOpt.price
			prob := p.isMatch[state][posState]
			matchPrice = curPrice + p.getPrice1(prob)
			litPrice = curPrice + p.getPrice0(prob)
		}

		nextOpt := &p.opt[cur+1]
		nextIsLit := false

		if (nextOpt.price < kInfinityPrice && matchByte == curByte) || litPrice > nextOpt.price {
			litPrice = 0
		} else {
			probs := p.litProbsAt(position, buf[data-1])
			if !isLitState(state) {
				litPrice += litMatchedGetPrice(probs, curByte, matchByte, &p.probPrices)
			} else {
				litPrice += litGetPrice(probs, curByte, &p.probPrices)
			}
			if litPrice < nextOpt.price {
				nextOpt.price = litPrice
				nextOpt.len = 1
				nextOpt.dist = markLit
				nextOpt.extra = 0
				nextIsLit = true
			}
		}

		repMatchPrice := matchPrice + p.getPrice1(p.isRep[state])

		numAvailFull := p.numAvail
		{
			temp := kNumOpts - 1 - cur
			if numAvailFull > temp {
				numAvailFull = temp
			}
		}

		// ---------- SHORT_REP ----------
		if isLitState(state) {
			if matchByte == curByte {
				if repMatchPrice < nextOpt.price {
					if nextOpt.len < 2 || nextOpt.dist != 0 {
						shortRepPrice := repMatchPrice + p.getPriceShortRep(state, posState)
						if shortRepPrice < nextOpt.price {
							nextOpt.price = shortRepPrice
							nextOpt.len = 1
							nextOpt.dist = 0
							nextOpt.extra = 0
							nextIsLit = false
						}
					}
				}
			}
		}

		if numAvailFull < 2 {
			continue
		}
		numAvail := numAvailFull
		if numAvail > p.numFastBytes {
			numAvail = p.numFastBytes
		}

		// ---------- LIT : REP_0 ----------
		if !nextIsLit && litPrice != 0 && matchByte != curByte && numAvailFull > 2 {
			data2 := data - int(reps[0])
			if buf[data+1] == buf[data2+1] && buf[data+2] == buf[data2+2] {
				limit := p.numFastBytes + 1
				if limit > numAvailFull {
					limit = numAvailFull
				}
				l := uint32(3)
				for l < limit && buf[data+int(l)] == buf[data2+int(l)] {
					l++
				}
				state2 := uint32(kLiteralNextStates[state])
				posState2 := (position + 1) & p.pbMask
				price := litPrice + p.getPriceRep0(state2, posState2)
				offset := cur + l
				if last < offset {
					last = offset
				}
				l--
				price2 := price + p.repLenEnc.price(posState2, l)
				opt := &p.opt[offset]
				if price2 < opt.price {
					opt.price = price2
					opt.len = l
					opt.dist = 0
					opt.extra = 1
				}
			}
		}

		startLen := uint32(2)

		{
			// ---------- REP ----------
			for repIndex := uint32(0); repIndex < lzmaNumReps; repIndex++ {
				data2 := data - int(reps[repIndex])
				if buf[data] != buf[data2] || buf[data+1] != buf[data2+1] {
					continue
				}
				l := uint32(2)
				for l < numAvail && buf[data+int(l)] == buf[data2+int(l)] {
					l++
				}
				{
					offset := cur + l
					if last < offset {
						last = offset
					}
				}
				var price uint32
				{
					len2 := l
					price = repMatchPrice + p.getPricePureRep(repIndex, state, posState)
					for {
						price2 := price + p.repLenEnc.price(posState, len2)
						opt := &p.opt[cur+len2]
						if price2 < opt.price {
							opt.price = price2
							opt.len = len2
							opt.dist = repIndex
							opt.extra = 0
						}
						len2--
						if len2 < 2 {
							break
						}
					}
				}
				if repIndex == 0 {
					startLen = l + 1
				}

				// ---------- REP : LIT : REP_0 ----------
				{
					len2 := l + 1
					limit := len2 + p.numFastBytes
					if limit > numAvailFull {
						limit = numAvailFull
					}
					len2 += 2
					if len2 <= limit && buf[data+int(len2)-2] == buf[data2+int(len2)-2] && buf[data+int(len2)-1] == buf[data2+int(len2)-1] {
						state2 := uint32(kRepNextStates[state])
						posState2 := (position + l) & p.pbMask
						price += p.repLenEnc.price(posState, l) +
							p.getPrice0(p.isMatch[state2][posState2]) +
							litMatchedGetPrice(p.litProbsAt(position+l, buf[data+int(l)-1]),
								uint32(buf[data+int(l)]), uint32(buf[data2+int(l)]), &p.probPrices)
						state2 = kStateLitAfterRep
						posState2 = (posState2 + 1) & p.pbMask
						price += p.getPriceRep0(state2, posState2)
						for len2 < limit && buf[data+int(len2)] == buf[data2+int(len2)] {
							len2++
						}
						len2 -= l
						offset := cur + l + len2
						if last < offset {
							last = offset
						}
						len2--
						price2 := price + p.repLenEnc.price(posState2, len2)
						opt := &p.opt[offset]
						if price2 < opt.price {
							opt.price = price2
							opt.len = len2
							opt.extra = uint16(l + 1)
							opt.dist = repIndex
						}
					}
				}
			}
		}

		// ---------- MATCH ----------
		if newLen > numAvail {
			newLen = numAvail
			numPairs = 0
			for newLen > matches[numPairs] {
				numPairs += 2
			}
			matches[numPairs] = newLen
			numPairs += 2
		}

		if newLen >= startLen {
			normalMatchPrice := matchPrice + p.getPrice0(p.isRep[state])
			{
				offset := cur + newLen
				if last < offset {
					last = offset
				}
			}
			offs := uint32(0)
			for startLen > matches[offs] {
				offs += 2
			}
			dist := matches[offs+1]
			posSlot := p.getPosSlot2(dist)

			for l := startLen; ; l++ {
				price := normalMatchPrice + p.lenEnc.price(posState, l)
				{
					lenNorm := l - 2
					lenNorm = getLenToPosState2(lenNorm)
					if dist < kNumFullDistances {
						price += p.distancesPrices[lenNorm][dist&(kNumFullDistances-1)]
					} else {
						price += p.posSlotPrices[lenNorm][posSlot] + p.alignPrices[dist&kAlignMask]
					}
					opt := &p.opt[cur+l]
					if price < opt.price {
						opt.price = price
						opt.len = l
						opt.dist = dist + lzmaNumReps
						opt.extra = 0
					}
				}

				if l == matches[offs] {
					// MATCH : LIT : REP_0
					data2 := data - int(dist) - 1
					len2 := l + 1
					limit := len2 + p.numFastBytes
					if limit > numAvailFull {
						limit = numAvailFull
					}
					len2 += 2
					if len2 <= limit && buf[data+int(len2)-2] == buf[data2+int(len2)-2] && buf[data+int(len2)-1] == buf[data2+int(len2)-1] {
						for len2 < limit && buf[data+int(len2)] == buf[data2+int(len2)] {
							len2++
						}
						len2 -= l
						state2 := uint32(kMatchNextStates[state])
						posState2 := (position + l) & p.pbMask
						price += p.getPrice0(p.isMatch[state2][posState2])
						price += litMatchedGetPrice(p.litProbsAt(position+l, buf[data+int(l)-1]),
							uint32(buf[data+int(l)]), uint32(buf[data2+int(l)]), &p.probPrices)
						state2 = kStateLitAfterMatch
						posState2 = (posState2 + 1) & p.pbMask
						price += p.getPriceRep0(state2, posState2)
						offset := cur + l + len2
						if last < offset {
							last = offset
						}
						len2--
						price2 := price + p.repLenEnc.price(posState2, len2)
						opt := &p.opt[offset]
						if price2 < opt.price {
							opt.price = price2
							opt.len = len2
							opt.extra = uint16(l + 1)
							opt.dist = dist + lzmaNumReps
						}
					}
					offs += 2
					if offs == numPairs {
						break
					}
					dist = matches[offs+1]
					posSlot = p.getPosSlot2(dist)
				}
			}
		}
	}

	for {
		p.opt[last].price = kInfinityPrice
		last--
		if last == 0 {
			break
		}
	}
	return p.backward(cur)
}

func changePair(smallDist, bigDist uint32) bool { return (bigDist >> 7) > smallDist }

// getOptimumFast is GetOptimumFast.
func (p *Encoder) getOptimumFast() uint32 {
	var mainLen, numPairs uint32
	buf := p.mf.bufBase

	if p.additionalOffset == 0 {
		mainLen = p.readMatchDistances(&numPairs)
	} else {
		mainLen = p.longestMatchLen
		numPairs = p.numPairs
	}

	numAvail := p.numAvail
	p.backRes = markLit
	if numAvail < 2 {
		return 1
	}
	if numAvail > lzmaMatchLenMax {
		numAvail = lzmaMatchLenMax
	}
	data := p.mf.buffer - 1
	var repLen, repIndex uint32

	for i := uint32(0); i < lzmaNumReps; i++ {
		data2 := data - int(p.reps[i])
		if buf[data] != buf[data2] || buf[data+1] != buf[data2+1] {
			continue
		}
		l := uint32(2)
		for l < numAvail && buf[data+int(l)] == buf[data2+int(l)] {
			l++
		}
		if l >= p.numFastBytes {
			p.backRes = i
			p.movePosN(l - 1)
			return l
		}
		if l > repLen {
			repIndex = i
			repLen = l
		}
	}

	if mainLen >= p.numFastBytes {
		p.backRes = p.matches[numPairs-1] + lzmaNumReps
		p.movePosN(mainLen - 1)
		return mainLen
	}

	mainDist := uint32(0)

	if mainLen >= 2 {
		mainDist = p.matches[numPairs-1]
		for numPairs > 2 {
			if mainLen != p.matches[numPairs-4]+1 {
				break
			}
			dist2 := p.matches[numPairs-3]
			if !changePair(dist2, mainDist) {
				break
			}
			numPairs -= 2
			mainLen--
			mainDist = dist2
		}
		if mainLen == 2 && mainDist >= 0x80 {
			mainLen = 1
		}
	}

	if repLen >= 2 {
		if repLen+1 >= mainLen ||
			(repLen+2 >= mainLen && mainDist >= 1<<9) ||
			(repLen+3 >= mainLen && mainDist >= 1<<15) {
			p.backRes = repIndex
			p.movePosN(repLen - 1)
			return repLen
		}
	}

	if mainLen < 2 || numAvail <= 2 {
		return 1
	}

	{
		len1 := p.readMatchDistances(&p.numPairs)
		p.longestMatchLen = len1
		if len1 >= 2 {
			newDist := p.matches[p.numPairs-1]
			if (len1 >= mainLen && newDist < mainDist) ||
				(len1 == mainLen+1 && !changePair(mainDist, newDist)) ||
				(len1 > mainLen+1) ||
				(len1+1 >= mainLen && mainLen >= 3 && changePair(newDist, mainDist)) {
				return 1
			}
		}
	}

	data = p.mf.buffer - 1

	for i := uint32(0); i < lzmaNumReps; i++ {
		data2 := data - int(p.reps[i])
		if buf[data] != buf[data2] || buf[data+1] != buf[data2+1] {
			continue
		}
		limit := mainLen - 1
		for l := uint32(2); ; l++ {
			if l >= limit {
				return 1
			}
			if buf[data+int(l)] != buf[data2+int(l)] {
				break
			}
		}
	}

	p.backRes = mainDist + lzmaNumReps
	if mainLen != 2 {
		p.movePosN(mainLen - 2)
	}
	return mainLen
}

// writeEndMarker is WriteEndMarker.
func (p *Encoder) writeEndMarker(posState uint32) {
	rc := &p.rc
	rc.bit1(&p.isMatch[p.state][posState])
	rc.bit0(&p.isRep[p.state])
	p.state = uint32(kMatchNextStates[p.state])
	p.lenProbs.encode(rc, 0, posState)
	{
		probs := p.posSlotEncoder[0][:]
		m := uint32(1)
		for {
			rc.bit1(&probs[m])
			m = (m << 1) + 1
			if m >= 1<<kNumPosSlotBits {
				break
			}
		}
	}
	{
		numBits := uint32(30 - kNumAlignBits)
		for {
			rc.rng >>= 1
			rc.low += uint64(rc.rng)
			if rc.rng < kTopValue {
				rc.rng <<= 8
				rc.shiftLow()
			}
			numBits--
			if numBits == 0 {
				break
			}
		}
	}
	{
		probs := p.posAlignEncoder[:]
		m := uint32(1)
		for {
			rc.bit1(&probs[m])
			m = (m << 1) + 1
			if m >= kAlignTableSize {
				break
			}
		}
	}
}

func (p *Encoder) checkErrors() error {
	if p.result != nil {
		return p.result
	}
	if p.rc.res != nil {
		p.result = ErrWrite
	}
	if p.mf.result != nil {
		p.result = p.mf.result
	}
	if p.result != nil {
		p.finished = true
	}
	return p.result
}

func (p *Encoder) flush(nowPos uint32) error {
	p.finished = true
	if p.writeEndMark {
		p.writeEndMarker(nowPos & p.pbMask)
	}
	p.rc.flushData()
	p.rc.flushStream()
	return p.checkErrors()
}

func (p *Encoder) fillAlignPrices() {
	pp := &p.probPrices
	probs := p.posAlignEncoder[:]
	for i := uint32(0); i < kAlignTableSize/2; i++ {
		price := uint32(0)
		sym := i
		m := uint32(1)
		bit := sym & 1
		sym >>= 1
		price += getPricea(pp, uint32(probs[m]), bit)
		m = (m << 1) + bit
		bit = sym & 1
		sym >>= 1
		price += getPricea(pp, uint32(probs[m]), bit)
		m = (m << 1) + bit
		bit = sym & 1
		price += getPricea(pp, uint32(probs[m]), bit)
		m = (m << 1) + bit
		prob := uint32(probs[m])
		p.alignPrices[i] = price + getPricea0(pp, prob)
		p.alignPrices[i+8] = price + getPricea1(pp, prob)
	}
}

func (p *Encoder) fillDistancesPrices() {
	var tempPrices [kNumFullDistances]uint32
	pp := &p.probPrices
	p.matchPriceCount = 0

	for i := uint32(kStartPosModelIndex / 2); i < kNumFullDistances/2; i++ {
		posSlot := p.getPosSlot1(i)
		footerBits := (posSlot >> 1) - 1
		base := (2 | (posSlot & 1)) << footerBits
		probs := p.posEncoders[base*2:]
		price := uint32(0)
		m := uint32(1)
		sym := i
		offset := uint32(1) << footerBits
		base += i
		if footerBits != 0 {
			for {
				bit := sym & 1
				sym >>= 1
				price += getPricea(pp, uint32(probs[m]), bit)
				m = (m << 1) + bit
				footerBits--
				if footerBits == 0 {
					break
				}
			}
		}
		prob := uint32(probs[m])
		tempPrices[base] = price + getPricea0(pp, prob)
		tempPrices[base+offset] = price + getPricea1(pp, prob)
	}

	for lps := uint32(0); lps < kNumLenToPosStates; lps++ {
		distTableSize2 := (p.distTableSize + 1) >> 1
		posSlotPrices := p.posSlotPrices[lps][:]
		probs := p.posSlotEncoder[lps][:]

		for slot := uint32(0); slot < distTableSize2; slot++ {
			sym := slot + (1 << (kNumPosSlotBits - 1))
			var price uint32
			bit := sym & 1
			sym >>= 1
			price = getPricea(pp, uint32(probs[sym]), bit)
			bit = sym & 1
			sym >>= 1
			price += getPricea(pp, uint32(probs[sym]), bit)
			bit = sym & 1
			sym >>= 1
			price += getPricea(pp, uint32(probs[sym]), bit)
			bit = sym & 1
			sym >>= 1
			price += getPricea(pp, uint32(probs[sym]), bit)
			bit = sym & 1
			sym >>= 1
			price += getPricea(pp, uint32(probs[sym]), bit)
			prob := uint32(probs[slot+(1<<(kNumPosSlotBits-1))])
			posSlotPrices[slot*2] = price + getPricea0(pp, prob)
			posSlotPrices[slot*2+1] = price + getPricea1(pp, prob)
		}

		{
			delta := uint32((kEndPosModelIndex/2-1)-kNumAlignBits) << kNumBitPriceShiftBits
			for slot := uint32(kEndPosModelIndex / 2); slot < distTableSize2; slot++ {
				posSlotPrices[slot*2] += delta
				posSlotPrices[slot*2+1] += delta
				delta += uint32(1) << kNumBitPriceShiftBits
			}
		}

		{
			dp := p.distancesPrices[lps][:]
			dp[0] = posSlotPrices[0]
			dp[1] = posSlotPrices[1]
			dp[2] = posSlotPrices[2]
			dp[3] = posSlotPrices[3]
			for i := uint32(4); i < kNumFullDistances; i += 2 {
				slotPrice := posSlotPrices[p.getPosSlot1(i)]
				dp[i] = slotPrice + tempPrices[i]
				dp[i+1] = slotPrice + tempPrices[i+1]
			}
		}
	}
}

// NewEncoder is LzmaEnc_Create (+ LzmaEnc_Construct).
func NewEncoder() *Encoder {
	p := &Encoder{}
	p.mf.construct()
	{
		var props EncProps
		props.Init()
		_ = p.SetProps(&props)
	}
	p.fastPosInit()
	initPriceTables(&p.probPrices)
	p.litProbs = nil
	p.saveState.litProbs = nil
	return p
}

// codeOneBlock is LzmaEnc_CodeOneBlock.
func (p *Encoder) codeOneBlock(maxPackSize, maxUnpackSize uint32) error {
	if p.needInit {
		p.mf.init()
		p.needInit = false
	}
	if p.finished {
		return p.result
	}
	if err := p.checkErrors(); err != nil {
		return err
	}

	nowPos32 := uint32(p.nowPos64)
	startPos32 := nowPos32

	if p.nowPos64 == 0 {
		var numPairs uint32
		if p.mf.availBytes() == 0 {
			return p.flush(nowPos32)
		}
		p.readMatchDistances(&numPairs)
		p.rc.bit0(&p.isMatch[kStateStart][0])
		curByte := p.mf.bufBase[p.mf.buffer-int(p.additionalOffset)]
		p.rc.litEncode(p.litProbs, uint32(curByte))
		p.additionalOffset--
		nowPos32++
	}

	if p.mf.availBytes() != 0 {
		for {
			var l uint32
			if p.fastMode {
				l = p.getOptimumFast()
			} else {
				oci := p.optCur
				if p.optEnd == oci {
					l = p.getOptimum(nowPos32)
				} else {
					opt := &p.opt[oci]
					l = opt.len
					p.backRes = opt.dist
					p.optCur = oci + 1
				}
			}

			posState := nowPos32 & p.pbMask
			rc := &p.rc
			dist := p.backRes

			if dist == markLit {
				rc.bit0(&p.isMatch[p.state][posState])
				data := p.mf.buffer - int(p.additionalOffset)
				probs := p.litProbsAt(nowPos32, p.mf.bufBase[data-1])
				curByte := uint32(p.mf.bufBase[data])
				state := p.state
				p.state = uint32(kLiteralNextStates[state])
				if isLitState(state) {
					rc.litEncode(probs, curByte)
				} else {
					rc.litEncodeMatched(probs, curByte, uint32(p.mf.bufBase[data-int(p.reps[0])]))
				}
			} else {
				rc.bit1(&p.isMatch[p.state][posState])
				if dist < lzmaNumReps {
					rc.bit1(&p.isRep[p.state])
					if dist == 0 {
						rc.bit0(&p.isRepG0[p.state])
						if l != 1 {
							rc.bit1(&p.isRep0Long[p.state][posState])
						} else {
							rc.bit0(&p.isRep0Long[p.state][posState])
							p.state = uint32(kShortRepNextStates[p.state])
						}
					} else {
						rc.bit1(&p.isRepG0[p.state])
						if dist == 1 {
							rc.bit0(&p.isRepG1[p.state])
							dist = p.reps[1]
						} else {
							rc.bit1(&p.isRepG1[p.state])
							if dist == 2 {
								rc.bit0(&p.isRepG2[p.state])
								dist = p.reps[2]
							} else {
								rc.bit1(&p.isRepG2[p.state])
								dist = p.reps[3]
								p.reps[3] = p.reps[2]
							}
							p.reps[2] = p.reps[1]
						}
						p.reps[1] = p.reps[0]
						p.reps[0] = dist
					}
					if l != 1 {
						p.repLenProbs.encode(rc, l-lzmaMatchLenMin, posState)
						p.repLenEncCounter--
						p.state = uint32(kRepNextStates[p.state])
					}
				} else {
					rc.bit0(&p.isRep[p.state])
					p.state = uint32(kMatchNextStates[p.state])
					p.lenProbs.encode(rc, l-lzmaMatchLenMin, posState)
					dist -= lzmaNumReps
					p.reps[3] = p.reps[2]
					p.reps[2] = p.reps[1]
					p.reps[1] = p.reps[0]
					p.reps[0] = dist + 1

					p.matchPriceCount++
					posSlot := p.getPosSlot(dist)
					{
						sym := posSlot + (1 << kNumPosSlotBits)
						probs := p.posSlotEncoder[getLenToPosState(l)][:]
						for {
							prob := &probs[sym>>kNumPosSlotBits]
							bit := (sym >> (kNumPosSlotBits - 1)) & 1
							sym <<= 1
							rc.bit(prob, bit)
							if sym >= 1<<(kNumPosSlotBits*2) {
								break
							}
						}
					}
					if dist >= kStartPosModelIndex {
						footerBits := (posSlot >> 1) - 1
						if dist < kNumFullDistances {
							base := (2 | (posSlot & 1)) << footerBits
							rc.rcTreeReverseEncode(p.posEncoders[base:], footerBits, dist)
						} else {
							pos2 := (dist | 0xF) << (32 - footerBits)
							for {
								rc.rng >>= 1
								rc.low += uint64(rc.rng & (0 - (pos2 >> 31)))
								pos2 += pos2
								if rc.rng < kTopValue {
									rc.rng <<= 8
									rc.shiftLow()
								}
								if pos2 == 0xF0000000 {
									break
								}
							}
							{
								m := uint32(1)
								bit := dist & 1
								dist >>= 1
								rc.bit(&p.posAlignEncoder[m], bit)
								m = (m << 1) + bit
								bit = dist & 1
								dist >>= 1
								rc.bit(&p.posAlignEncoder[m], bit)
								m = (m << 1) + bit
								bit = dist & 1
								dist >>= 1
								rc.bit(&p.posAlignEncoder[m], bit)
								m = (m << 1) + bit
								bit = dist & 1
								rc.bit(&p.posAlignEncoder[m], bit)
							}
						}
					}
				}
			}

			nowPos32 += l
			p.additionalOffset -= l

			if p.additionalOffset == 0 {
				if !p.fastMode {
					if p.matchPriceCount >= 64 {
						p.fillAlignPrices()
						p.fillDistancesPrices()
						p.lenEnc.updateTables(uint32(1)<<p.pb, &p.lenProbs, &p.probPrices)
					}
					if p.repLenEncCounter <= 0 {
						p.repLenEncCounter = repLenCount
						p.repLenEnc.updateTables(uint32(1)<<p.pb, &p.repLenProbs, &p.probPrices)
					}
				}
				if p.mf.availBytes() == 0 {
					break
				}
				processed := nowPos32 - startPos32
				if maxPackSize != 0 {
					if processed+kNumOpts+300 >= maxUnpackSize ||
						p.rc.getProcessed()+kPackReserve >= uint64(maxPackSize) {
						break
					}
				} else if processed >= 1<<17 {
					p.nowPos64 += uint64(nowPos32 - startPos32)
					return p.checkErrors()
				}
			}
		}
	}

	p.nowPos64 += uint64(nowPos32 - startPos32)
	return p.flush(nowPos32)
}

// alloc is LzmaEnc_Alloc.
func (p *Encoder) alloc(keepWindowSize uint32) error {
	beforeSize := uint32(kNumOpts)
	p.rc.alloc()
	{
		lclp := p.lc + p.lp
		if p.litProbs == nil || p.saveState.litProbs == nil || p.lclp != lclp {
			p.litProbs = make([]uint16, 0x300<<lclp)
			p.saveState.litProbs = make([]uint16, 0x300<<lclp)
			p.lclp = lclp
		}
	}
	p.mf.bigHash = p.dictSize > kBigHashDicLimit
	dictSize := p.dictSize
	if dictSize == uint32(2)<<30 || dictSize == uint32(3)<<30 {
		dictSize--
	}
	if beforeSize+dictSize < keepWindowSize {
		beforeSize = keepWindowSize - dictSize
	}
	if !p.mf.create(dictSize, beforeSize, p.numFastBytes, lzmaMatchLenMax+1) {
		return errMatchFinderMem
	}
	p.vt = p.mf.createVTable()
	return nil
}

// initState is LzmaEnc_Init.
func (p *Encoder) initState() {
	p.state = 0
	p.reps = [lzmaNumReps]uint32{1, 1, 1, 1}
	p.rc.init()
	for i := range p.posAlignEncoder {
		p.posAlignEncoder[i] = kProbInitValue
	}
	for i := 0; i < kNumStates; i++ {
		for j := 0; j < lzmaNumPbStatesMax; j++ {
			p.isMatch[i][j] = kProbInitValue
			p.isRep0Long[i][j] = kProbInitValue
		}
		p.isRep[i] = kProbInitValue
		p.isRepG0[i] = kProbInitValue
		p.isRepG1[i] = kProbInitValue
		p.isRepG2[i] = kProbInitValue
	}
	for i := 0; i < kNumLenToPosStates; i++ {
		for j := range p.posSlotEncoder[i] {
			p.posSlotEncoder[i][j] = kProbInitValue
		}
	}
	for i := range p.posEncoders {
		p.posEncoders[i] = kProbInitValue
	}
	{
		num := 0x300 << (p.lp + p.lc)
		probs := p.litProbs
		for k := 0; k < num; k++ {
			probs[k] = kProbInitValue
		}
	}
	p.lenProbs.init()
	p.repLenProbs.init()
	p.optEnd = 0
	p.optCur = 0
	for i := range p.opt {
		p.opt[i].price = kInfinityPrice
	}
	p.additionalOffset = 0
	p.pbMask = (uint32(1) << p.pb) - 1
	p.lpMask = (uint32(0x100) << p.lp) - (uint32(0x100) >> p.lc)
}

func (p *Encoder) initPrices() {
	if !p.fastMode {
		p.fillDistancesPrices()
		p.fillAlignPrices()
	}
	p.lenEnc.tableSize = p.numFastBytes + 1 - lzmaMatchLenMin
	p.repLenEnc.tableSize = p.lenEnc.tableSize
	p.repLenEncCounter = repLenCount
	p.lenEnc.updateTables(uint32(1)<<p.pb, &p.lenProbs, &p.probPrices)
	p.repLenEnc.updateTables(uint32(1)<<p.pb, &p.repLenProbs, &p.probPrices)
}

func (p *Encoder) allocAndInit(keepWindowSize uint32) error {
	i := uint32(kEndPosModelIndex / 2)
	for ; i < kDicLogSizeMax; i++ {
		if p.dictSize <= uint32(1)<<i {
			break
		}
	}
	p.distTableSize = i * 2
	p.finished = false
	p.result = nil
	p.nowPos64 = 0
	p.needInit = true
	if err := p.alloc(keepWindowSize); err != nil {
		return err
	}
	p.initState()
	p.initPrices()
	return nil
}

func (p *Encoder) prepare(out io.Writer, in io.Reader) error {
	p.mf.setStream(in)
	p.rc.out = out
	return p.allocAndInit(0)
}

// prepareForLzma2 is LzmaEnc_PrepareForLzma2.
func (p *Encoder) prepareForLzma2(in io.Reader, keepWindowSize uint32) error {
	p.mf.setStream(in)
	return p.allocAndInit(keepWindowSize)
}

// memPrepare is LzmaEnc_MemPrepare.
func (p *Encoder) memPrepare(src []byte, keepWindowSize uint32) error {
	p.mf.setDirectInput(src)
	p.SetDataSize(uint64(len(src)))
	return p.allocAndInit(keepWindowSize)
}

// seqOutStreamBuf is CLzmaEnc_SeqOutStreamBuf.
type seqOutStreamBuf struct {
	data     []byte
	pos      int
	overflow bool
}

func (s *seqOutStreamBuf) Write(b []byte) (int, error) {
	size := len(b)
	if len(s.data)-s.pos < size {
		size = len(s.data) - s.pos
		s.overflow = true
	}
	if size != 0 {
		copy(s.data[s.pos:], b[:size])
		s.pos += size
	}
	return size, nil
}

// curBuf is LzmaEnc_GetCurBuf: the window and the index of the next byte
// to be encoded.
func (p *Encoder) curBuf() ([]byte, int) {
	return p.mf.bufBase, p.mf.buffer - int(p.additionalOffset)
}

// codeOneMemBlock is LzmaEnc_CodeOneMemBlock. dest receives the packed
// bytes; it returns the number written, the unpacked size consumed, and
// an error (ErrOutputEOF if dest overflowed).
func (p *Encoder) codeOneMemBlock(reInit bool, dest []byte, desiredPackSize uint32, unpackSize uint32) (packed int, unpacked uint32, err error) {
	out := seqOutStreamBuf{data: dest}
	p.writeEndMark = false
	p.finished = false
	p.result = nil
	if reInit {
		p.initState()
	}
	p.initPrices()
	p.rc.init()
	p.rc.out = &out
	nowPos64 := p.nowPos64
	res := p.codeOneBlock(desiredPackSize, unpackSize)
	unpacked = uint32(p.nowPos64 - nowPos64)
	packed = out.pos
	if out.overflow {
		return packed, unpacked, ErrOutputEOF
	}
	return packed, unpacked, res
}

func (p *Encoder) encode2() error {
	for {
		if err := p.codeOneBlock(0, 0); err != nil || p.finished {
			return err
		}
	}
}

// Encode is LzmaEnc_Encode: encodes everything from in to out (stream
// mode, bounded memory).
func (p *Encoder) Encode(out io.Writer, in io.Reader) error {
	if err := p.prepare(out, in); err != nil {
		return err
	}
	return p.encode2()
}

// WriteProperties is LzmaEnc_WriteProperties: the 5-byte LZMA header
// properties (lc/lp/pb byte and the aligned dictionary size).
func (p *Encoder) WriteProperties() [lzmaPropsSize]byte {
	var props [lzmaPropsSize]byte
	dictSize := p.dictSize
	var v uint32
	props[0] = byte((p.pb*5+p.lp)*9 + p.lc)
	if dictSize >= uint32(1)<<21 {
		const kDictMask = (uint32(1) << 20) - 1
		v = (dictSize + kDictMask) &^ kDictMask
		if v < dictSize {
			v = dictSize
		}
	} else {
		i := uint32(11 * 2)
		for {
			v = (2 + (i & 1)) << (i >> 1)
			i++
			if v >= dictSize {
				break
			}
		}
	}
	props[1] = byte(v)
	props[2] = byte(v >> 8)
	props[3] = byte(v >> 16)
	props[4] = byte(v >> 24)
	return props
}

// IsWriteEndMark is LzmaEnc_IsWriteEndMark.
func (p *Encoder) IsWriteEndMark() bool { return p.writeEndMark }

// MemEncode is LzmaEnc_MemEncode: encodes src into dest (direct-input
// mode) and returns the number of bytes written. ErrOutputEOF means dest
// was too small.
func (p *Encoder) MemEncode(dest, src []byte, writeEndMark bool) (int, error) {
	out := seqOutStreamBuf{data: dest}
	p.writeEndMark = writeEndMark
	p.rc.out = &out
	res := p.memPrepare(src, 0)
	if res == nil {
		res = p.encode2()
		if res == nil && p.nowPos64 != uint64(len(src)) {
			res = ErrFail
		}
	}
	if out.overflow {
		return out.pos, ErrOutputEOF
	}
	return out.pos, res
}

// EncodeBytes is the LzmaEncode one-call interface with a growing output:
// it returns the packed stream and the 5 encoded property bytes.
func EncodeBytes(src []byte, props *EncProps, writeEndMark bool) (packed []byte, propsEncoded [lzmaPropsSize]byte, err error) {
	p := NewEncoder()
	if err = p.SetProps(props); err != nil {
		return nil, propsEncoded, err
	}
	propsEncoded = p.WriteProperties()
	var out growBuf
	p.writeEndMark = writeEndMark
	p.rc.out = &out
	if err = p.memPrepare(src, 0); err != nil {
		return nil, propsEncoded, err
	}
	if err = p.encode2(); err != nil {
		return nil, propsEncoded, err
	}
	if p.nowPos64 != uint64(len(src)) {
		return nil, propsEncoded, ErrFail
	}
	return out.b, propsEncoded, nil
}

type growBuf struct{ b []byte }

func (g *growBuf) Write(p []byte) (int, error) {
	g.b = append(g.b, p...)
	return len(p), nil
}
