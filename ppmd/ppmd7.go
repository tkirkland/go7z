// Package ppmd is the port of 7-Zip's public-domain PPMd var.H codec
// (C/Ppmd.h, C/Ppmd7.h, C/Ppmd7.c, C/Ppmd7Enc.c, C/Ppmd7Dec.c; Igor
// Pavlov, based on Dmitry Shkarin's PPMd var.H), the PPMD method of the
// 7z format (id 030401) with the 7z range coder (Ppmd7z_*).
//
// The C code keeps the model in one byte arena and addresses records by
// 32-bit offsets from its base (the non-PPMD_32BIT layout); every struct
// field is read and written here at the same byte offsets, little-endian,
// so the aliasing the C relies on (a one-symbol context stores its state
// over the SummFreq and Stats fields; a free unit stores its list link
// over the first four bytes) works the same way.
package ppmd

import "encoding/binary"

const (
	intBits    = 7
	periodBits = 7
	binScale   = 1 << (intBits + periodBits)

	numN1      = 4
	numN2      = 4
	numN3      = 4
	numN4      = (128 + 3 - 1*numN1 - 2*numN2 - 3*numN3) / 4
	numIndexes = numN1 + numN2 + numN3 + numN4

	maxFreq  = 124
	unitSize = 12

	// MinOrder, MaxOrder, MinMemSize and MaxMemSize are PPMD7_MIN_ORDER,
	// PPMD7_MAX_ORDER, PPMD7_MIN_MEM_SIZE and PPMD7_MAX_MEM_SIZE.
	MinOrder   = 2
	MaxOrder   = 64
	MinMemSize = 1 << 11
	MaxMemSize = 0xFFFFFFFF - 12*3
)

var kExpEscape = [16]byte{25, 14, 9, 7, 5, 5, 4, 4, 4, 3, 3, 3, 2, 2, 2, 2}
var kInitBinEsc = [8]uint16{0x3CDD, 0x1F3F, 0x59BF, 0x48F3, 0x64A1, 0x5ABC, 0x6632, 0x6051}

// see is CPpmd_See.
type see struct {
	summ  uint16
	shift byte
	count byte
}

// update is Ppmd_See_UPDATE.
func (s *see) update() {
	if s.shift < periodBits {
		s.count--
		if s.count == 0 {
			s.summ <<= 1
			s.count = byte(3 << s.shift)
			s.shift++
		}
	}
}

// Model is CPpmd7: the context model shared by the encoder and the
// decoder. Offsets (uint32) into base stand for the C pointers and refs.
type Model struct {
	minContext, maxContext uint32 // CPpmd7_Context offsets
	foundState             uint32 // CPpmd_State offset
	orderFall, initEsc     uint32
	prevSuccess, maxOrder  uint32
	hiBitsFlag             uint32
	runLength, initRL      int32
	size                   uint32
	glueCount              uint32
	alignOffset            uint32
	base                   []byte
	loUnit, hiUnit         uint32
	text, unitsStart       uint32

	indx2Units [numIndexes + 2]byte
	units2Indx [128]byte
	freeList   [numIndexes]uint32
	ns2BSIndx  [256]byte
	ns2Indx    [256]byte
	expEscape  [16]byte
	dummySee   see
	see        [25][16]see
	binSumm    [128][64]uint16
}

// Record field access. A state is 6 bytes: Symbol, Freq, Successor
// (UInt32 as two little-endian halves, so one little-endian UInt32). A
// context is 12 bytes: NumStats (UInt16), SummFreq (UInt16), Stats
// (UInt32), Suffix (UInt32); its one-state record overlaps bytes 2..7.
// A free-list node is 12 bytes: Stamp (UInt16), NU (UInt16), Next
// (UInt32), Prev (UInt32).

func (p *Model) u16(o uint32) uint32       { return uint32(binary.LittleEndian.Uint16(p.base[o:])) }
func (p *Model) setU16(o uint32, v uint32) { binary.LittleEndian.PutUint16(p.base[o:], uint16(v)) }
func (p *Model) u32(o uint32) uint32       { return binary.LittleEndian.Uint32(p.base[o:]) }
func (p *Model) setU32(o uint32, v uint32) { binary.LittleEndian.PutUint32(p.base[o:], v) }

func (p *Model) stSymbol(s uint32) uint32        { return uint32(p.base[s]) }
func (p *Model) stFreq(s uint32) uint32          { return uint32(p.base[s+1]) }
func (p *Model) setStFreq(s uint32, v uint32)    { p.base[s+1] = byte(v) }
func (p *Model) successor(s uint32) uint32       { return p.u32(s + 2) }
func (p *Model) setSuccessor(s uint32, v uint32) { p.setU32(s+2, v) }

func (p *Model) numStats(c uint32) uint32       { return p.u16(c) }
func (p *Model) setNumStats(c uint32, v uint32) { p.setU16(c, v) }
func (p *Model) summFreq(c uint32) uint32       { return p.u16(c + 2) }
func (p *Model) setSummFreq(c uint32, v uint32) { p.setU16(c+2, v) }
func (p *Model) stats(c uint32) uint32          { return p.u32(c + 4) }
func (p *Model) setStats(c uint32, v uint32)    { p.setU32(c+4, v) }
func (p *Model) suffix(c uint32) uint32         { return p.u32(c + 8) }
func (p *Model) setSuffix(c uint32, v uint32)   { p.setU32(c+8, v) }
func oneState(c uint32) uint32                  { return c + 2 }

func (p *Model) nodeStamp(n uint32) uint32       { return p.u16(n) }
func (p *Model) setNodeStamp(n uint32, v uint32) { p.setU16(n, v) }
func (p *Model) nodeNU(n uint32) uint32          { return p.u16(n + 2) }
func (p *Model) setNodeNU(n uint32, v uint32)    { p.setU16(n+2, v) }
func (p *Model) nodeNext(n uint32) uint32        { return p.u32(n + 4) }
func (p *Model) setNodeNext(n uint32, v uint32)  { p.setU32(n+4, v) }

// copyState copies one 6-byte state record.
func (p *Model) copyState(dst, src uint32) { copy(p.base[dst:dst+6], p.base[src:src+6]) }

// swapStates is SWAP_STATES(s): exchanges s[0] and s[-1].
func (p *Model) swapStates(s uint32) {
	var tmp [6]byte
	copy(tmp[:], p.base[s:s+6])
	copy(p.base[s:s+6], p.base[s-6:s])
	copy(p.base[s-6:s], tmp[:])
}

func u2b(nu uint32) uint32 { return nu * unitSize }

func (p *Model) u2i(nu uint32) uint32   { return uint32(p.units2Indx[nu-1]) }
func (p *Model) i2u(indx uint32) uint32 { return uint32(p.indx2Units[indx]) }

// NewModel is Ppmd7_Construct.
func NewModel() *Model {
	p := &Model{}
	k := 0
	for i := 0; i < numIndexes; i++ {
		step := 4
		if i < 12 {
			step = (i >> 2) + 1
		}
		for ; step > 0; step-- {
			p.units2Indx[k] = byte(i)
			k++
		}
		p.indx2Units[i] = byte(k)
	}
	p.ns2BSIndx[0] = 0 << 1
	p.ns2BSIndx[1] = 1 << 1
	for i := 2; i < 11; i++ {
		p.ns2BSIndx[i] = 2 << 1
	}
	for i := 11; i < 256; i++ {
		p.ns2BSIndx[i] = 3 << 1
	}
	i := 0
	for ; i < 3; i++ {
		p.ns2Indx[i] = byte(i)
	}
	m, kk := i, 1
	for ; i < 256; i++ {
		p.ns2Indx[i] = byte(m)
		kk--
		if kk == 0 {
			m++
			kk = m - 2
		}
	}
	p.expEscape = kExpEscape
	return p
}

// Alloc is Ppmd7_Alloc: sets the arena to size bytes.
func (p *Model) Alloc(size uint32) {
	if p.base == nil || p.size != size {
		p.alignOffset = (4 - size) & 3
		p.base = make([]byte, uint64(p.alignOffset)+uint64(size))
		p.size = size
	}
}

// insertNode is Ppmd7_InsertNode.
func (p *Model) insertNode(node uint32, indx uint32) {
	p.setU32(node, p.freeList[indx])
	p.freeList[indx] = node
}

// removeNode is Ppmd7_RemoveNode.
func (p *Model) removeNode(indx uint32) uint32 {
	node := p.freeList[indx]
	p.freeList[indx] = p.u32(node)
	return node
}

// splitBlock is Ppmd7_SplitBlock.
func (p *Model) splitBlock(ptr uint32, oldIndx, newIndx uint32) {
	nu := p.i2u(oldIndx) - p.i2u(newIndx)
	ptr += u2b(p.i2u(newIndx))
	i := p.u2i(nu)
	if p.i2u(i) != nu {
		i--
		k := p.i2u(i)
		p.insertNode(ptr+u2b(k), nu-k-1)
	}
	p.insertNode(ptr, i)
}

// glueFreeBlocks is Ppmd7_GlueFreeBlocks.
func (p *Model) glueFreeBlocks() {
	var head, n uint32
	p.glueCount = 255
	// Guard node at LoUnit.
	if p.loUnit != p.hiUnit {
		p.setNodeStamp(p.loUnit, 1)
	}
	// Build the list of free blocks.
	for i := uint32(0); i < numIndexes; i++ {
		nu := p.i2u(i)
		next := p.freeList[i]
		p.freeList[i] = 0
		for next != 0 {
			un := next
			tmp := next
			next = p.u32(un) // NextRef
			p.setNodeStamp(un, 0)
			p.setNodeNU(un, nu)
			p.setNodeNext(un, n)
			n = tmp
		}
	}
	head = n
	// Glue.
	{
		prevIsHead := true
		var prev uint32 // node whose Next is the link, when !prevIsHead
		for n != 0 {
			node := n
			nu := p.nodeNU(node)
			n = p.nodeNext(node)
			if nu == 0 {
				if prevIsHead {
					head = n
				} else {
					p.setNodeNext(prev, n)
				}
				continue
			}
			prevIsHead = false
			prev = node
			for {
				node2 := node + nu*unitSize
				nu += p.nodeNU(node2)
				if p.nodeStamp(node2) != 0 || nu >= 0x10000 {
					break
				}
				p.setNodeNU(node, nu)
				p.setNodeNU(node2, 0)
			}
		}
	}
	// Fill the free lists.
	for n = head; n != 0; {
		node := n
		nu := p.nodeNU(node)
		n = p.nodeNext(node)
		if nu == 0 {
			continue
		}
		for ; nu > 128; nu, node = nu-128, node+128*unitSize {
			p.insertNode(node, numIndexes-1)
		}
		i := p.u2i(nu)
		if p.i2u(i) != nu {
			i--
			k := p.i2u(i)
			p.insertNode(node+k*unitSize, nu-k-1)
		}
		p.insertNode(node, i)
	}
}

// allocUnitsRare is Ppmd7_AllocUnitsRare; 0 means no memory.
func (p *Model) allocUnitsRare(indx uint32) uint32 {
	if p.glueCount == 0 {
		p.glueFreeBlocks()
		if p.freeList[indx] != 0 {
			return p.removeNode(indx)
		}
	}
	i := indx
	for {
		i++
		if i == numIndexes {
			numBytes := u2b(p.i2u(indx))
			us := p.unitsStart
			p.glueCount--
			if us-p.text > numBytes {
				p.unitsStart = us - numBytes
				return p.unitsStart
			}
			return 0
		}
		if p.freeList[i] != 0 {
			break
		}
	}
	block := p.removeNode(i)
	p.splitBlock(block, i, indx)
	return block
}

// allocUnits is Ppmd7_AllocUnits; 0 means no memory.
func (p *Model) allocUnits(indx uint32) uint32 {
	if p.freeList[indx] != 0 {
		return p.removeNode(indx)
	}
	numBytes := u2b(p.i2u(indx))
	lo := p.loUnit
	if p.hiUnit-lo >= numBytes {
		p.loUnit = lo + numBytes
		return lo
	}
	return p.allocUnitsRare(indx)
}

// mem12Cpy is MEM_12_CPY: copies num units.
func (p *Model) mem12Cpy(dst, src uint32, num uint32) {
	copy(p.base[dst:dst+num*unitSize], p.base[src:src+num*unitSize])
}

// restartModel is Ppmd7_RestartModel.
func (p *Model) restartModel() {
	for i := range p.freeList {
		p.freeList[i] = 0
	}
	p.text = p.alignOffset
	p.hiUnit = p.text + p.size
	p.loUnit = p.hiUnit - p.size/8/unitSize*7*unitSize
	p.unitsStart = p.loUnit
	p.glueCount = 0

	p.orderFall = p.maxOrder
	rl := p.maxOrder
	if rl > 12 {
		rl = 12
	}
	p.initRL = -int32(rl) - 1
	p.runLength = p.initRL
	p.prevSuccess = 0

	p.hiUnit -= unitSize
	mc := p.hiUnit
	s := p.loUnit
	p.loUnit += u2b(256 / 2)
	p.maxContext = mc
	p.minContext = mc
	p.foundState = s
	p.setNumStats(mc, 256)
	p.setSummFreq(mc, 256+1)
	p.setStats(mc, s)
	p.setSuffix(mc, 0)
	for i := uint32(0); i < 256; i++ {
		p.base[s] = byte(i)
		p.base[s+1] = 1
		p.setSuccessor(s, 0)
		s += 6
	}

	for i := 0; i < 128; i++ {
		for k := 0; k < 8; k++ {
			val := uint16(binScale - uint32(kInitBinEsc[k])/uint32(i+2))
			for m := 0; m < 64; m += 8 {
				p.binSumm[i][k+m] = val
			}
		}
	}
	for i := 0; i < 25; i++ {
		summ := uint16((5*i + 10) << (periodBits - 4))
		for k := 0; k < 16; k++ {
			p.see[i][k] = see{summ: summ, shift: periodBits - 4, count: 4}
		}
	}
	p.dummySee = see{summ: 0, shift: periodBits, count: 64}
}

// Init is Ppmd7_Init.
func (p *Model) Init(maxOrder uint32) {
	p.maxOrder = maxOrder
	p.restartModel()
}

// createSuccessors is Ppmd7_CreateSuccessors; 0 means no memory.
func (p *Model) createSuccessors() uint32 {
	c := p.minContext
	upBranch := p.successor(p.foundState)
	var ps [MaxOrder]uint32
	numPs := 0
	if p.orderFall != 0 {
		ps[numPs] = p.foundState
		numPs++
	}
	for p.suffix(c) != 0 {
		c = p.suffix(c)
		var s uint32
		if p.numStats(c) != 1 {
			sym := p.stSymbol(p.foundState)
			for s = p.stats(c); p.stSymbol(s) != sym; s += 6 {
			}
		} else {
			s = oneState(c)
		}
		successor := p.successor(s)
		if successor != upBranch {
			c = successor
			if numPs == 0 {
				return c
			}
			break
		}
		ps[numPs] = s
		numPs++
	}
	newSym := uint32(p.base[upBranch])
	upBranch++
	var newFreq uint32
	if p.numStats(c) == 1 {
		newFreq = p.stFreq(oneState(c))
	} else {
		var s uint32
		for s = p.stats(c); p.stSymbol(s) != newSym; s += 6 {
		}
		cf := p.stFreq(s) - 1
		s0 := p.summFreq(c) - p.numStats(c) - cf
		if 2*cf <= s0 {
			newFreq = 1
			if 5*cf > s0 {
				newFreq = 2
			}
		} else {
			newFreq = 1 + (2*cf+s0-1)/(2*s0) + 1
		}
	}
	for {
		var c1 uint32
		if p.hiUnit != p.loUnit {
			p.hiUnit -= unitSize
			c1 = p.hiUnit
		} else if p.freeList[0] != 0 {
			c1 = p.removeNode(0)
		} else {
			c1 = p.allocUnitsRare(0)
			if c1 == 0 {
				return 0
			}
		}
		p.setNumStats(c1, 1)
		p.base[oneState(c1)] = byte(newSym)
		p.base[oneState(c1)+1] = byte(newFreq)
		p.setSuccessor(oneState(c1), upBranch)
		p.setSuffix(c1, c)
		numPs--
		p.setSuccessor(ps[numPs], c1)
		c = c1
		if numPs == 0 {
			break
		}
	}
	return c
}

// updateModel is Ppmd7_UpdateModel.
func (p *Model) updateModel() {
	var maxSuccessor, minSuccessor uint32
	if p.stFreq(p.foundState) < maxFreq/4 && p.suffix(p.minContext) != 0 {
		c := p.suffix(p.minContext)
		if p.numStats(c) == 1 {
			s := oneState(c)
			if p.stFreq(s) < 32 {
				p.setStFreq(s, p.stFreq(s)+1)
			}
		} else {
			s := p.stats(c)
			sym := p.stSymbol(p.foundState)
			if p.stSymbol(s) != sym {
				for {
					s += 6
					if p.stSymbol(s) == sym {
						break
					}
				}
				if p.stFreq(s) >= p.stFreq(s-6) {
					p.swapStates(s)
					s -= 6
				}
			}
			if p.stFreq(s) < maxFreq-9 {
				p.setStFreq(s, p.stFreq(s)+2)
				p.setSummFreq(c, p.summFreq(c)+2)
			}
		}
	}

	if p.orderFall == 0 {
		p.minContext = p.createSuccessors()
		p.maxContext = p.minContext
		if p.minContext == 0 {
			p.restartModel()
			return
		}
		p.setSuccessor(p.foundState, p.minContext)
		return
	}

	{
		text := p.text
		p.base[text] = byte(p.stSymbol(p.foundState))
		text++
		p.text = text
		if text >= p.unitsStart {
			p.restartModel()
			return
		}
		maxSuccessor = text
	}

	minSuccessor = p.successor(p.foundState)
	if minSuccessor != 0 {
		if minSuccessor <= maxSuccessor {
			cs := p.createSuccessors()
			if cs == 0 {
				p.restartModel()
				return
			}
			minSuccessor = cs
		}
		p.orderFall--
		if p.orderFall == 0 {
			maxSuccessor = minSuccessor
			if p.maxContext != p.minContext {
				p.text--
			}
		}
	} else {
		p.setSuccessor(p.foundState, maxSuccessor)
		minSuccessor = p.minContext
	}

	mc := p.minContext
	c := p.maxContext
	p.minContext = minSuccessor
	p.maxContext = minSuccessor
	if c == mc {
		return
	}
	ns := p.numStats(mc)
	s0 := p.summFreq(mc) - ns - (p.stFreq(p.foundState) - 1)
	for {
		var sum uint32
		ns1 := p.numStats(c)
		if ns1 != 1 {
			if ns1&1 == 0 {
				oldNU := ns1 >> 1
				i := p.u2i(oldNU)
				if i != p.u2i(oldNU+1) {
					ptr := p.allocUnits(i + 1)
					if ptr == 0 {
						p.restartModel()
						return
					}
					oldPtr := p.stats(c)
					p.mem12Cpy(ptr, oldPtr, oldNU)
					p.insertNode(oldPtr, i)
					p.setStats(c, ptr)
				}
			}
			sum = p.summFreq(c)
			var inc uint32
			if 2*ns1 < ns {
				inc = 1
			}
			if 4*ns1 <= ns && sum <= 8*ns1 {
				inc += 2
			}
			sum += inc
		} else {
			s := p.allocUnits(0)
			if s == 0 {
				p.restartModel()
				return
			}
			freq := p.stFreq(oneState(c))
			p.base[s] = byte(p.stSymbol(oneState(c)))
			p.setSuccessor(s, p.successor(oneState(c)))
			p.setStats(c, s)
			if freq < maxFreq/4-1 {
				freq <<= 1
			} else {
				freq = maxFreq - 4
			}
			p.setStFreq(s, freq)
			sum = freq + p.initEsc
			if ns > 3 {
				sum++
			}
		}
		{
			s := p.stats(c) + ns1*6
			cf := 2 * (sum + 6) * p.stFreq(p.foundState)
			sf := s0 + sum
			p.base[s] = byte(p.stSymbol(p.foundState))
			p.setNumStats(c, ns1+1)
			p.setSuccessor(s, maxSuccessor)
			if cf < 6*sf {
				v := uint32(1)
				if cf > sf {
					v++
				}
				if cf >= 4*sf {
					v++
				}
				cf = v
				sum += 3
			} else {
				v := uint32(4)
				if cf >= 9*sf {
					v++
				}
				if cf >= 12*sf {
					v++
				}
				if cf >= 15*sf {
					v++
				}
				cf = v
				sum += cf
			}
			p.setSummFreq(c, sum)
			p.setStFreq(s, cf)
		}
		c = p.suffix(c)
		if c == mc {
			break
		}
	}
}

// rescale is Ppmd7_Rescale.
func (p *Model) rescale() {
	stats := p.stats(p.minContext)
	s := p.foundState
	if s != stats {
		var tmp [6]byte
		copy(tmp[:], p.base[s:s+6])
		for {
			p.copyState(s, s-6)
			s -= 6
			if s == stats {
				break
			}
		}
		copy(p.base[s:s+6], tmp[:])
	}
	sumFreq := p.stFreq(s)
	escFreq := p.summFreq(p.minContext) - sumFreq
	var adder uint32
	if p.orderFall != 0 {
		adder = 1
	}
	sumFreq = (sumFreq + 4 + adder) >> 1
	i := p.numStats(p.minContext) - 1
	p.setStFreq(s, sumFreq)
	for {
		s += 6
		freq := p.stFreq(s)
		escFreq -= freq
		freq = (freq + adder) >> 1
		sumFreq += freq
		p.setStFreq(s, freq)
		if freq > p.stFreq(s-6) {
			var tmp [6]byte
			copy(tmp[:], p.base[s:s+6])
			s1 := s
			for {
				p.copyState(s1, s1-6)
				s1 -= 6
				if s1 == stats || freq <= p.stFreq(s1-6) {
					break
				}
			}
			copy(p.base[s1:s1+6], tmp[:])
		}
		i--
		if i == 0 {
			break
		}
	}
	if p.stFreq(s) == 0 {
		i = 0
		for {
			i++
			s -= 6
			if p.stFreq(s) != 0 {
				break
			}
		}
		escFreq += i
		mc := p.minContext
		numStats := p.numStats(mc)
		numStatsNew := numStats - i
		p.setNumStats(mc, numStatsNew)
		n0 := (numStats + 1) >> 1
		if numStatsNew == 1 {
			freq := p.stFreq(stats)
			for {
				escFreq >>= 1
				freq = (freq + 1) >> 1
				if escFreq <= 1 {
					break
				}
			}
			s = oneState(mc)
			p.copyState(s, stats)
			p.setStFreq(s, freq)
			p.foundState = s
			p.insertNode(stats, p.u2i(n0))
			return
		}
		n1 := (numStatsNew + 1) >> 1
		if n0 != n1 {
			i0 := p.u2i(n0)
			i1 := p.u2i(n1)
			if i0 != i1 {
				if p.freeList[i1] != 0 {
					ptr := p.removeNode(i1)
					p.setStats(p.minContext, ptr)
					p.mem12Cpy(ptr, stats, n1)
					p.insertNode(stats, i0)
				} else {
					p.splitBlock(stats, i0, i1)
				}
			}
		}
	}
	mc := p.minContext
	p.setSummFreq(mc, sumFreq+escFreq-(escFreq>>1))
	p.foundState = p.stats(mc)
}

// makeEscFreq is Ppmd7_MakeEscFreq.
func (p *Model) makeEscFreq(numMasked uint32) (*see, uint32) {
	mc := p.minContext
	numStats := p.numStats(mc)
	if numStats != 256 {
		nonMasked := numStats - numMasked
		idx := uint32(0)
		if nonMasked < p.numStats(p.suffix(mc))-numStats {
			idx++
		}
		if p.summFreq(mc) < 11*numStats {
			idx += 2
		}
		if numMasked > nonMasked {
			idx += 4
		}
		idx += p.hiBitsFlag
		s := &p.see[p.ns2Indx[nonMasked-1]][idx]
		summ := uint32(s.summ)
		r := summ >> s.shift
		s.summ = uint16(summ - r)
		if r == 0 {
			r = 1
		}
		return s, r
	}
	return &p.dummySee, 1
}

// nextContext is Ppmd7_NextContext.
func (p *Model) nextContext() {
	c := p.successor(p.foundState)
	if p.orderFall == 0 && c > p.text {
		p.maxContext = c
		p.minContext = c
	} else {
		p.updateModel()
	}
}

// update1 is Ppmd7_Update1.
func (p *Model) update1() {
	s := p.foundState
	freq := p.stFreq(s) + 4
	p.setSummFreq(p.minContext, p.summFreq(p.minContext)+4)
	p.setStFreq(s, freq)
	if freq > p.stFreq(s-6) {
		p.swapStates(s)
		s -= 6
		p.foundState = s
		if freq > maxFreq {
			p.rescale()
		}
	}
	p.nextContext()
}

// update1_0 is Ppmd7_Update1_0.
func (p *Model) update1_0() {
	s := p.foundState
	mc := p.minContext
	freq := p.stFreq(s)
	summFreq := p.summFreq(mc)
	if 2*freq > summFreq {
		p.prevSuccess = 1
	} else {
		p.prevSuccess = 0
	}
	p.runLength += int32(p.prevSuccess)
	p.setSummFreq(mc, summFreq+4)
	freq += 4
	p.setStFreq(s, freq)
	if freq > maxFreq {
		p.rescale()
	}
	p.nextContext()
}

// update2 is Ppmd7_Update2.
func (p *Model) update2() {
	s := p.foundState
	freq := p.stFreq(s) + 4
	p.runLength = p.initRL
	p.setSummFreq(p.minContext, p.summFreq(p.minContext)+4)
	p.setStFreq(s, freq)
	if freq > maxFreq {
		p.rescale()
	}
	p.updateModel()
}

// hiBitsFlag3 and hiBitsFlag4 are PPMD7_HiBitsFlag_3 and _4.
func hiBitsFlag3(sym uint32) uint32 { return ((sym + 0xC0) >> (8 - 3)) & (1 << 3) }
func hiBitsFlag4(sym uint32) uint32 { return ((sym + 0xC0) >> (8 - 4)) & (1 << 4) }

// binSummIndex is Ppmd7_GetBinSumm: the BinSumm cell for the one-state
// MinContext (and sets HiBitsFlag from FoundState as the macro does).
func (p *Model) binSummIndex() *uint16 {
	os := oneState(p.minContext)
	p.hiBitsFlag = hiBitsFlag3(p.stSymbol(p.foundState))
	j := p.prevSuccess +
		(uint32(p.runLength>>26) & 0x20) +
		uint32(p.ns2BSIndx[p.numStats(p.suffix(p.minContext))-1]) +
		hiBitsFlag4(p.stSymbol(os)) +
		p.hiBitsFlag
	return &p.binSumm[p.stFreq(os)-1][j]
}
