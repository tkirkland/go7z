package ppmd

import "errors"

// dec.go is the port of C/Ppmd7Dec.c: the 7z range decoder
// (Ppmd7z_RangeDec) and Ppmd7z_DecodeSymbol, plus the decode loop of
// 7zDec.c's SzDecodePpmd.

// ErrData is the decoder's data error.
var ErrData = errors.New("ppmd: data error")

const (
	symEnd   = -1
	symError = -2
)

// byteIn is CByteInToLook: reads 0 past the end and remembers it.
type byteIn struct {
	b     []byte
	pos   int
	extra bool
}

func (r *byteIn) read() byte {
	if r.pos >= len(r.b) {
		r.extra = true
		return 0
	}
	c := r.b[r.pos]
	r.pos++
	return c
}

// rangeDec is CPpmd7_RangeDec.
type rangeDec struct {
	rng  uint32
	code uint32
	in   byteIn
}

// init is Ppmd7z_RangeDec_Init.
func (r *rangeDec) init() bool {
	r.code = 0
	r.rng = 0xFFFFFFFF
	if r.in.read() != 0 {
		return false
	}
	for i := 0; i < 4; i++ {
		r.code = r.code<<8 | uint32(r.in.read())
	}
	return r.code < 0xFFFFFFFF
}

func (r *rangeDec) norm1() {
	if r.rng < kTopValue {
		r.code = r.code<<8 | uint32(r.in.read())
		r.rng <<= 8
	}
}

func (r *rangeDec) norm() {
	if r.rng < kTopValue {
		r.code = r.code<<8 | uint32(r.in.read())
		r.rng <<= 8
		if r.rng < kTopValue {
			r.code = r.code<<8 | uint32(r.in.read())
			r.rng <<= 8
		}
	}
}

// decode is Ppmd7z_RD_Decode.
func (r *rangeDec) decode(start, size uint32) {
	r.code -= start * r.rng
	r.rng *= size
}

// getThreshold is RC_GetThreshold.
func (r *rangeDec) getThreshold(total uint32) uint32 {
	r.rng /= total
	return r.code / r.rng
}

// Decoder decodes a PPMd7z stream.
type Decoder struct {
	p  *Model
	rc rangeDec
}

// NewDecoder returns a decoder with the model allocated for memSize and
// initialised for order.
func NewDecoder(order uint32, memSize uint32) (*Decoder, error) {
	if order < MinOrder || order > MaxOrder || memSize < MinMemSize || memSize > MaxMemSize {
		return nil, errors.New("ppmd: order or memory out of range")
	}
	d := &Decoder{p: NewModel()}
	d.p.Alloc(memSize)
	d.p.Init(order)
	return d, nil
}

// DecodeBytes is SzDecodePpmd's loop: decodes exactly outSize bytes from
// in and requires the range coder to finish cleanly (Code == 0) with the
// whole input consumed.
func DecodeBytes(in []byte, order uint32, memSize uint32, outSize int) ([]byte, error) {
	d, err := NewDecoder(order, memSize)
	if err != nil {
		return nil, err
	}
	d.rc.in = byteIn{b: in}
	if !d.rc.init() || d.rc.in.extra {
		return nil, ErrData
	}
	out := make([]byte, outSize)
	for i := 0; i < outSize; i++ {
		sym := d.decodeSymbol()
		if d.rc.in.extra || sym < 0 {
			return nil, ErrData
		}
		out[i] = byte(sym)
	}
	if d.rc.code != 0 || d.rc.in.extra || d.rc.in.pos != len(in) {
		return nil, ErrData
	}
	return out, nil
}

// decodeSymbol is Ppmd7z_DecodeSymbol.
func (d *Decoder) decodeSymbol() int {
	p := d.p
	r := &d.rc
	var charMask [256]byte
	if p.numStats(p.minContext) != 1 {
		s := p.stats(p.minContext)
		summFreq := p.summFreq(p.minContext)
		count := r.getThreshold(summFreq)
		hiCnt := count
		count -= p.stFreq(s)
		if int32(count) < 0 {
			r.decode(0, p.stFreq(s))
			r.norm()
			p.foundState = s
			sym := p.stSymbol(s)
			p.update1_0()
			return int(sym)
		}
		p.prevSuccess = 0
		i := p.numStats(p.minContext) - 1
		for {
			s += 6
			count -= p.stFreq(s)
			if int32(count) < 0 {
				r.decode((hiCnt-count)-p.stFreq(s), p.stFreq(s))
				r.norm()
				p.foundState = s
				sym := p.stSymbol(s)
				p.update1()
				return int(sym)
			}
			i--
			if i == 0 {
				break
			}
		}
		if hiCnt >= summFreq {
			return symError
		}
		hiCnt -= count
		r.decode(hiCnt, summFreq-hiCnt)
		p.hiBitsFlag = hiBitsFlag3(p.stSymbol(p.foundState))
		for i := range charMask {
			charMask[i] = 0xFF
		}
		s2 := p.stats(p.minContext)
		charMask[p.stSymbol(s)] = 0
		for {
			sym0 := p.stSymbol(s2)
			sym1 := p.stSymbol(s2 + 6)
			s2 += 12
			charMask[sym0] = 0
			charMask[sym1] = 0
			if s2 >= s {
				break
			}
		}
	} else {
		s := oneState(p.minContext)
		prob := p.binSummIndex()
		pr := uint32(*prob)
		size0 := (r.rng >> 14) * pr
		pr = pr - ((pr + (1 << (periodBits - 2))) >> periodBits)
		if r.code < size0 {
			*prob = uint16(pr + (1 << intBits))
			r.rng = size0
			r.norm1()
			freq := p.stFreq(s)
			c := p.successor(s)
			sym := p.stSymbol(s)
			p.foundState = s
			p.prevSuccess = 1
			p.runLength++
			if freq < 128 {
				freq++
			}
			p.setStFreq(s, freq)
			if p.orderFall == 0 && c > p.text {
				p.maxContext = c
				p.minContext = c
			} else {
				p.updateModel()
			}
			return int(sym)
		}
		*prob = uint16(pr)
		p.initEsc = uint32(p.expEscape[pr>>10])
		r.code -= size0
		r.rng -= size0
		for i := range charMask {
			charMask[i] = 0xFF
		}
		charMask[p.stSymbol(s)] = 0
		p.prevSuccess = 0
	}
	for {
		r.norm()
		mc := p.minContext
		numMasked := p.numStats(mc)
		for {
			p.orderFall++
			if p.suffix(mc) == 0 {
				return symEnd
			}
			mc = p.suffix(mc)
			if p.numStats(mc) != numMasked {
				break
			}
		}
		s := p.stats(mc)
		var hiCnt uint32
		{
			num := p.numStats(mc)
			num2 := num / 2
			num &= 1
			hiCnt = (p.stFreq(s) & uint32(charMask[p.stSymbol(s)])) & (0 - num)
			s += num * 6
			p.minContext = mc
			for {
				sym0 := p.stSymbol(s)
				sym1 := p.stSymbol(s + 6)
				s += 12
				hiCnt += p.stFreq(s-12) & uint32(charMask[sym0])
				hiCnt += p.stFreq(s-6) & uint32(charMask[sym1])
				num2--
				if num2 == 0 {
					break
				}
			}
		}
		sp, freqSum := p.makeEscFreq(numMasked)
		freqSum += hiCnt
		count := r.getThreshold(freqSum)
		if count < hiCnt {
			s = p.stats(p.minContext)
			hiCnt = count
			for {
				count -= p.stFreq(s) & uint32(charMask[p.stSymbol(s)])
				s += 6
				if int32(count) < 0 {
					break
				}
			}
			s -= 6
			r.decode((hiCnt-count)-p.stFreq(s), p.stFreq(s))
			r.norm()
			sp.update()
			p.foundState = s
			sym := p.stSymbol(s)
			p.update2()
			return int(sym)
		}
		if count >= freqSum {
			return symError
		}
		r.decode(hiCnt, freqSum-hiCnt)
		sp.summ = uint16(uint32(sp.summ) + freqSum)
		s = p.stats(p.minContext)
		s2 := s + p.numStats(p.minContext)*6
		for {
			charMask[p.stSymbol(s)] = 0
			s += 6
			if s == s2 {
				break
			}
		}
	}
}
