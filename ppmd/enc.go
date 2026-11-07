package ppmd

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
)

// enc.go is the port of C/Ppmd7Enc.c: the 7z range encoder
// (Ppmd7z_RangeEnc) and Ppmd7z_EncodeSymbol.

const kTopValue = uint32(1) << 24

// rangeEnc is CPpmd7z_RangeEnc.
type rangeEnc struct {
	rng       uint32
	cache     byte
	low       uint64
	cacheSize uint64
	w         *bufio.Writer
	err       error
}

// init is Ppmd7z_Init_RangeEnc.
func (r *rangeEnc) init() {
	r.low = 0
	r.rng = 0xFFFFFFFF
	r.cache = 0
	r.cacheSize = 1
}

func (r *rangeEnc) writeByte(b byte) {
	if r.err == nil {
		r.err = r.w.WriteByte(b)
	}
}

// shiftLow is Ppmd7z_RangeEnc_ShiftLow.
func (r *rangeEnc) shiftLow() {
	if uint32(r.low) < 0xFF000000 || uint32(r.low>>32) != 0 {
		temp := r.cache
		for {
			r.writeByte(temp + byte(r.low>>32))
			temp = 0xFF
			r.cacheSize--
			if r.cacheSize == 0 {
				break
			}
		}
		r.cache = byte(uint32(r.low) >> 24)
	}
	r.cacheSize++
	r.low = uint64(uint32(r.low) << 8)
}

// norm1 is RC_NORM_1; norm is RC_NORM (two steps).
func (r *rangeEnc) norm1() {
	if r.rng < kTopValue {
		r.rng <<= 8
		r.shiftLow()
	}
}

func (r *rangeEnc) norm() {
	if r.rng < kTopValue {
		r.rng <<= 8
		r.shiftLow()
		if r.rng < kTopValue {
			r.rng <<= 8
			r.shiftLow()
		}
	}
}

// encode is Ppmd7z_RangeEnc_Encode (RC_NORM_LOCAL is empty).
func (r *rangeEnc) encode(start, size uint32) {
	r.low += uint64(start * r.rng)
	r.rng *= size
}

// flush is Ppmd7z_Flush_RangeEnc.
func (r *rangeEnc) flush() {
	for i := 0; i < 5; i++ {
		r.shiftLow()
	}
}

// Encoder encodes a stream with the PPMd7z method.
type Encoder struct {
	p  *Model
	rc rangeEnc
}

// NewEncoder returns an encoder with the model allocated for memSize
// bytes and initialised for order (Ppmd7_Alloc, Ppmd7_Init,
// Ppmd7z_Init_RangeEnc).
func NewEncoder(order uint32, memSize uint32) (*Encoder, error) {
	if order < MinOrder || order > MaxOrder || memSize < MinMemSize || memSize > MaxMemSize {
		return nil, fmt.Errorf("ppmd: order %d or memory %d out of range", order, memSize)
	}
	e := &Encoder{p: NewModel()}
	e.p.Alloc(memSize)
	e.p.Init(order)
	return e, nil
}

// Encode encodes all of r into w and flushes the range coder.
func (e *Encoder) Encode(w io.Writer, r io.Reader) error {
	bw := bufio.NewWriterSize(w, 1<<16)
	e.rc.w = bw
	e.rc.err = nil
	e.rc.init()
	buf := make([]byte, 1<<16)
	for {
		n, err := r.Read(buf)
		for _, b := range buf[:n] {
			e.encodeSymbol(int(b))
		}
		if e.rc.err != nil {
			return e.rc.err
		}
		if err == io.EOF {
			break
		}
		if err != nil {
			return err
		}
	}
	e.rc.flush()
	if e.rc.err != nil {
		return e.rc.err
	}
	return bw.Flush()
}

// EncodeBytes encodes data with a fresh encoder.
func EncodeBytes(data []byte, order uint32, memSize uint32) ([]byte, error) {
	e, err := NewEncoder(order, memSize)
	if err != nil {
		return nil, err
	}
	var out bytes.Buffer
	if err := e.Encode(&out, bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return out.Bytes(), nil
}

// encodeSymbol is Ppmd7z_EncodeSymbol.
func (e *Encoder) encodeSymbol(symbol int) {
	p := e.p
	r := &e.rc
	var charMask [256]byte
	if p.numStats(p.minContext) != 1 {
		s := p.stats(p.minContext)
		r.rng /= p.summFreq(p.minContext)
		if int(p.stSymbol(s)) == symbol {
			r.encode(0, p.stFreq(s))
			r.norm()
			p.foundState = s
			p.update1_0()
			return
		}
		p.prevSuccess = 0
		sum := p.stFreq(s)
		i := p.numStats(p.minContext) - 1
		for {
			s += 6
			if int(p.stSymbol(s)) == symbol {
				r.encode(sum, p.stFreq(s))
				r.norm()
				p.foundState = s
				p.update1()
				return
			}
			sum += p.stFreq(s)
			i--
			if i == 0 {
				break
			}
		}
		r.encode(sum, p.summFreq(p.minContext)-sum)
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
		prob := p.binSummIndex()
		s := oneState(p.minContext)
		pr := uint32(*prob)
		bound := (r.rng >> 14) * pr
		pr = pr - ((pr + (1 << (periodBits - 2))) >> periodBits) // PPMD_UPDATE_PROB_1
		if int(p.stSymbol(s)) == symbol {
			*prob = uint16(pr + (1 << intBits))
			r.rng = bound
			r.norm1()
			freq := p.stFreq(s)
			c := p.successor(s)
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
			return
		}
		*prob = uint16(pr)
		p.initEsc = uint32(p.expEscape[pr>>10])
		r.low += uint64(bound)
		r.rng -= bound
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
		var i uint32
		for {
			p.orderFall++
			if p.suffix(mc) == 0 {
				return // end marker (symbol -1)
			}
			mc = p.suffix(mc)
			i = p.numStats(mc)
			if i != numMasked {
				break
			}
		}
		p.minContext = mc
		var sp *see
		var escFreq uint32
		if i != 256 {
			nonMasked := i - numMasked
			idx := p.hiBitsFlag
			if nonMasked < p.numStats(p.suffix(mc))-i {
				idx++
			}
			if p.summFreq(mc) < 11*i {
				idx += 2
			}
			if numMasked > nonMasked {
				idx += 4
			}
			sp = &p.see[p.ns2Indx[nonMasked-1]][idx]
			summ := uint32(sp.summ)
			rr := summ >> sp.shift
			sp.summ = uint16(summ - rr)
			escFreq = rr
			if rr == 0 {
				escFreq = 1
			}
		} else {
			sp = &p.dummySee
			escFreq = 1
		}
		s := p.stats(mc)
		var sum uint32
		for {
			cur := p.stSymbol(s)
			if int(cur) == symbol {
				low := sum
				freq := p.stFreq(s)
				sp.update()
				p.foundState = s
				sum += escFreq
				num2 := i / 2
				i &= 1
				if i != 0 {
					sum += freq
				}
				if num2 != 0 {
					s += i * 6
					for {
						sym0 := p.stSymbol(s)
						sym1 := p.stSymbol(s + 6)
						s += 12
						sum += p.stFreq(s-12) & uint32(charMask[sym0])
						sum += p.stFreq(s-6) & uint32(charMask[sym1])
						num2--
						if num2 == 0 {
							break
						}
					}
				}
				r.rng /= sum
				r.encode(low, freq)
				r.norm()
				p.update2()
				return
			}
			sum += p.stFreq(s) & uint32(charMask[cur])
			s += 6
			i--
			if i == 0 {
				break
			}
		}
		total := sum + escFreq
		sp.summ = uint16(uint32(sp.summ) + total)
		r.rng /= total
		r.encode(sum, escFreq)
		s2 := p.stats(p.minContext)
		s -= 6
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
	}
}
