package lzma

// Decoder is a faithful port of the LZMA decoder from LzmaDec.c (7-Zip
// 26.05, portable configuration). It implements the dictionary interface
// (Decode) and the one-call interface (DecodeOneShot).
type Decoder struct {
	prop         Props
	probs        []uint16
	dic          []byte
	dicBufSize   int
	dicPos       int
	r, code      uint32
	processedPos uint32
	checkDicSize uint32
	reps         [4]uint32
	state        uint32
	remainLen    uint32
	tempBuf      [lzmaRequiredInputMax]byte
	tempBufSize  int
}

// NewDecoder allocates a decoder for the given 5-byte LZMA properties
// (LzmaDec_Allocate + LzmaDec_Init).
func NewDecoder(props []byte) (*Decoder, error) {
	p, err := DecodeProps(props)
	if err != nil {
		return nil, err
	}
	d := &Decoder{
		prop:       p,
		probs:      make([]uint16, p.NumProbs()),
		dicBufSize: dicBufSizeFor(p.DicSize),
	}
	d.dic = make([]byte, d.dicBufSize)
	d.Init()
	return d, nil
}

func dicBufSizeFor(dicSize uint32) int {
	mask := uint32((1 << 12) - 1)
	switch {
	case dicSize >= 1<<30:
		mask = (1 << 22) - 1
	case dicSize >= 1<<22:
		mask = (1 << 20) - 1
	}
	sz := (uint64(dicSize) + uint64(mask)) &^ uint64(mask)
	if sz < uint64(dicSize) {
		sz = uint64(dicSize)
	}
	return int(sz)
}

// Init resets the decoder for a new stream (LzmaDec_Init).
func (d *Decoder) Init() {
	d.dicPos = 0
	d.processedPos = 0
	d.checkDicSize = 0
	d.remainLen = kMatchSpecLenStart + 2
	d.tempBufSize = 0
}

func (d *Decoder) initDicAndState(initDic, initState bool) {
	d.remainLen = kMatchSpecLenStart + 1
	d.tempBufSize = 0
	if initDic {
		d.processedPos = 0
		d.checkDicSize = 0
		d.remainLen = kMatchSpecLenStart + 2
	}
	if initState {
		d.remainLen = kMatchSpecLenStart + 2
	}
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

// writeRem copies p->remainLen bytes from rep0 (LzmaDec_WriteRem).
func (d *Decoder) writeRem(limit int) {
	length := int(d.remainLen)
	if length == 0 {
		return
	}
	rem := limit - d.dicPos
	if rem < length {
		length = rem
		if length == 0 {
			return
		}
	}
	if d.checkDicSize == 0 && uint32(d.prop.DicSize)-d.processedPos <= uint32(length) {
		d.checkDicSize = d.prop.DicSize
	}
	d.processedPos += uint32(length)
	d.remainLen -= uint32(length)
	dicPos := d.dicPos
	rep0 := int(d.reps[0])
	dicBufSize := d.dicBufSize
	for i := 0; i < length; i++ {
		idx := dicPos - rep0
		if dicPos < rep0 {
			idx += dicBufSize
		}
		d.dic[dicPos] = d.dic[idx]
		dicPos++
	}
	d.dicPos = dicPos
}

// updateWithUncompressed appends raw bytes to the dictionary
// (LzmaDec_UpdateWithUncompressed).
func (d *Decoder) updateWithUncompressed(src []byte) {
	copy(d.dic[d.dicPos:], src)
	d.dicPos += len(src)
	if d.checkDicSize == 0 && uint32(d.prop.DicSize)-d.processedPos <= uint32(len(src)) {
		d.checkDicSize = d.prop.DicSize
	}
	d.processedPos += uint32(len(src))
}

// rcIn is the input cursor of decodeReal. Its normalize reports ErrInternal
// if the caller's invariant (enough bytes behind bufLimit) is violated.
type rcIn struct {
	src []byte
	pos int
}

func (in *rcIn) normalize(r, c *uint32) error {
	if *r < kTopValue {
		if in.pos >= len(in.src) {
			return ErrInternal
		}
		*r <<= 8
		*c = *c<<8 | uint32(in.src[in.pos])
		in.pos++
	}
	return nil
}

// bit implements IF_BIT_0: normalize, read ttt, compute bound, compare.
func (in *rcIn) bit(r, c *uint32, prob *uint16) (bit, ttt, bound uint32, err error) {
	if err = in.normalize(r, c); err != nil {
		return 0, 0, 0, err
	}
	ttt = uint32(*prob)
	bound = (*r >> kNumBitModelTotalBits) * ttt
	if *c < bound {
		return 0, ttt, bound, nil
	}
	return 1, ttt, bound, nil
}

func update0(r, c *uint32, prob *uint16, ttt, bound uint32) {
	*r = bound
	*prob = uint16(ttt + ((kBitModelTotal - ttt) >> kNumMoveBits))
}

func update1(r, c *uint32, prob *uint16, ttt, bound uint32) {
	*r -= bound
	*c -= bound
	*prob = uint16(ttt - (ttt >> kNumMoveBits))
}

// lenDecode decodes a match length from the coder at baseIdx with the given
// posState (the non-size-opt path of decodeReal).
func lenDecode(r, c *uint32, baseIdx, posState int, probs []uint16, in *rcIn) (int, error) {
	length := 0
	probLen := baseIdx + lenChoice
	bit, ttt, bound, err := in.bit(r, c, &probs[probLen])
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		update0(r, c, &probs[probLen], ttt, bound)
		probLen = baseIdx + lenLow + posState
		length = 1
		for i := 0; i < kLenNumLowBits; i++ {
			idx := probLen + length
			b, t, bo, err := in.bit(r, c, &probs[idx])
			if err != nil {
				return 0, err
			}
			length += length
			if b == 0 {
				update0(r, c, &probs[idx], t, bo)
			} else {
				update1(r, c, &probs[idx], t, bo)
				length++
			}
		}
		length -= kLenNumLowSymbols
		return length, nil
	}
	update1(r, c, &probs[probLen], ttt, bound)
	probLen = baseIdx + lenChoice2
	bit, ttt, bound, err = in.bit(r, c, &probs[probLen])
	if err != nil {
		return 0, err
	}
	if bit == 0 {
		update0(r, c, &probs[probLen], ttt, bound)
		probLen = baseIdx + lenLow + kLenNumLowSymbols + posState
		length = 1
		for i := 0; i < kLenNumLowBits; i++ {
			idx := probLen + length
			b, t, bo, err := in.bit(r, c, &probs[idx])
			if err != nil {
				return 0, err
			}
			length += length
			if b == 0 {
				update0(r, c, &probs[idx], t, bo)
			} else {
				update1(r, c, &probs[idx], t, bo)
				length++
			}
		}
		return length, nil
	}
	update1(r, c, &probs[probLen], ttt, bound)
	probLen = baseIdx + lenHigh
	length = 1
	for i := 0; i < kLenNumHighBits; i++ {
		idx := probLen + length
		b, t, bo, err := in.bit(r, c, &probs[idx])
		if err != nil {
			return 0, err
		}
		length += length
		if b == 0 {
			update0(r, c, &probs[idx], t, bo)
		} else {
			update1(r, c, &probs[idx], t, bo)
			length++
		}
	}
	length -= kLenNumHighSymbols
	return length + kLenNumLowSymbols*2, nil
}

// decodeReal is LzmaDec_DecodeReal_3. It reads from in.src starting at
// in.pos and stops decoding symbols at bufLimit (an absolute position in
// in.src). It returns the number of input bytes consumed.
func (d *Decoder) decodeReal(limit int, in *rcIn, bufLimit int) (consumed int, err error) {
	probs := d.probs
	state := int(d.state)
	rep0, rep1, rep2, rep3 := d.reps[0], d.reps[1], d.reps[2], d.reps[3]
	pbMask := (1 << d.prop.Pb) - 1
	lc := int(d.prop.Lc)
	lpMask := (0x100 << d.prop.Lp) - (0x100 >> lc)
	dic := d.dic
	dicBufSize := d.dicBufSize
	dicPos := d.dicPos
	processedPos := d.processedPos
	checkDicSize := d.checkDicSize
	length := 0
	start := in.pos
	r, c := d.r, d.code

	writeBack := func() {
		d.r, d.code = r, c
		d.remainLen = uint32(length)
		d.dicPos = dicPos
		d.processedPos = processedPos
		d.reps = [4]uint32{rep0, rep1, rep2, rep3}
		d.state = uint32(state)
	}

	for first := true; first || (dicPos < limit && in.pos < bufLimit); first = false {
		posState := (int(processedPos) & pbMask) << 4

		// IsMatch + posState + state
		prob := &probs[probsIsMatch+posState+state]
		bit, ttt, bound, err := in.bit(&r, &c, prob)
		if err != nil {
			writeBack()
			return in.pos - start, err
		}
		if bit == 0 {
			update0(&r, &c, prob, ttt, bound)
			// Literal.
			probLit := probsLiteral
			if processedPos != 0 || checkDicSize != 0 {
				prevIdx := dicPos - 1
				if dicPos == 0 {
					prevIdx = dicBufSize - 1
				}
				probLit += int(3 * ((((processedPos << 8) + uint32(dic[prevIdx])) & uint32(lpMask)) << lc))
			}
			processedPos++
			var symbol uint32
			if state < kNumLitStates {
				if state < 4 {
					state = 0
				} else {
					state -= 3
				}
				symbol = 1
				for i := 0; i < 8; i++ {
					idx := probLit + int(symbol)
					b, t, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						writeBack()
						return in.pos - start, err
					}
					symbol <<= 1
					if b == 0 {
						update0(&r, &c, &probs[idx], t, bo)
					} else {
						update1(&r, &c, &probs[idx], t, bo)
						symbol++
					}
				}
			} else {
				matchByte := uint32(dic[dicPos-int(rep0)+boolToInt(dicPos < int(rep0))*dicBufSize])
				offs := uint32(0x100)
				if state < 10 {
					state -= 3
				} else {
					state -= 6
				}
				symbol = 1
				for i := 0; i < 8; i++ {
					matchByte += matchByte
					bitv := offs
					offs &= matchByte
					idx := probLit + int(offs+bitv+symbol)
					b, t, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						writeBack()
						return in.pos - start, err
					}
					symbol <<= 1
					if b == 0 {
						update0(&r, &c, &probs[idx], t, bo)
						offs ^= bitv
					} else {
						update1(&r, &c, &probs[idx], t, bo)
						symbol++
					}
				}
			}
			dic[dicPos] = byte(symbol)
			dicPos++
			continue
		}

		update1(&r, &c, prob, ttt, bound)

		// IsRep + state
		prob = &probs[probsIsRep+state]
		bit, ttt, bound, err = in.bit(&r, &c, prob)
		if err != nil {
			writeBack()
			return in.pos - start, err
		}
		if bit == 0 {
			update0(&r, &c, prob, ttt, bound)
			state += kNumStates
			length, err = lenDecode(&r, &c, probsLenCoder, posState, probs, in)
			if err != nil {
				writeBack()
				return in.pos - start, err
			}
		} else {
			update1(&r, &c, prob, ttt, bound)
			prob = &probs[probsIsRepG0+state]
			bit, ttt, bound, err = in.bit(&r, &c, prob)
			if err != nil {
				writeBack()
				return in.pos - start, err
			}
			if bit == 0 {
				update0(&r, &c, prob, ttt, bound)
				prob = &probs[probsIsRep0Long+posState+state]
				bit, ttt, bound, err = in.bit(&r, &c, prob)
				if err != nil {
					writeBack()
					return in.pos - start, err
				}
				if bit == 0 {
					update0(&r, &c, prob, ttt, bound)
					// Short rep.
					idx := dicPos - int(rep0)
					if dicPos < int(rep0) {
						idx += dicBufSize
					}
					dic[dicPos] = dic[idx]
					dicPos++
					processedPos++
					if state < kNumLitStates {
						state = 9
					} else {
						state = 11
					}
					continue
				}
				update1(&r, &c, prob, ttt, bound)
			} else {
				update1(&r, &c, prob, ttt, bound)
				var distance uint32
				prob = &probs[probsIsRepG1+state]
				bit, ttt, bound, err = in.bit(&r, &c, prob)
				if err != nil {
					writeBack()
					return in.pos - start, err
				}
				if bit == 0 {
					update0(&r, &c, prob, ttt, bound)
					distance = rep1
				} else {
					update1(&r, &c, prob, ttt, bound)
					prob = &probs[probsIsRepG2+state]
					bit, ttt, bound, err = in.bit(&r, &c, prob)
					if err != nil {
						writeBack()
						return in.pos - start, err
					}
					if bit == 0 {
						update0(&r, &c, prob, ttt, bound)
						distance = rep2
					} else {
						update1(&r, &c, prob, ttt, bound)
						distance = rep3
						rep3 = rep2
					}
					rep2 = rep1
				}
				rep1 = rep0
				rep0 = distance
			}
			if state < kNumLitStates {
				state = 8
			} else {
				state = 11
			}
			length, err = lenDecode(&r, &c, probsRepLenCoder, posState, probs, in)
			if err != nil {
				writeBack()
				return in.pos - start, err
			}
		}

		if state >= kNumStates {
			var distance uint32
			temp := length
			if temp >= kNumLenToPosStates {
				temp = kNumLenToPosStates - 1
			}
			// TREE_6_DECODE
			{
				i := 1
				base := probsPosSlot + temp*(1<<kNumPosSlotBits)
				for k := 0; k < kNumPosSlotBits; k++ {
					idx := base + i
					b, t, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						writeBack()
						return in.pos - start, err
					}
					i += i
					if b == 0 {
						update0(&r, &c, &probs[idx], t, bo)
					} else {
						update1(&r, &c, &probs[idx], t, bo)
						i++
					}
				}
				distance = uint32(i - 0x40)
			}
			if distance >= kStartPosModelIndex {
				posSlot := distance
				numDirectBits := (posSlot >> 1) - 1
				distance = 2 | (posSlot & 1)
				if posSlot < kEndPosModelIndex {
					distance <<= numDirectBits
					m := uint32(1)
					distance++
					for {
						idx := int(distance)
						b, t, bo, err := in.bit(&r, &c, &probs[idx])
						if err != nil {
							writeBack()
							return in.pos - start, err
						}
						if b == 0 {
							update0(&r, &c, &probs[idx], t, bo)
							distance += m
							m += m
						} else {
							update1(&r, &c, &probs[idx], t, bo)
							m += m
							distance += m
						}
						numDirectBits--
						if numDirectBits == 0 {
							break
						}
					}
					distance -= m
				} else {
					numDirectBits -= kNumAlignBits
					for {
						if err := in.normalize(&r, &c); err != nil {
							writeBack()
							return in.pos - start, err
						}
						r >>= 1
						c -= r
						t := uint32(0 - (c >> 31))
						distance = distance<<1 + t + 1
						c += r & t
						numDirectBits--
						if numDirectBits == 0 {
							break
						}
					}
					distance <<= kNumAlignBits
					i := 1
					for _, m := range [4]uint32{1, 2, 4, 8} {
						idx := probsAlign + i
						b, t, bo, err := in.bit(&r, &c, &probs[idx])
						if err != nil {
							writeBack()
							return in.pos - start, err
						}
						if b == 0 {
							update0(&r, &c, &probs[idx], t, bo)
							if m == 8 {
								i -= 8
							} else {
								i += int(m)
							}
						} else {
							update1(&r, &c, &probs[idx], t, bo)
							if m != 8 {
								i += int(m * 2)
							}
						}
					}
					distance |= uint32(i)
				}
				if distance == 0xFFFFFFFF {
					length = kMatchSpecLenStart
					state -= kNumStates
					break
				}
			}

			rep3 = rep2
			rep2 = rep1
			rep1 = rep0
			rep0 = distance + 1
			if state < kNumStates+kNumLitStates {
				state = kNumLitStates
			} else {
				state = kNumLitStates + 3
			}
			limit := processedPos
			if checkDicSize != 0 {
				limit = checkDicSize
			}
			if distance >= limit {
				length += kMatchSpecLenErrorData + kMatchMinLen
				break
			}
		}
		length += kMatchMinLen

		rem := limit - dicPos
		if rem == 0 {
			break
		}
		curLen := rem
		if curLen > length {
			curLen = length
		}
		pos := dicPos - int(rep0)
		if dicPos < int(rep0) {
			pos += dicBufSize
		}
		processedPos += uint32(curLen)
		length -= curLen
		if curLen <= dicBufSize-pos {
			// Forward byte-by-byte copy exactly like the C decoder: when the
			// source overlaps the destination (rep0 < curLen), each byte is
			// read from the just-written value. Go's copy() is memmove and
			// would preserve the old overlapping bytes instead.
			for i := 0; i < curLen; i++ {
				dic[dicPos] = dic[pos]
				dicPos++
				pos++
			}
		} else {
			for i := 0; i < curLen; i++ {
				dic[dicPos] = dic[pos]
				dicPos++
				pos++
				if pos == dicBufSize {
					pos = 0
				}
			}
		}
	}

	if err := in.normalize(&r, &c); err != nil {
		writeBack()
		return in.pos - start, err
	}
	writeBack()
	if length >= kMatchSpecLenErrorData {
		return in.pos - start, ErrData
	}
	return in.pos - start, nil
}

// Dummy-decode results (ELzmaDummy).
const (
	dummyInputEOF = iota
	dummyLit
	dummyMatch
	dummyRep
)

// dummyIn is the checked input cursor of tryDummy (NORMALIZE_CHECK).
type dummyIn struct {
	src   []byte
	pos   int
	limit int
}

func (in *dummyIn) normalize(r, c *uint32) error {
	if *r < kTopValue {
		if in.pos >= in.limit {
			return ErrInputEOF
		}
		*r <<= 8
		*c = *c<<8 | uint32(in.src[in.pos])
		in.pos++
	}
	return nil
}

func (in *dummyIn) bit(r, c *uint32, prob *uint16) (bit, ttt, bound uint32, err error) {
	if err = in.normalize(r, c); err != nil {
		return 0, 0, 0, err
	}
	ttt = uint32(*prob)
	bound = (*r >> kNumBitModelTotalBits) * ttt
	if *c < bound {
		return 0, ttt, bound, nil
	}
	return 1, ttt, bound, nil
}

func update0Check(r, c *uint32, bound uint32) {
	*r = bound
}

func update1Check(r, c *uint32, bound uint32) {
	*r -= bound
	*c -= bound
}

// tryDummy is LzmaDec_TryDummy. It decodes one symbol without writing the
// dictionary or the probability table, returning the symbol class and the
// number of input bytes consumed.
func (d *Decoder) tryDummy(src []byte) (res int, consumed int) {
	r, c := d.r, d.code
	in := &dummyIn{src: src, limit: len(src)}
	probs := d.probs
	state := int(d.state)

	for {
		posState := (int(d.processedPos) & ((1 << d.prop.Pb) - 1)) << 4

		prob := &probs[probsIsMatch+posState+state]
		bit, _, bound, err := in.bit(&r, &c, prob)
		if err != nil {
			return dummyInputEOF, in.pos
		}
		if bit == 0 {
			update0Check(&r, &c, bound)
			probLit := probsLiteral
			if d.checkDicSize != 0 || d.processedPos != 0 {
				prevIdx := d.dicPos - 1
				if d.dicPos == 0 {
					prevIdx = d.dicBufSize - 1
				}
				probLit += int(lzmaLitSize * (((int(d.processedPos) & ((1 << d.prop.Lp) - 1)) << d.prop.Lc) +
					int(d.dic[prevIdx])>>(8-d.prop.Lc)))
			}
			if state < kNumLitStates {
				symbol := 1
				for {
					idx := probLit + symbol
					b, _, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						return dummyInputEOF, in.pos
					}
					symbol += symbol
					if b == 0 {
						update0Check(&r, &c, bo)
					} else {
						update1Check(&r, &c, bo)
						symbol++
					}
					if symbol >= 0x100 {
						break
					}
				}
			} else {
				matchByte := uint32(d.dic[d.dicPos-int(d.reps[0])+boolToInt(d.dicPos < int(d.reps[0]))*d.dicBufSize])
				offs := uint32(0x100)
				symbol := 1
				for {
					matchByte += matchByte
					bitv := offs
					offs &= matchByte
					idx := probLit + int(offs+bitv) + symbol
					b, _, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						return dummyInputEOF, in.pos
					}
					symbol += symbol
					if b == 0 {
						update0Check(&r, &c, bo)
						offs ^= bitv
					} else {
						update1Check(&r, &c, bo)
						symbol++
					}
					if symbol >= 0x100 {
						break
					}
				}
			}
			res = dummyLit
		} else {
			update1Check(&r, &c, bound)
			length := 0
			prob = &probs[probsIsRep+state]
			bit, _, bound, err = in.bit(&r, &c, prob)
			if err != nil {
				return dummyInputEOF, in.pos
			}
			if bit == 0 {
				update0Check(&r, &c, bound)
				state = 0
				baseIdx := probsLenCoder
				res = dummyMatch
				// length decode
				var lim, offset int
				probLen := baseIdx + lenChoice
				b, _, bo, err := in.bit(&r, &c, &probs[probLen])
				if err != nil {
					return dummyInputEOF, in.pos
				}
				if b == 0 {
					update0Check(&r, &c, bo)
					probLen = baseIdx + lenLow + posState
					offset = 0
					lim = kLenNumLowSymbols
				} else {
					update1Check(&r, &c, bo)
					probLen = baseIdx + lenChoice2
					b, _, bo, err = in.bit(&r, &c, &probs[probLen])
					if err != nil {
						return dummyInputEOF, in.pos
					}
					if b == 0 {
						update0Check(&r, &c, bo)
						probLen = baseIdx + lenLow + posState + kLenNumLowSymbols
						offset = kLenNumLowSymbols
						lim = kLenNumLowSymbols
					} else {
						update1Check(&r, &c, bo)
						probLen = baseIdx + lenHigh
						offset = kLenNumLowSymbols * 2
						lim = kLenNumHighSymbols
					}
				}
				length = 1
				for {
					idx := probLen + length
					b, _, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						return dummyInputEOF, in.pos
					}
					length += length
					if b == 0 {
						update0Check(&r, &c, bo)
					} else {
						update1Check(&r, &c, bo)
						length++
					}
					if length >= lim {
						break
					}
				}
				length -= lim
				length += offset
			} else {
				update1Check(&r, &c, bound)
				res = dummyRep
				prob = &probs[probsIsRepG0+state]
				bit, _, bound, err = in.bit(&r, &c, prob)
				if err != nil {
					return dummyInputEOF, in.pos
				}
				if bit == 0 {
					update0Check(&r, &c, bound)
					prob = &probs[probsIsRep0Long+posState+state]
					bit, _, bound, err = in.bit(&r, &c, prob)
					if err != nil {
						return dummyInputEOF, in.pos
					}
					if bit == 0 {
						update0Check(&r, &c, bound)
						break
					}
					update1Check(&r, &c, bound)
				} else {
					update1Check(&r, &c, bound)
					prob = &probs[probsIsRepG1+state]
					bit, _, bound, err = in.bit(&r, &c, prob)
					if err != nil {
						return dummyInputEOF, in.pos
					}
					if bit == 0 {
						update0Check(&r, &c, bound)
					} else {
						update1Check(&r, &c, bound)
						prob = &probs[probsIsRepG2+state]
						bit, _, bound, err = in.bit(&r, &c, prob)
						if err != nil {
							return dummyInputEOF, in.pos
						}
						if bit == 0 {
							update0Check(&r, &c, bound)
						} else {
							update1Check(&r, &c, bound)
						}
					}
				}
				state = kNumStates
				baseIdx := probsRepLenCoder
				// length decode (same as above)
				var lim, offset int
				probLen := baseIdx + lenChoice
				b, _, bo, err := in.bit(&r, &c, &probs[probLen])
				if err != nil {
					return dummyInputEOF, in.pos
				}
				if b == 0 {
					update0Check(&r, &c, bo)
					probLen = baseIdx + lenLow + posState
					offset = 0
					lim = kLenNumLowSymbols
				} else {
					update1Check(&r, &c, bo)
					probLen = baseIdx + lenChoice2
					b, _, bo, err = in.bit(&r, &c, &probs[probLen])
					if err != nil {
						return dummyInputEOF, in.pos
					}
					if b == 0 {
						update0Check(&r, &c, bo)
						probLen = baseIdx + lenLow + posState + kLenNumLowSymbols
						offset = kLenNumLowSymbols
						lim = kLenNumLowSymbols
					} else {
						update1Check(&r, &c, bo)
						probLen = baseIdx + lenHigh
						offset = kLenNumLowSymbols * 2
						lim = kLenNumHighSymbols
					}
				}
				length = 1
				for {
					idx := probLen + length
					b, _, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						return dummyInputEOF, in.pos
					}
					length += length
					if b == 0 {
						update0Check(&r, &c, bo)
					} else {
						update1Check(&r, &c, bo)
						length++
					}
					if length >= lim {
						break
					}
				}
				length -= lim
				length += offset
			}

			if state < 4 {
				var posSlot int
				temp := length
				if temp >= kNumLenToPosStates-1 {
					temp = kNumLenToPosStates - 1
				}
				base := probsPosSlot + temp*(1<<kNumPosSlotBits)
				posSlot = 1
				for {
					idx := base + posSlot
					b, _, bo, err := in.bit(&r, &c, &probs[idx])
					if err != nil {
						return dummyInputEOF, in.pos
					}
					posSlot += posSlot
					if b == 0 {
						update0Check(&r, &c, bo)
					} else {
						update1Check(&r, &c, bo)
						posSlot++
					}
					if posSlot >= 1<<kNumPosSlotBits {
						break
					}
				}
				posSlot -= 1 << kNumPosSlotBits
				if posSlot >= kStartPosModelIndex {
					numDirectBits := (posSlot >> 1) - 1
					base := probsSpecPos
					if posSlot < kEndPosModelIndex {
						temp = (2 | (posSlot & 1)) << numDirectBits
						base += temp
					} else {
						numDirectBits -= kNumAlignBits
						for {
							if err := in.normalize(&r, &c); err != nil {
								return dummyInputEOF, in.pos
							}
							r >>= 1
							if c >= r {
								c -= r
							}
							numDirectBits--
							if numDirectBits == 0 {
								break
							}
						}
						base = probsAlign
						numDirectBits = kNumAlignBits
					}
					i := 1
					m := 1
					for {
						idx := base + i
						b, _, bo, err := in.bit(&r, &c, &probs[idx])
						if err != nil {
							return dummyInputEOF, in.pos
						}
						if b == 0 {
							update0Check(&r, &c, bo)
							i += m
							m += m
						} else {
							update1Check(&r, &c, bo)
							m += m
							i += m
						}
						numDirectBits--
						if numDirectBits == 0 {
							break
						}
					}
				}
			}
		}
		break
	}

	if err := in.normalize(&r, &c); err != nil {
		return dummyInputEOF, in.pos
	}
	return res, in.pos
}

// Decode is LzmaDec_DecodeToDic. It consumes some prefix of src and decodes
// up to dicLimit dictionary bytes. Returns the number of input bytes
// consumed and the stream status.
func (d *Decoder) Decode(dicLimit int, src []byte, finish FinishMode) (int, Status, error) {
	inSize := len(src)
	consumed := 0
	status := StatusNotSpecified

	if d.remainLen > kMatchSpecLenStart {
		if d.remainLen > kMatchSpecLenStart+2 {
			if d.remainLen == kMatchSpecLenErrorFail {
				return consumed, status, ErrInternal
			}
			return consumed, status, ErrData
		}
		for inSize > 0 && d.tempBufSize < rcInitSize {
			d.tempBuf[d.tempBufSize] = src[0]
			d.tempBufSize++
			src = src[1:]
			consumed++
			inSize--
		}
		if d.tempBufSize != 0 && d.tempBuf[0] != 0 {
			return consumed, status, ErrData
		}
		if d.tempBufSize < rcInitSize {
			return consumed, StatusNeedsMoreInput, nil
		}
		d.code = uint32(d.tempBuf[1])<<24 | uint32(d.tempBuf[2])<<16 | uint32(d.tempBuf[3])<<8 | uint32(d.tempBuf[4])
		if d.checkDicSize == 0 && d.processedPos == 0 && d.code >= kBadRepCode {
			return consumed, status, ErrData
		}
		d.r = kRange0
		d.tempBufSize = 0
		if d.remainLen > kMatchSpecLenStart+1 {
			for i := range d.probs {
				d.probs[i] = kBitModelTotal >> 1
			}
			d.reps = [4]uint32{1, 1, 1, 1}
			d.state = 0
		}
		d.remainLen = 0
	}

	for {
		if d.remainLen == kMatchSpecLenStart {
			if d.code != 0 {
				return consumed, status, ErrData
			}
			return consumed, StatusFinishedWithMark, nil
		}

		d.writeRem(dicLimit)

		checkEndMarkNow := false
		if d.dicPos >= dicLimit {
			if d.remainLen == 0 && d.code == 0 {
				return consumed, StatusMaybeFinishedWithoutMark, nil
			}
			if finish == FinishAny {
				return consumed, StatusNotFinished, nil
			}
			if d.remainLen != 0 {
				// RETURN_NOT_FINISHED_FOR_FINISH (strict mode)
				return consumed, StatusNotFinished, ErrData
			}
			checkEndMarkNow = true
		}

		if d.tempBufSize == 0 {
			dummyProcessed := -1
			var bufLimit int
			if inSize < lzmaRequiredInputMax || checkEndMarkNow {
				dummyRes, dummyEnd := d.tryDummy(src)
				if dummyRes == dummyInputEOF {
					if inSize >= lzmaRequiredInputMax {
						break
					}
					consumed += inSize
					d.tempBufSize = inSize
					copy(d.tempBuf[:], src)
					return consumed, StatusNeedsMoreInput, nil
				}
				dummyProcessed = dummyEnd
				if dummyProcessed > lzmaRequiredInputMax {
					break
				}
				if checkEndMarkNow && dummyRes != dummyMatch {
					consumed += dummyProcessed
					d.tempBufSize = dummyProcessed
					copy(d.tempBuf[:], src[:dummyProcessed])
					return consumed, StatusNotFinished, ErrData
				}
				bufLimit = 0
			} else {
				bufLimit = inSize - lzmaRequiredInputMax
			}

			in := &rcIn{src: src}
			processed, err := d.decodeReal(dicLimit, in, bufLimit)
			if dummyProcessed < 0 {
				if processed > inSize {
					break
				}
			} else if dummyProcessed != processed {
				break
			}
			src = src[processed:]
			inSize -= processed
			consumed += processed
			if err != nil {
				d.remainLen = kMatchSpecLenErrorData
				return consumed, status, err
			}
			continue
		}

		// Some data is parked in tempBuf.
		rem := d.tempBufSize
		ahead := 0
		for rem < lzmaRequiredInputMax && ahead < inSize {
			d.tempBuf[rem] = src[ahead]
			rem++
			ahead++
		}
		dummyProcessed := -1
		if rem < lzmaRequiredInputMax || checkEndMarkNow {
			dummyRes, dummyEnd := d.tryDummy(d.tempBuf[:rem])
			if dummyRes == dummyInputEOF {
				if rem >= lzmaRequiredInputMax {
					break
				}
				d.tempBufSize = rem
				consumed += ahead
				return consumed, StatusNeedsMoreInput, nil
			}
			dummyProcessed = dummyEnd
			if dummyProcessed < d.tempBufSize {
				break
			}
			if checkEndMarkNow && dummyRes != dummyMatch {
				consumed += dummyProcessed - d.tempBufSize
				d.tempBufSize = dummyProcessed
				return consumed, StatusNotFinished, ErrData
			}
		}

		in := &rcIn{src: d.tempBuf[:rem]}
		processed, err := d.decodeReal(dicLimit, in, 0)
		rem2 := d.tempBufSize
		if dummyProcessed < 0 {
			if processed > lzmaRequiredInputMax {
				break
			}
			if processed < rem2 {
				break
			}
		} else if dummyProcessed != processed {
			break
		}
		processed -= rem2
		src = src[processed:]
		inSize -= processed
		consumed += processed
		d.tempBufSize = 0
		if err != nil {
			d.remainLen = kMatchSpecLenErrorData
			return consumed, status, err
		}
	}

	d.remainLen = kMatchSpecLenErrorFail
	return consumed, status, ErrInternal
}

// DecodeOneShot is LzmaDecode: it decodes src into dst using the given
// 5-byte properties. The dictionary is the output buffer itself.
func DecodeOneShot(dst, src, props []byte, finish FinishMode) (written, consumed int, status Status, err error) {
	status = StatusNotSpecified
	if len(src) < rcInitSize {
		return 0, 0, status, ErrInputEOF
	}
	if len(dst) == 0 {
		return 0, 0, status, nil
	}
	p, err := DecodeProps(props)
	if err != nil {
		return 0, 0, status, err
	}
	d := &Decoder{
		prop:       p,
		probs:      make([]uint16, p.NumProbs()),
		dic:        dst,
		dicBufSize: len(dst),
	}
	d.Init()
	consumed, status, err = d.Decode(len(dst), src, finish)
	written = d.dicPos
	if err == nil && status == StatusNeedsMoreInput {
		err = ErrInputEOF
	}
	return written, consumed, status, err
}
