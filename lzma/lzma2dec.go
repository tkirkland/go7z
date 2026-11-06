package lzma

// Lzma2Decoder is a faithful port of Lzma2Dec.c (7-Zip 26.05).
type Lzma2Decoder struct {
	state         int
	control       byte
	needInitLevel byte
	isExtraMode   bool
	packSize      uint32
	unpackSize    uint32
	dec           *Decoder
}

// LZMA2 chunk states (ELzma2State).
const (
	lzma2StateControl = iota
	lzma2StateUnpack0
	lzma2StateUnpack1
	lzma2StatePack0
	lzma2StatePack1
	lzma2StateProp
	lzma2StateData
	lzma2StateDataCont
	lzma2StateFinished
	lzma2StateError
)

const (
	lzma2ControlCopyResetDic = 1
	lzma2LclpMax             = 4
)

// NewLzma2Decoder allocates a decoder for the given 1-byte LZMA2 property
// (Lzma2Dec_Allocate + Lzma2Dec_Init).
func NewLzma2Decoder(prop byte) (*Lzma2Decoder, error) {
	p, err := lzma2PropsFromByte(prop)
	if err != nil {
		return nil, err
	}
	d := &Decoder{
		prop:       p,
		probs:      make([]uint16, p.NumProbs()),
		dicBufSize: dicBufSizeFor(p.DicSize),
	}
	d.dic = make([]byte, d.dicBufSize)
	l := &Lzma2Decoder{dec: d}
	l.Init()
	return l, nil
}

// Init resets the decoder for a new stream (Lzma2Dec_Init).
func (l *Lzma2Decoder) Init() {
	l.state = lzma2StateControl
	l.needInitLevel = 0xE0
	l.isExtraMode = false
	l.unpackSize = 0
	l.dec.Init()
}

func (l *Lzma2Decoder) updateState(b byte) int {
	switch l.state {
	case lzma2StateControl:
		l.isExtraMode = false
		l.control = b
		if b == 0 {
			return lzma2StateFinished
		}
		if l.control&(1<<7) == 0 {
			if b == lzma2ControlCopyResetDic {
				l.needInitLevel = 0xC0
			} else if b > 2 || l.needInitLevel == 0xE0 {
				return lzma2StateError
			}
		} else {
			if b < l.needInitLevel {
				return lzma2StateError
			}
			l.needInitLevel = 0
			l.unpackSize = uint32(b&0x1F) << 16
		}
		return lzma2StateUnpack0

	case lzma2StateUnpack0:
		l.unpackSize |= uint32(b) << 8
		return lzma2StateUnpack1

	case lzma2StateUnpack1:
		l.unpackSize |= uint32(b)
		l.unpackSize++
		if l.control&(1<<7) == 0 {
			return lzma2StateData
		}
		return lzma2StatePack0

	case lzma2StatePack0:
		l.packSize = uint32(b) << 8
		return lzma2StatePack1

	case lzma2StatePack1:
		l.packSize |= uint32(b)
		l.packSize++
		if l.control&0x40 != 0 {
			return lzma2StateProp
		}
		return lzma2StateData

	case lzma2StateProp:
		if b >= 9*5*5 {
			return lzma2StateError
		}
		lc := int(b % 9)
		b /= 9
		l.dec.prop.Pb = b / 5
		lp := int(b % 5)
		if lc+lp > lzma2LclpMax {
			return lzma2StateError
		}
		l.dec.prop.Lc = byte(lc)
		l.dec.prop.Lp = byte(lp)
		return lzma2StateData

	default:
		return lzma2StateError
	}
}

func (l *Lzma2Decoder) isUncompressed() bool {
	return l.control&(1<<7) == 0
}

// Decode is Lzma2Dec_DecodeToDic. It consumes some prefix of src and decodes
// up to dicLimit dictionary bytes.
func (l *Lzma2Decoder) Decode(dicLimit int, src []byte, finish FinishMode) (int, Status, error) {
	consumed := 0

	for l.state != lzma2StateError {
		if l.state == lzma2StateFinished {
			return consumed, StatusFinishedWithMark, nil
		}

		dicPos := l.dec.dicPos
		if dicPos == dicLimit && finish == FinishAny {
			return consumed, StatusNotFinished, nil
		}

		if l.state != lzma2StateData && l.state != lzma2StateDataCont {
			if consumed == len(src) {
				return consumed, StatusNeedsMoreInput, nil
			}
			b := src[consumed]
			consumed++
			l.state = l.updateState(b)
			if dicPos == dicLimit && l.state != lzma2StateFinished {
				break
			}
			continue
		}

		inCur := len(src) - consumed
		outCur := dicLimit - dicPos
		curFinish := FinishAny
		if outCur >= int(l.unpackSize) {
			outCur = int(l.unpackSize)
			curFinish = FinishEnd
		}

		if l.isUncompressed() {
			if inCur == 0 {
				return consumed, StatusNeedsMoreInput, nil
			}
			if l.state == lzma2StateData {
				initDic := l.control == lzma2ControlCopyResetDic
				l.dec.initDicAndState(initDic, false)
			}
			if inCur > outCur {
				inCur = outCur
			}
			if inCur == 0 {
				break
			}
			l.dec.updateWithUncompressed(src[consumed : consumed+inCur])
			consumed += inCur
			l.unpackSize -= uint32(inCur)
			if l.unpackSize == 0 {
				l.state = lzma2StateControl
			} else {
				l.state = lzma2StateDataCont
			}
		} else {
			if l.state == lzma2StateData {
				initDic := l.control >= 0xE0
				initState := l.control >= 0xA0
				l.dec.initDicAndState(initDic, initState)
				l.state = lzma2StateDataCont
			}
			if inCur > int(l.packSize) {
				inCur = int(l.packSize)
			}
			inConsumed, st, err := l.dec.Decode(dicPos+outCur, src[consumed:consumed+inCur], curFinish)
			consumed += inConsumed
			l.packSize -= uint32(inConsumed)
			outCur = l.dec.dicPos - dicPos
			l.unpackSize -= uint32(outCur)
			if err != nil {
				break
			}
			if st == StatusNeedsMoreInput {
				if l.packSize == 0 {
					break
				}
				return consumed, st, nil
			}
			if inConsumed == 0 && outCur == 0 {
				if st != StatusMaybeFinishedWithoutMark || l.unpackSize != 0 || l.packSize != 0 {
					break
				}
				l.state = lzma2StateControl
			}
		}
	}

	return consumed, StatusNotSpecified, ErrData
}

// Lzma2DecodeOneShot is Lzma2Decode: it decodes src into dst using the
// 1-byte LZMA2 property. The dictionary is the output buffer itself.
func Lzma2DecodeOneShot(dst, src []byte, prop byte, finish FinishMode) (written, consumed int, status Status, err error) {
	status = StatusNotSpecified
	if len(dst) == 0 {
		return 0, 0, status, nil
	}
	p, err := lzma2PropsFromByte(prop)
	if err != nil {
		return 0, 0, status, err
	}
	d := &Decoder{
		prop:       p,
		probs:      make([]uint16, p.NumProbs()),
		dic:        dst,
		dicBufSize: len(dst),
	}
	l := &Lzma2Decoder{dec: d}
	l.Init()
	consumed, status, err = l.Decode(len(dst), src, finish)
	written = l.dec.dicPos
	if err == nil && status == StatusNeedsMoreInput {
		err = ErrInputEOF
	}
	return written, consumed, status, err
}
