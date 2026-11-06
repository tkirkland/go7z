// Package lzma implements the LZMA/LZMA2 codecs and the .lzma/.lzma86
// stream formats, ported from the public-domain C sources of the 7-Zip
// 26.05 SDK (reference/7zip/C/LzmaDec.c, Lzma2Dec.c, Lzma86Enc.c,
// Lzma86Dec.c).
package lzma

import "errors"

var (
	// ErrUnsupportedProps is returned for LZMA properties that the decoder
	// rejects.
	ErrUnsupportedProps = errors.New("lzma: unsupported properties")
	// ErrData is returned when the compressed data is corrupt.
	ErrData = errors.New("lzma: corrupt data")
	// ErrInputEOF is returned when the input ends before the stream does.
	ErrInputEOF = errors.New("lzma: unexpected end of input")
	// ErrInternal is returned for the decoder's internal failure state.
	ErrInternal = errors.New("lzma: internal error")
)

// Constants from LzmaDec.c (26.05), portable (non-ASM) configuration.
const (
	kNumTopBits           = 24
	kTopValue             = 1 << 24
	kNumBitModelTotalBits = 11
	kBitModelTotal        = 1 << 11
	rcInitSize            = 5
	kNumMoveBits          = 5

	kNumPosBitsMax     = 4
	kNumPosStatesMax   = 1 << kNumPosBitsMax
	kLenNumLowBits     = 3
	kLenNumLowSymbols  = 1 << kLenNumLowBits
	kLenNumHighBits    = 8
	kLenNumHighSymbols = 1 << kLenNumHighBits

	kNumStates    = 12
	kNumStates2   = 16
	kNumLitStates = 7

	kStartPosModelIndex = 4
	kEndPosModelIndex   = 14
	kNumFullDistances   = 1 << (kEndPosModelIndex >> 1)

	kNumPosSlotBits    = 6
	kNumLenToPosStates = 4
	kNumAlignBits      = 4
	kAlignTableSize    = 1 << kNumAlignBits

	kMatchMinLen           = 2
	kMatchSpecLenStart     = kMatchMinLen + kLenNumLowSymbols*2 + kLenNumHighSymbols
	kMatchSpecLenErrorData = 1 << 9
	kMatchSpecLenErrorFail = kMatchSpecLenErrorData - 1

	lzmaLitSize          = 0x300
	lzmaRequiredInputMax = 20

	kRange0     = 0xFFFFFFFF
	kBadRepCode = 0xC0000000 - 0x400
)

// Absolute probability-table offsets. The C decoder indexes the table
// through probs_1664 = probs + 1664; these constants are the equivalent
// absolute offsets into the full table.
const (
	probsSpecPos     = 0
	probsIsRep0Long  = probsSpecPos + kNumFullDistances                       // 128
	probsRepLenCoder = probsIsRep0Long + kNumStates2*kNumPosStatesMax         // 384
	probsLenCoder    = probsRepLenCoder + 512                                 // 896
	probsIsMatch     = probsLenCoder + 512                                    // 1408
	probsAlign       = probsIsMatch + kNumStates2*kNumPosStatesMax            // 1664
	probsIsRep       = probsAlign + kAlignTableSize                           // 1680
	probsIsRepG0     = probsIsRep + kNumStates                                // 1692
	probsIsRepG1     = probsIsRepG0 + kNumStates                              // 1704
	probsIsRepG2     = probsIsRepG1 + kNumStates                              // 1716
	probsPosSlot     = probsIsRepG2 + kNumStates                              // 1728
	probsLiteral     = probsPosSlot + kNumLenToPosStates*(1<<kNumPosSlotBits) // 1984
)

// Length-coder offsets relative to probsLenCoder / probsRepLenCoder.
const (
	lenLow     = 0
	lenChoice  = lenLow
	lenChoice2 = lenLow + kLenNumLowSymbols
	lenHigh    = lenLow + 2*(kNumPosStatesMax*kLenNumLowSymbols)
)

// Props are the decoded 5-byte LZMA properties.
type Props struct {
	Lc, Lp, Pb byte
	DicSize    uint32
}

// DecodeProps decodes 5-byte LZMA properties (LzmaProps_Decode).
func DecodeProps(data []byte) (Props, error) {
	var p Props
	if len(data) < 5 {
		return p, ErrUnsupportedProps
	}
	dicSize := uint32(data[1]) | uint32(data[2])<<8 | uint32(data[3])<<16 | uint32(data[4])<<24
	if dicSize < (1 << 12) {
		dicSize = 1 << 12
	}
	p.DicSize = dicSize
	d := data[0]
	if d >= 9*5*5 {
		return p, ErrUnsupportedProps
	}
	p.Lc = d % 9
	d /= 9
	p.Pb = d / 5
	p.Lp = d % 5
	return p, nil
}

// NumProbs returns the probability-table size for these properties
// (LzmaProps_GetNumProbs).
func (p Props) NumProbs() int {
	return 1984 + (lzmaLitSize << (p.Lc + p.Lp))
}

// FinishMode selects decoder behaviour at the output limit
// (ELzmaFinishMode).
type FinishMode int

const (
	// FinishAny stops decoding at the output limit.
	FinishAny FinishMode = iota
	// FinishEnd requires the block to finish at the output limit.
	FinishEnd
)

// Status reports stream state (ELzmaStatus).
type Status int

const (
	StatusNotSpecified Status = iota
	StatusFinishedWithMark
	StatusNotFinished
	StatusNeedsMoreInput
	StatusMaybeFinishedWithoutMark
)

// Lzma2Dec_GetOldProps (Lzma2Dec.c): expands the 1-byte LZMA2 dictionary
// property into 5-byte LZMA properties with lc+lp clamped to 4.
func lzma2PropsFromByte(prop byte) (Props, error) {
	if prop > 40 {
		return Props{}, ErrUnsupportedProps
	}
	dicSize := uint32(0xFFFFFFFF)
	if prop != 40 {
		dicSize = (2 | uint32(prop&1)) << (uint(prop)/2 + 11)
	}
	return Props{Lc: 4, Lp: 0, Pb: 0, DicSize: dicSize}, nil
}
