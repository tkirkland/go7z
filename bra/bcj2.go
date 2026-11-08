package bra

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
)

// Port of C/Bcj2.h, C/Bcj2.c and C/Bcj2Enc.c (26.05, public domain):
// the BCJ2 converter for x86 code (branch CALL/JUMP variant 2). The
// converter splits one input into four streams: MAIN (the code with the
// branch operands removed), CALL and JUMP (big-endian absolute targets of
// the converted E8 and E9/0F8x instructions, 4 bytes each) and RC (a
// range-coded bit per marker saying whether its operand was converted).
// The state machines below keep the SDK's structure field for field so
// that the output is the SDK's byte for byte, including the look-ahead
// buffer that makes the encoder's output independent of how the input is
// chunked. Each state-machine step of the C loop is one Go method; the
// method boundaries carry no behavior of their own.

// The four BCJ2 streams, in the SDK's order.
const (
	Bcj2StreamMain = iota
	Bcj2StreamCall
	Bcj2StreamJump
	Bcj2StreamRC
	Bcj2NumStreams
)

const (
	bcj2TopValue             = uint32(1) << 24
	bcj2NumBitModelTotalBits = 11
	bcj2BitModelTotal        = uint32(1) << bcj2NumBitModelTotalBits
	bcj2NumMoveBits          = 5
	bcj2NumShiftBits         = 24
	bcj2ConvFlag             = uint32(1) << 16
)

// Encoder states beyond the four streams (BCJ2_ENC_STATE_*).
const (
	Bcj2EncStateOrig     = Bcj2NumStreams
	Bcj2EncStateFinished = Bcj2NumStreams + 1
)

// Why the MAIN scan stopped (scanMain's report to encode2). The SDK
// writes the same three exits as a return, a break and a fall-through.
const (
	bcj2ScanStop   = 0 // an input or an output stream stopped: encode2 returns
	bcj2ScanFlush  = 1 // all of Src is consumed and the mode ends the stream
	bcj2ScanMarker = 2 // a marker byte was found at src[-1]
)

// Decoder states beyond the four streams (BCJ2_DEC_STATE_*).
// noinspection GoUnusedConst
const (
	Bcj2DecStateOrig0 = Bcj2NumStreams + iota
	Bcj2DecStateOrig1
	Bcj2DecStateOrig2
	Bcj2DecStateOrig3
	Bcj2DecStateOrig
	Bcj2DecStateError
)

// Bcj2FinishMode is EBcj2Enc_FinishMode.
type Bcj2FinishMode int

const (
	Bcj2FinishContinue  Bcj2FinishMode = iota // more input follows this call
	Bcj2FinishEndBlock                        // finish the block at the end of Src, no RC flush
	Bcj2FinishEndStream                       // finish the stream, flush RC
)

// Encoder limits (Bcj2.h).
// noinspection GoUnusedConst
const (
	Bcj2RelatLimitDefault = uint32(0x0f) << 24 // BCJ2_ENC_RELAT_LIMIT_DEFAULT
	Bcj2RelatLimitMax     = uint32(1) << 31    // BCJ2_ENC_RELAT_LIMIT_MAX
	Bcj2FileSizeMax       = ^uint64(0) - 1     // BCJ2_ENC_FileSize_MAX
	// Bcj2FileSizeUnlimited is the FileSize64Minus1 value that disables
	// the absolute-address limit (BCJ2_ENC_FileSizeField_UNLIMITED).
	Bcj2FileSizeUnlimited = ^uint64(0)
)

// ErrBcj2Data is returned when the RC stream is not a valid BCJ2 range
// coder stream (SZ_ERROR_DATA).
var ErrBcj2Data = errors.New("bcj2: data error")

func isBcj2Stream32(s int) bool { return uint(s-Bcj2StreamCall) < 2 }

// Bcj2Enc is CBcj2Enc. Bufs[i][Pos[i]:] is the free part of output
// stream i; Src[SrcPos:] is the unprocessed input.
type Bcj2Enc struct {
	Bufs   [Bcj2NumStreams][]byte
	Pos    [Bcj2NumStreams]int
	Src    []byte
	SrcPos int

	State      int
	FinishMode Bcj2FinishMode

	context      byte
	flushRem     byte
	isFlushState bool

	cache     byte
	rng       uint32
	low       uint64
	cacheSize uint64

	// IP64 and FileIP64 are the virtual source positions that do not
	// include the data in temp.
	IP64             uint64 // current ip
	FileIP64         uint64 // ip where the current file starts
	FileSize64Minus1 uint64 // size of the current file minus 1, or Bcj2FileSizeUnlimited
	RelatLimit       uint32 // <= Bcj2RelatLimitMax; 0 disables conversion

	tempTarget uint32
	tempPos    int
	temp       [8]byte
	probs      [2 + 256]uint16
}

// Init is Bcj2Enc_Init.
func (p *Bcj2Enc) Init() {
	p.State = Bcj2EncStateOrig
	p.FinishMode = Bcj2FinishContinue
	p.context = 0
	p.flushRem = 5
	p.isFlushState = false
	p.cache = 0
	p.rng = 0xffffffff
	p.low = 0
	p.cacheSize = 1
	p.IP64 = 0
	p.FileIP64 = 0
	p.FileSize64Minus1 = Bcj2FileSizeUnlimited
	p.RelatLimit = Bcj2RelatLimitDefault
	p.tempPos = 0
	for i := range p.probs {
		p.probs[i] = uint16(bcj2BitModelTotal >> 1)
	}
}

// SetFileSize is Bcj2Enc_SET_FileSize.
func (p *Bcj2Enc) SetFileSize(fileSize uint64) { p.FileSize64Minus1 = fileSize - 1 }

// IsFinished is Bcj2Enc_IsFinished.
func (p *Bcj2Enc) IsFinished() bool { return p.flushRem == 0 }

// AvailInputSizeInTemp is Bcj2Enc_Get_AvailInputSize_in_Temp: the number
// of input bytes held back in the look-ahead buffer.
func (p *Bcj2Enc) AvailInputSizeInTemp() int { return p.tempPos }

// shiftLow is Bcj2_RangeEnc_ShiftLow; it returns true when the RC output
// buffer is full.
func (p *Bcj2Enc) shiftLow() bool {
	low := uint32(p.low)
	high := uint32(p.low >> 32)
	if low < 0xff000000 || high != 0 {
		buf := p.Pos[Bcj2StreamRC]
		out := p.Bufs[Bcj2StreamRC]
		for {
			if buf == len(out) {
				p.State = Bcj2StreamRC
				p.Pos[Bcj2StreamRC] = buf
				return true
			}
			out[buf] = byte(uint32(p.cache) + high)
			buf++
			p.cache = 0xff
			p.cacheSize--
			if p.cacheSize == 0 {
				break
			}
		}
		p.Pos[Bcj2StreamRC] = buf
		p.cache = byte(low >> 24)
	}
	p.cacheSize++
	p.low = uint64(low << 8)
	return false
}

// writePendingConv is the loop-entry step: a CALL/JUMP target held over
// from a previous call is written now; true when its stream is full and
// encode2 must return with State still 32-bit.
func (p *Bcj2Enc) writePendingConv() bool {
	state := p.State
	if !isBcj2Stream32(state) {
		return false
	}
	if p.Pos[state] == len(p.Bufs[state]) {
		return true
	}
	binary.BigEndian.PutUint32(p.Bufs[state][p.Pos[state]:], p.tempTarget)
	p.Pos[state] += 4
	return false
}

// renormRc is the range-coder normalization at the top of encode2's loop:
// it first saves the loop position (SrcPos and context, where encode2
// resumes from) because shiftLow can report a full RC stream, then
// renormalizes. false means the RC stream is full and encode2 returns.
func (p *Bcj2Enc) renormRc(src int, v uint32) (int, uint32, bool) {
	if p.rng >= bcj2TopValue {
		return src, v, true
	}
	p.SrcPos = src
	p.context = byte(v)
	if p.shiftLow() {
		return src, v, false
	}
	p.rng <<= 8
	// The SDK takes back the locals it saved, which truncates v to a byte.
	src = p.SrcPos
	return src, uint32(p.context), true
}

// scanMain is the MAIN-copy block of Bcj2Enc_Encode_2. It returns (src,
// v, signal), one of the bcj2Scan* signals.
func (p *Bcj2Enc) scanMain(src int, v uint32) (int, uint32, int) {
	in := p.Src
	main := p.Bufs[Bcj2StreamMain]
	dest := p.Pos[Bcj2StreamMain]
	destStart := dest
	remSrc := len(in) - src
	rem := min(len(main)-dest, remSrc)
	srcLim := src + rem
	// p.context holds the previous byte in bits 0..7.
	if src != srcLim {
		src, dest, v = p.scanMarkers(in, main, src, srcLim, dest, v)
	}
	ip := p.IP64 + uint64(dest-destStart)
	p.Pos[Bcj2StreamMain] = dest
	p.IP64 = ip

	if src == srcLim {
		p.SrcPos = src
		p.context = byte(v)
		if src != len(in) {
			p.State = Bcj2StreamMain
			return src, v, bcj2ScanStop
		}
		if p.FinishMode != Bcj2FinishEndStream {
			return src, v, bcj2ScanStop
		}
		p.isFlushState = true
		return src, v, bcj2ScanFlush
	}
	return src + 1, v, bcj2ScanMarker
}

// scanMarkers is the SDK's byte-copying loop: it copies MAIN bytes until
// a marker (e8/e9 after the 0f/x test) or the scan limit.
func (p *Bcj2Enc) scanMarkers(in, main []byte, src, srcLim, dest int, v uint32) (int, int, uint32) {
	for {
		b := uint32(in[src])
		main[dest] = byte(b)
		dest++
		v = (v << bcj2NumShiftBits) | b
		if ((b + (0x100 - 0xe8)) & 0xfe) == 0 {
			break
		}
		if ((v - ((uint32(0x0f) << bcj2NumShiftBits) + 0x80)) &
			(((uint32(1) << (4 + bcj2NumShiftBits)) - 0x1) << 4)) == 0 {
			break
		}
		src++
		if src == srcLim {
			break
		}
	}
	return src, dest, v
}

// markOperand is the marker-operand decision: it sets the conversion
// flag when the 4-byte operand is convertible (inside the file and
// within RelatLimit), and in continue mode rolls the marker back when
// fewer than 4 bytes follow. false means encode2 returns now.
func (p *Bcj2Enc) markOperand(src int, v uint32) (uint32, bool) {
	in := p.Src
	if len(in)-src >= 4 {
		relat := binary.LittleEndian.Uint32(in[src:])
		ip := p.IP64 - p.FileIP64
		// 23.00: no conversion across a block boundary for (0f 80) and (e8/e9).
		if ip > uint64(((v+0x20)>>5)&1) {
			if uint64(int64(ip)+4+int64(int32(relat))) <= p.FileSize64Minus1 {
				if ((relat + p.RelatLimit) >> 1) < p.RelatLimit {
					v |= bcj2ConvFlag
				}
			}
		}
		return v, true
	}
	if p.FinishMode == Bcj2FinishContinue {
		// Fewer than 4 bytes follow the marker: give the marker byte
		// back and wait for more input.
		p.IP64--
		p.Pos[Bcj2StreamMain]--
		src--
		v >>= bcj2NumShiftBits
		p.SrcPos = src
		p.context = byte(v)
		return v, false
	}
	return v, true
}

// rangeBit is the SDK's range-coding of the conversion flag: it returns
// true when the flag is 1 (the operand goes to its CALL/JUMP stream).
func (p *Bcj2Enc) rangeBit(v uint32) bool {
	c := ((v + 0x17) >> 6) & 1
	idx := ((0 - c) & uint32(byte(v>>bcj2NumShiftBits))) + c + ((v >> 5) & 1)
	prob := &p.probs[idx]
	ttt := uint32(*prob)
	bound := (p.rng >> bcj2NumBitModelTotalBits) * ttt
	if v&bcj2ConvFlag == 0 {
		p.rng = bound
		*prob = uint16(ttt + ((bcj2BitModelTotal - ttt) >> bcj2NumMoveBits))
		return false
	}
	p.low += uint64(bound)
	p.rng -= bound
	*prob = uint16(ttt - (ttt >> bcj2NumMoveBits))
	return true
}

// writeConv is the converted-operand step: it stores the absolute target
// into the CALL/JUMP stream. false means the stream was full and encode2
// returns with State = that stream and the target kept in tempTarget.
func (p *Bcj2Enc) writeConv(src int, v uint32) (int, uint32, bool) {
	cj := int(((v+0x57)>>6)&1) + Bcj2StreamCall
	ip := p.IP64 + 4
	v = binary.LittleEndian.Uint32(p.Src[src:]) // relat
	p.IP64 = ip
	src += 4
	absol := uint32(ip) + v
	v >>= 24
	if p.Pos[cj] == len(p.Bufs[cj]) {
		p.State = cj
		p.tempTarget = absol
		p.SrcPos = src
		p.context = byte(v)
		return src, v, false
	}
	binary.BigEndian.PutUint32(p.Bufs[cj][p.Pos[cj]:], absol)
	p.Pos[cj] += 4
	return src, v, true
}

// encodeMarker is the marker half of encode2's loop: the operand decision
// (markOperand), the range-coded conversion bit (rangeBit) and, when that
// bit says converted, the target write (writeConv). false means one of the
// three steps ended the call (it has recorded why in State); the
// not-converted case, where the SDK's continue skips the target write,
// just continues the loop.
func (p *Bcj2Enc) encodeMarker(src int, v uint32) (int, uint32, bool) {
	v, ok := p.markOperand(src, v)
	if !ok {
		return src, v, false
	}
	if !p.rangeBit(v) {
		return src, v, true
	}
	src, v, ok = p.writeConv(src, v)
	return src, v, ok
}

// finishFlush is the SDK's trailing flush: five shiftLow calls.
func (p *Bcj2Enc) finishFlush() {
	for p.flushRem != 0 {
		if p.shiftLow() {
			return
		}
		p.flushRem--
	}
	p.State = Bcj2EncStateFinished
}

// encode2 is Bcj2Enc_Encode_2 (the non-marker version the SDK builds):
// the range coder's renormalization, then the MAIN scan and the marker
// steps, carrying the loop position (the offset in Src and the marker
// word v) across the steps that can end the call.
func (p *Bcj2Enc) encode2() {
	if p.isFlushState {
		p.finishFlush()
		return
	}
	if p.writePendingConv() {
		return
	}
	p.State = Bcj2EncStateOrig
	src, v := p.SrcPos, uint32(p.context)
	for {
		var ok bool
		src, v, ok = p.renormRc(src, v)
		if !ok {
			return
		}
		var sig int
		src, v, sig = p.scanMain(src, v)
		if sig == bcj2ScanStop {
			return
		}
		if sig == bcj2ScanFlush {
			break
		}
		src, v, ok = p.encodeMarker(src, v)
		if !ok {
			return
		}
	}
	p.finishFlush()
}

// encodeWithTemp is the look-ahead-buffer path of Bcj2Enc_Encode: while
// temp holds data, temp is fed through encode2 one byte at a time from
// Src until temp's data is fully encoded. true when Encode returns now
// (for the same reason encode2 did, rolling back the extra bytes when
// possible).
func (p *Bcj2Enc) encodeWithTemp() bool {
	// extra: bytes copied from Src to temp in this call.
	var extra int
	for {
		// (0 < tempPos <= 5)
		src, srcPos := p.Src, p.SrcPos
		finishMode := p.FinishMode
		if srcPos != len(src) {
			// Data follows the look-ahead bytes: encode temp in
			// continue mode.
			p.FinishMode = Bcj2FinishContinue
		}
		p.Src = p.temp[:p.tempPos]
		p.SrcPos = 0
		p.encode2()
		num := p.SrcPos
		tempPos := p.tempPos - num
		p.tempPos = tempPos
		copy(p.temp[:tempPos], p.temp[num:num+tempPos])
		p.Src = src
		p.SrcPos = srcPos
		p.FinishMode = finishMode
		if p.State != Bcj2EncStateOrig {
			if extra >= tempPos {
				extra = tempPos
			}
			p.SrcPos = srcPos - extra
			p.tempPos = tempPos - extra
			return true
		}
		// The encoder needs more data than temp holds.
		if srcPos == len(src) {
			return true
		}
		if extra >= tempPos {
			// temp holds only data from this call's Src: encode
			// from Src directly.
			p.SrcPos = srcPos - tempPos
			p.tempPos = 0
			return false
		}
		// Append one more byte from Src to temp.
		p.temp[tempPos] = src[srcPos]
		p.tempPos = tempPos + 1
		p.SrcPos = srcPos + 1
		extra++
	}
}

// keepTailInTemp keeps up to the last 4 unprocessed input bytes in
// temp when all of Src was consumed (Bcj2Enc_Encode's tail).
func (p *Bcj2Enc) keepTailInTemp() {
	if p.State != Bcj2EncStateOrig {
		return
	}
	rem := len(p.Src) - p.SrcPos
	// (rem <= 4): keep the unprocessed tail in temp.
	if rem != 0 {
		copy(p.temp[:rem], p.Src[p.SrcPos:])
		p.SrcPos = len(p.Src)
		p.tempPos = rem
	}
}

// Encode is Bcj2Enc_Encode. At exit State < Bcj2NumStreams means that
// output stream is full, State == Bcj2EncStateOrig that all of Src was
// consumed (up to 4 bytes may be held in the look-ahead buffer), and
// State == Bcj2EncStateFinished that the stream is complete and flushed.
func (p *Bcj2Enc) Encode() {
	if p.tempPos != 0 && p.encodeWithTemp() {
		return
	}
	// (tempPos == 0)
	p.encode2()
	p.keepTailInTemp()
}

// Bcj2Dec is CBcj2Dec. Bufs[i][Pos[i]:] is the unread part of input
// stream i; Dest[DestPos:] is the free output.
type Bcj2Dec struct {
	Bufs    [Bcj2NumStreams][]byte
	Pos     [Bcj2NumStreams]int
	Dest    []byte
	DestPos int

	State int // Bcj2StreamMain has priority over Bcj2DecStateOrig

	IP    uint32 // starting base for decoding (property)
	temp  uint32
	rng   uint32
	code  uint32
	probs [2 + 256]uint16
}

// Init is Bcj2Dec_Init (it sets IP to 0; set IP after Init when the
// stream was encoded with a non-zero start address).
func (p *Bcj2Dec) Init() {
	p.State = Bcj2StreamRC
	p.IP = 0
	p.temp = 0
	p.rng = 0
	p.code = 0
	for i := range p.probs {
		p.probs[i] = uint16(bcj2BitModelTotal >> 1)
	}
}

// IsMaybeFinished is Bcj2Dec_IsMaybeFinished: an additional check after
// the sizes of the processed streams have been verified.
func (p *Bcj2Dec) IsMaybeFinished() bool { return p.State == Bcj2StreamMain && p.code == 0 }

// decInitRc is Bcj2Dec_Decode's initial RC fill when rng <= 5: the first
// five RC bytes must be valid (a zero byte at position 1 or the all-ones
// stream is SZ_ERROR_DATA). Return: -1 data error, 1 resume at the RC
// stream, 0 continue.
func (p *Bcj2Dec) decInitRc() int {
	if p.rng > 5 {
		return 0
	}
	code := p.code
	p.State = Bcj2DecStateError
	for ; p.rng != 5; p.rng++ {
		if p.rng == 1 && code != 0 {
			return -1
		}
		if p.Pos[Bcj2StreamRC] == len(p.Bufs[Bcj2StreamRC]) {
			p.State = Bcj2StreamRC
			return 1
		}
		code = (code << 8) | uint32(p.Bufs[Bcj2StreamRC][p.Pos[Bcj2StreamRC]])
		p.Pos[Bcj2StreamRC]++
		p.code = code
	}
	if code == 0xffffffff {
		return -1
	}
	p.rng = 0xffffffff
	return 0
}

// writeVBytes resumes a CALL/JUMP target that was cut across a buffer
// boundary (states Bcj2DecStateOrig0..3): up to 4 bytes of temp go to
// Dest. false means Dest filled first and the resume state is recorded.
func (p *Bcj2Dec) writeVBytes(v uint32, state int) (uint32, bool) {
	dest := p.DestPos
	for {
		if dest == len(p.Dest) {
			p.State = state
			p.temp = v
			return v, false
		}
		p.Dest[dest] = byte(v)
		dest++
		p.DestPos = dest
		state++
		if state == Bcj2DecStateOrig3+1 {
			break
		}
		v >>= 8
	}
	return v, true
}

// decHead reads the pending state at Decode's entry: a CALL/JUMP stream
// target (32-bit states) or the tail of a split target. false means
// Decode returns nil with the resume state recorded.
func (p *Bcj2Dec) decHead(v uint32) (uint32, bool) {
	state := p.State
	if isBcj2Stream32(state) {
		if p.Pos[state] == len(p.Bufs[state]) {
			return v, false
		}
		cur := p.Bufs[state][p.Pos[state]:]
		p.Pos[state] += 4
		ip := p.IP + 4
		v = binary.BigEndian.Uint32(cur) - ip
		p.IP = ip
		state = Bcj2DecStateOrig0
	}
	if uint(state-Bcj2DecStateOrig0) < 4 {
		var cont bool
		v, cont = p.writeVBytes(v, state)
		if !cont {
			return v, false
		}
	}
	return v, true
}

// oneIter is ONE_ITER(indx): it returns true when b is a marker byte
// (e8, e9, or 8x after 0f).
func (p *Bcj2Dec) oneIter(mainBuf []byte, src, indx int, dest *int, v *uint32) bool {
	b := uint32(mainBuf[src+indx])
	p.Dest[*dest] = byte(b)
	*dest += 1
	*v = (*v << bcj2NumShiftBits) | b
	if ((b + (0x100 - 0xe8)) & 0xfe) == 0 {
		return true
	}
	if ((*v - ((uint32(0x0f) << bcj2NumShiftBits) + 0x80)) &
		(((uint32(1) << (4 + bcj2NumShiftBits)) - 0x1) << 4)) == 0 {
		return true
	}
	return false
}

// scanBlock1 copies the main stream up to the scan limit four bytes at
// a time (NUM_ITERS = 4).
func (p *Bcj2Dec) scanBlock1(mainBuf []byte, src, dest, srcLim int, v uint32) (int, int, uint32) {
	for {
		if p.oneIter(mainBuf, src, 0, &dest, &v) || p.oneIter(mainBuf, src, 1, &dest, &v) ||
			p.oneIter(mainBuf, src, 2, &dest, &v) || p.oneIter(mainBuf, src, 3, &dest, &v) {
			break
		}
		src += 4
		if src == srcLim {
			break
		}
	}
	return src, dest, v
}

// decScanTail copies single bytes past the scan limit until a marker is
// found (true) or a stream end records the resume state (false).
func (p *Bcj2Dec) decScanTail(mainBuf []byte, src, dest int, v uint32) (int, int, uint32, bool) {
	for {
		if src == len(mainBuf) || dest == len(p.Dest) {
			num := src - p.Pos[Bcj2StreamMain]
			p.Pos[Bcj2StreamMain] = src
			p.DestPos = dest
			p.IP += uint32(num)
			// State Bcj2StreamMain has priority over Bcj2DecStateOrig.
			if src == len(mainBuf) {
				p.State = Bcj2StreamMain
			} else {
				p.State = Bcj2DecStateOrig
			}
			p.temp = v
			return src, dest, v, false
		}
		if p.oneIter(mainBuf, src, 0, &dest, &v) {
			break
		}
		src++
	}
	return src, dest, v, true
}

// decScan is the main-stream scan of Bcj2Dec_Decode's loop: it copies
// MAIN to Dest up to a marker or a stream end and commits the consumed
// counts. Return: (v, signal) with signal 0 = Decode returns nil (the
// resume state is recorded on p), 1 = a marker was found.
func (p *Bcj2Dec) decScan(v uint32) (uint32, int) {
	mainBuf := p.Bufs[Bcj2StreamMain]
	src := p.Pos[Bcj2StreamMain]
	dest := p.DestPos
	{
		rem := len(mainBuf) - src
		num := min(len(p.Dest)-dest, rem)
		num &^= 4 - 1 // numItems = 4
		srcLim := src + num
		if src != srcLim {
			src, dest, v = p.scanBlock1(mainBuf, src, dest, srcLim, v)
		}
		if src == srcLim {
			var found bool
			src, dest, v, found = p.decScanTail(mainBuf, src, dest, v)
			if !found {
				return v, 0
			}
		}
	}
	{
		num := dest - p.DestPos
		p.DestPos = dest
		p.Pos[Bcj2StreamMain] += num
		p.IP += uint32(num)
	}
	return v, 1
}

// decRangeBit is the range-coding test of the conversion flag: false
// when the operand was not converted (continue the loop).
func (p *Bcj2Dec) rangeBit(v uint32) bool {
	c := ((v + 0x17) >> 6) & 1
	prob := &p.probs[((0-c)&uint32(byte(v>>bcj2NumShiftBits)))+c+((v>>5)&1)]
	ttt := uint32(*prob)
	bound := (p.rng >> bcj2NumBitModelTotalBits) * ttt
	if p.code < bound {
		p.rng = bound
		*prob = uint16(ttt + ((bcj2BitModelTotal - ttt) >> bcj2NumMoveBits))
		return false
	}
	p.rng -= bound
	p.code -= bound
	*prob = uint16(ttt - (ttt >> bcj2NumMoveBits))
	return true
}

// writePartialAbsol writes the operand bytes of a converted target that
// fit at Dest and records the rest as the Bcj2DecStateOrig0+rem resume
// state.
func (p *Bcj2Dec) writePartialAbsol(v uint32, dest, rem int) uint32 {
	if rem > 0 {
		p.Dest[dest] = byte(v)
		v >>= 8
		if rem > 1 {
			p.Dest[dest+1] = byte(v)
			v >>= 8
			if rem > 2 {
				p.Dest[dest+2] = byte(v)
				v >>= 8
			}
		}
	}
	p.temp = v
	p.DestPos = dest + rem
	p.State = Bcj2DecStateOrig0 + rem
	return v
}

// decAbsol reads one converted absolute target from the CALL/JUMP stream
// and writes it to Dest. false means the loop ends with the resume
// state recorded on p.
func (p *Bcj2Dec) decAbsol(v uint32) (uint32, bool) {
	cj := int(((v+0x57)>>6)&1) + Bcj2StreamCall
	if p.Pos[cj] == len(p.Bufs[cj]) {
		p.State = cj
		return v, false
	}
	v = binary.BigEndian.Uint32(p.Bufs[cj][p.Pos[cj]:])
	p.Pos[cj] += 4
	ip := p.IP + 4
	v -= ip
	p.IP = ip
	dest := p.DestPos
	rem := len(p.Dest) - dest
	if rem < 4 {
		return p.writePartialAbsol(v, dest, rem), false
	}
	binary.LittleEndian.PutUint32(p.Dest[dest:], v)
	v >>= 24
	p.DestPos = dest + 4
	return v, true
}

// decFillRc normalizes the range coder in the loop; false when the RC
// stream is exhausted (it records the stop state on p).
func (p *Bcj2Dec) decFillRc(v uint32) bool {
	if p.rng >= bcj2TopValue {
		return true
	}
	if p.Pos[Bcj2StreamRC] == len(p.Bufs[Bcj2StreamRC]) {
		p.State = Bcj2StreamRC
		p.temp = v
		return false
	}
	p.rng <<= 8
	p.code = (p.code << 8) | uint32(p.Bufs[Bcj2StreamRC][p.Pos[Bcj2StreamRC]])
	p.Pos[Bcj2StreamRC]++
	return true
}

// decFillFinalRc is Decode's post-loop step: one more RC byte is read
// when both the range coder needs it and the stream has it.
func (p *Bcj2Dec) decFillFinalRc() {
	if p.rng < bcj2TopValue && p.Pos[Bcj2StreamRC] != len(p.Bufs[Bcj2StreamRC]) {
		p.rng <<= 8
		p.code = (p.code << 8) | uint32(p.Bufs[Bcj2StreamRC][p.Pos[Bcj2StreamRC]])
		p.Pos[Bcj2StreamRC]++
	}
}

// Decode is Bcj2Dec_Decode. It returns ErrBcj2Data when the first 5
// bytes of the RC stream are not valid.
func (p *Bcj2Dec) Decode() error {
	v := p.temp
	switch p.decInitRc() {
	case -1:
		return ErrBcj2Data
	case 1:
		return nil
	}
	var cont bool
	v, cont = p.decHead(v)
	if !cont {
		return nil
	}
	for {
		if !p.decFillRc(v) {
			return nil
		}
		var sig int
		v, sig = p.decScan(v)
		if sig == 0 {
			return nil
		}
		if !p.rangeBit(v) {
			continue
		}
		v, cont = p.decAbsol(v)
		if !cont {
			break
		}
	}
	p.decFillFinalRc()
	return nil
}

// Bcj2Encoder drives Bcj2Enc over whole buffers or streams the way
// 7-Zip's BCJ2 coder does. The input is a sequence of files: each file
// starts at its own address (the offset of its first byte in the
// stream) and has its own size, so branches whose absolute target falls
// outside the file are left unconverted, and the block is finished at
// every file boundary (Bcj2FinishEndBlock) so that no marker's operand
// is read across it (observed on both SoTs: a solid block of three
// slices of a PE converts differently from the same bytes as one file,
// and only this reproduces it). The relative-offset limit is the SDK's
// default unless RelatLimit is set.
type Bcj2Encoder struct {
	// FileSizes are the sizes of the consecutive files in the input,
	// for Encode. When nil, the whole input is one file of FileSize.
	FileSizes []uint64
	// FileSize is the size of the single file when FileSizes is nil; 0
	// means unlimited (Bcj2FileSizeUnlimited).
	FileSize uint64
	// RelatLimit is CBcj2Enc::relatLimit; zero selects the default.
	RelatLimit uint32
}

// bcj2OutChunk is the output buffer size per stream for streaming use.
const bcj2OutChunk = 1 << 16

// ErrBcj2ShortInput is returned by Encode when r ends before the files
// in FileSizes do.
var ErrBcj2ShortInput = errors.New("bcj2: input shorter than the file sizes")

// bcj2FinishModeFor selects the finish mode at a chunk end of a file
// of bounded size: Continue while bytes remain, otherwise EndStream
// for the last file and EndBlock for the others.
func bcj2FinishModeFor(rem uint64, last bool) Bcj2FinishMode {
	if rem > 0 {
		return Bcj2FinishContinue
	}
	if last {
		return Bcj2FinishEndStream
	}
	return Bcj2FinishEndBlock
}

// bcj2UnlimitedMode is the finish mode for an unlimited-length file:
// the read's EOF ends the stream.
func bcj2UnlimitedMode(n int) Bcj2FinishMode {
	if n == 0 {
		return Bcj2FinishEndStream
	}
	return Bcj2FinishContinue
}

// bcj2Driver drives one Bcj2Enc over output writers with a chunk
// buffer, the way Bcj2Encoder.Encode does.
type bcj2Driver struct {
	p    *Bcj2Enc
	outs [Bcj2NumStreams]io.Writer
	in   []byte
}

// readBcj2Chunk reads one chunk, skipping empty reads.
func readBcj2Chunk(r io.Reader, buf []byte) (int, error) {
	n, err := r.Read(buf)
	for n == 0 && err == nil {
		n, err = r.Read(buf)
	}
	return n, err
}

// nextChunk reads the next chunk of one file and selects the finish
// mode at its end (ErrBcj2ShortInput when the input runs out first).
func (d *bcj2Driver) nextChunk(r io.Reader, rem uint64, unlimited, last bool) (int, uint64, Bcj2FinishMode, error) {
	want := len(d.in)
	if !unlimited && uint64(want) > rem {
		want = int(rem)
	}
	n := 0
	if want > 0 {
		var e error
		n, e = readBcj2Chunk(r, d.in[:want])
		if e != nil && !errors.Is(e, io.EOF) {
			return n, rem, Bcj2FinishContinue, e
		}
	}
	if unlimited {
		return n, rem, bcj2UnlimitedMode(n), nil
	}
	rem -= uint64(n)
	if n == 0 && rem > 0 {
		return n, rem, Bcj2FinishContinue, ErrBcj2ShortInput
	}
	return n, rem, bcj2FinishModeFor(rem, last), nil
}

// run drives the encoder until it needs more input or has finished,
// flushing a full output stream when the encoder stops on it and
// flushing all streams at the end of the file.
func (d *bcj2Driver) run() error {
	for {
		d.p.Encode()
		if d.p.State < Bcj2NumStreams {
			if _, err := d.outs[d.p.State].Write(d.p.Bufs[d.p.State][:d.p.Pos[d.p.State]]); err != nil {
				return err
			}
			d.p.Pos[d.p.State] = 0
			continue
		}
		if d.p.State == Bcj2EncStateFinished {
			return d.flushAll()
		}
		return nil
	}
}

// flushAll writes the tails of all four output streams.
func (d *bcj2Driver) flushAll() error {
	for i := range d.outs {
		if d.p.Pos[i] > 0 {
			if _, err := d.outs[i].Write(d.p.Bufs[i][:d.p.Pos[i]]); err != nil {
				return err
			}
			d.p.Pos[i] = 0
		}
	}
	return nil
}

// encodeFile converts one file's bytes: its own virtual start address
// and size, then chunks until the file's boundary finish mode is
// reached.
func (d *bcj2Driver) encodeFile(r io.Reader, size, start uint64, last, unlimited bool) error {
	p := d.p
	p.FileIP64 = start
	if unlimited {
		p.FileSize64Minus1 = Bcj2FileSizeUnlimited
	} else {
		p.SetFileSize(size)
	}
	rem := size
	for {
		var n int
		var mode Bcj2FinishMode
		var err error
		n, rem, mode, err = d.nextChunk(r, rem, unlimited, last)
		if err != nil {
			return err
		}
		p.Src, p.SrcPos = d.in[:n], 0
		p.FinishMode = mode
		if err := d.run(); err != nil {
			return err
		}
		if p.State == Bcj2EncStateFinished {
			return nil
		}
		if p.FinishMode == Bcj2FinishEndBlock {
			// The block is finished (state Orig, all of Src consumed).
			break
		}
		if p.FinishMode == Bcj2FinishEndStream {
			return errors.New("bcj2: encoder stalled at end of stream")
		}
	}
	return nil
}

// Encode reads all of r and writes the four streams to outs (in the
// order Bcj2StreamMain, Bcj2StreamCall, Bcj2StreamJump, Bcj2StreamRC).
// Input is consumed in chunks with the look-ahead buffer carried
// between them, so the output does not depend on the chunking; only
// the file boundaries (FileSizes) matter.
func (e *Bcj2Encoder) Encode(outs [Bcj2NumStreams]io.Writer, r io.Reader) error {
	var p Bcj2Enc
	p.Init()
	if e.RelatLimit != 0 {
		p.RelatLimit = e.RelatLimit
	}
	for i := range p.Bufs {
		p.Bufs[i] = make([]byte, bcj2OutChunk)
	}
	sizes := e.FileSizes
	unlimited := false
	if sizes == nil {
		if e.FileSize == 0 {
			unlimited = true
		}
		sizes = []uint64{e.FileSize}
	}
	d := bcj2Driver{p: &p, outs: outs, in: make([]byte, 1<<16)}
	start := uint64(0)
	for fi, size := range sizes {
		if err := d.encodeFile(r, size, start, fi == len(sizes)-1, unlimited); err != nil {
			return err
		}
		start += size
	}
	return nil
}

// EncodeBytes converts src and returns the four streams.
func (e *Bcj2Encoder) EncodeBytes(src []byte) [Bcj2NumStreams][]byte {
	if e.FileSizes != nil {
		return e.encodeBytesViaStreams(src)
	}
	return e.encodeBytesDirect(src)
}

// encodeBytesViaStreams converts src through Encode with the four
// streams buffered in memory.
func (e *Bcj2Encoder) encodeBytesViaStreams(src []byte) [Bcj2NumStreams][]byte {
	var bufs [Bcj2NumStreams]bytes.Buffer
	var outs [Bcj2NumStreams]io.Writer
	for i := range bufs {
		outs[i] = &bufs[i]
	}
	if err := e.Encode(outs, bytes.NewReader(src)); err != nil {
		panic(err)
	}
	var out [Bcj2NumStreams][]byte
	for i := range bufs {
		out[i] = bufs[i].Bytes()
	}
	return out
}

// encodeBytesDirect converts src with one Bcj2Enc sized for the input,
// doubling a stream's buffer when it fills. MAIN never exceeds the input;
// CALL and JUMP hold at most 4 bytes per 5 of input; RC is small but is
// grown on demand.
func (e *Bcj2Encoder) encodeBytesDirect(src []byte) [Bcj2NumStreams][]byte {
	var p Bcj2Enc
	p.Init()
	if e.FileSize != 0 {
		p.SetFileSize(e.FileSize)
	}
	if e.RelatLimit != 0 {
		p.RelatLimit = e.RelatLimit
	}
	var out [Bcj2NumStreams][]byte
	p.Bufs[Bcj2StreamMain] = make([]byte, len(src))
	p.Bufs[Bcj2StreamCall] = make([]byte, (len(src)/5+1)*4)
	p.Bufs[Bcj2StreamJump] = make([]byte, (len(src)/5+1)*4)
	p.Bufs[Bcj2StreamRC] = make([]byte, len(src)/16+64)
	p.Src, p.SrcPos = src, 0
	p.FinishMode = Bcj2FinishEndStream
	for {
		p.Encode()
		if p.State == Bcj2EncStateFinished {
			break
		}
		if p.State >= Bcj2NumStreams {
			panic("bcj2: encoder stopped without output pressure")
		}
		s := p.State
		grown := make([]byte, len(p.Bufs[s])*2+64)
		copy(grown, p.Bufs[s][:p.Pos[s]])
		p.Bufs[s] = grown
	}
	for i := range out {
		out[i] = p.Bufs[i][:p.Pos[i]]
	}
	return out
}

// Bcj2EncodeBytes converts src with the defaults 7-Zip uses for a
// stream of known size (see Bcj2Encoder).
func Bcj2EncodeBytes(src []byte) [Bcj2NumStreams][]byte {
	e := Bcj2Encoder{FileSize: uint64(len(src))}
	return e.EncodeBytes(src)
}

// Bcj2DecodeBytes reassembles the original from the four streams the
// way 7zDec.c does: outSize must equal the sum of the MAIN, CALL and
// JUMP sizes, every stream must be consumed exactly, and the range coder
// must end cleanly; anything else is ErrBcj2Data.
func Bcj2DecodeBytes(streams [Bcj2NumStreams][]byte, outSize int) ([]byte, error) {
	if len(streams[Bcj2StreamCall])&3 != 0 || len(streams[Bcj2StreamJump])&3 != 0 ||
		len(streams[Bcj2StreamMain])+len(streams[Bcj2StreamCall])+len(streams[Bcj2StreamJump]) != outSize {
		return nil, ErrBcj2Data
	}
	var p Bcj2Dec
	p.Bufs = streams
	p.Dest = make([]byte, outSize)
	p.Init()
	if err := p.Decode(); err != nil {
		return nil, err
	}
	for i := range p.Bufs {
		if p.Pos[i] != len(p.Bufs[i]) {
			return nil, ErrBcj2Data
		}
	}
	if p.DestPos != len(p.Dest) || !p.IsMaybeFinished() {
		return nil, ErrBcj2Data
	}
	return p.Dest, nil
}
