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
// chunked.

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

// Decoder states beyond the four streams (BCJ2_DEC_STATE_*).
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

// encode2 is Bcj2Enc_Encode_2 (the non-marker version the SDK builds).
func (p *Bcj2Enc) encode2() {
	if !p.isFlushState {
		{
			state := p.State
			if isBcj2Stream32(state) {
				if p.Pos[state] == len(p.Bufs[state]) {
					return
				}
				binary.BigEndian.PutUint32(p.Bufs[state][p.Pos[state]:], p.tempTarget)
				p.Pos[state] += 4
			}
		}
		p.State = Bcj2EncStateOrig
		src := p.SrcPos
		v := uint32(p.context)
		in := p.Src
		main := p.Bufs[Bcj2StreamMain]

		for {
			var ip uint64
			if p.rng < bcj2TopValue {
				p.SrcPos = src
				p.context = byte(v)
				if p.shiftLow() {
					return
				}
				p.rng <<= 8
				src = p.SrcPos
				v = uint32(p.context)
			}
			{
				dest := p.Pos[Bcj2StreamMain]
				destStart := dest
				remSrc := len(in) - src
				rem := len(main) - dest
				if rem >= remSrc {
					rem = remSrc
				}
				srcLim := src + rem
				// p.context holds the previous byte in bits 0..7.
				if src != srcLim {
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
				}
				ip = p.IP64 + uint64(dest-destStart)
				p.Pos[Bcj2StreamMain] = dest
				p.IP64 = ip

				if src == srcLim {
					p.SrcPos = src
					p.context = byte(v)
					if src != len(in) {
						p.State = Bcj2StreamMain
						return
					}
					if p.FinishMode != Bcj2FinishEndStream {
						return
					}
					p.isFlushState = true
					break
				}
				src++
			}
			// A marker was found: v holds src[-2] in bits 24..31
			// (xx/xx/0f) and src[-1] in bits 0..7 (e8/e9/8x).
			if len(in)-src >= 4 {
				relat := binary.LittleEndian.Uint32(in[src:])
				ip -= p.FileIP64
				// 23.00: no conversion across a block boundary for (0f 80) and (e8/e9).
				if ip > uint64(((v+0x20)>>5)&1) {
					if uint64(int64(ip)+4+int64(int32(relat))) <= p.FileSize64Minus1 {
						if ((relat + p.RelatLimit) >> 1) < p.RelatLimit {
							v |= bcj2ConvFlag
						}
					}
				}
			} else if p.FinishMode == Bcj2FinishContinue {
				// Fewer than 4 bytes follow the marker: give the marker
				// byte back and wait for more input.
				p.IP64--
				p.Pos[Bcj2StreamMain]--
				src--
				v >>= bcj2NumShiftBits
				p.SrcPos = src
				p.context = byte(v)
				return
			}
			{
				c := ((v + 0x17) >> 6) & 1
				idx := ((0 - c) & uint32(byte(v>>bcj2NumShiftBits))) + c + ((v >> 5) & 1)
				prob := &p.probs[idx]
				ttt := uint32(*prob)
				bound := (p.rng >> bcj2NumBitModelTotalBits) * ttt
				if v&bcj2ConvFlag == 0 {
					p.rng = bound
					*prob = uint16(ttt + ((bcj2BitModelTotal - ttt) >> bcj2NumMoveBits))
					continue
				}
				p.low += uint64(bound)
				p.rng -= bound
				*prob = uint16(ttt - (ttt >> bcj2NumMoveBits))
			}
			{
				cj := int(((v+0x57)>>6)&1) + Bcj2StreamCall
				ip = p.IP64
				v = binary.LittleEndian.Uint32(in[src:]) // relat
				ip += 4
				p.IP64 = ip
				src += 4
				absol := uint32(ip) + v
				v >>= 24
				if p.Pos[cj] == len(p.Bufs[cj]) {
					p.State = cj
					p.tempTarget = absol
					p.SrcPos = src
					p.context = byte(v)
					return
				}
				binary.BigEndian.PutUint32(p.Bufs[cj][p.Pos[cj]:], absol)
				p.Pos[cj] += 4
			}
		}
	}

	for p.flushRem != 0 {
		if p.shiftLow() {
			return
		}
		p.flushRem--
	}
	p.State = Bcj2EncStateFinished
}

// Encode is Bcj2Enc_Encode. At exit State < Bcj2NumStreams means that
// output stream is full, State == Bcj2EncStateOrig that all of Src was
// consumed (up to 4 bytes may be held in the look-ahead buffer), and
// State == Bcj2EncStateFinished that the stream is complete and flushed.
func (p *Bcj2Enc) Encode() {
	if p.tempPos != 0 {
		// extra: bytes copied from Src to temp in this call.
		extra := 0
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
			{
				num := p.SrcPos
				tempPos := p.tempPos - num
				p.tempPos = tempPos
				copy(p.temp[:tempPos], p.temp[num:num+tempPos])
				p.Src = src
				p.SrcPos = srcPos
				p.FinishMode = finishMode
				if p.State != Bcj2EncStateOrig {
					// Exit for the same reason encode2 did, rolling
					// back the extra bytes when possible.
					if extra >= tempPos {
						extra = tempPos
					}
					p.SrcPos = srcPos - extra
					p.tempPos = tempPos - extra
					return
				}
				// The encoder needs more data than temp holds.
				if srcPos == len(src) {
					return
				}
				if extra >= tempPos {
					// temp holds only data from this call's Src: encode
					// from Src directly.
					p.SrcPos = srcPos - tempPos
					p.tempPos = 0
					break
				}
				// Append one more byte from Src to temp.
				p.temp[tempPos] = src[srcPos]
				p.tempPos = tempPos + 1
				p.SrcPos = srcPos + 1
				extra++
			}
		}
	}

	// (tempPos == 0)
	p.encode2()

	if p.State == Bcj2EncStateOrig {
		rem := len(p.Src) - p.SrcPos
		// (rem <= 4): keep the unprocessed tail in temp.
		if rem != 0 {
			copy(p.temp[:rem], p.Src[p.SrcPos:])
			p.SrcPos = len(p.Src)
			p.tempPos = rem
		}
	}
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

// Decode is Bcj2Dec_Decode. It returns ErrBcj2Data when the first 5
// bytes of the RC stream are not valid.
func (p *Bcj2Dec) Decode() error {
	v := p.temp
	if p.rng <= 5 {
		code := p.code
		p.State = Bcj2DecStateError
		for ; p.rng != 5; p.rng++ {
			if p.rng == 1 && code != 0 {
				return ErrBcj2Data
			}
			if p.Pos[Bcj2StreamRC] == len(p.Bufs[Bcj2StreamRC]) {
				p.State = Bcj2StreamRC
				return nil
			}
			code = (code << 8) | uint32(p.Bufs[Bcj2StreamRC][p.Pos[Bcj2StreamRC]])
			p.Pos[Bcj2StreamRC]++
			p.code = code
		}
		if code == 0xffffffff {
			return ErrBcj2Data
		}
		p.rng = 0xffffffff
	}
	{
		state := p.State
		if isBcj2Stream32(state) {
			if p.Pos[state] == len(p.Bufs[state]) {
				return nil
			}
			cur := p.Bufs[state][p.Pos[state]:]
			p.Pos[state] += 4
			ip := p.IP + 4
			v = binary.BigEndian.Uint32(cur) - ip
			p.IP = ip
			state = Bcj2DecStateOrig0
		}
		if uint(state-Bcj2DecStateOrig0) < 4 {
			dest := p.DestPos
			for {
				if dest == len(p.Dest) {
					p.State = state
					p.temp = v
					return nil
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
		}
	}

	mainBuf := p.Bufs[Bcj2StreamMain]
	for {
		if p.rng < bcj2TopValue {
			if p.Pos[Bcj2StreamRC] == len(p.Bufs[Bcj2StreamRC]) {
				p.State = Bcj2StreamRC
				p.temp = v
				return nil
			}
			p.rng <<= 8
			p.code = (p.code << 8) | uint32(p.Bufs[Bcj2StreamRC][p.Pos[Bcj2StreamRC]])
			p.Pos[Bcj2StreamRC]++
		}
		{
			src := p.Pos[Bcj2StreamMain]
			dest := p.DestPos
			var srcLim int
			{
				rem := len(mainBuf) - src
				num := len(p.Dest) - dest
				if num >= rem {
					num = rem
				}
				num &^= 4 - 1 // NUM_ITERS = 4
				srcLim = src + num
			}
			// oneIter is ONE_ITER(indx): it returns true when b is a
			// marker byte (e8, e9, or 8x after 0f).
			oneIter := func(indx int) bool {
				b := uint32(mainBuf[src+indx])
				p.Dest[dest] = byte(b)
				dest++
				v = (v << bcj2NumShiftBits) | b
				if ((b + (0x100 - 0xe8)) & 0xfe) == 0 {
					return true
				}
				if ((v - ((uint32(0x0f) << bcj2NumShiftBits) + 0x80)) &
					(((uint32(1) << (4 + bcj2NumShiftBits)) - 0x1) << 4)) == 0 {
					return true
				}
				return false
			}
			if src != srcLim {
				for {
					if oneIter(0) || oneIter(1) || oneIter(2) || oneIter(3) {
						break
					}
					src += 4
					if src == srcLim {
						break
					}
				}
			}
			if src == srcLim {
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
						return nil
					}
					if oneIter(0) {
						break
					}
					src++
				}
			}
			{
				num := dest - p.DestPos
				p.DestPos = dest
				p.Pos[Bcj2StreamMain] += num
				p.IP += uint32(num)
			}
			{
				c := ((v + 0x17) >> 6) & 1
				prob := &p.probs[((0-c)&uint32(byte(v>>bcj2NumShiftBits)))+c+((v>>5)&1)]
				ttt := uint32(*prob)
				bound := (p.rng >> bcj2NumBitModelTotalBits) * ttt
				if p.code < bound {
					p.rng = bound
					*prob = uint16(ttt + ((bcj2BitModelTotal - ttt) >> bcj2NumMoveBits))
					continue
				}
				p.rng -= bound
				p.code -= bound
				*prob = uint16(ttt - (ttt >> bcj2NumMoveBits))
			}
		}
		{
			cj := int(((v+0x57)>>6)&1) + Bcj2StreamCall
			if p.Pos[cj] == len(p.Bufs[cj]) {
				p.State = cj
				break
			}
			v = binary.BigEndian.Uint32(p.Bufs[cj][p.Pos[cj]:])
			p.Pos[cj] += 4
			{
				ip := p.IP + 4
				v -= ip
				p.IP = ip
			}
			dest := p.DestPos
			rem := len(p.Dest) - dest
			if rem < 4 {
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
				break
			}
			binary.LittleEndian.PutUint32(p.Dest[dest:], v)
			v >>= 24
			p.DestPos = dest + 4
		}
	}

	if p.rng < bcj2TopValue && p.Pos[Bcj2StreamRC] != len(p.Bufs[Bcj2StreamRC]) {
		p.rng <<= 8
		p.code = (p.code << 8) | uint32(p.Bufs[Bcj2StreamRC][p.Pos[Bcj2StreamRC]])
		p.Pos[Bcj2StreamRC]++
	}
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
	in := make([]byte, 1<<16)

	// run drives the encoder over p.Src until it needs more input or
	// has finished.
	run := func() error {
		for {
			p.Encode()
			switch {
			case p.State < Bcj2NumStreams:
				if _, err := outs[p.State].Write(p.Bufs[p.State][:p.Pos[p.State]]); err != nil {
					return err
				}
				p.Pos[p.State] = 0
			case p.State == Bcj2EncStateFinished:
				for i := range outs {
					if p.Pos[i] > 0 {
						if _, err := outs[i].Write(p.Bufs[i][:p.Pos[i]]); err != nil {
							return err
						}
						p.Pos[i] = 0
					}
				}
				return nil
			default:
				return nil
			}
		}
	}

	sizes := e.FileSizes
	unlimited := false
	if sizes == nil {
		if e.FileSize == 0 {
			unlimited = true
		}
		sizes = []uint64{e.FileSize}
	}
	start := uint64(0)
	for fi, size := range sizes {
		last := fi == len(sizes)-1
		p.FileIP64 = start
		if unlimited {
			p.FileSize64Minus1 = Bcj2FileSizeUnlimited
		} else {
			p.SetFileSize(size)
		}
		rem := size
		for {
			want := len(in)
			if !unlimited && uint64(want) > rem {
				want = int(rem)
			}
			n := 0
			var err error
			if want > 0 {
				n, err = r.Read(in[:want])
				for n == 0 && err == nil {
					n, err = r.Read(in[:want])
				}
				if err != nil && err != io.EOF {
					return err
				}
			}
			p.Src, p.SrcPos = in[:n], 0
			if unlimited {
				if n == 0 {
					p.FinishMode = Bcj2FinishEndStream
				} else {
					p.FinishMode = Bcj2FinishContinue
				}
			} else {
				rem -= uint64(n)
				if n == 0 && rem > 0 {
					return ErrBcj2ShortInput
				}
				switch {
				case rem > 0:
					p.FinishMode = Bcj2FinishContinue
				case last:
					p.FinishMode = Bcj2FinishEndStream
				default:
					p.FinishMode = Bcj2FinishEndBlock
				}
			}
			if err := run(); err != nil {
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
		start += size
	}
	return nil
}

// EncodeBytes converts src and returns the four streams.
func (e *Bcj2Encoder) EncodeBytes(src []byte) [Bcj2NumStreams][]byte {
	if e.FileSizes != nil {
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
	var p Bcj2Enc
	p.Init()
	if e.FileSize != 0 {
		p.SetFileSize(e.FileSize)
	}
	if e.RelatLimit != 0 {
		p.RelatLimit = e.RelatLimit
	}
	var out [Bcj2NumStreams][]byte
	// MAIN never exceeds the input; CALL and JUMP hold at most 4 bytes
	// per 5 of input; RC is small but is grown on demand.
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
