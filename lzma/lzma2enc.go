package lzma

// Port of reference/7zip/C/Lzma2Enc.c (26.05, public domain): the LZMA2
// chunk layer over the LZMA encoder. The block-threaded path of the C code
// (MtCoder) encodes independent blocks whose outputs are concatenated in
// order; here the same blocks are encoded sequentially with the same
// per-block setup (direct input, expected size = block size), so the bytes
// are identical to the multithreaded oracle's.

import "io"

const (
	lzma2ControlLzma        = 1 << 7
	lzma2ControlCopyNoReset = 2
	lzma2ControlCopyReset   = 1
	lzma2ControlEOF         = 0

	lzma2PackSizeMax            = 1 << 16
	lzma2CopyChunkSize          = lzma2PackSizeMax
	lzma2UnpackSizeMax          = 1 << 21
	lzma2KeepWindowSize         = lzma2UnpackSizeMax
	lzma2ChunkSizeCompressedMax = (1 << 16) + 16

	mtCoderThreadsMax = 256

	// Lzma2BlockSizeAuto / Lzma2BlockSizeSolid are the BlockSize values
	// LZMA2_ENC_PROPS_BLOCK_SIZE_AUTO and _SOLID.
	Lzma2BlockSizeAuto  = uint64(0)
	Lzma2BlockSizeSolid = ^uint64(0)
)

func lzma2DicSizeFromProp(p uint32) uint32 { return (2 | (p & 1)) << (p/2 + 11) }

// Lzma2EncProps is CLzma2EncProps.
type Lzma2EncProps struct {
	LzmaProps              EncProps
	BlockSize              uint64
	NumBlockThreadsReduced int
	NumBlockThreadsMax     int
	NumTotalThreads        int
}

// Init is Lzma2EncProps_Init.
func (p *Lzma2EncProps) Init() {
	p.LzmaProps.Init()
	p.BlockSize = Lzma2BlockSizeAuto
	p.NumBlockThreadsReduced = -1
	p.NumBlockThreadsMax = -1
	p.NumTotalThreads = -1
}

// Normalize is Lzma2EncProps_Normalize.
func (p *Lzma2EncProps) Normalize() {
	var t1n int
	{
		lzmaProps := p.LzmaProps
		lzmaProps.Normalize()
		t1n = lzmaProps.NumThreads
	}
	t1 := p.LzmaProps.NumThreads
	t2 := p.NumBlockThreadsMax
	t3 := p.NumTotalThreads

	if t2 > mtCoderThreadsMax {
		t2 = mtCoderThreadsMax
	}
	if t3 <= 0 {
		if t2 <= 0 {
			t2 = 1
		}
		t3 = t1n * t2
	} else if t2 <= 0 {
		t2 = t3 / t1n
		if t2 == 0 {
			t1 = 1
			t2 = t3
		}
		if t2 > mtCoderThreadsMax {
			t2 = mtCoderThreadsMax
		}
	} else if t1 <= 0 {
		t1 = t3 / t2
		if t1 == 0 {
			t1 = 1
		}
	} else {
		t3 = t1n * t2
	}
	p.LzmaProps.NumThreads = t1
	t2r := t2

	fileSize := p.LzmaProps.ReduceSize

	if p.BlockSize != Lzma2BlockSizeSolid && p.BlockSize != Lzma2BlockSizeAuto &&
		(p.BlockSize < fileSize || fileSize == ^uint64(0)) {
		p.LzmaProps.ReduceSize = p.BlockSize
	}
	p.LzmaProps.Normalize()
	p.LzmaProps.ReduceSize = fileSize

	t1 = p.LzmaProps.NumThreads

	if p.BlockSize == Lzma2BlockSizeSolid {
		t2r = 1
		t2 = 1
		t3 = t1
	} else if p.BlockSize == Lzma2BlockSizeAuto && t2 <= 1 {
		p.BlockSize = Lzma2BlockSizeSolid
	} else {
		if p.BlockSize == Lzma2BlockSizeAuto {
			const kMinSize = uint64(1) << 20
			const kMaxSize = uint64(1) << 28
			dictSize := uint64(p.LzmaProps.DictSize)
			blockSize := dictSize << 2
			if blockSize < kMinSize {
				blockSize = kMinSize
			}
			if blockSize > kMaxSize {
				blockSize = kMaxSize
			}
			if blockSize < dictSize {
				blockSize = dictSize
			}
			blockSize += kMinSize - 1
			blockSize &^= kMinSize - 1
			p.BlockSize = blockSize
		}
		if t2 > 1 && fileSize != ^uint64(0) {
			numBlocks := fileSize / p.BlockSize
			if numBlocks*p.BlockSize != fileSize {
				numBlocks++
			}
			if numBlocks < uint64(t2) {
				t2r = int(numBlocks)
				if t2r == 0 {
					t2r = 1
				}
				t3 = t1 * t2r
			}
		}
	}
	p.NumBlockThreadsMax = t2
	p.NumBlockThreadsReduced = t2r
	p.NumTotalThreads = t3
}

// limitedReader is CLimitedSeqInStream.
type limitedReader struct {
	real      io.Reader
	limit     uint64
	processed uint64
	finished  bool
}

func (p *limitedReader) init() {
	p.limit = ^uint64(0)
	p.processed = 0
	p.finished = false
}

func (p *limitedReader) Read(data []byte) (int, error) {
	size2 := len(data)
	if p.limit != ^uint64(0) {
		rem := p.limit - p.processed
		if uint64(size2) > rem {
			size2 = int(rem)
		}
	}
	if size2 == 0 {
		return 0, io.EOF
	}
	n, err := readSome(p.real, data[:size2])
	if err != nil {
		return 0, err
	}
	p.finished = n == 0
	p.processed += uint64(n)
	if n == 0 {
		return 0, io.EOF
	}
	return n, nil
}

// lzma2EncInt is CLzma2EncInt.
type lzma2EncInt struct {
	enc           *Encoder
	propsAreSet   bool
	propsByte     byte
	needInitState bool
	needInitProp  bool
	srcPos        uint64
}

func (p *lzma2EncInt) initStream(props *Lzma2EncProps) error {
	if !p.propsAreSet {
		if err := p.enc.SetProps(&props.LzmaProps); err != nil {
			return err
		}
		pe := p.enc.WriteProperties()
		p.propsByte = pe[0]
		p.propsAreSet = true
	}
	return nil
}

func (p *lzma2EncInt) initBlock() {
	p.srcPos = 0
	p.needInitState = true
	p.needInitProp = true
}

// encodeSubblock is Lzma2EncInt_EncodeSubblock. outBuf is the chunk
// buffer (its length is the pack size limit). With outStream non-nil the
// chunk is written to it; the number of bytes produced is returned.
func (p *lzma2EncInt) encodeSubblock(outBuf []byte, outStream io.Writer) (int, error) {
	packSizeLimit := len(outBuf)
	packSize := packSizeLimit
	unpackSize := uint32(lzma2UnpackSizeMax)
	lzHeaderSize := 5
	if p.needInitProp {
		lzHeaderSize = 6
	}
	if packSize < lzHeaderSize {
		return 0, ErrOutputEOF
	}
	packSize -= lzHeaderSize

	p.enc.saveStateNow()
	packed, unpacked, res := p.enc.codeOneMemBlock(p.needInitState, outBuf[lzHeaderSize:lzHeaderSize+packSize], lzma2PackSizeMax, unpackSize)
	packSize = packed
	unpackSize = unpacked

	if unpackSize == 0 {
		return 0, res
	}

	if res == ErrOutputEOF || (res == nil && (packSize+2 >= int(unpackSize) || packSize > 1<<16)) {
		destPos := 0
		packSizeRes := 0
		buf, cur := p.enc.curBuf()
		for unpackSize != 0 {
			u := unpackSize
			if u > lzma2CopyChunkSize {
				u = lzma2CopyChunkSize
			}
			if packSizeLimit-destPos < int(u)+3 {
				return packSizeRes, ErrOutputEOF
			}
			if p.srcPos == 0 {
				outBuf[destPos] = lzma2ControlCopyReset
			} else {
				outBuf[destPos] = lzma2ControlCopyNoReset
			}
			destPos++
			outBuf[destPos] = byte((u - 1) >> 8)
			destPos++
			outBuf[destPos] = byte(u - 1)
			destPos++
			start := cur - int(unpackSize)
			copy(outBuf[destPos:destPos+int(u)], buf[start:start+int(u)])
			unpackSize -= u
			destPos += int(u)
			p.srcPos += uint64(u)
			if outStream != nil {
				packSizeRes += destPos
				if n, err := outStream.Write(outBuf[:destPos]); err != nil || n != destPos {
					return packSizeRes, ErrWrite
				}
				destPos = 0
			} else {
				packSizeRes = destPos
			}
		}
		p.enc.restoreState()
		return packSizeRes, nil
	}

	if res != nil {
		return 0, res
	}
	{
		destPos := 0
		u := unpackSize - 1
		pm := uint32(packSize - 1)
		var mode uint32
		switch {
		case p.srcPos == 0:
			mode = 3
		case p.needInitState && p.needInitProp:
			mode = 2
		case p.needInitState:
			mode = 1
		default:
			mode = 0
		}
		outBuf[destPos] = byte(lzma2ControlLzma | (mode << 5) | ((u >> 16) & 0x1F))
		destPos++
		outBuf[destPos] = byte(u >> 8)
		destPos++
		outBuf[destPos] = byte(u)
		destPos++
		outBuf[destPos] = byte(pm >> 8)
		destPos++
		outBuf[destPos] = byte(pm)
		destPos++
		if p.needInitProp {
			outBuf[destPos] = p.propsByte
			destPos++
		}
		p.needInitProp = false
		p.needInitState = false
		destPos += packSize
		p.srcPos += uint64(unpackSize)
		if outStream != nil {
			if n, err := outStream.Write(outBuf[:destPos]); err != nil || n != destPos {
				return 0, ErrWrite
			}
		}
		return destPos, nil
	}
}

// Lzma2Encoder is CLzma2Enc.
type Lzma2Encoder struct {
	props            Lzma2EncProps
	expectedDataSize uint64
	tempBufLzma      []byte
	coders           []lzma2EncInt
}

// NewLzma2Encoder is Lzma2Enc_Create.
func NewLzma2Encoder() *Lzma2Encoder {
	p := &Lzma2Encoder{}
	p.props.Init()
	p.props.Normalize()
	p.expectedDataSize = ^uint64(0)
	p.coders = make([]lzma2EncInt, 1)
	return p
}

// SetProps is Lzma2Enc_SetProps.
func (p *Lzma2Encoder) SetProps(props *Lzma2EncProps) error {
	lzmaProps := props.LzmaProps
	lzmaProps.Normalize()
	if lzmaProps.Lc+lzmaProps.Lp > lzma2LclpMax {
		return ErrParam
	}
	p.props = *props
	p.props.Normalize()
	return nil
}

// SetDataSize is Lzma2Enc_SetDataSize.
func (p *Lzma2Encoder) SetDataSize(expectedDataSize uint64) {
	p.expectedDataSize = expectedDataSize
}

// WriteProperties is Lzma2Enc_WriteProperties: the 1-byte LZMA2
// dictionary property.
func (p *Lzma2Encoder) WriteProperties() byte {
	dicSize := p.props.LzmaProps.GetDictSize()
	i := uint32(0)
	for ; i < 40; i++ {
		if dicSize <= lzma2DicSizeFromProp(i) {
			break
		}
	}
	return byte(i)
}

// encodeMt1 is Lzma2Enc_EncodeMt1. Exactly one of outStream/outBuf and
// exactly one of inStream/inData is used. With outBuf, the bytes written
// are returned as n.
func (p *Lzma2Encoder) encodeMt1(c *lzma2EncInt, outStream io.Writer, outBuf []byte,
	inStream io.Reader, inData []byte, finished bool) (n int, err error) {
	var unpackTotal, packTotal uint64
	outLim := 0
	if outBuf != nil {
		outLim = len(outBuf)
	}
	if c.enc == nil {
		c.propsAreSet = false
		c.enc = NewEncoder()
	}
	var limited limitedReader
	limited.real = inStream

	if outBuf == nil {
		if p.tempBufLzma == nil {
			p.tempBufLzma = make([]byte, lzma2ChunkSizeCompressedMax)
		}
	}
	if err := c.initStream(&p.props); err != nil {
		return 0, err
	}

	for {
		var res error
		inSizeCur := 0

		c.initBlock()
		limited.init()
		limited.limit = p.props.BlockSize

		if inStream != nil {
			expected := ^uint64(0)
			if p.expectedDataSize != ^uint64(0) && p.expectedDataSize >= unpackTotal {
				expected = p.expectedDataSize - unpackTotal
			}
			if p.props.BlockSize != Lzma2BlockSizeSolid && expected > p.props.BlockSize {
				expected = p.props.BlockSize
			}
			c.enc.SetDataSize(expected)
			if err := c.enc.prepareForLzma2(&limited, lzma2KeepWindowSize); err != nil {
				return int(packTotal), err
			}
		} else {
			inSizeCur = len(inData) - int(unpackTotal)
			if p.props.BlockSize != Lzma2BlockSizeSolid && uint64(inSizeCur) > p.props.BlockSize {
				inSizeCur = int(p.props.BlockSize)
			}
			if err := c.enc.memPrepare(inData[int(unpackTotal):int(unpackTotal)+inSizeCur], lzma2KeepWindowSize); err != nil {
				return int(packTotal), err
			}
		}

		for {
			var packSize int
			if outBuf != nil {
				packSize, res = c.encodeSubblock(outBuf[int(packTotal):outLim], nil)
			} else {
				packSize, res = c.encodeSubblock(p.tempBufLzma, outStream)
			}
			if res != nil {
				break
			}
			packTotal += uint64(packSize)
			if packSize == 0 {
				break
			}
		}

		unpackTotal += c.srcPos

		if res != nil {
			return int(packTotal), res
		}
		if inStream != nil {
			if c.srcPos != limited.processed {
				return int(packTotal), ErrFail
			}
		} else if c.srcPos != uint64(inSizeCur) {
			return int(packTotal), ErrFail
		}

		var done bool
		if inStream != nil {
			done = limited.finished
		} else {
			done = unpackTotal == uint64(len(inData))
		}
		if done {
			if finished {
				if outBuf != nil {
					destPos := int(packTotal)
					if destPos >= outLim {
						return destPos, ErrOutputEOF
					}
					outBuf[destPos] = lzma2ControlEOF
					packTotal++
				} else {
					if n, err := outStream.Write([]byte{lzma2ControlEOF}); err != nil || n != 1 {
						return int(packTotal), ErrWrite
					}
				}
			}
			return int(packTotal), nil
		}
	}
}

// Encode is Lzma2Enc_Encode2 for the stream/stream case: it encodes
// everything from in to out, including the LZMA2 end marker. With more
// than one block thread configured, the input is split into BlockSize
// blocks encoded independently (as the oracle's MtCoder does) and
// concatenated in order.
func (p *Lzma2Encoder) Encode(out io.Writer, in io.Reader) error {
	for i := range p.coders {
		p.coders[i].propsAreSet = false
	}
	if p.props.NumBlockThreadsReduced > 1 {
		return p.encodeBlocks(out, in)
	}
	_, err := p.encodeMt1(&p.coders[0], out, nil, in, nil, true)
	return err
}

// EncodeBytes encodes src in memory (direct input) and returns the LZMA2
// stream including the end marker.
func (p *Lzma2Encoder) EncodeBytes(src []byte) ([]byte, error) {
	var out growBuf
	if err := p.Encode(&out, &bytesReader{b: src}); err != nil {
		return nil, err
	}
	return out.b, nil
}

type bytesReader struct {
	b   []byte
	pos int
}

func (r *bytesReader) Read(p []byte) (int, error) {
	if r.pos >= len(r.b) {
		return 0, io.EOF
	}
	n := copy(p, r.b[r.pos:])
	r.pos += n
	return n, nil
}

// encodeBlocks reproduces MtCoder_Code + Lzma2Enc_MtCallback_Code /
// _Write sequentially: blocks of BlockSize bytes are read from in, each
// encoded by encodeMt1 in direct-input mode, and written in order. As in
// MtCoder's stream mode a block is the last one when it is short, so an
// input that is an exact multiple of BlockSize ends with an empty block
// that carries only the end marker.
func (p *Lzma2Encoder) encodeBlocks(out io.Writer, in io.Reader) error {
	blockSize := p.props.BlockSize
	if uint64(int(blockSize)) != blockSize {
		return ErrParam
	}
	destBlockSize := int(blockSize) + (int(blockSize) >> 10) + 16
	if destBlockSize < int(blockSize) {
		return ErrParam
	}
	dest := make([]byte, destBlockSize)
	src := make([]byte, blockSize)
	for {
		n, err := readFull(in, src)
		if err != nil {
			return err
		}
		finished := n != int(blockSize)
		size, err := p.encodeMt1(&p.coders[0], nil, dest, nil, src[:n], finished)
		if err != nil {
			return err
		}
		if w, err := out.Write(dest[:size]); err != nil || w != size {
			return ErrWrite
		}
		if finished {
			return nil
		}
	}
}

// readFull reads until buf is full or the stream ends.
func readFull(r io.Reader, buf []byte) (int, error) {
	total := 0
	for total < len(buf) {
		n, err := readSome(r, buf[total:])
		if err != nil {
			return total, err
		}
		if n == 0 {
			break
		}
		total += n
	}
	return total, nil
}
