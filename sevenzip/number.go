package sevenzip

import "errors"

// 7z property IDs (DOC/7zFormat.txt).
const (
	idEnd                   = 0x00
	idHeader                = 0x01
	idArchiveProperties     = 0x02
	idAdditionalStreamsInfo = 0x03
	idMainStreamsInfo       = 0x04
	idFilesInfo             = 0x05
	idPackInfo              = 0x06
	idUnpackInfo            = 0x07
	idSubStreamsInfo        = 0x08
	idSize                  = 0x09
	idCRC                   = 0x0A
	idFolder                = 0x0B
	idCodersUnpackSize      = 0x0C
	idNumUnpackStream       = 0x0D
	idEmptyStream           = 0x0E
	idEmptyFile             = 0x0F
	idAnti                  = 0x10
	idName                  = 0x11
	idCTime                 = 0x12
	idATime                 = 0x13
	idMTime                 = 0x14
	idWinAttrib             = 0x15
	idComment               = 0x16
	idEncodedHeader         = 0x17
	idStartPos              = 0x18
	idDummy                 = 0x19
)

// Method IDs.
const (
	MethodCopy  uint32 = 0x00
	MethodLZMA  uint32 = 0x030101
	MethodLZMA2 uint32 = 0x21
	MethodBCJ   uint32 = 0x03030103
	MethodBCJ2  uint32 = 0x0303011B
	MethodPPC   uint32 = 0x03030205
	MethodIA64  uint32 = 0x03030401
	MethodARM   uint32 = 0x03030501
	MethodARMT  uint32 = 0x03030701
	MethodSPARC uint32 = 0x03030805
	MethodARM64 uint32 = 0x0A
	MethodRISCV uint32 = 0x0B
	MethodDelta uint32 = 0x03
	MethodSwap2 uint32 = 0x020302 // observed: coder record 03 02 03 02, no properties
	MethodSwap4 uint32 = 0x020304 // observed: coder record 03 02 03 04, no properties
	MethodAES   uint32 = 0x06F10701
)

var signature = [6]byte{'7', 'z', 0xBC, 0xAF, 0x27, 0x1C}

const startHeaderSize = 32

var (
	ErrNotArchive  = errors.New("sevenzip: not a 7z archive")
	ErrArchive     = errors.New("sevenzip: malformed archive")
	ErrUnsupported = errors.New("sevenzip: unsupported archive feature")
	ErrCRC         = errors.New("sevenzip: CRC mismatch")
	ErrData        = errors.New("sevenzip: data error")
	ErrInputEOF    = errors.New("sevenzip: unexpected end of archive")
)

// szData is CSzData: a cursor over header bytes.
type szData struct {
	b []byte
}

func (d *szData) readByte() (byte, error) {
	if len(d.b) == 0 {
		return 0, ErrArchive
	}
	v := d.b[0]
	d.b = d.b[1:]
	return v, nil
}

// readNumber is ReadNumber: the 7z variable-length UINT64.
func (d *szData) readNumber() (uint64, error) {
	first, err := d.readByte()
	if err != nil {
		return 0, err
	}
	if first&0x80 == 0 {
		return uint64(first), nil
	}
	v, err := d.readByte()
	if err != nil {
		return 0, err
	}
	if first&0x40 == 0 {
		return (uint64(first&0x3F) << 8) | uint64(v), nil
	}
	m, err := d.readByte()
	if err != nil {
		return 0, err
	}
	value := uint64(v) | (uint64(m) << 8)
	mask := uint32(0x20)
	for i := uint(2 * 8); i < 8*8; i += 8 {
		if uint32(first)&mask == 0 {
			high := uint64(first) & uint64(mask-1)
			value |= high << i
			return value, nil
		}
		mask >>= 1
		b, err := d.readByte()
		if err != nil {
			return 0, err
		}
		value |= uint64(b) << i
	}
	return value, nil
}

// readNumber32 is SzReadNumber32.
func (d *szData) readNumber32() (uint32, error) {
	if len(d.b) == 0 {
		return 0, ErrArchive
	}
	if d.b[0]&0x80 == 0 {
		v := uint32(d.b[0])
		d.b = d.b[1:]
		return v, nil
	}
	v, err := d.readNumber()
	if err != nil {
		return 0, err
	}
	if v >= uint64(0x80000000)-1 {
		return 0, ErrUnsupported
	}
	return uint32(v), nil
}

func (d *szData) skip(n uint64) error {
	if n > uint64(len(d.b)) {
		return ErrArchive
	}
	d.b = d.b[n:]
	return nil
}

// skipData is SkipData: a size-prefixed blob.
func (d *szData) skipData() error {
	n, err := d.readNumber()
	if err != nil {
		return err
	}
	return d.skip(n)
}

// waitID is WaitId.
func (d *szData) waitID(id uint64) error {
	for {
		t, err := d.readNumber()
		if err != nil {
			return err
		}
		if t == id {
			return nil
		}
		if t == idEnd {
			return ErrArchive
		}
		if err := d.skipData(); err != nil {
			return err
		}
	}
}

func getUi32(b []byte) uint32 {
	return uint32(b[0]) | uint32(b[1])<<8 | uint32(b[2])<<16 | uint32(b[3])<<24
}

func getUi64(b []byte) uint64 {
	return uint64(getUi32(b)) | uint64(getUi32(b[4:]))<<32
}

func putUi32(b []byte, v uint32) {
	b[0], b[1], b[2], b[3] = byte(v), byte(v>>8), byte(v>>16), byte(v>>24)
}

func putUi64(b []byte, v uint64) {
	putUi32(b, uint32(v))
	putUi32(b[4:], uint32(v>>32))
}

// bitCheck is SzBitArray_Check: MSB-first bit numbering.
func bitCheck(bits []byte, i int) bool {
	return bits[i>>3]&(0x80>>(uint(i)&7)) != 0
}

func countDefinedBits(bits []byte, n int) int {
	sum := 0
	for i := 0; i < n; i++ {
		if bitCheck(bits, i) {
			sum++
		}
	}
	return sum
}

// readBitVector is ReadBitVector: AllAreDefined byte, then the bits.
func (d *szData) readBitVector(n int) ([]byte, error) {
	allDefined, err := d.readByte()
	if err != nil {
		return nil, err
	}
	numBytes := (n + 7) >> 3
	if numBytes == 0 {
		return []byte{}, nil
	}
	if allDefined == 0 {
		if numBytes > len(d.b) {
			return nil, ErrArchive
		}
		v := make([]byte, numBytes)
		copy(v, d.b)
		d.b = d.b[numBytes:]
		return v, nil
	}
	v := make([]byte, numBytes)
	for i := range v {
		v[i] = 0xFF
	}
	if r := uint(n) & 7; r != 0 {
		v[numBytes-1] = byte(uint16(0xFF00) >> r)
	}
	return v, nil
}

// bitUi32s is CSzBitUi32s.
type bitUi32s struct {
	defs []byte
	vals []uint32
}

func (p *bitUi32s) check(i int) bool { return p.defs != nil && bitCheck(p.defs, i) }

// readUi32s is ReadUi32s.
func (d *szData) readUi32s(n int, p *bitUi32s) error {
	p.vals = make([]uint32, n)
	for i := 0; i < n; i++ {
		if bitCheck(p.defs, i) {
			if len(d.b) < 4 {
				return ErrArchive
			}
			p.vals[i] = getUi32(d.b)
			d.b = d.b[4:]
		}
	}
	return nil
}

// readBitUi32s is ReadBitUi32s.
func (d *szData) readBitUi32s(n int, p *bitUi32s) error {
	if p.defs != nil {
		return ErrArchive
	}
	defs, err := d.readBitVector(n)
	if err != nil {
		return err
	}
	p.defs = defs
	return d.readUi32s(n, p)
}

// skipBitUi32s is SkipBitUi32s.
func (d *szData) skipBitUi32s(n int) error {
	allDefined, err := d.readByte()
	if err != nil {
		return err
	}
	numDefined := n
	if allDefined == 0 {
		numBytes := (n + 7) >> 3
		if numBytes > len(d.b) {
			return ErrArchive
		}
		numDefined = countDefinedBits(d.b, n)
		d.b = d.b[numBytes:]
	}
	if numDefined > len(d.b)>>2 {
		return ErrArchive
	}
	d.b = d.b[numDefined*4:]
	return nil
}

// skipNumbers is SkipNumbers.
func (d *szData) skipNumbers(n int) error {
	for ; n != 0; n-- {
		if len(d.b) == 0 {
			return ErrArchive
		}
		first := d.b[0]
		i := 1
		for first&0x80 != 0 {
			first <<= 1
			i++
		}
		if len(d.b) < i {
			return ErrArchive
		}
		d.b = d.b[i:]
	}
	return nil
}

// writeNumber appends the 7z variable-length encoding of v
// (DOC/7zFormat.txt, "UINT64"): the first byte's leading one bits give
// the number of extra little-endian bytes; the rest of the first byte
// holds the high bits.
func writeNumber(dst []byte, v uint64) []byte {
	first := byte(0)
	mask := byte(0x80)
	i := 0
	for ; i < 8; i++ {
		if v < uint64(1)<<(7*uint(i+1)) {
			first |= byte(v >> (8 * uint(i)))
			break
		}
		first |= mask
		mask >>= 1
	}
	dst = append(dst, first)
	for j := 0; j < i; j++ {
		dst = append(dst, byte(v>>(8*uint(j))))
	}
	return dst
}

// numberSize is the encoded length writeNumber produces for v.
func numberSize(v uint64) int {
	for i := 0; i < 8; i++ {
		if v < uint64(1)<<(7*uint(i+1)) {
			return i + 1
		}
	}
	return 9
}
