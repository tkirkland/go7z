package sevenzip

import (
	"hash/crc32"
	"io"
	"unicode/utf16"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/lzma"
)

// Port of C/7zArcIn.c and C/7zDec.c (26.05, public domain): the 7z
// archive reader. The structures follow CSzAr / CSzArEx; the header walk
// keeps the same validations so that what the SDK rejects, this rejects.

// coderInfo is CSzCoderInfo.
type coderInfo struct {
	methodID   uint32
	numStreams uint32
	props      []byte
}

// bond is CSzBond.
type bond struct {
	inIndex  uint32
	outIndex uint32
}

// folder is CSzFolder plus the per-folder data the SDK keeps in CSzAr
// arrays (coder unpack sizes, pack stream start, CRC).
type folder struct {
	coders          []coderInfo
	bonds           []bond
	packStreams     []uint32 // indices into the folder's in-streams
	unpackStream    uint32   // index of the main (unbound) coder
	coderUnpackSize []uint64 // one per coder
	startPackStream int      // index into szAr.packPositions
	crc             uint32
	crcDefined      bool
}

func (f *folder) unpackSize() uint64 { return f.coderUnpackSize[f.unpackStream] }

// szAr is CSzAr: pack streams and folders of one streams-info block.
type szAr struct {
	packPositions []uint64 // numPackStreams + 1, relative to the data start
	folders       []folder
	rangeLimit    uint64
}

// Entry is one item of the archive.
type Entry struct {
	Name      string // archive path, slash separated
	IsDir     bool
	Size      uint64
	CRC       uint32
	HasCRC    bool
	Attrib    uint32
	HasAttrib bool
	MTime     uint64 // Windows FILETIME; 0 when !HasMTime
	HasMTime  bool
	CTime     uint64
	HasCTime  bool
	ATime     uint64
	HasATime  bool
	folder    int // -1 for items without a stream
	unpackPos uint64
}

// Archive is CSzArEx: an opened 7z archive.
type Archive struct {
	r       io.ReaderAt
	size    int64
	db      szAr
	dataPos uint64 // absolute offset of the packed streams
	Entries []Entry

	folderToFile []int
	cacheFolder  int
	cacheData    []byte
}

func crc(b []byte) uint32 { return crc32.ChecksumIEEE(b) }

// Open parses the archive in r (size bytes).
func Open(r io.ReaderAt, size int64) (*Archive, error) {
	a := &Archive{r: r, size: size, cacheFolder: -1}
	if err := a.open(); err != nil {
		return nil, err
	}
	return a, nil
}

func (a *Archive) readAt(off uint64, n uint64) ([]byte, error) {
	if off+n > uint64(a.size) {
		return nil, ErrInputEOF
	}
	buf := make([]byte, n)
	if _, err := a.r.ReadAt(buf, int64(off)); err != nil && err != io.EOF {
		return nil, err
	}
	return buf, nil
}

// open is SzArEx_Open2.
func (a *Archive) open() error {
	if a.size < startHeaderSize {
		return ErrNotArchive
	}
	header, err := a.readAt(0, startHeaderSize)
	if err != nil {
		return ErrNotArchive
	}
	for i := 0; i < 6; i++ {
		if header[i] != signature[i] {
			return ErrNotArchive
		}
	}
	if header[6] != 0 {
		return ErrUnsupported
	}
	if crc(header[12:32]) != getUi32(header[8:]) {
		return ErrCRC
	}
	nextHeaderOffset := getUi64(header[12:])
	nextHeaderSize := getUi64(header[20:])
	nextHeaderCRC := getUi32(header[28:])
	a.db.rangeLimit = nextHeaderOffset
	if nextHeaderOffset >= uint64(1)<<62 || nextHeaderSize >= uint64(1)<<48 {
		return ErrNotArchive
	}
	if nextHeaderSize == 0 {
		if nextHeaderOffset != 0 || nextHeaderCRC != 0 {
			return ErrNotArchive
		}
		return nil
	}
	if uint64(a.size)-startHeaderSize < nextHeaderOffset+nextHeaderSize {
		return ErrInputEOF
	}
	buf, err := a.readAt(startHeaderSize+nextHeaderOffset, nextHeaderSize)
	if err != nil {
		return err
	}
	if crc(buf) != nextHeaderCRC {
		return ErrArchive
	}
	sd := &szData{b: buf}
	t, err := sd.readNumber()
	if err != nil {
		return err
	}
	if t == idEncodedHeader {
		var tempAr szAr
		tempAr.rangeLimit = a.db.rangeLimit
		bufs, err := a.readAndDecodePackedStreams(sd, 1, &tempAr)
		if err != nil {
			return err
		}
		sd = &szData{b: bufs[0]}
		if t, err = sd.readNumber(); err != nil {
			return err
		}
	}
	if t != idHeader {
		return ErrUnsupported
	}
	if err := a.readHeader(sd); err != nil {
		return err
	}
	if len(sd.b) != 0 {
		return ErrArchive
	}
	return nil
}

// readPackInfo is ReadPackInfo.
func (p *szAr) readPackInfo(sd *szData) error {
	numPackStreams, err := sd.readNumber32()
	if err != nil {
		return err
	}
	if err := sd.waitID(idSize); err != nil {
		return err
	}
	p.packPositions = make([]uint64, int(numPackStreams)+1)
	var sum uint64
	for i := 0; i < int(numPackStreams); i++ {
		p.packPositions[i] = sum
		size, err := sd.readNumber()
		if err != nil {
			return err
		}
		sum += size
		if sum < size {
			return ErrArchive
		}
	}
	p.packPositions[numPackStreams] = sum
	for {
		t, err := sd.readNumber()
		if err != nil {
			return err
		}
		if t == idEnd {
			return nil
		}
		if t == idCRC {
			if err := sd.skipBitUi32s(int(numPackStreams)); err != nil {
				return err
			}
			continue
		}
		if err := sd.skipData(); err != nil {
			return err
		}
	}
}

const (
	numCodersInFolderMax        = 64
	numCodersStreamsInFolderMax = 64
)

// readFolder is SzGetNextFolderItem without the per-decoder limits of
// the SDK's CSzFolder (those are applied when decoding).
func readFolder(sd *szData) (*folder, error) {
	f := &folder{}
	numCoders, err := sd.readNumber32()
	if err != nil {
		return nil, err
	}
	if numCoders == 0 || numCoders > numCodersInFolderMax {
		return nil, ErrUnsupported
	}
	numInStreams := uint32(0)
	for i := uint32(0); i < numCoders; i++ {
		mainByte, err := sd.readByte()
		if err != nil {
			return nil, err
		}
		if mainByte&0xC0 != 0 {
			return nil, ErrUnsupported
		}
		idSize := int(mainByte & 0xF)
		if idSize > 8 {
			return nil, ErrUnsupported
		}
		if idSize > len(sd.b) {
			return nil, ErrArchive
		}
		var id uint64
		for j := 0; j < idSize; j++ {
			id = id<<8 | uint64(sd.b[j])
		}
		sd.b = sd.b[idSize:]
		if id > 0xFFFFFFFF {
			return nil, ErrUnsupported
		}
		c := coderInfo{methodID: uint32(id), numStreams: 1}
		if mainByte&0x10 != 0 {
			ns, err := sd.readNumber32()
			if err != nil {
				return nil, err
			}
			if ns > numCodersStreamsInFolderMax {
				return nil, ErrUnsupported
			}
			c.numStreams = ns
			out, err := sd.readNumber32()
			if err != nil {
				return nil, err
			}
			if out != 1 {
				return nil, ErrUnsupported
			}
		}
		numInStreams += c.numStreams
		if numInStreams > numCodersStreamsInFolderMax {
			return nil, ErrUnsupported
		}
		if mainByte&0x20 != 0 {
			propsSize, err := sd.readNumber32()
			if err != nil {
				return nil, err
			}
			if int(propsSize) > len(sd.b) {
				return nil, ErrArchive
			}
			c.props = append([]byte(nil), sd.b[:propsSize]...)
			sd.b = sd.b[propsSize:]
		}
		f.coders = append(f.coders, c)
	}
	numBonds := numCoders - 1
	if numInStreams < numBonds {
		return nil, ErrArchive
	}
	numPackStreams := numInStreams - numBonds
	streamUsed := make([]bool, numInStreams)
	coderUsed := make([]bool, numCoders)
	for i := uint32(0); i < numBonds; i++ {
		var b bond
		if b.inIndex, err = sd.readNumber32(); err != nil {
			return nil, err
		}
		if b.inIndex >= numInStreams || streamUsed[b.inIndex] {
			return nil, ErrArchive
		}
		streamUsed[b.inIndex] = true
		if b.outIndex, err = sd.readNumber32(); err != nil {
			return nil, err
		}
		if b.outIndex >= numCoders || coderUsed[b.outIndex] {
			return nil, ErrArchive
		}
		coderUsed[b.outIndex] = true
		f.bonds = append(f.bonds, b)
	}
	if numPackStreams == 1 {
		i := uint32(0)
		for ; ; i++ {
			if i == numInStreams {
				return nil, ErrArchive
			}
			if !streamUsed[i] {
				break
			}
		}
		f.packStreams = []uint32{i}
	} else {
		for i := uint32(0); i < numPackStreams; i++ {
			idx, err := sd.readNumber32()
			if err != nil {
				return nil, err
			}
			if idx >= numInStreams || streamUsed[idx] {
				return nil, ErrArchive
			}
			streamUsed[idx] = true
			f.packStreams = append(f.packStreams, idx)
		}
	}
	i := uint32(0)
	for {
		if !coderUsed[i] {
			break
		}
		i++
		if i == numCoders {
			return nil, ErrArchive
		}
	}
	f.unpackStream = i
	return f, nil
}

// readUnpackInfo is ReadUnpackInfo.
func (p *szAr) readUnpackInfo(sd *szData, numFoldersMax uint32, tempBufs [][]byte) error {
	if err := sd.waitID(idFolder); err != nil {
		return err
	}
	numFolders, err := sd.readNumber32()
	if err != nil {
		return err
	}
	if numFolders > numFoldersMax {
		return ErrUnsupported
	}
	external, err := sd.readByte()
	if err != nil {
		return err
	}
	fsd := sd
	if external != 0 {
		idx, err := sd.readNumber32()
		if err != nil {
			return err
		}
		if int(idx) >= len(tempBufs) {
			return ErrArchive
		}
		fsd = &szData{b: tempBufs[idx]}
	}
	p.folders = make([]folder, 0, numFolders)
	packStreamIndex := 0
	for fo := uint32(0); fo < numFolders; fo++ {
		f, err := readFolder(fsd)
		if err != nil {
			return err
		}
		f.startPackStream = packStreamIndex
		if len(f.packStreams) > len(p.packPositions)-1-packStreamIndex {
			return ErrArchive
		}
		packStreamIndex += len(f.packStreams)
		p.folders = append(p.folders, *f)
	}
	if external != 0 {
		if len(fsd.b) != 0 {
			return ErrArchive
		}
	}
	if err := sd.waitID(idCodersUnpackSize); err != nil {
		return err
	}
	for fo := range p.folders {
		f := &p.folders[fo]
		f.coderUnpackSize = make([]uint64, len(f.coders))
		for ci := range f.coders {
			if f.coderUnpackSize[ci], err = sd.readNumber(); err != nil {
				return err
			}
		}
	}
	for {
		t, err := sd.readNumber()
		if err != nil {
			return err
		}
		if t == idEnd {
			return nil
		}
		if t == idCRC {
			var crcs bitUi32s
			if err := sd.readBitUi32s(int(numFolders), &crcs); err != nil {
				return err
			}
			for fo := range p.folders {
				if crcs.check(fo) {
					p.folders[fo].crc = crcs.vals[fo]
					p.folders[fo].crcDefined = true
				}
			}
			continue
		}
		if err := sd.skipData(); err != nil {
			return err
		}
	}
}

// subStreamInfo is CSubStreamInfo.
type subStreamInfo struct {
	numTotalSubStreams int
	numSubDigests      int
	sdNumSubStreams    []byte
	sdSizes            []byte
	sdCRCs             []byte
}

// readSubStreamsInfo is ReadSubStreamsInfo.
func (p *szAr) readSubStreamsInfo(sd *szData, ssi *subStreamInfo) error {
	numFolders := len(p.folders)
	numUnpackStreams := numFolders
	numSubDigests := numFolders
	numUnpackSizesInData := 0
	var t uint64
	var err error
	for {
		if t, err = sd.readNumber(); err != nil {
			return err
		}
		if t == idNumUnpackStream {
			if ssi.sdNumSubStreams != nil {
				return ErrUnsupported
			}
			start := sd.b
			numUnpackStreams = 0
			numSubDigests = 0
			for i := 0; i < numFolders; i++ {
				ns, err := sd.readNumber32()
				if err != nil {
					return err
				}
				numUnpackStreams += int(ns)
				if ns != 0 {
					numUnpackSizesInData += int(ns) - 1
				}
				if ns != 1 || !p.folders[i].crcDefined {
					numSubDigests += int(ns)
				}
			}
			ssi.sdNumSubStreams = start[:len(start)-len(sd.b)]
			continue
		}
		if t == idCRC || t == idSize || t == idEnd {
			break
		}
		if err := sd.skipData(); err != nil {
			return err
		}
	}
	if ssi.sdNumSubStreams == nil {
		defined := 0
		for i := range p.folders {
			if p.folders[i].crcDefined {
				defined++
			}
		}
		numSubDigests = numFolders - defined
	}
	ssi.numTotalSubStreams = numUnpackStreams
	ssi.numSubDigests = numSubDigests
	if t == idSize {
		start := sd.b
		if err := sd.skipNumbers(numUnpackSizesInData); err != nil {
			return err
		}
		ssi.sdSizes = start[:len(start)-len(sd.b)]
		if t, err = sd.readNumber(); err != nil {
			return err
		}
	}
	for {
		if t == idEnd {
			return nil
		}
		if t == idCRC {
			if ssi.sdCRCs != nil {
				return ErrUnsupported
			}
			start := sd.b
			if err := sd.skipBitUi32s(numSubDigests); err != nil {
				return err
			}
			ssi.sdCRCs = start[:len(start)-len(sd.b)]
		} else if err := sd.skipData(); err != nil {
			return err
		}
		if t, err = sd.readNumber(); err != nil {
			return err
		}
	}
}

// readStreamsInfo is SzReadStreamsInfo. It returns the data offset
// (PackPos) read from PackInfo.
func (p *szAr) readStreamsInfo(sd *szData, numFoldersMax uint32, tempBufs [][]byte, ssi *subStreamInfo) (uint64, error) {
	var dataOffset uint64
	t, err := sd.readNumber()
	if err != nil {
		return 0, err
	}
	if t == idPackInfo {
		if dataOffset, err = sd.readNumber(); err != nil {
			return 0, err
		}
		if dataOffset > p.rangeLimit {
			return 0, ErrArchive
		}
		if err := p.readPackInfo(sd); err != nil {
			return 0, err
		}
		if p.packPositions[len(p.packPositions)-1] > p.rangeLimit-dataOffset {
			return 0, ErrArchive
		}
		if t, err = sd.readNumber(); err != nil {
			return 0, err
		}
	}
	if t == idUnpackInfo {
		if err := p.readUnpackInfo(sd, numFoldersMax, tempBufs); err != nil {
			return 0, err
		}
		if t, err = sd.readNumber(); err != nil {
			return 0, err
		}
	}
	if t == idSubStreamsInfo {
		if err := p.readSubStreamsInfo(sd, ssi); err != nil {
			return 0, err
		}
		if t, err = sd.readNumber(); err != nil {
			return 0, err
		}
	} else {
		ssi.numTotalSubStreams = len(p.folders)
	}
	if t != idEnd {
		return 0, ErrUnsupported
	}
	return dataOffset, nil
}

// readAndDecodePackedStreams is SzReadAndDecodePackedStreams: it reads a
// streams-info block and decodes every folder into a buffer.
func (a *Archive) readAndDecodePackedStreams(sd *szData, numFoldersMax uint32, p *szAr) ([][]byte, error) {
	var ssi subStreamInfo
	dataStart, err := p.readStreamsInfo(sd, numFoldersMax, nil, &ssi)
	if err != nil {
		return nil, err
	}
	dataStart += startHeaderSize
	if len(p.folders) == 0 {
		return nil, ErrArchive
	}
	bufs := make([][]byte, len(p.folders))
	for fo := range p.folders {
		buf, err := a.decodeFolder(p, fo, dataStart)
		if err != nil {
			return nil, err
		}
		bufs[fo] = buf
	}
	return bufs, nil
}

// readTime is ReadTime: a defined-bit vector, external byte, then the
// 8-byte FILETIME values.
func readTime(sd *szData, n int, tempBufs [][]byte) (defs []byte, vals []uint64, err error) {
	if defs, err = sd.readBitVector(n); err != nil {
		return nil, nil, err
	}
	external, err := sd.readByte()
	if err != nil {
		return nil, nil, err
	}
	data := sd.b
	if external != 0 {
		idx, err := sd.readNumber32()
		if err != nil {
			return nil, nil, err
		}
		if int(idx) >= len(tempBufs) || len(sd.b) != 0 {
			return nil, nil, ErrArchive
		}
		data = tempBufs[idx]
	}
	vals = make([]uint64, n)
	for i := 0; i < n; i++ {
		if bitCheck(defs, i) {
			if len(data) < 8 {
				return nil, nil, ErrArchive
			}
			vals[i] = getUi64(data)
			data = data[8:]
		}
	}
	if len(data) != 0 {
		return nil, nil, ErrArchive
	}
	if external == 0 {
		sd.b = data
	}
	return defs, vals, nil
}

const numAdditionalStreamsMax = 8

// readHeader is SzReadHeader2.
func (a *Archive) readHeader(sd *szData) error {
	var ssi subStreamInfo
	var tempBufs [][]byte
	t, err := sd.readNumber()
	if err != nil {
		return err
	}
	if t == idArchiveProperties {
		for {
			t2, err := sd.readNumber()
			if err != nil {
				return err
			}
			if t2 == idEnd {
				break
			}
			if err := sd.skipData(); err != nil {
				return err
			}
		}
		if t, err = sd.readNumber(); err != nil {
			return err
		}
	}
	if t == idAdditionalStreamsInfo {
		var tempAr szAr
		tempAr.rangeLimit = a.db.rangeLimit
		if tempBufs, err = a.readAndDecodePackedStreams(sd, numAdditionalStreamsMax, &tempAr); err != nil {
			return err
		}
		if t, err = sd.readNumber(); err != nil {
			return err
		}
	}
	if t == idMainStreamsInfo {
		dataPos, err := a.db.readStreamsInfo(sd, 1<<30, tempBufs, &ssi)
		if err != nil {
			return err
		}
		a.dataPos = dataPos + startHeaderSize
		if t, err = sd.readNumber(); err != nil {
			return err
		}
	}
	if t == idEnd {
		return nil
	}
	if t != idFilesInfo {
		return ErrArchive
	}

	numFiles, err := sd.readNumber32()
	if err != nil {
		return err
	}
	n := int(numFiles)
	entries := make([]Entry, n)
	var emptyStreams, emptyFiles []byte
	numEmptyStreams := 0
	var names []byte
	var attribs bitUi32s
	var mtimeDefs, ctimeDefs, atimeDefs []byte
	var mtimes, ctimes, atimes []uint64
	for {
		t, err := sd.readNumber()
		if err != nil {
			return err
		}
		if t == idEnd {
			break
		}
		size, err := sd.readNumber()
		if err != nil {
			return err
		}
		if size > uint64(len(sd.b)) {
			return ErrArchive
		}
		sw := &szData{b: sd.b[:size]}
		sd.b = sd.b[size:]
		if t >= 64 {
			continue
		}
		switch t {
		case idEmptyStream:
			if emptyStreams != nil || emptyFiles != nil {
				return ErrArchive
			}
			if (n+7)>>3 != len(sw.b) {
				return ErrArchive
			}
			emptyStreams = sw.b
			numEmptyStreams = countDefinedBits(emptyStreams, n)
		case idEmptyFile:
			if emptyFiles != nil {
				return ErrArchive
			}
			if (numEmptyStreams+7)>>3 != len(sw.b) {
				return ErrArchive
			}
			emptyFiles = sw.b
		case idName:
			if names != nil {
				return ErrArchive
			}
			external, err := sw.readByte()
			if err != nil {
				return err
			}
			data := sw.b
			if external != 0 {
				idx, err := sw.readNumber32()
				if err != nil {
					return err
				}
				if int(idx) >= len(tempBufs) || len(sw.b) != 0 {
					return ErrArchive
				}
				data = tempBufs[idx]
			}
			if len(data)&1 != 0 {
				return ErrArchive
			}
			names = data
			if err := readFileNames(names, entries); err != nil {
				return err
			}
		case idWinAttrib:
			if attribs.defs != nil {
				return ErrArchive
			}
			if attribs.defs, err = sw.readBitVector(n); err != nil {
				return err
			}
			external, err := sw.readByte()
			if err != nil {
				return err
			}
			if external != 0 {
				idx, err := sw.readNumber32()
				if err != nil {
					return err
				}
				if int(idx) >= len(tempBufs) || len(sw.b) != 0 {
					return ErrArchive
				}
				sw = &szData{b: tempBufs[idx]}
			}
			if err := sw.readUi32s(n, &attribs); err != nil {
				return err
			}
			if len(sw.b) != 0 {
				return ErrArchive
			}
		case idMTime:
			if mtimeDefs != nil {
				return ErrArchive
			}
			if mtimeDefs, mtimes, err = readTime(sw, n, tempBufs); err != nil {
				return err
			}
		case idCTime:
			if ctimeDefs != nil {
				return ErrArchive
			}
			if ctimeDefs, ctimes, err = readTime(sw, n, tempBufs); err != nil {
				return err
			}
		case idATime:
			if atimeDefs != nil {
				return ErrArchive
			}
			if atimeDefs, atimes, err = readTime(sw, n, tempBufs); err != nil {
				return err
			}
		}
	}
	if n-numEmptyStreams != ssi.numTotalSubStreams {
		return ErrArchive
	}
	for {
		t, err := sd.readNumber()
		if err != nil {
			return err
		}
		if t == idEnd {
			break
		}
		if err := sd.skipData(); err != nil {
			return err
		}
	}

	// Assign files to folders and sub-streams (the second half of
	// SzReadHeader2).
	numFolders := len(a.db.folders)
	a.folderToFile = make([]int, numFolders+1)
	emptyFileIndex := 0
	folderIndex := 0
	remSubStreams := 0
	numSubStreams := 0
	var unpackPos uint64
	var digestsDefs, digestsVals []byte
	digestIndex := 0
	if len(ssi.sdCRCs) != 0 {
		allDefined := ssi.sdCRCs[0]
		if allDefined != 0 {
			digestsVals = ssi.sdCRCs[1:]
		} else {
			numBytes := (ssi.numSubDigests + 7) >> 3
			digestsDefs = ssi.sdCRCs[1:]
			digestsVals = digestsDefs[numBytes:]
		}
	}
	nss := &szData{b: ssi.sdNumSubStreams}
	sizes := &szData{b: ssi.sdSizes}
	for i := 0; i < n; i++ {
		e := &entries[i]
		e.unpackPos = unpackPos
		e.folder = -1
		if attribs.check(i) {
			e.Attrib = attribs.vals[i]
			e.HasAttrib = true
		}
		if mtimeDefs != nil && bitCheck(mtimeDefs, i) {
			e.MTime, e.HasMTime = mtimes[i], true
		}
		if ctimeDefs != nil && bitCheck(ctimeDefs, i) {
			e.CTime, e.HasCTime = ctimes[i], true
		}
		if atimeDefs != nil && bitCheck(atimeDefs, i) {
			e.ATime, e.HasATime = atimes[i], true
		}
		isEmptyStream := emptyStreams != nil && bitCheck(emptyStreams, i)
		if isEmptyStream {
			if emptyFiles != nil {
				if !bitCheck(emptyFiles, emptyFileIndex) {
					e.IsDir = true
				}
				emptyFileIndex++
			} else {
				e.IsDir = true
			}
			if remSubStreams == 0 {
				continue
			}
		}
		if remSubStreams == 0 {
			for {
				if folderIndex >= numFolders {
					return ErrArchive
				}
				a.folderToFile[folderIndex] = i
				numSubStreams = 1
				if ssi.sdNumSubStreams != nil {
					v, err := nss.readNumber32()
					if err != nil {
						return err
					}
					numSubStreams = int(v)
				}
				remSubStreams = numSubStreams
				if numSubStreams != 0 {
					break
				}
				fus := a.db.folders[folderIndex].unpackSize()
				unpackPos += fus
				if unpackPos < fus {
					return ErrArchive
				}
				folderIndex++
			}
		}
		e.folder = folderIndex
		if isEmptyStream {
			continue
		}
		remSubStreams--
		if remSubStreams == 0 {
			f := &a.db.folders[folderIndex]
			fus := f.unpackSize()
			startFolderUnpackPos := entries[a.folderToFile[folderIndex]].unpackPos
			if fus < unpackPos-startFolderUnpackPos {
				return ErrArchive
			}
			unpackPos = startFolderUnpackPos + fus
			if unpackPos < fus {
				return ErrArchive
			}
			if numSubStreams == 1 && f.crcDefined {
				e.CRC, e.HasCRC = f.crc, true
			}
			folderIndex++
		} else {
			v, err := sizes.readNumber()
			if err != nil {
				return err
			}
			unpackPos += v
			if unpackPos < v {
				return ErrArchive
			}
		}
		if !e.HasCRC && digestsVals != nil {
			if digestsDefs == nil || bitCheck(digestsDefs, digestIndex) {
				if len(digestsVals) < 4 {
					return ErrArchive
				}
				e.CRC, e.HasCRC = getUi32(digestsVals), true
				digestsVals = digestsVals[4:]
			}
			digestIndex++
		}
		e.Size = unpackPos - e.unpackPos
	}
	if remSubStreams != 0 {
		return ErrArchive
	}
	for {
		a.folderToFile[folderIndex] = n
		if folderIndex >= numFolders {
			break
		}
		if ssi.sdNumSubStreams == nil {
			return ErrArchive
		}
		v, err := nss.readNumber32()
		if err != nil {
			return err
		}
		if v != 0 {
			return ErrArchive
		}
		folderIndex++
	}
	if ssi.sdNumSubStreams != nil && len(nss.b) != 0 {
		return ErrArchive
	}
	a.Entries = entries
	return nil
}

// readFileNames is SzReadFileNames: UTF-16LE, each name NUL-terminated.
func readFileNames(data []byte, entries []Entry) error {
	if len(entries) == 0 {
		if len(data) != 0 {
			return ErrArchive
		}
		return nil
	}
	if len(data) < 2 {
		return ErrArchive
	}
	if data[len(data)-2] != 0 || data[len(data)-1] != 0 {
		return ErrArchive
	}
	p := 0
	for i := range entries {
		if p >= len(data) {
			return ErrArchive
		}
		start := p
		for p+1 < len(data) && (data[p] != 0 || data[p+1] != 0) {
			p += 2
		}
		u := make([]uint16, 0, (p-start)/2)
		for j := start; j < p; j += 2 {
			u = append(u, uint16(data[j])|uint16(data[j+1])<<8)
		}
		entries[i].Name = string(utf16.Decode(u))
		p += 2
	}
	if p != len(data) {
		return ErrArchive
	}
	return nil
}

// decodeFolder is SzAr_DecodeFolder + SzFolder_Decode2 for the folders
// this module can decode (CheckSupportedFolder): one coder, Copy, LZMA
// or LZMA2, optionally with one filter coder bound to it (two coders,
// bond in-stream 1 from coder 0, one pack stream). A filter not yet
// ported and BCJ2 are their own parity lines and return ErrUnsupported.
func (a *Archive) decodeFolder(p *szAr, fo int, dataStart uint64) ([]byte, error) {
	f := &p.folders[fo]
	outSize := f.unpackSize()
	var filter *coderInfo
	switch len(f.coders) {
	case 1:
		if len(f.packStreams) != 1 || f.packStreams[0] != 0 || len(f.bonds) != 0 {
			return nil, ErrUnsupported
		}
	case 2:
		filter = &f.coders[1]
		if filter.numStreams != 1 || len(f.packStreams) != 1 || f.packStreams[0] != 0 ||
			len(f.bonds) != 1 || f.bonds[0].inIndex != 1 || f.bonds[0].outIndex != 0 {
			return nil, ErrUnsupported
		}
		switch filter.methodID {
		case MethodBCJ:
			if len(filter.props) != 0 {
				return nil, ErrUnsupported
			}
		default:
			return nil, ErrUnsupported
		}
	default:
		return nil, ErrUnsupported
	}
	c := &f.coders[0]
	if c.numStreams != 1 {
		return nil, ErrUnsupported
	}
	packIndex := f.startPackStream
	offset := p.packPositions[packIndex]
	inSize := p.packPositions[packIndex+1] - offset
	in, err := a.readAt(dataStart+offset, inSize)
	if err != nil {
		return nil, err
	}
	out := make([]byte, outSize)
	switch c.methodID {
	case MethodCopy:
		if inSize != outSize {
			return nil, ErrData
		}
		copy(out, in)
	case MethodBCJ:
		// The filter as the folder's only coder (-m0=BCJ with no -m1).
		// 7zDec.c rejects this (the first coder must be a main method);
		// the oracle writes and reads it, so the module reads it too.
		if filter != nil || len(c.props) != 0 || inSize != outSize {
			return nil, ErrUnsupported
		}
		copy(out, in)
		filter = c
	case MethodLZMA:
		written, consumed, status, err := lzma.DecodeOneShot(out, in, c.props, lzma.FinishEnd)
		if err != nil {
			return nil, ErrData
		}
		if status == lzma.StatusFinishedWithMark {
			if uint64(written) != outSize || uint64(consumed) != inSize {
				return nil, ErrData
			}
		} else if !(uint64(written) == outSize && uint64(consumed) == inSize && status == lzma.StatusMaybeFinishedWithoutMark) {
			return nil, ErrData
		}
	case MethodLZMA2:
		if len(c.props) != 1 {
			return nil, ErrData
		}
		written, consumed, status, err := lzma.Lzma2DecodeOneShot(out, in, c.props[0], lzma.FinishEnd)
		if err != nil {
			return nil, ErrData
		}
		if status != lzma.StatusFinishedWithMark || uint64(written) != outSize || uint64(consumed) != inSize {
			return nil, ErrData
		}
	default:
		return nil, ErrUnsupported
	}
	if filter != nil {
		// 7zDec.c: the branch converter runs over the whole unpacked
		// folder with pc 0.
		switch filter.methodID {
		case MethodBCJ:
			bra.X86Decode(out)
		default:
			return nil, ErrUnsupported
		}
	}
	if f.crcDefined && crc(out) != f.crc {
		return nil, ErrCRC
	}
	return out, nil
}

// Extract returns the contents of entry i (SzArEx_Extract). Folders are
// decoded whole and cached, so extracting the files of a solid block in
// order decodes it once.
func (a *Archive) Extract(i int) ([]byte, error) {
	e := &a.Entries[i]
	if e.folder < 0 {
		return []byte{}, nil
	}
	if a.cacheFolder != e.folder {
		buf, err := a.decodeFolder(&a.db, e.folder, a.dataPos)
		if err != nil {
			return nil, err
		}
		a.cacheFolder, a.cacheData = e.folder, buf
	}
	start := e.unpackPos - a.Entries[a.folderToFile[e.folder]].unpackPos
	if start+e.Size > uint64(len(a.cacheData)) {
		return nil, ErrArchive
	}
	out := a.cacheData[start : start+e.Size]
	if e.HasCRC && crc(out) != e.CRC {
		return nil, ErrCRC
	}
	return out, nil
}
