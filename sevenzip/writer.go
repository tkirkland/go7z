package sevenzip

import (
	"bytes"
	"errors"
	"fmt"
	"hash"
	"hash/crc32"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"unicode"
	"unicode/utf16"

	"github.com/tkirkland/go7z/bra"
	"github.com/tkirkland/go7z/lzma"
)

// The 7z writer. There is no public-domain SDK source for writing 7z
// archives (the C++ archive layer is LGPL and is not ported), so the
// layout here is reproduced from DOC/7zFormat.txt and from observation
// of what the pinned 7zr writes. Every rule below that is not in the
// format document is marked "observed".

// Method selects the coder for file data.
type Method int

const (
	LZMA2 Method = iota // default
	LZMA
	Copy
	// None stores the filter output with no coder behind it: -m0=BCJ
	// with no -m1 (observed: the folder's only coder is the filter).
	// It requires a Filter.
	None
)

// Filter selects the branch converter placed in front of the coder
// (-m0=<Filter> -m1=<Method>, or -mf=<Filter>; observed: the folder has
// two coders, the method first and the filter second, bound filter
// output to method input, and one unpack size per coder).
type Filter int

const (
	NoFilter Filter = iota
	BCJ             // x86 (bra.X86Convert)
	// BCJ2 is the four-stream x86 converter (bra.Bcj2Encoder). Observed:
	// -mf=BCJ2 (or -m0=BCJ2 -m1=<M> -m2=LZMA -m3=LZMA with the bonds
	// 7-Zip writes) gives a four-coder folder: two LZMA coders for the
	// JUMP and CALL streams (dictionary 1 MB, lc0 lp2, fb 128, normal
	// parser, bt4), the method for MAIN, then BCJ2; the RC stream is a
	// pack stream as is. With Method None (-m0=BCJ2 alone) the folder's
	// only coder is BCJ2 with four pack streams MAIN, CALL, JUMP, RC.
	BCJ2
	ARM  // ARM (32-bit) BL converter (bra.ARMConvert); same folder shapes as BCJ
	ARMT // Thumb BL converter (bra.ARMTConvert); same folder shapes as BCJ
)

// LevelStore is the Level value for -mx0.
const LevelStore = -1

// Options control archive creation. The zero value is the SoT's
// default: LZMA2 at level 5, solid, compressed header, MTime stored.
type Options struct {
	Method Method
	Filter Filter // branch converter in front of Method; NoFilter = none
	Level  int    // -mx 1..9; 0 = default (5); LevelStore = -mx0, which selects Copy (observed)

	// LZMAProps / LZMA2Props override the level defaults for the data
	// coder. Level and ReduceSize are set by the writer.
	LZMAProps  *lzma.EncProps
	LZMA2Props *lzma.Lzma2EncProps

	SolidOff  bool   // -ms=off: one folder per file
	SolidSize uint64 // -ms=s: solid block byte limit; 0 = default (observed, see solidSize)

	NoHeaderCompression bool // -mhc=off
	Threads             int  // -mmt; 0 = default (the number of logical processors, as 7-Zip). See Threads.
	WordSize            int  // sizeof(size_t) of the 7-Zip build reproduced: lzma.WordSize32 or lzma.WordSize64; 0 = WordSize64
	StoreCTime          bool // -mtc=on
	StoreATime          bool // -mta=on
	NoMTime             bool // -mtm=off
}

// item is one archive entry before writing.
type item struct {
	name   string // archive path with '/'
	path   string // on disk
	isDir  bool
	size   uint64
	attrib uint32
	mtime  uint64
	ctime  uint64
	atime  uint64
	crc    uint32
}

// Writer collects items and writes the archive.
type Writer struct {
	opts  Options
	items []item
	seen  map[string]bool
}

// NewWriter returns a writer with the given options.
func NewWriter(opts Options) *Writer {
	return &Writer{opts: opts, seen: map[string]bool{}}
}

// AddPath adds a file or, recursively, a directory, the way "7zr a"
// does for a path argument: the archive name is the path as given
// (separators normalised to '/'), and a directory argument is itself an
// entry followed by its contents.
func (w *Writer) AddPath(path string) error {
	name := strings.ReplaceAll(filepath.ToSlash(path), "\\", "/")
	name = strings.TrimRight(name, "/")
	return w.add(path, name)
}

// AddPathIn is AddPath for the path argument rel as given from inside
// the directory base ("7zr a" run in base): the archive name is rel.
func (w *Writer) AddPathIn(base, rel string) error {
	name := strings.ReplaceAll(filepath.ToSlash(rel), "\\", "/")
	name = strings.TrimRight(name, "/")
	return w.add(filepath.Join(base, filepath.FromSlash(name)), name)
}

func (w *Writer) add(path, name string) error {
	if w.seen[name] {
		return nil
	}
	fi, err := os.Stat(path)
	if err != nil {
		return err
	}
	it := item{name: name, path: path, isDir: fi.IsDir()}
	if !fi.IsDir() {
		if !fi.Mode().IsRegular() {
			return fmt.Errorf("sevenzip: %s: not a regular file", path)
		}
		it.size = uint64(fi.Size())
	}
	it.attrib, it.ctime, it.atime, it.mtime = fileMeta(fi)
	w.seen[name] = true
	w.items = append(w.items, it)
	if fi.IsDir() {
		ents, err := os.ReadDir(path)
		if err != nil {
			return err
		}
		for _, e := range ents {
			if err := w.add(filepath.Join(path, e.Name()), name+"/"+e.Name()); err != nil {
				return err
			}
		}
	}
	return nil
}

// Create writes the archive at archivePath from paths with opts.
func Create(archivePath string, paths []string, opts Options) error {
	w := NewWriter(opts)
	for _, p := range paths {
		if err := w.AddPath(p); err != nil {
			return err
		}
	}
	f, err := os.Create(archivePath)
	if err != nil {
		return err
	}
	if err := w.Write(f); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// nameKey maps a rune for ordering: the separator sorts before every
// other character and letters compare case-insensitively (observed:
// "sub/q" < "subz" < "sub_x" < "_x", "B2" after "b").
func nameKey(r rune) rune {
	if r == '/' {
		return 0
	}
	return unicode.ToUpper(r)
}

// nameLess orders archive names as the SoT does.
func nameLess(a, b string) bool {
	ra, rb := []rune(a), []rune(b)
	for i := 0; i < len(ra) && i < len(rb); i++ {
		ka, kb := nameKey(ra[i]), nameKey(rb[i])
		if ka != kb {
			return ka < kb
		}
	}
	if len(ra) != len(rb) {
		return len(ra) < len(rb)
	}
	return a < b
}

// group is the item class for ordering (observed: directories, then
// empty files, then files with data, each class sorted by name).
func (it *item) group() int {
	switch {
	case it.isDir:
		return 0
	case it.size == 0:
		return 1
	default:
		return 2
	}
}

// solidSize is the default solid block limit (observed on the SoT
// with 1 MB files: LZMA mx1 32 MB, -md=64k and -md=4k 16 MB, -md=1m 128 MB;
// LZMA2 mx1 and -md=4k/64k/256k 64 MB, -md=512k 128 MB). dict is the
// coder dictionary for the level before reduction. Inputs above 200 MB
// were not observed; an upper clamp, if any, is unknown.
func solidSize(m Method, dict uint32) uint64 {
	switch m {
	case LZMA:
		s := uint64(dict) << 7
		if s < 1<<24 {
			s = 1 << 24
		}
		return s
	default:
		s := uint64(dict) << 8
		if s < 1<<26 {
			s = 1 << 26
		}
		return s
	}
}

// coderProps returns the data coder properties for the options; dict is
// the unreduced dictionary.
func (w *Writer) lzmaProps() (lzma.EncProps, uint32) {
	var p lzma.EncProps
	if w.opts.LZMAProps != nil {
		p = *w.opts.LZMAProps
	} else {
		p.Init()
	}
	p.Level = w.level()
	p.WordSize = w.opts.WordSize
	q := p
	q.ReduceSize = ^uint64(0)
	q.Normalize()
	return p, q.DictSize
}

func (w *Writer) lzma2Props() (lzma.Lzma2EncProps, uint32) {
	var p lzma.Lzma2EncProps
	if w.opts.LZMA2Props != nil {
		p = *w.opts.LZMA2Props
	} else {
		p.Init()
	}
	p.LzmaProps.Level = w.level()
	p.LzmaProps.WordSize = w.opts.WordSize
	if w.opts.LZMA2Props == nil {
		p.NumTotalThreads = Threads(w.opts.WordSize, w.opts.Threads, &p)
	}
	q := p.LzmaProps
	q.ReduceSize = ^uint64(0)
	q.Normalize()
	return p, q.DictSize
}

func (w *Writer) level() int {
	switch w.opts.Level {
	case 0:
		return 5
	case LevelStore:
		return 0
	}
	return w.opts.Level
}

// folderPlan is one folder to encode: a run of data items.
type folderPlan struct {
	items      []int // indices into sorted items
	unpackSize uint64
	packSize   uint64 // total of packSizes
	coderID    uint32 // main coder; MethodCopy when the filter stands alone (not written then)
	coderProps []byte
	filterID   uint32 // 0 = no filter; otherwise the second coder, bound to the first
	noCoder    bool   // Method None: the filter is the only coder

	// BCJ2 folders have four pack streams, in stored order (packSizes),
	// LZMA side coders (sideProps) and one unpack size per coder.
	packSizes  []uint64
	sideProps  []byte
	sideUnpack [3]uint64 // JUMP, CALL, MAIN stream sizes
}

// packStreamCount is how many pack streams the plan's folder has.
func (p *folderPlan) packStreamCount() int {
	if p.filterID == MethodBCJ2 {
		return 4
	}
	return 1
}

// Write writes the archive. out must support seeking back to the start
// header, which is written last.
func (w *Writer) Write(out io.WriteSeeker) error {
	items := append([]item(nil), w.items...)
	sort.SliceStable(items, func(i, j int) bool {
		gi, gj := items[i].group(), items[j].group()
		if gi != gj {
			return gi < gj
		}
		return nameLess(items[i].name, items[j].name)
	})

	method := w.opts.Method
	if w.opts.Level == LevelStore && method == LZMA2 {
		// -mx0 with the default method selects Copy (observed, also
		// behind a filter: -mf=BCJ -mx0 gives BCJ + Copy).
		method = Copy
	}
	var filterID uint32
	switch w.opts.Filter {
	case NoFilter:
		if method == None {
			return errors.New("sevenzip: Method None needs a Filter")
		}
	case BCJ:
		filterID = MethodBCJ
	case BCJ2:
		filterID = MethodBCJ2
	case ARM:
		filterID = MethodARM
	case ARMT:
		filterID = MethodARMT
	default:
		return fmt.Errorf("sevenzip: unknown filter %d", w.opts.Filter)
	}

	// Plan folders. The solid limit follows the coder's dictionary
	// (solidSize); a filter alone or in front of Copy is solid with no
	// split observed up to 600 MB.
	var plans []folderPlan
	limit := ^uint64(0)
	switch method {
	case LZMA:
		_, dict := w.lzmaProps()
		limit = solidSize(LZMA, dict)
	case LZMA2:
		_, dict := w.lzma2Props()
		limit = solidSize(LZMA2, dict)
	}
	if w.opts.SolidSize != 0 {
		limit = w.opts.SolidSize
	}
	solid := !w.opts.SolidOff && (method != Copy || filterID != 0)
	for i := range items {
		if items[i].group() != 2 {
			continue
		}
		if solid && len(plans) > 0 {
			last := &plans[len(plans)-1]
			if last.unpackSize+items[i].size <= limit {
				last.items = append(last.items, i)
				last.unpackSize += items[i].size
				continue
			}
		}
		plans = append(plans, folderPlan{items: []int{i}, unpackSize: items[i].size, filterID: filterID, noCoder: method == None})
	}

	// Start header placeholder.
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := out.Write(make([]byte, startHeaderSize)); err != nil {
		return err
	}

	// The coder dictionary is reduced to the size of all data files taken
	// together, not to the folder's size: their sum when solid, the
	// largest file when not (observed: -ms=4m with ten 1 MB files gives
	// every 4 MB block a 12 MB dictionary; -ms=off with the same files
	// gives 1 MB, and with 100 and 10000 byte files gives both 12 KB).
	var dataTotal uint64
	for i := range items {
		if solid {
			dataTotal += items[i].size
		} else if items[i].size > dataTotal {
			dataTotal = items[i].size
		}
	}

	// Pack streams.
	var packTotal uint64
	for pi := range plans {
		p := &plans[pi]
		cw := &countWriter{w: out}
		fr := &folderReader{items: items, idx: p.items}
		var src io.Reader = fr
		switch p.filterID {
		case MethodBCJ:
			src = bra.NewX86EncodeReader(fr)
		case MethodARM:
			src = bra.NewARMEncodeReader(fr)
		case MethodARMT:
			src = bra.NewARMTEncodeReader(fr)
		}
		var err error
		if p.filterID == MethodBCJ2 {
			sizes := make([]uint64, len(p.items))
			for i, it := range p.items {
				sizes[i] = items[it].size
			}
			if method == None {
				err = encodeBCJ2Only(p, fr, cw, sizes)
			} else {
				err = w.encodeBCJ2Folder(p, fr, cw, method, dataTotal, sizes)
			}
			if err != nil {
				return err
			}
			if err := fr.Close(); err != nil {
				return err
			}
			if fr.total != p.unpackSize {
				return fmt.Errorf("sevenzip: %s changed size while reading", items[p.items[len(p.items)-1]].path)
			}
			p.packSize = cw.n
			packTotal += cw.n
			continue
		}
		switch method {
		case None:
			_, err = io.Copy(cw, src)
		case Copy:
			p.coderID = MethodCopy
			_, err = io.Copy(cw, src)
		case LZMA:
			props, _ := w.lzmaProps()
			props.ReduceSize = dataTotal
			enc := lzma.NewEncoder()
			if err = enc.SetProps(&props); err != nil {
				return err
			}
			enc.SetDataSize(p.unpackSize)
			pr := enc.WriteProperties()
			p.coderID, p.coderProps = MethodLZMA, pr[:]
			err = enc.Encode(cw, src)
		case LZMA2:
			props, _ := w.lzma2Props()
			props.LzmaProps.ReduceSize = dataTotal
			enc := lzma.NewLzma2Encoder()
			if err = enc.SetProps(&props); err != nil {
				return err
			}
			enc.SetDataSize(p.unpackSize)
			p.coderID, p.coderProps = MethodLZMA2, []byte{enc.WriteProperties()}
			err = enc.Encode(cw, src)
		}
		if err != nil {
			return err
		}
		if err := fr.Close(); err != nil {
			return err
		}
		if fr.total != p.unpackSize {
			return fmt.Errorf("sevenzip: %s changed size while reading", items[p.items[len(p.items)-1]].path)
		}
		p.packSize = cw.n
		packTotal += cw.n
	}

	header := buildHeader(items, plans, w.opts.StoreCTime, w.opts.StoreATime, !w.opts.NoMTime)

	// Header compression (observed: used when the archive has two or
	// more items; the header coder is LZMA, dictionary 1 MB).
	var nextHeader []byte
	nextOffset := packTotal
	if !w.opts.NoHeaderCompression && len(items) >= 2 {
		packed, props, err := encodeHeader(header)
		if err != nil {
			return err
		}
		if _, err := out.Write(packed); err != nil {
			return err
		}
		var b []byte
		b = append(b, idEncodedHeader, idPackInfo)
		b = writeNumber(b, packTotal)
		b = writeNumber(b, 1)
		b = append(b, idSize)
		b = writeNumber(b, uint64(len(packed)))
		b = append(b, idEnd)
		b = append(b, idUnpackInfo, idFolder)
		b = writeNumber(b, 1)
		b = append(b, 0) // external
		b = appendCoder(b, MethodLZMA, props[:])
		b = append(b, idCodersUnpackSize)
		b = writeNumber(b, uint64(len(header)))
		b = append(b, idCRC, 1)
		b = appendUi32(b, crc(header))
		b = append(b, idEnd, idEnd)
		nextHeader = b
		nextOffset += uint64(len(packed))
	} else {
		nextHeader = header
	}
	if _, err := out.Write(nextHeader); err != nil {
		return err
	}

	// Start header.
	sh := make([]byte, startHeaderSize)
	copy(sh, signature[:])
	sh[6], sh[7] = 0, 4
	putUi64(sh[12:], nextOffset)
	putUi64(sh[20:], uint64(len(nextHeader)))
	putUi32(sh[28:], crc(nextHeader))
	putUi32(sh[8:], crc(sh[12:32]))
	if _, err := out.Seek(0, io.SeekStart); err != nil {
		return err
	}
	if _, err := out.Write(sh); err != nil {
		return err
	}
	_, err := out.Seek(0, io.SeekEnd)
	return err
}

// bcj2SideProps are the LZMA parameters the SoT uses for the CALL and
// JUMP streams of a BCJ2 folder, at every level including -mx0
// (observed 2026-11-06 on both builds by byte identity with the SoT's
// side streams for the SoT binary and a 100 KB slice of it: dictionary
// 1 MB reduced like the main coder, lc 0, lp 2, pb 2, fb 128, normal
// parser, bt4; fb 64 and bt3/bt5 also matched some streams, 128 and
// bt4 matched all of them). The data-size hint made no difference and
// is not given.
func (w *Writer) bcj2SideProps(reduceSize uint64) lzma.EncProps {
	var p lzma.EncProps
	p.Init()
	p.DictSize = 1 << 20
	p.Lc, p.Lp, p.Pb = 0, 2, 2
	p.Fb = 128
	p.Algo = 1
	p.BtMode, p.NumHashBytes = 1, 4
	p.ReduceSize = reduceSize
	p.WordSize = w.opts.WordSize
	return p
}

// encodeBCJ2Folder encodes one folder behind BCJ2: the converter runs
// over the folder's data file by file (bra.Bcj2Encoder.FileSizes;
// observed: each file is converted with its own start address and
// size, and the block is finished at every file boundary), MAIN goes through the method straight to out, CALL and
// JUMP through the side LZMA coders into memory and RC into memory, and
// the three are written after MAIN in the order the SoT stores them
// (MAIN packed, RC, CALL packed, JUMP packed). Like 7-Zip's mixer, no
// coder is told its data size.
func (w *Writer) encodeBCJ2Folder(p *folderPlan, src io.Reader, out *countWriter, method Method, dataTotal uint64, fileSizes []uint64) error {
	mainR, mainW := io.Pipe()
	callR, callW := io.Pipe()
	jumpR, jumpW := io.Pipe()
	var rc, callPacked, jumpPacked bytes.Buffer
	var callN, jumpN uint64
	errc := make(chan error, 3)

	go func() {
		enc := bra.Bcj2Encoder{FileSizes: fileSizes}
		err := enc.Encode([bra.Bcj2NumStreams]io.Writer{mainW, callW, jumpW, &rc}, src)
		if err == nil {
			// The converter reads exactly the files' sizes; read on to the
			// end so the source sees EOF (and any growth is reported).
			_, err = io.Copy(io.Discard, src)
		}
		mainW.CloseWithError(err)
		callW.CloseWithError(err)
		jumpW.CloseWithError(err)
		errc <- err
	}()

	sideProps := w.bcj2SideProps(dataTotal)
	side := func(r *io.PipeReader, dst *bytes.Buffer, n *uint64) {
		enc := lzma.NewEncoder()
		err := enc.SetProps(&sideProps)
		if err == nil {
			cr := &countReader{r: r}
			err = enc.Encode(dst, cr)
			*n = cr.n
		}
		r.CloseWithError(err)
		errc <- err
	}
	go side(callR, &callPacked, &callN)
	go side(jumpR, &jumpPacked, &jumpN)

	mainIn := &countReader{r: mainR}
	var err error
	switch method {
	case Copy:
		p.coderID = MethodCopy
		_, err = io.Copy(out, mainIn)
	case LZMA:
		props, _ := w.lzmaProps()
		props.ReduceSize = dataTotal
		enc := lzma.NewEncoder()
		if err = enc.SetProps(&props); err == nil {
			pr := enc.WriteProperties()
			p.coderID, p.coderProps = MethodLZMA, pr[:]
			err = enc.Encode(out, mainIn)
		}
	case LZMA2:
		props, _ := w.lzma2Props()
		props.LzmaProps.ReduceSize = dataTotal
		enc := lzma.NewLzma2Encoder()
		if err = enc.SetProps(&props); err == nil {
			p.coderID, p.coderProps = MethodLZMA2, []byte{enc.WriteProperties()}
			err = enc.Encode(out, mainIn)
		}
	default:
		err = fmt.Errorf("sevenzip: method %d cannot stand behind BCJ2", method)
	}
	mainR.CloseWithError(err)
	for i := 0; i < 3; i++ {
		if e := <-errc; e != nil && err == nil {
			err = e
		}
	}
	if err != nil {
		return err
	}
	mainPacked := out.n
	for _, b := range []*bytes.Buffer{&rc, &callPacked, &jumpPacked} {
		if _, err := out.Write(b.Bytes()); err != nil {
			return err
		}
	}
	pr := lzma.NewEncoder()
	if err := pr.SetProps(&sideProps); err != nil {
		return err
	}
	sp := pr.WriteProperties()
	p.sideProps = sp[:]
	p.sideUnpack = [3]uint64{jumpN, callN, mainIn.n}
	p.packSizes = []uint64{mainPacked, uint64(rc.Len()), uint64(callPacked.Len()), uint64(jumpPacked.Len())}
	return nil
}

// encodeBCJ2Only writes a Method None BCJ2 folder: the four streams as
// pack streams in the order MAIN, CALL, JUMP, RC (observed for
// -m0=BCJ2 with no -m1).
func encodeBCJ2Only(p *folderPlan, src io.Reader, out *countWriter, fileSizes []uint64) error {
	var bufs [bra.Bcj2NumStreams]bytes.Buffer
	var outs [bra.Bcj2NumStreams]io.Writer
	for i := range bufs {
		outs[i] = &bufs[i]
	}
	enc := bra.Bcj2Encoder{FileSizes: fileSizes}
	if err := enc.Encode(outs, src); err != nil {
		return err
	}
	if _, err := io.Copy(io.Discard, src); err != nil {
		return err
	}
	p.packSizes = make([]uint64, bra.Bcj2NumStreams)
	for i := range bufs {
		if _, err := out.Write(bufs[i].Bytes()); err != nil {
			return err
		}
		p.packSizes[i] = uint64(bufs[i].Len())
	}
	return nil
}

// countReader counts bytes read through it.
type countReader struct {
	r io.Reader
	n uint64
}

func (c *countReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += uint64(n)
	return n, err
}

// headerEncProps are the LZMA parameters the SoT uses for the packed
// header: dictionary 1 MB (in the coder record), fast bytes 273, normal
// parser, bt2 match finder, default cycles (pinned by byte identity on a
// 74 KB header in TestHeaderEncoderParams; bt3 also matched there).
var headerEncProps = func() lzma.EncProps {
	var p lzma.EncProps
	p.Init()
	p.DictSize = 1 << 20
	p.Fb = 273
	p.Algo = 1
	p.BtMode, p.NumHashBytes = 1, 2
	return p
}()

// headerSetDataSize says whether the header encoder is told the header
// size (it changes the match finder's hash size and so the bytes).
var headerSetDataSize = false

// encodeHeader compresses the raw header with the SoT's header coder.
// The dictionary is reduced to the header size (observed: the coder
// record of a 278-byte header says 4096).
func encodeHeader(header []byte) ([]byte, [5]byte, error) {
	props := headerEncProps
	props.ReduceSize = uint64(len(header))
	enc := lzma.NewEncoder()
	if err := enc.SetProps(&props); err != nil {
		return nil, [5]byte{}, err
	}
	if headerSetDataSize {
		enc.SetDataSize(uint64(len(header)))
	}
	var out bytes.Buffer
	if err := enc.Encode(&out, bytes.NewReader(header)); err != nil {
		return nil, [5]byte{}, err
	}
	return out.Bytes(), enc.WriteProperties(), nil
}

// appendCoder writes one folder with one coder (NumCoders = 1).
func appendCoder(b []byte, id uint32, props []byte) []byte {
	b = writeNumber(b, 1)
	return appendCoderRecord(b, id, props)
}

// appendFolder writes the folder record of a plan: the main coder, then
// the filter coder bound to it (observed: coder order method, filter;
// bond InIndex 1 OutIndex 0; the single pack stream is implicit), or
// the filter alone for Method None. BCJ2 folders are appendBCJ2Folder.
func appendFolder(b []byte, p *folderPlan) []byte {
	switch {
	case p.filterID == MethodBCJ2:
		return appendBCJ2Folder(b, p)
	case p.filterID == 0:
		return appendCoder(b, p.coderID, p.coderProps)
	case p.noCoder:
		return appendCoder(b, p.filterID, nil)
	}
	b = writeNumber(b, 2)
	b = appendCoderRecord(b, p.coderID, p.coderProps)
	b = appendCoderRecord(b, p.filterID, nil)
	b = writeNumber(b, 1) // bond: in-stream 1 (the filter's input)
	b = writeNumber(b, 0) // ... from coder 0's output
	return b
}

// numCoders is how many coders the plan's folder has (one unpack size
// is written per coder).
func (p *folderPlan) numCoders() int {
	switch {
	case p.filterID == MethodBCJ2 && !p.noCoder:
		return 4
	case p.filterID != 0 && !p.noCoder:
		return 2
	}
	return 1
}

// coderUnpackSize is the unpack size written for coder c of the plan's
// folder (observed for BCJ2: JUMP, CALL, MAIN, then the folder size;
// otherwise every coder carries the folder size).
func (p *folderPlan) coderUnpackSize(c int) uint64 {
	if p.filterID == MethodBCJ2 && !p.noCoder && c < 3 {
		return p.sideUnpack[c]
	}
	return p.unpackSize
}

// appendBCJ2Folder writes a BCJ2 folder record (observed from the SoT's
// -mf=BCJ2 archives, the shape 7zDec.c accepts): coders LZMA (JUMP),
// LZMA (CALL), the method (MAIN), BCJ2 with four in-streams; bonds
// in-stream 5 from coder 0, 4 from 1, 3 from 2; pack streams in-streams
// 2 (MAIN packed), 6 (RC), 1 (CALL packed), 0 (JUMP packed). For Method
// None the only coder is BCJ2 and its four in-streams are the pack
// streams in order.
func appendBCJ2Folder(b []byte, p *folderPlan) []byte {
	if p.noCoder {
		b = writeNumber(b, 1)
		b = appendComplexCoderRecord(b, MethodBCJ2, 4)
		for i := 0; i < 4; i++ {
			b = writeNumber(b, uint64(i))
		}
		return b
	}
	b = writeNumber(b, 4)
	b = appendCoderRecord(b, MethodLZMA, p.sideProps)
	b = appendCoderRecord(b, MethodLZMA, p.sideProps)
	b = appendCoderRecord(b, p.coderID, p.coderProps)
	b = appendComplexCoderRecord(b, MethodBCJ2, 4)
	for _, bond := range [][2]uint64{{5, 0}, {4, 1}, {3, 2}} {
		b = writeNumber(b, bond[0])
		b = writeNumber(b, bond[1])
	}
	for _, ps := range []uint64{2, 6, 1, 0} {
		b = writeNumber(b, ps)
	}
	return b
}

// appendComplexCoderRecord writes a coder record with numIn in-streams
// and one out-stream (the 0x10 flag) and no properties.
func appendComplexCoderRecord(b []byte, id uint32, numIn int) []byte {
	var idBytes []byte
	for v := id; v != 0; v >>= 8 {
		idBytes = append([]byte{byte(v)}, idBytes...)
	}
	b = append(b, byte(len(idBytes))|0x10)
	b = append(b, idBytes...)
	b = writeNumber(b, uint64(numIn))
	b = writeNumber(b, 1)
	return b
}

// appendCoderRecord writes one coder record (id, number of streams,
// properties).
func appendCoderRecord(b []byte, id uint32, props []byte) []byte {
	var idBytes []byte
	switch {
	case id == 0:
		idBytes = []byte{0} // observed: Copy is written with a 1-byte id
	default:
		for v := id; v != 0; v >>= 8 {
			idBytes = append([]byte{byte(v)}, idBytes...)
		}
	}
	mainByte := byte(len(idBytes))
	if len(props) > 0 {
		mainByte |= 0x20
	}
	b = append(b, mainByte)
	b = append(b, idBytes...)
	if len(props) > 0 {
		b = writeNumber(b, uint64(len(props)))
		b = append(b, props...)
	}
	return b
}

func appendUi32(b []byte, v uint32) []byte {
	return append(b, byte(v), byte(v>>8), byte(v>>16), byte(v>>24))
}

func appendUi64(b []byte, v uint64) []byte {
	return appendUi32(appendUi32(b, uint32(v)), uint32(v>>32))
}

// hdr accumulates the raw header.
type hdr struct {
	b []byte
}

// skipToAligned pads with kDummy so that the data that follows the next
// property's pre bytes starts at a multiple of 1<<shift from the header
// start (observed: names 16, times 8, attributes 4).
func (h *hdr) skipToAligned(pre int, shift uint) {
	align := 1 << shift
	pos := (len(h.b) + pre) & (align - 1)
	if pos == 0 {
		return
	}
	skip := align - pos
	if skip < 2 {
		skip += align
	}
	skip -= 2
	h.b = append(h.b, idDummy, byte(skip))
	h.b = append(h.b, make([]byte, skip)...)
}

func buildHeader(items []item, plans []folderPlan, storeCTime, storeATime, storeMTime bool) []byte {
	h := &hdr{}
	h.b = append(h.b, idHeader)

	if len(plans) > 0 {
		h.b = append(h.b, idMainStreamsInfo)
		// PackInfo
		h.b = append(h.b, idPackInfo)
		h.b = writeNumber(h.b, 0)
		numPack := 0
		for i := range plans {
			numPack += plans[i].packStreamCount()
		}
		h.b = writeNumber(h.b, uint64(numPack))
		h.b = append(h.b, idSize)
		for i := range plans {
			if plans[i].packStreamCount() == 1 {
				h.b = writeNumber(h.b, plans[i].packSize)
				continue
			}
			for _, ps := range plans[i].packSizes {
				h.b = writeNumber(h.b, ps)
			}
		}
		h.b = append(h.b, idEnd)
		// UnpackInfo
		h.b = append(h.b, idUnpackInfo, idFolder)
		h.b = writeNumber(h.b, uint64(len(plans)))
		h.b = append(h.b, 0)
		for i := range plans {
			h.b = appendFolder(h.b, &plans[i])
		}
		h.b = append(h.b, idCodersUnpackSize)
		for i := range plans {
			// One size per coder; a filter keeps the size (observed:
			// both sizes equal the folder's unpack size); BCJ2's side
			// coders carry their stream sizes.
			for c := 0; c < plans[i].numCoders(); c++ {
				h.b = writeNumber(h.b, plans[i].coderUnpackSize(c))
			}
		}
		h.b = append(h.b, idEnd)
		// SubStreamsInfo (observed: CRCs always here, never as folder CRCs)
		h.b = append(h.b, idSubStreamsInfo)
		multi := false
		for i := range plans {
			if len(plans[i].items) != 1 {
				multi = true
			}
		}
		if multi {
			h.b = append(h.b, idNumUnpackStream)
			for i := range plans {
				h.b = writeNumber(h.b, uint64(len(plans[i].items)))
			}
			h.b = append(h.b, idSize)
			for i := range plans {
				for _, it := range plans[i].items[:len(plans[i].items)-1] {
					h.b = writeNumber(h.b, items[it].size)
				}
			}
		}
		h.b = append(h.b, idCRC, 1)
		for i := range plans {
			for _, it := range plans[i].items {
				h.b = appendUi32(h.b, items[it].crc)
			}
		}
		h.b = append(h.b, idEnd)
		h.b = append(h.b, idEnd)
	}

	// FilesInfo
	n := len(items)
	h.b = append(h.b, idFilesInfo)
	h.b = writeNumber(h.b, uint64(n))
	numEmpty := 0
	for i := range items {
		if items[i].group() != 2 {
			numEmpty++
		}
	}
	if numEmpty > 0 {
		bits := make([]byte, (n+7)/8)
		for i := range items {
			if items[i].group() != 2 {
				bits[i>>3] |= 0x80 >> (uint(i) & 7)
			}
		}
		h.b = append(h.b, idEmptyStream)
		h.b = writeNumber(h.b, uint64(len(bits)))
		h.b = append(h.b, bits...)
		numEmptyFiles := 0
		ef := make([]byte, (numEmpty+7)/8)
		j := 0
		for i := range items {
			if items[i].group() == 2 {
				continue
			}
			if !items[i].isDir {
				ef[j>>3] |= 0x80 >> (uint(j) & 7)
				numEmptyFiles++
			}
			j++
		}
		if numEmptyFiles > 0 {
			h.b = append(h.b, idEmptyFile)
			h.b = writeNumber(h.b, uint64(len(ef)))
			h.b = append(h.b, ef...)
		}
	}

	// Names
	var names []byte
	for i := range items {
		for _, u := range utf16.Encode([]rune(items[i].name)) {
			names = append(names, byte(u), byte(u>>8))
		}
		names = append(names, 0, 0)
	}
	nameSize := uint64(len(names) + 1)
	h.skipToAligned(1+numberSize(nameSize)+1, 4)
	h.b = append(h.b, idName)
	h.b = writeNumber(h.b, nameSize)
	h.b = append(h.b, 0)
	h.b = append(h.b, names...)

	writeTimes := func(id byte, get func(*item) uint64) {
		size := uint64(2 + 8*n)
		h.skipToAligned(1+numberSize(size)+2, 3)
		h.b = append(h.b, id)
		h.b = writeNumber(h.b, size)
		h.b = append(h.b, 1, 0)
		for i := range items {
			h.b = appendUi64(h.b, get(&items[i]))
		}
	}
	if storeCTime {
		writeTimes(idCTime, func(it *item) uint64 { return it.ctime })
	}
	if storeATime {
		writeTimes(idATime, func(it *item) uint64 { return it.atime })
	}
	if storeMTime {
		writeTimes(idMTime, func(it *item) uint64 { return it.mtime })
	}

	// Attributes
	{
		size := uint64(2 + 4*n)
		h.skipToAligned(1+numberSize(size)+2, 2)
		h.b = append(h.b, idWinAttrib)
		h.b = writeNumber(h.b, size)
		h.b = append(h.b, 1, 0)
		for i := range items {
			h.b = appendUi32(h.b, items[i].attrib)
		}
	}
	h.b = append(h.b, idEnd)
	h.b = append(h.b, idEnd)
	return h.b
}

// countWriter counts bytes written through it.
type countWriter struct {
	w io.Writer
	n uint64
}

func (c *countWriter) Write(p []byte) (int, error) {
	n, err := c.w.Write(p)
	c.n += uint64(n)
	return n, err
}

// folderReader concatenates the data of the folder's items and records
// each item's CRC as it goes.
type folderReader struct {
	items []item
	idx   []int
	pos   int
	cur   *os.File
	h     hash.Hash32
	total uint64
	got   uint64
}

func (r *folderReader) Read(p []byte) (int, error) {
	for {
		if r.cur == nil {
			if r.pos >= len(r.idx) {
				return 0, io.EOF
			}
			it := &r.items[r.idx[r.pos]]
			f, err := os.Open(it.path)
			if err != nil {
				return 0, err
			}
			r.cur = f
			r.h = crc32.NewIEEE()
			r.got = 0
		}
		it := &r.items[r.idx[r.pos]]
		n, err := r.cur.Read(p)
		if n > 0 {
			r.h.Write(p[:n])
			r.got += uint64(n)
			r.total += uint64(n)
			if r.got > it.size {
				return 0, fmt.Errorf("sevenzip: %s grew while reading", it.path)
			}
		}
		if err == io.EOF {
			if r.got != it.size {
				return 0, fmt.Errorf("sevenzip: %s shrank while reading", it.path)
			}
			it.crc = r.h.Sum32()
			r.cur.Close()
			r.cur = nil
			r.pos++
			if n > 0 {
				return n, nil
			}
			continue
		}
		if err != nil {
			return n, err
		}
		if n == 0 {
			continue
		}
		return n, nil
	}
}

func (r *folderReader) Close() error {
	if r.cur != nil {
		r.cur.Close()
		r.cur = nil
		return errors.New("sevenzip: folder data not fully read")
	}
	return nil
}
