package sevenzip

import (
	"bytes"
	"crypto/rand"
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
	"github.com/tkirkland/go7z/ppmd"
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
	// PPMd is the PPMD method (ppmd package, Ppmd7z); order and memory
	// follow the level unless Options.PPMdOrder / PPMdMem are set (see
	// ppmd.go for the observed rules).
	PPMd
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
	// ARM64 is the AArch64 BL/ADRP converter (bra.ARM64Convert); same
	// folder shapes as BCJ. Observed: coder record 01 0A (1-byte id, no
	// properties) in both lanes; the SoT rejects -m0=ARM64:pc=N.
	ARM64
	// Swap2 and Swap4 are the byte-swap filters (bra.Swap2Convert,
	// bra.Swap4Convert); same folder shapes as BCJ. Observed: coder
	// records 03 02 03 02 and 03 02 03 04, no properties, identical in
	// both lanes; -mf=Swap2 is accepted; a parameter is rejected.
	Swap2
	Swap4
	// Delta is the Delta filter (bra.DeltaEncode, ported from Delta.c)
	// with Options.DeltaDistance; same folder shapes as BCJ. Observed:
	// coder record 21 03 01 <distance-1>, identical in both lanes;
	// -m0=Delta is distance 1; 0 and 257 are rejected.
	Delta
)

// LevelStore is the Level value for -mx0.
const LevelStore = -1

// Options control archive creation. The zero value is the SoT's
// default: LZMA2 at level 5, solid, compressed header, MTime stored.
type Options struct {
	Method Method
	Filter Filter // branch converter in front of Method; NoFilter = none
	// DeltaDistance is the Delta filter's distance, 1..256; 0 means the
	// SoT's default (1). Ignored for the other filters.
	DeltaDistance int
	// PPMdOrder and PPMdMem are -m0=PPMd:o=N:mem=M for Method PPMd; 0
	// means the level's default (ppmd.go).
	PPMdOrder int
	PPMdMem   uint32
	// NoAutoFilter is -mf=off. By default (as the SoT's -mf=on) files
	// that look like executables get a branch filter chosen by
	// analysis (analyze.go) when Filter is NoFilter. Analysis is -myx:
	// 0 means the default level (5); AnalysisNone is -myx0.
	NoAutoFilter bool
	Analysis     int
	Level        int // -mx 1..9; 0 = default (5); LevelStore = -mx0, which selects Copy (observed)

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

	// Password enables 7zAES (-p): every pack stream is encrypted with
	// AES-256-CBC under a key derived from the password (see aes.go).
	Password string
	// EncryptHeader is -mhe: the header is compressed and encrypted too,
	// so the file names need the password.
	EncryptHeader bool
	// Random supplies the 16-byte IVs, one per 7zAES coder in the order
	// the coders are written (folder by folder, each folder's coders in
	// record order, then the header's). nil means crypto/rand. Tests
	// inject the SoT's IVs here to reproduce its bytes.
	Random io.Reader
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
	kind   exeKind // analysis result (analyze.go); exeNone unless -mf=on applies
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
	items       []int // indices into sorted items
	unpackSize  uint64
	packSize    uint64 // total of packSizes
	coderID     uint32 // main coder; MethodCopy when the filter stands alone (not written then)
	coderProps  []byte
	filterID    uint32  // 0 = no filter; otherwise the second coder, bound to the first
	filterProps []byte  // the filter coder's properties (Delta: one byte, distance-1)
	noCoder     bool    // Method None: the filter is the only coder
	kind        exeKind // the automatic filter's kind (sets lc/lp for LZMA), exeNone when forced or none

	// BCJ2 folders have four pack streams, in stored order (packSizes),
	// LZMA side coders (sideProps) and one unpack size per coder.
	packSizes  []uint64
	sideProps  []byte
	sideUnpack [3]uint64 // JUMP, CALL, MAIN stream sizes

	// 7zAES: when encrypt is set, every pack stream is encrypted and the
	// folder record gains one 7zAES coder per pack stream (coder j wraps
	// stored pack stream k-1-j; see aes.go). aesIVs and aesUnpack are in
	// coder order; packSize/packSizes are the padded sizes.
	encrypt   bool
	aesKey    [32]byte
	aesIVs    [][aesBlock]byte
	aesUnpack []uint64
}

// wrapPack returns the writer for stored pack stream i: an encrypting
// writer when the folder is encrypted, w itself otherwise. close must
// be called when the stream is complete; it pads the last block and
// records the unpadded size as the 7zAES coder's unpack size.
func (p *folderPlan) wrapPack(i int, w io.Writer) (io.Writer, func() error, error) {
	if !p.encrypt {
		return w, func() error { return nil }, nil
	}
	j := len(p.aesIVs) - 1 - i
	aw, err := newAESWriter(w, p.aesKey, p.aesIVs[j])
	if err != nil {
		return nil, nil, err
	}
	return aw, func() error {
		if err := aw.Close(); err != nil {
			return err
		}
		p.aesUnpack[j] = aw.plain
		return nil
	}, nil
}

// prepareAES draws the folder's IVs (one per pack stream) from random
// and sets the key.
func (p *folderPlan) prepareAES(key [32]byte, random io.Reader) error {
	k := p.packStreamCount()
	p.encrypt = true
	p.aesKey = key
	p.aesIVs = make([][aesBlock]byte, k)
	p.aesUnpack = make([]uint64, k)
	for j := range p.aesIVs {
		if _, err := io.ReadFull(random, p.aesIVs[j][:]); err != nil {
			return fmt.Errorf("sevenzip: reading IV: %w", err)
		}
	}
	return nil
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

	method := w.opts.Method
	if w.opts.Level == LevelStore && method == LZMA2 {
		// -mx0 with the default method selects Copy (observed, also
		// behind a filter: -mf=BCJ -mx0 gives BCJ + Copy).
		method = Copy
	}

	// Automatic filters (-mf=on, analyze.go): with no forced filter and
	// a level above 0, every data file whose name the analysis level
	// selects is inspected and gets its kind; items are then grouped by
	// kind.
	auto := w.opts.Filter == NoFilter && !w.opts.NoAutoFilter && method != None && w.level() > 0
	analysis := w.opts.Analysis
	if analysis == 0 {
		analysis = AnalysisDefault
	}
	if auto && analysis > 0 {
		for i := range items {
			it := &items[i]
			if it.group() != 2 || !analysisWanted(it.name, analysis) {
				continue
			}
			k, err := analyzeFile(it.path, it.size)
			if err != nil {
				return err
			}
			if k.omittedConverter() {
				return fmt.Errorf("sevenzip: %s is a PPC, SPARC or IA64 image; the SoT applies a converter this module omits", it.path)
			}
			it.kind = k
		}
	}

	sort.SliceStable(items, func(i, j int) bool {
		gi, gj := items[i].group(), items[j].group()
		if gi != gj {
			return gi < gj
		}
		if items[i].kind != items[j].kind {
			return items[i].kind < items[j].kind
		}
		return nameLess(items[i].name, items[j].name)
	})

	var filterID uint32
	var filterProps []byte
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
	case ARM64:
		filterID = MethodARM64
	case Swap2:
		filterID = MethodSwap2
	case Swap4:
		filterID = MethodSwap4
	case Delta:
		filterID = MethodDelta
		d := w.opts.DeltaDistance
		if d == 0 {
			d = 1
		}
		if d < 1 || d > 256 {
			return fmt.Errorf("sevenzip: Delta distance %d out of range 1..256", d)
		}
		filterProps = []byte{byte(d - 1)}
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
	case PPMd:
		// Observed: the LZMA rule on the PPMd memory (ppmd.go).
		_, mem := w.ppmdParams()
		limit = solidSize(LZMA, mem)
	}
	if w.opts.SolidSize != 0 {
		limit = w.opts.SolidSize
	}
	solid := !w.opts.SolidOff && (method != Copy || filterID != 0)
	for i := range items {
		if items[i].group() != 2 {
			continue
		}
		kind := items[i].kind
		if solid && len(plans) > 0 {
			last := &plans[len(plans)-1]
			if last.kind == kind && last.unpackSize+items[i].size <= limit {
				last.items = append(last.items, i)
				last.unpackSize += items[i].size
				continue
			}
		}
		p := folderPlan{items: []int{i}, unpackSize: items[i].size, filterID: filterID, filterProps: filterProps, noCoder: method == None, kind: kind}
		if kind != exeNone {
			p.filterID, _ = kindFilter(kind, w.level())
		}
		plans = append(plans, p)
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

	// 7zAES: one key for the archive, IVs drawn per coder in writing
	// order.
	var key [32]byte
	random := w.opts.Random
	if w.opts.Password != "" {
		key = aesKey(w.opts.Password, nil, aesDefaultCycles)
		if random == nil {
			random = rand.Reader
		}
	}

	// Pack streams.
	var packTotal uint64
	for pi := range plans {
		p := &plans[pi]
		cw := &countWriter{w: out}
		if w.opts.Password != "" {
			if err := p.prepareAES(key, random); err != nil {
				return err
			}
		}
		fr := &folderReader{items: items, idx: p.items}
		var src io.Reader = fr
		switch p.filterID {
		case MethodBCJ:
			src = bra.NewX86EncodeReader(fr)
		case MethodARM:
			src = bra.NewARMEncodeReader(fr)
		case MethodARMT:
			src = bra.NewARMTEncodeReader(fr)
		case MethodARM64:
			src = bra.NewARM64EncodeReader(fr)
		case MethodSwap2:
			src = bra.NewSwap2EncodeReader(fr)
		case MethodSwap4:
			src = bra.NewSwap4EncodeReader(fr)
		case MethodDelta:
			src = bra.NewDeltaEncodeReader(int(p.filterProps[0])+1, fr)
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
		dst, closeDst, werr := p.wrapPack(0, cw)
		if werr != nil {
			return werr
		}
		switch method {
		case None:
			_, err = io.Copy(dst, src)
		case Copy:
			p.coderID = MethodCopy
			_, err = io.Copy(dst, src)
		case LZMA:
			props, _ := w.lzmaProps()
			props.ReduceSize = dataTotal
			applyKindProps(p.kind, &props)
			enc := lzma.NewEncoder()
			if err = enc.SetProps(&props); err != nil {
				return err
			}
			enc.SetDataSize(p.unpackSize)
			pr := enc.WriteProperties()
			p.coderID, p.coderProps = MethodLZMA, pr[:]
			err = enc.Encode(dst, src)
		case LZMA2:
			props, _ := w.lzma2Props()
			props.LzmaProps.ReduceSize = dataTotal
			applyKindProps(p.kind, &props.LzmaProps)
			enc := lzma.NewLzma2Encoder()
			if err = enc.SetProps(&props); err != nil {
				return err
			}
			enc.SetDataSize(p.unpackSize)
			p.coderID, p.coderProps = MethodLZMA2, []byte{enc.WriteProperties()}
			err = enc.Encode(dst, src)
		case PPMd:
			order, mem := w.ppmdParams()
			mem = PPMdReducedMem(mem, dataTotal)
			var enc *ppmd.Encoder
			if enc, err = ppmd.NewEncoder(order, mem); err != nil {
				return err
			}
			p.coderID, p.coderProps = MethodPPMD, ppmdProps(order, mem)
			err = enc.Encode(dst, src)
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
		if err := closeDst(); err != nil {
			return err
		}
		p.packSize = cw.n
		packTotal += cw.n
	}

	header := buildHeader(items, plans, w.opts.StoreCTime, w.opts.StoreATime, !w.opts.NoMTime)

	// Header compression (observed: used when the archive has two or
	// more items; the header coder is LZMA, dictionary 1 MB).
	var nextHeader []byte
	nextOffset := packTotal
	encryptHeader := w.opts.Password != "" && w.opts.EncryptHeader
	compressHeader := !w.opts.NoHeaderCompression && len(items) >= 2
	if compressHeader || encryptHeader {
		// The header folder: LZMA when compressed, wrapped in 7zAES for
		// -mhe (observed: coders 7zAES, LZMA; bond in-stream 1 from coder
		// 0; unpack sizes the LZMA stream's length, then the header's).
		// With -mhe but no compression (one item, or -mhc=off) the folder
		// is 7zAES alone over the raw header (observed).
		hs := folderShape{packs: []int{0}, unpack: []uint64{uint64(len(header))}}
		stored := header
		if compressHeader {
			packed, props, err := encodeHeader(header)
			if err != nil {
				return err
			}
			hs.coders = []coderRec{{MethodLZMA, props[:], 1}}
			stored = packed
		}
		if encryptHeader {
			packed := stored
			var iv [aesBlock]byte
			if _, err := io.ReadFull(random, iv[:]); err != nil {
				return fmt.Errorf("sevenzip: reading IV: %w", err)
			}
			var enc bytes.Buffer
			aw, err := newAESWriter(&enc, key, iv)
			if err != nil {
				return err
			}
			if _, err := aw.Write(packed); err != nil {
				return err
			}
			if err := aw.Close(); err != nil {
				return err
			}
			stored = enc.Bytes()
			hs = hs.encrypted([][aesBlock]byte{iv}, []uint64{uint64(len(packed))})
		}
		if _, err := out.Write(stored); err != nil {
			return err
		}
		var b []byte
		b = append(b, idEncodedHeader, idPackInfo)
		b = writeNumber(b, packTotal)
		b = writeNumber(b, 1)
		b = append(b, idSize)
		b = writeNumber(b, uint64(len(stored)))
		b = append(b, idEnd)
		b = append(b, idUnpackInfo, idFolder)
		b = writeNumber(b, 1)
		b = append(b, 0) // external
		b = appendShape(b, hs)
		b = append(b, idCodersUnpackSize)
		for _, u := range hs.unpack {
			b = writeNumber(b, u)
		}
		b = append(b, idCRC, 1)
		b = appendUi32(b, crc(header))
		b = append(b, idEnd, idEnd)
		nextHeader = b
		nextOffset += uint64(len(stored))
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
	mainOut, closeMain, err := p.wrapPack(0, out)
	if err != nil {
		mainR.CloseWithError(err)
		return err
	}
	switch method {
	case Copy:
		p.coderID = MethodCopy
		_, err = io.Copy(mainOut, mainIn)
	case LZMA:
		props, _ := w.lzmaProps()
		props.ReduceSize = dataTotal
		enc := lzma.NewEncoder()
		if err = enc.SetProps(&props); err == nil {
			pr := enc.WriteProperties()
			p.coderID, p.coderProps = MethodLZMA, pr[:]
			err = enc.Encode(mainOut, mainIn)
		}
	case LZMA2:
		props, _ := w.lzma2Props()
		props.LzmaProps.ReduceSize = dataTotal
		enc := lzma.NewLzma2Encoder()
		if err = enc.SetProps(&props); err == nil {
			p.coderID, p.coderProps = MethodLZMA2, []byte{enc.WriteProperties()}
			err = enc.Encode(mainOut, mainIn)
		}
	case PPMd:
		order, mem := w.ppmdParams()
		mem = PPMdReducedMem(mem, dataTotal)
		var enc *ppmd.Encoder
		if enc, err = ppmd.NewEncoder(order, mem); err == nil {
			p.coderID, p.coderProps = MethodPPMD, ppmdProps(order, mem)
			err = enc.Encode(mainOut, mainIn)
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
	if err := closeMain(); err != nil {
		return err
	}
	mainPacked := out.n
	sidePacked := make([]uint64, 3)
	for i, b := range []*bytes.Buffer{&rc, &callPacked, &jumpPacked} {
		start := out.n
		sw, closeSide, err := p.wrapPack(i+1, out)
		if err != nil {
			return err
		}
		if _, err := sw.Write(b.Bytes()); err != nil {
			return err
		}
		if err := closeSide(); err != nil {
			return err
		}
		sidePacked[i] = out.n - start
	}
	pr := lzma.NewEncoder()
	if err := pr.SetProps(&sideProps); err != nil {
		return err
	}
	sp := pr.WriteProperties()
	p.sideProps = sp[:]
	p.sideUnpack = [3]uint64{jumpN, callN, mainIn.n}
	p.packSizes = []uint64{mainPacked, sidePacked[0], sidePacked[1], sidePacked[2]}
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
		start := out.n
		sw, closeStream, err := p.wrapPack(i, out)
		if err != nil {
			return err
		}
		if _, err := sw.Write(bufs[i].Bytes()); err != nil {
			return err
		}
		if err := closeStream(); err != nil {
			return err
		}
		p.packSizes[i] = out.n - start
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

// coderRec is one coder of a folder record.
type coderRec struct {
	id    uint32
	props []byte
	numIn int // in-streams (1, or 4 for BCJ2)
}

// folderShape is a folder record before serialisation: the coders in
// record order, the bonds (in-stream index from coder out index), the
// pack streams (in-stream indices in stored order) and one unpack size
// per coder.
type folderShape struct {
	coders []coderRec
	bonds  [][2]int
	packs  []int
	unpack []uint64
}

// shape is the folder record of a plan (observed from the SoT):
//   - one coder: the method, or the filter alone for Method None;
//   - method + filter: coder order method, filter; bond in-stream 1
//     from coder 0; the single pack stream implicit; both unpack sizes
//     the folder size;
//   - BCJ2 (-mf=BCJ2, the shape 7zDec.c accepts): coders LZMA (JUMP),
//     LZMA (CALL), the method (MAIN), BCJ2 with four in-streams; bonds
//     in-stream 5 from coder 0, 4 from 1, 3 from 2; pack streams
//     in-streams 2 (MAIN packed), 6 (RC), 1 (CALL packed), 0 (JUMP
//     packed); unpack sizes JUMP, CALL, MAIN, folder;
//   - BCJ2 alone (Method None): the only coder is BCJ2 and its four
//     in-streams are the pack streams in order.
//
// With a password the record is then wrapped by encrypted.
func (p *folderPlan) shape() folderShape {
	var s folderShape
	switch {
	case p.filterID == MethodBCJ2 && p.noCoder:
		s.coders = []coderRec{{MethodBCJ2, nil, 4}}
		s.packs = []int{0, 1, 2, 3}
		s.unpack = []uint64{p.unpackSize}
	case p.filterID == MethodBCJ2:
		s.coders = []coderRec{{MethodLZMA, p.sideProps, 1}, {MethodLZMA, p.sideProps, 1}, {p.coderID, p.coderProps, 1}, {MethodBCJ2, nil, 4}}
		s.bonds = [][2]int{{5, 0}, {4, 1}, {3, 2}}
		s.packs = []int{2, 6, 1, 0}
		s.unpack = []uint64{p.sideUnpack[0], p.sideUnpack[1], p.sideUnpack[2], p.unpackSize}
	case p.filterID == 0:
		s.coders = []coderRec{{p.coderID, p.coderProps, 1}}
		s.packs = []int{0}
		s.unpack = []uint64{p.unpackSize}
	case p.noCoder:
		s.coders = []coderRec{{p.filterID, p.filterProps, 1}}
		s.packs = []int{0}
		s.unpack = []uint64{p.unpackSize}
	default:
		s.coders = []coderRec{{p.coderID, p.coderProps, 1}, {p.filterID, p.filterProps, 1}}
		s.bonds = [][2]int{{1, 0}}
		s.packs = []int{0}
		s.unpack = []uint64{p.unpackSize, p.unpackSize}
	}
	if p.encrypt {
		s = s.encrypted(p.aesIVs, p.aesUnpack)
	}
	return s
}

// encrypted wraps every pack stream of the shape in a 7zAES coder
// (observed on both SoTs for one, two and four pack streams): the k
// 7zAES coders come first, coder j reading the new pack stream j and
// feeding the in-stream that was stored pack stream k-1-j; the old
// bonds shift by k; the new pack streams are in-streams k-1 .. 0, so
// the stored order is unchanged; the 7zAES unpack sizes (the unpadded
// lengths) come first.
func (s folderShape) encrypted(ivs [][aesBlock]byte, unpack []uint64) folderShape {
	k := len(s.packs)
	var n folderShape
	if len(s.coders) == 0 {
		// A raw stream (the uncompressed header): 7zAES is the only coder.
		n.coders = []coderRec{{MethodAES, aesProps(ivs[0]), 1}}
		n.packs = []int{0}
		n.unpack = append([]uint64(nil), unpack...)
		return n
	}
	for j := 0; j < k; j++ {
		n.coders = append(n.coders, coderRec{MethodAES, aesProps(ivs[j]), 1})
		n.bonds = append(n.bonds, [2]int{k + s.packs[k-1-j], j})
	}
	n.coders = append(n.coders, s.coders...)
	for _, b := range s.bonds {
		n.bonds = append(n.bonds, [2]int{b[0] + k, b[1] + k})
	}
	for j := k - 1; j >= 0; j-- {
		n.packs = append(n.packs, j)
	}
	n.unpack = append(append([]uint64(nil), unpack...), s.unpack...)
	return n
}

// appendShape serialises a folder record: NumCoders, the coder records,
// the bonds, then the pack stream indices when there is more than one.
func appendShape(b []byte, s folderShape) []byte {
	b = writeNumber(b, uint64(len(s.coders)))
	for _, c := range s.coders {
		if c.numIn == 1 {
			b = appendCoderRecord(b, c.id, c.props)
		} else {
			b = appendComplexCoderRecord(b, c.id, c.numIn)
		}
	}
	for _, bond := range s.bonds {
		b = writeNumber(b, uint64(bond[0]))
		b = writeNumber(b, uint64(bond[1]))
	}
	if len(s.packs) > 1 {
		for _, ps := range s.packs {
			b = writeNumber(b, uint64(ps))
		}
	}
	return b
}

// appendFolder writes the folder record of a plan.
func appendFolder(b []byte, p *folderPlan) []byte {
	return appendShape(b, p.shape())
}

// numCoders is how many coders the plan's folder has (one unpack size
// is written per coder).
func (p *folderPlan) numCoders() int { return len(p.shape().coders) }

// coderUnpackSize is the unpack size written for coder c of the plan's
// folder.
func (p *folderPlan) coderUnpackSize(c int) uint64 { return p.shape().unpack[c] }

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
