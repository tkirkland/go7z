package sevenzip

import (
	"encoding/binary"
	"errors"
	"io"
	"os"
	"strings"

	"github.com/tkirkland/go7z/lzma"
)

// analyze.go: the SoT's default filter automation (-mf=on with the
// analysis level -myx), reproduced from observation on both SoTs
// (2026-11-07; the C++ 7zUpdate.cpp is LGPL and not ported):
//
//   - Which files are analyzed depends on -myx (default 5): 0..4 none;
//     5 and 6 files whose extension (case-insensitive) is exe, dll,
//     sys, ocx, dylib or so, where "so" may be followed by numeric
//     extensions (x.so.1, x.so.1.2.3; not x.so.abc, not x.dll.1); 7
//     and 8 also files with no extension; 9 every file.
//   - A file is analyzed only if it is at least 512 bytes. PE: "MZ",
//     e_lfanew at 0x3C, "PE\0\0" there, and the file must hold 512
//     bytes from e_lfanew; the machine field selects the filter: 014C
//     and 8664 x86, 01C0 and 01C2 ARM, 01C4 ARMT, AA64 ARM64, 0200
//     IA64; others (PPC, RISC-V) none. ELF: class 1 or 2, data 1 or 2
//     (the machine is read in that byte order), EI_VERSION 1, any
//     e_type; machine 3 and 3E x86, 28 ARM, B7 ARM64; others none.
//     Mach-O: little-endian magic FEEDFACE/FEEDFACF only; cpu type 7 and
//     01000007 x86, C ARM, 0100000C ARM64; fat binaries none.
//   - x86 gets BCJ at levels 1..7 and BCJ2 at 8 and 9. -mx0 (Copy)
//     applies no analysis; -m0=Copy at other levels does, one folder
//     per file.
//   - With LZMA or LZMA2 the automatically chosen ARM and ARM64 use
//     lc1 lp2, ARMT lc2 lp1, IA64 lc0 lp4 pb4; x86 keeps the defaults.
//     A filter forced with -mf or -m0 never changes lc/lp.
//   - Data items are grouped by filter, the groups in the order none,
//     ARM64, x86, IA64, ARM, ARMT, each group sorted by name as usual,
//     and each group packed into its own solid blocks.
//
// The IA64 converter is omitted by the user; an IA64 image is reported
// by Analyze and the writer refuses it rather than writing different
// bytes.

// AnalysisDefault is the SoT's default -myx level; AnalysisNone is
// -myx0 (Options.Analysis 0 means the default).
const (
	AnalysisDefault = 5
	AnalysisNone    = -1
)

// exeKind is the result of the analysis.
type exeKind int

// noinspection GoUnusedConst
const (
	exeNone  exeKind = iota
	exeARM64         // group order observed: none, ARM64, RISCV, x86, IA64, ARM, ARMT
	exeRISCV         // grouped but no filter applied (observed)
	exeX86
	exePPC   // PPC, SPARC and IA64: the SoT applies converters this module omits
	exeSPARC // (their position among the groups after x86 is not observed)
	exeIA64
	exeARM
	exeARMT
	numExeKinds
)

// omittedConverter is true for the kinds whose converter the user
// omitted; the writer refuses such input rather than writing other
// bytes than the SoT.
func (k exeKind) omittedConverter() bool {
	return k == exePPC || k == exeSPARC || k == exeIA64
}

// analysisWanted says whether a file name is analyzed at the level.
func analysisWanted(name string, level int) bool {
	if level <= 4 {
		return false
	}
	if level >= 9 {
		return true
	}
	lower := strings.ToLower(name)
	if i := strings.LastIndexAny(lower, "/\\"); i >= 0 {
		lower = lower[i+1:]
	}
	dot := strings.LastIndexByte(lower, '.')
	if dot < 0 {
		return level >= 7
	}
	ext := lower[dot+1:]
	if wantedExt(ext) {
		return true
	}
	// x.so.1, x.so.1.2.3: numeric extensions after .so (observed; not
	// x.so.abc, not x.dll.1).
	for isNumericExt(ext) {
		lower = lower[:dot]
		dot = strings.LastIndexByte(lower, '.')
		if dot < 0 {
			return false
		}
		ext = lower[dot+1:]
		if ext == "so" {
			return true
		}
	}
	return false
}

// wantedExt is an extension analyzed at levels 5..8 (observed)
func wantedExt(ext string) bool {
	switch ext {
	case "exe", "dll", "sys", "ocx", "dylib", "so":
		return true
	default:
		return false
	}
}

// isNumericExt is a non-empty extension made of digits only.
func isNumericExt(s string) bool {
	if s == "" {
		return false
	}
	for _, c := range s {
		if c < '0' || c > '9' {
			return false
		}
	}
	return true
}

// analyzeExe inspects the head of a file (at least the first 512+
// bytes of it; head may be the whole file) of the given total size.
func analyzeExe(head []byte, size uint64) exeKind {
	if size < 512 || len(head) < 4 {
		return exeNone
	}
	if head[0] == 'M' && head[1] == 'Z' {
		return analyzePE(head, size)
	}
	if head[0] == 0x7F && head[1] == 'E' && head[2] == 'L' && head[3] == 'F' {
		return analyzeELF(head)
	}
	return analyzeMacho(head)
}

// analyzePE is the PE branch: "MZ", e_lfanew at 0x3C, "PE\0\0" there, and
// the file must hold 512 bytes from e_lfanew; the machine field selects
// the filter.
func analyzePE(head []byte, size uint64) exeKind {
	if len(head) < 0x40 {
		return exeNone
	}
	off := uint64(binary.LittleEndian.Uint32(head[0x3C:]))
	if off+512 > size || off+6 > uint64(len(head)) {
		return exeNone
	}
	if string(head[off:off+4]) != "PE\x00\x00" {
		return exeNone
	}
	switch binary.LittleEndian.Uint16(head[off+4:]) {
	case 0x014C, 0x8664:
		return exeX86
	case 0x01C0, 0x01C2:
		return exeARM
	case 0x01C4:
		return exeARMT
	case 0xAA64:
		return exeARM64
	case 0x0200:
		return exeIA64
	case 0x5032, 0x5064:
		return exeRISCV // observed: grouped, no filter (5128 is none)
	}
	return exeNone
}

// analyzeELF is the ELF branch: class 1 or 2, data 1 or 2 (the machine
// is read in that byte order), EI_VERSION 1, any e_type; the machine
// field selects the filter.
func analyzeELF(head []byte) exeKind {
	if len(head) < 20 {
		return exeNone
	}
	class, data, version := head[4], head[5], head[6]
	if (class != 1 && class != 2) || (data != 1 && data != 2) || version != 1 {
		return exeNone
	}
	var machine uint16
	if data == 1 {
		machine = binary.LittleEndian.Uint16(head[18:])
	} else {
		machine = binary.BigEndian.Uint16(head[18:])
	}
	// Observed: x86 and SPARC in either byte order; ARM, ARM64 and RISC-V
	// only little-endian (data 1); PPC only big-endian (data 2); IA64 none.
	switch machine {
	case 3, 0x3E:
		return exeX86
	case 2, 0x2B:
		return exeSPARC
	case 0x28:
		if data == 1 {
			return exeARM
		}
	case 0xB7:
		if data == 1 {
			return exeARM64
		}
	case 0xF3:
		if data == 1 {
			return exeRISCV
		}
	case 0x14, 0x15:
		if data == 2 {
			return exePPC
		}
	}
	return exeNone
}

// analyzeMacho is the Mach-O branch: the little-endian magic FEEDFACE or
// FEEDFACF; the cpu type selects the filter, and a fat binary (a big-endian
// magic) is none.
func analyzeMacho(head []byte) exeKind {
	if len(head) < 8 {
		return exeNone
	}
	switch binary.LittleEndian.Uint32(head) {
	case 0xFEEDFACE, 0xFEEDFACF:
		switch binary.LittleEndian.Uint32(head[4:]) {
		case 7, 0x01000007:
			return exeX86
		case 0xC:
			return exeARM
		case 0x0100000C:
			return exeARM64
		}
	}
	return exeNone
}

// CompatDefault stands for the SoT's default -myv (the emulated 7-Zip
// version, MMNN): observed to behave like 2300..2401, that is with the
// ARM64 filter and without the RISC-V filter.
const CompatDefault = 2300

// kindFilter is the filter coder for a kind at a level and emulated
// version (x86: BCJ up to mx7, BCJ2 from mx8; ARM64 only from -myv=2300,
// RISC-V only from -myv=2402, observed; an older version keeps the
// group and its lc/lp but applies no filter). omitted is true when the
// SoT would apply a converter this module does not have.
func kindFilter(k exeKind, level int, version int) (filterID uint32, filter Filter, omitted bool) {
	switch k {
	case exeX86:
		if level >= 8 {
			return MethodBCJ2, BCJ2, false
		}
		return MethodBCJ, BCJ, false
	case exeARM64:
		if version >= 2300 {
			return MethodARM64, ARM64, false
		}
	case exeRISCV:
		if version >= 2402 {
			return 0, NoFilter, true
		}
	case exeARM:
		return MethodARM, ARM, false
	case exeARMT:
		return MethodARMT, ARMT, false
	case exePPC, exeSPARC, exeIA64:
		return 0, NoFilter, true
	default:
		// exeNone, and exeARM64/exeRISCV under an older -myv: no filter.
	}
	return 0, NoFilter, false
}

// kindLcLpPb is the LZMA lc/lp/pb the SoT uses with an automatically
// chosen filter; ok is false when the defaults stay.
func kindLcLpPb(k exeKind) (lc, lp, pb int, ok bool) {
	switch k {
	case exeARM64, exeARM:
		return 1, 2, 2, true
	case exeARMT, exeRISCV:
		// RISC-V: no filter, but lc2 lp1 like ARMT (observed with -m0=LZMA).
		return 2, 1, 2, true
	case exeIA64:
		return 0, 4, 4, true
	default:
		// Other kinds: the defaults stay.
	}
	return 0, 0, 0, false
}

// applyKindProps sets the LZMA properties an automatic filter implies.
func applyKindProps(k exeKind, p *lzma.EncProps) {
	if lc, lp, pb, ok := kindLcLpPb(k); ok {
		p.Lc, p.Lp, p.Pb = lc, lp, pb
	}
}

// analyzeFile reads the head of a file for analyzeExe.
func analyzeFile(path string, size uint64) (exeKind, error) {
	if size < 512 {
		return exeNone, nil
	}
	f, err := os.Open(path)
	if err != nil {
		return exeNone, err
	}
	defer func() { _ = f.Close() }()
	head := make([]byte, 1<<16)
	n, err := io.ReadFull(f, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) {
		return exeNone, err
	}
	head = head[:n]
	// A PE whose e_lfanew lies beyond the buffer: read further.
	if n >= 0x40 && head[0] == 'M' && head[1] == 'Z' {
		off := uint64(binary.LittleEndian.Uint32(head[0x3C:]))
		if off+6 > uint64(n) && off+512 <= size && off < 1<<24 {
			more := make([]byte, off+6)
			if _, err := f.ReadAt(more, 0); err != nil && err != io.EOF {
				return exeNone, err
			}
			head = more
		}
	}
	return analyzeExe(head, size), nil
}
