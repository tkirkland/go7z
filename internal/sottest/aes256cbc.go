package sottest

import (
	"bytes"
	"encoding/binary"
	"errors"
	"hash/crc32"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/tkirkland/go7z/internal/sot"
	"github.com/tkirkland/go7z/sevenzip"
)

// The AES256CBC line (7za i: the raw AES256CBC codec, MyAesReg.cpp, id
// 6F00181). The user ruled 2026-11-07 that the module matches the SoT
// 1:1, rejections included. Observed in both lanes:
//
//   - writing: every way to name it as a method or filter fails with
//     exit code 2 and no archive is left: 7z and zip with "Not
//     implemented", xz with "The parameter is incorrect.";
//   - reading: a 7z folder holding it is listed ("Method = Copy
//     AES256CBC", exit 0), but testing it fails with "Unsupported
//     Method", with or without a password.
//
// The module matches: no Method or Filter writes the codec, and the
// reader opens such an archive, reports the coder and returns
// ErrUnsupported when extracting.

// aes256CBCWriteCases are the SoT's refusals: arguments to "a" and the
// error line 7za prints.
var aes256CBCWriteCases = []aes256CBCWriteCase{
	{"7z_m0", []string{"-t7z", "-m0=AES256CBC"}, "Not implemented"},
	{"7z_m1", []string{"-t7z", "-m0=LZMA2", "-m1=AES256CBC"}, "Not implemented"},
	{"7z_mf", []string{"-t7z", "-mf=AES256CBC"}, "Not implemented"},
	{"7z_m0_p", []string{"-t7z", "-m0=AES256CBC", "-pabc"}, "Not implemented"},
	{"zip_m0", []string{"-tzip", "-m0=AES256CBC"}, "Not implemented"},
	{"zip_mm", []string{"-tzip", "-mm=AES256CBC"}, "Not implemented"},
	{"xz_m0", []string{"-txz", "-m0=AES256CBC"}, "The parameter is incorrect."},
}

type aes256CBCWriteCase struct {
	name string
	args []string
	msg  string
}

// aes256CBCReadSources are the two archives a folder holding the codec is
// made from: the SoT's Copy + 7zAES archive and the module's.
var aes256CBCReadSources = []aes256CBCReadSource{
	{"read_sot_archive", true},
	{"read_module_archive", false},
}

type aes256CBCReadSource struct {
	name    string
	fromSoT bool
}

// RunAES256CBCMatrix proves the AES256CBC line in one lane. Three claims,
// in the order the SoT was observed: it refuses every way to write the
// codec, the module has no way to write it either, and a folder holding
// it is listed by both and extracted by neither.
func RunAES256CBCMatrix(t *testing.T, root string, lane sot.Lane) {
	t.Run("sot_refuses_write", func(t *testing.T) {
		for _, c := range aes256CBCWriteCases {
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
				aes256CBCRefusesWrite(t, root, lane, c)
			})
		}
	})

	t.Run("module_never_writes", func(t *testing.T) {
		aes256CBCNeverWrites(t, lane)
	})

	for _, s := range aes256CBCReadSources {
		t.Run(s.name, func(t *testing.T) {
			t.Parallel()
			aes256CBCReadCodec(t, root, lane, s.fromSoT)
		})
	}
}

// aes256CBCRefusesWrite runs one of the SoT's refusals: exit code 2, the
// error line it prints, and no archive left behind.
func aes256CBCRefusesWrite(t *testing.T, root string, lane sot.Lane, c aes256CBCWriteCase) {
	dir := t.TempDir()
	MakeTree(t, dir, []TreeFile{{"f.txt", []byte("hello\n")}})
	args := append([]string{"a"}, c.args...)
	args = append(args, "out.arc", "f.txt")
	out, err := runSoTIn(root, lane, dir, args...)
	wantExit(t, err, 2, out)
	if !strings.Contains(string(out), "System ERROR:\r\n"+c.msg) {
		t.Fatalf("SoT %v: want %q, got\n%s", args, c.msg, out)
	}
	if _, err := os.Stat(filepath.Join(dir, "out.arc")); err == nil {
		t.Fatalf("SoT %v left an archive behind", args)
	}
}

// aes256CBCMethods and aes256CBCFilters are every member of sevenzip's
// Method and Filter enums in enum order (writer.go), so "no Method or
// Filter writes the codec" covers both enums. PPMd and Delta are the last
// members; aes256CBCEnumsCovered checks the count before the matrix runs.
var aes256CBCMethods = []sevenzip.Method{
	sevenzip.LZMA2, sevenzip.LZMA, sevenzip.Copy, sevenzip.None, sevenzip.PPMd,
}
var aes256CBCFilters = []sevenzip.Filter{
	sevenzip.NoFilter, sevenzip.BCJ, sevenzip.BCJ2, sevenzip.ARM, sevenzip.ARMT,
	sevenzip.ARM64, sevenzip.Swap2, sevenzip.Swap4, sevenzip.Delta,
}

// aes256CBCWriteShape is one Method and Filter pair with the Options for
// it: one of the two passwords and the lane's WordSize.
type aes256CBCWriteShape struct {
	method sevenzip.Method
	filter sevenzip.Filter
	opts   sevenzip.Options
}

// aes256CBCWriteShapes is both enums crossed with both passwords, 90
// shapes: the pair that writes the codec, if the module had one, is in
// there somewhere. It keeps Method None + NoFilter, the pair writer.go
// refuses ("Method None needs a Filter": Method None stores the filter
// output with no coder behind it, so without a Filter there is nothing
// to write), and aes256CBCRefused plus aes256CBCRefusesPair check that
// refusal instead of assuming it.
func aes256CBCWriteShapes(t *testing.T, lane sot.Lane) []aes256CBCWriteShape {
	t.Helper()
	aes256CBCEnumsCovered(t)
	var out []aes256CBCWriteShape
	for _, pw := range []string{"", "abc"} {
		for _, m := range aes256CBCMethods {
			for _, f := range aes256CBCFilters {
				out = append(out, aes256CBCWriteShape{m, f, sevenzip.Options{Method: m, Filter: f, Password: pw, WordSize: lane.SizeT()}})
			}
		}
	}
	return out
}

// aes256CBCEnumsCovered fails the test unless the two lists above hold
// every member of sevenzip's Method and Filter enums, so the matrix
// cannot shrink when an enum grows (writer.go: PPMd and Delta are the
// last members).
func aes256CBCEnumsCovered(t *testing.T) {
	t.Helper()
	if len(aes256CBCMethods) != int(sevenzip.PPMd)+1 || len(aes256CBCFilters) != int(sevenzip.Delta)+1 {
		t.Fatalf("the Method and Filter lists do not cover the enums: %d of %d, %d of %d",
			len(aes256CBCMethods), int(sevenzip.PPMd)+1, len(aes256CBCFilters), int(sevenzip.Delta)+1)
	}
}

// aes256CBCRefused reports whether the module refuses this Method and
// Filter pair. Method None with no Filter is the only pair it refuses
// (writer.go: "Method None needs a Filter"), every other pair writes an
// archive.
func aes256CBCRefused(s aes256CBCWriteShape) bool {
	return s.method == sevenzip.None && s.filter == sevenzip.NoFilter
}

// aes256CBCNeverWrites proves to write half of the line over every Method
// and Filter pair: the pairs the module accepts write an archive whose
// coders are never AES256CBC, and the pair it refuses does so with its own
// error and nothing else.
func aes256CBCNeverWrites(t *testing.T, lane sot.Lane) {
	dir := t.TempDir()
	MakeTree(t, dir, []TreeFile{{"f.txt", []byte("hello\n")}})
	n := 0
	for _, s := range aes256CBCWriteShapes(t, lane) {
		if aes256CBCRefused(s) {
			aes256CBCRefusesPair(t, dir, s)
			continue
		}
		aes256CBCWritesNoCodec(t, dir, s)
		n++
	}
	if n == 0 {
		t.Fatal("no archive written")
	}
}

// aes256CBCRefusesPair: the refusal has to be writer.go's "Method None
// needs a Filter" (Method None stores the filter output with no coder
// behind it, so without a Filter there is nothing to write). Any other
// error, or an archive, fails the line.
func aes256CBCRefusesPair(t *testing.T, dir string, s aes256CBCWriteShape) {
	t.Helper()
	_, err := moduleArchive(t, dir, "f.txt", s.opts)
	if err == nil || !strings.Contains(err.Error(), "Method None needs a Filter") {
		t.Fatalf("method %d filter %d: want Method None's refusal, got %v", s.method, s.filter, err)
	}
}

// aes256CBCWritesNoCodec writes the module's archive for one pair, opens
// it again with the same password, and requires that no coder it reports,
// in the encoded header's folder or in any folder, is AES256CBC.
func aes256CBCWritesNoCodec(t *testing.T, dir string, s aes256CBCWriteShape) {
	t.Helper()
	data, err := moduleArchive(t, dir, "f.txt", s.opts)
	if err != nil {
		t.Fatalf("method %d filter %d: %v", s.method, s.filter, err)
	}
	coders, err := moduleCoders(data, s.opts.Password)
	if err != nil {
		t.Fatalf("method %d filter %d: module cannot open its archive: %v", s.method, s.filter, err)
	}
	if hasCoder(coders, sevenzip.MethodAES256CBC) {
		t.Fatalf("method %d filter %d: module wrote an AES256CBC coder", s.method, s.filter)
	}
}

// moduleCoders opens the module's archive with pw and returns every coder
// it reports: the encoded header's folder plus each folder.
func moduleCoders(data []byte, pw string) ([]sevenzip.Coder, error) {
	a, err := sevenzip.OpenWithPassword(bytes.NewReader(data), int64(len(data)), pw)
	if err != nil {
		return nil, err
	}
	out := a.HeaderCoders()
	for i := 0; i < a.NumFolders(); i++ {
		out = append(out, a.FolderCoders(i)...)
	}
	return out, nil
}

// hasCoder reports whether coders holds a coder of method id.
func hasCoder(coders []sevenzip.Coder, id uint32) bool {
	for _, c := range coders {
		if c.MethodID == id {
			return true
		}
	}
	return false
}

// aes256CBCReadCodec proves the read half for one source archive: the
// SoT lists the folder and refuses to extract it, and the module opens
// the same bytes, reports the coder and returns ErrUnsupported.
func aes256CBCReadCodec(t *testing.T, root string, lane sot.Lane, fromSoT bool) {
	dir := t.TempDir()
	MakeTree(t, dir, []TreeFile{{"f.txt", []byte("hello\n")}})
	b := toAES256CBC(t, aes256CBCSrcArchive(t, root, lane, dir, fromSoT))
	if err := os.WriteFile(filepath.Join(dir, "cbc.7z"), b, 0o644); err != nil {
		t.Fatal(err)
	}
	aes256CBCSoTListsCodec(t, root, lane, dir)
	aes256CBCSoTRefusesTest(t, root, lane, dir)
	aes256CBCModuleRefuses(t, b)
}

// aes256CBCSrcArchive is the Copy + 7zAES archive the codec folder is
// made from: the SoT's or the module's, both with an uncompressed header.
func aes256CBCSrcArchive(t *testing.T, root string, lane sot.Lane, dir string, fromSoT bool) []byte {
	t.Helper()
	if fromSoT {
		return aes256CBCSoTSrc(t, root, lane, dir)
	}
	return aes256CBCModuleSrc(t, dir, lane)
}

// aes256CBCSoTSrc is the SoT's Copy + 7zAES archive: "a -t7z -m0=Copy
// -pabc -mhc=off src.7z f.txt", read back from src.7z.
func aes256CBCSoTSrc(t *testing.T, root string, lane sot.Lane, dir string) []byte {
	t.Helper()
	out, err := runSoTIn(root, lane, dir, "a", "-t7z", "-m0=Copy", "-pabc", "-mhc=off", "src.7z", "f.txt")
	if err != nil {
		t.Fatalf("SoT: %v\n%s", err, out)
	}
	b, err := os.ReadFile(filepath.Join(dir, "src.7z"))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// aes256CBCModuleSrc is the module's equivalent: Method Copy, password
// abc, header not compressed, the lane's WordSize.
func aes256CBCModuleSrc(t *testing.T, dir string, lane sot.Lane) []byte {
	t.Helper()
	b, err := moduleArchive(t, dir, "f.txt", sevenzip.Options{Method: sevenzip.Copy, Password: "abc", NoHeaderCompression: true, WordSize: lane.SizeT()})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// aes256CBCSoTListsCodec: the SoT lists the folder of cbc.7z as
// "Method = Copy AES256CBC", exit 0.
func aes256CBCSoTListsCodec(t *testing.T, root string, lane sot.Lane, dir string) {
	t.Helper()
	out, err := runSoTIn(root, lane, dir, "l", "-slt", "cbc.7z")
	wantExit(t, err, 0, out)
	if !strings.Contains(string(out), "\r\nMethod = Copy AES256CBC\r\n") {
		t.Fatalf("SoT l -slt: no AES256CBC method\n%s", out)
	}
}

// aes256CBCSoTRefusesTest: the SoT tests cbc.7z with and without the
// password and fails both with "Unsupported Method", exit 2.
func aes256CBCSoTRefusesTest(t *testing.T, root string, lane sot.Lane, dir string) {
	t.Helper()
	for _, args := range [][]string{{"t", "cbc.7z"}, {"t", "-pabc", "cbc.7z"}} {
		out, err := runSoTIn(root, lane, dir, args...)
		wantExit(t, err, 2, out)
		if !strings.Contains(string(out), "ERROR: Unsupported Method : f.txt") {
			t.Fatalf("SoT %v: want Unsupported Method\n%s", args, out)
		}
	}
}

// aes256CBCModuleRefuses: with and without the password the module opens
// the same bytes, reports the coder and returns ErrUnsupported from
// Extract.
func aes256CBCModuleRefuses(t *testing.T, b []byte) {
	for _, pw := range []string{"", "abc"} {
		a := aes256CBCOpensAndReportsCodec(t, b, pw)
		if _, err := a.Extract(0); !errors.Is(err, sevenzip.ErrUnsupported) {
			t.Fatalf("password %q: module extract: %v, want ErrUnsupported", pw, err)
		}
	}
}

// aes256CBCOpensAndReportsCodec opens b with pw - the SoT lists the archive,
// so opening has to work - and requires that its one folder reports an
// AES256CBC coder.
func aes256CBCOpensAndReportsCodec(t *testing.T, b []byte, pw string) *sevenzip.Archive {
	t.Helper()
	a, err := sevenzip.OpenWithPassword(bytes.NewReader(b), int64(len(b)), pw)
	if err != nil {
		t.Fatalf("password %q: module cannot open (the SoT lists it): %v", pw, err)
	}
	if a.NumFolders() != 1 {
		t.Fatalf("password %q: want one folder, got %d", pw, a.NumFolders())
	}
	if !hasCoder(a.FolderCoders(0), sevenzip.MethodAES256CBC) {
		t.Fatalf("password %q: module does not report the AES256CBC coder: %+v", pw, a.FolderCoders(0))
	}
	return a
}

// moduleArchive writes the module's archive of dir/name and returns its
// bytes: written to a temp file in dir, closed, read back. dir is a
// t.TempDir, so the file is taken away when the test ends; the close
// happens before the read and a failed close is reported.
func moduleArchive(t *testing.T, dir, name string, opts sevenzip.Options) ([]byte, error) {
	w := sevenzip.NewWriter(opts)
	if err := w.AddPathIn(dir, name); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "module-*.7z")
	if err != nil {
		return nil, err
	}
	defer func() {
		if err := f.Close(); err != nil {
			t.Errorf("close %s: %v", f.Name(), err)
		}
	}()
	if err := w.Write(f); err != nil {
		return nil, err
	}
	return os.ReadFile(f.Name())
}

// The start header's fields, named as sevenzip/reader.go's open names
// them: the start header is 32 bytes, its own CRC (at 8) covers bytes
// 12..32, and inside that range the next header's offset is at 12, its
// size at 20 and its CRC at 28.
const (
	aes256CBCStartHeader      = 32
	aes256CBCStartHeaderCRC   = 8
	aes256CBCNextHeaderOffset = 12
	aes256CBCNextHeaderSize   = 20
	aes256CBCNextHeaderCRC    = 28
)

// The stored coder ids in a coder record: sevenzip's MethodAES (0x06F10701)
// and MethodAES256CBC (0x06F00181). Both are four bytes, so replacing one
// with the other keeps the header's length and only the CRCs need fixing.
var aes7zID = []byte{0x06, 0xF1, 0x07, 0x01}
var aes256CBCID = []byte{0x06, 0xF0, 0x01, 0x81}

// toAES256CBC replaces the single 7zAES coder id in an uncompressed
// header with AES256CBC's (same length) and fixes the start header's CRCs.
func toAES256CBC(t *testing.T, b []byte) []byte {
	t.Helper()
	b = append([]byte(nil), b...)
	off := aes256CBCStartHeader + binary.LittleEndian.Uint64(b[aes256CBCNextHeaderOffset:])
	n := binary.LittleEndian.Uint64(b[aes256CBCNextHeaderSize:])
	h := b[off : off+n]
	if bytes.Count(h, aes7zID) != 1 {
		t.Fatalf("want exactly one 7zAES id in the header, got %d", bytes.Count(h, aes7zID))
	}
	copy(h[bytes.Index(h, aes7zID):], aes256CBCID)
	// The next header's CRC (28) is inside the range the start header's
	// own CRC covers, so it is written first.
	binary.LittleEndian.PutUint32(b[aes256CBCNextHeaderCRC:], crc32.ChecksumIEEE(h))
	binary.LittleEndian.PutUint32(b[aes256CBCStartHeaderCRC:], crc32.ChecksumIEEE(b[aes256CBCNextHeaderOffset:aes256CBCStartHeader]))
	return b
}

// wantExit checks a SoT run's exit code.
func wantExit(t *testing.T, err error, code int, out []byte) {
	t.Helper()
	got := 0
	if ee, ok := errors.AsType[*exec.ExitError](err); ok {
		got = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("SoT: %v\n%s", err, out)
	}
	if got != code {
		t.Fatalf("SoT exit code %d, want %d\n%s", got, code, out)
	}
}
