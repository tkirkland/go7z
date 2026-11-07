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
var aes256CBCWriteCases = []struct {
	name string
	args []string
	msg  string
}{
	{"7z_m0", []string{"-t7z", "-m0=AES256CBC"}, "Not implemented"},
	{"7z_m1", []string{"-t7z", "-m0=LZMA2", "-m1=AES256CBC"}, "Not implemented"},
	{"7z_mf", []string{"-t7z", "-mf=AES256CBC"}, "Not implemented"},
	{"7z_m0_p", []string{"-t7z", "-m0=AES256CBC", "-pabc"}, "Not implemented"},
	{"zip_m0", []string{"-tzip", "-m0=AES256CBC"}, "Not implemented"},
	{"zip_mm", []string{"-tzip", "-mm=AES256CBC"}, "Not implemented"},
	{"xz_m0", []string{"-txz", "-m0=AES256CBC"}, "The parameter is incorrect."},
}

// RunAES256CBCMatrix proves the AES256CBC line in one lane.
func RunAES256CBCMatrix(t *testing.T, root string, lane sot.Lane) {
	t.Run("sot_refuses_write", func(t *testing.T) {
		for _, c := range aes256CBCWriteCases {
			c := c
			t.Run(c.name, func(t *testing.T) {
				t.Parallel()
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
			})
		}
	})

	t.Run("module_never_writes", func(t *testing.T) {
		dir := t.TempDir()
		MakeTree(t, dir, []TreeFile{{"f.txt", []byte("hello\n")}})
		n := 0
		for _, pw := range []string{"", "abc"} {
			for _, m := range []sevenzip.Method{sevenzip.LZMA2, sevenzip.LZMA, sevenzip.Copy, sevenzip.None, sevenzip.PPMd} {
				for f := sevenzip.NoFilter; ; f++ {
					opts := sevenzip.Options{Method: m, Filter: f, Password: pw, WordSize: lane.SizeT()}
					data, err := moduleArchive(dir, "f.txt", opts)
					if err != nil {
						if strings.Contains(err.Error(), "unknown filter") {
							break
						}
						continue // e.g. Method None without a Filter
					}
					a, err := sevenzip.OpenWithPassword(bytes.NewReader(data), int64(len(data)), pw)
					if err != nil {
						t.Fatalf("method %d filter %d: module cannot open its archive: %v", m, f, err)
					}
					coders := a.HeaderCoders()
					for i := 0; i < a.NumFolders(); i++ {
						coders = append(coders, a.FolderCoders(i)...)
					}
					for _, co := range coders {
						if co.MethodID == sevenzip.MethodAES256CBC {
							t.Fatalf("method %d filter %d: module wrote an AES256CBC coder", m, f)
						}
					}
					n++
				}
			}
		}
		if n == 0 {
			t.Fatal("no archive written")
		}
	})

	// A folder holding the codec: a Copy + 7zAES archive with an
	// uncompressed header whose 7zAES id is replaced by AES256CBC's
	// (same length) and whose CRCs are fixed. Made from the SoT's archive
	// and from the module's.
	src := func(t *testing.T, dir string, fromSoT bool) []byte {
		if fromSoT {
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
		b, err := moduleArchive(dir, "f.txt", sevenzip.Options{Method: sevenzip.Copy, Password: "abc", NoHeaderCompression: true, WordSize: lane.SizeT()})
		if err != nil {
			t.Fatal(err)
		}
		return b
	}
	for _, fromSoT := range []bool{true, false} {
		fromSoT := fromSoT
		name := "read_module_archive"
		if fromSoT {
			name = "read_sot_archive"
		}
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			dir := t.TempDir()
			MakeTree(t, dir, []TreeFile{{"f.txt", []byte("hello\n")}})
			b := toAES256CBC(t, src(t, dir, fromSoT))
			if err := os.WriteFile(filepath.Join(dir, "cbc.7z"), b, 0o644); err != nil {
				t.Fatal(err)
			}

			out, err := runSoTIn(root, lane, dir, "l", "-slt", "cbc.7z")
			wantExit(t, err, 0, out)
			if !strings.Contains(string(out), "\r\nMethod = Copy AES256CBC\r\n") {
				t.Fatalf("SoT l -slt: no AES256CBC method\n%s", out)
			}
			for _, args := range [][]string{{"t", "cbc.7z"}, {"t", "-pabc", "cbc.7z"}} {
				out, err := runSoTIn(root, lane, dir, args...)
				wantExit(t, err, 2, out)
				if !strings.Contains(string(out), "ERROR: Unsupported Method : f.txt") {
					t.Fatalf("SoT %v: want Unsupported Method\n%s", args, out)
				}
			}

			for _, pw := range []string{"", "abc"} {
				a, err := sevenzip.OpenWithPassword(bytes.NewReader(b), int64(len(b)), pw)
				if err != nil {
					t.Fatalf("password %q: module cannot open (the SoT lists it): %v", pw, err)
				}
				found := false
				for _, co := range a.FolderCoders(0) {
					found = found || co.MethodID == sevenzip.MethodAES256CBC
				}
				if !found {
					t.Fatalf("module does not report the AES256CBC coder: %+v", a.FolderCoders(0))
				}
				if _, err := a.Extract(0); !errors.Is(err, sevenzip.ErrUnsupported) {
					t.Fatalf("password %q: module extract: %v, want ErrUnsupported", pw, err)
				}
			}
		})
	}
}

// moduleArchive writes the module's archive of dir/name and returns it.
func moduleArchive(dir, name string, opts sevenzip.Options) ([]byte, error) {
	w := sevenzip.NewWriter(opts)
	if err := w.AddPathIn(dir, name); err != nil {
		return nil, err
	}
	f, err := os.CreateTemp(dir, "module-*.7z")
	if err != nil {
		return nil, err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err := w.Write(f); err != nil {
		return nil, err
	}
	return os.ReadFile(f.Name())
}

// toAES256CBC replaces the single 7zAES coder id in an uncompressed
// header with AES256CBC's and fixes the start header's CRCs.
func toAES256CBC(t *testing.T, b []byte) []byte {
	t.Helper()
	b = append([]byte(nil), b...)
	off := 32 + binary.LittleEndian.Uint64(b[12:])
	n := binary.LittleEndian.Uint64(b[20:])
	h := b[off : off+n]
	aes := []byte{0x06, 0xF1, 0x07, 0x01}
	if bytes.Count(h, aes) != 1 {
		t.Fatalf("want exactly one 7zAES id in the header, got %d", bytes.Count(h, aes))
	}
	copy(h[bytes.Index(h, aes):], []byte{0x06, 0xF0, 0x01, 0x81})
	binary.LittleEndian.PutUint32(b[28:], crc32.ChecksumIEEE(h))
	binary.LittleEndian.PutUint32(b[8:], crc32.ChecksumIEEE(b[12:32]))
	return b
}

// wantExit checks a SoT run's exit code.
func wantExit(t *testing.T, err error, code int, out []byte) {
	t.Helper()
	got := 0
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		got = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("SoT: %v\n%s", err, out)
	}
	if got != code {
		t.Fatalf("SoT exit code %d, want %d\n%s", got, code, out)
	}
}
