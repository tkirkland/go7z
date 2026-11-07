// Package hasher is the module's side of 7za's hashers (`7za i` lists
// CRC32, CRC64, SHA256, SHA1 and XXH64) and of the hash report that
// `7za h` prints. The hash values are the standard algorithms (the
// standard library for CRC32, CRC64-ECMA, SHA-1 and SHA-256; xxh64.go
// for XXH64); everything about the report is observed on both SoTs
// (2026-11-07, see report.go). The C++ HashCalc.cpp is LGPL and not
// ported.
package hasher

import (
	"crypto/sha1"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"hash"
	"hash/crc32"
	"hash/crc64"
	"slices"
	"strings"
)

// Algorithm is one hasher as 7za lists it.
type Algorithm struct {
	Name       string // as 7za prints it: CRC32, CRC64, SHA256, SHA1, XXH64
	DigestSize int
	New        func() hash.Hash
	// Upper is whether the hex digest is printed in upper case (the
	// CRC and XXH64 values are; the SHA digests are lower case).
	Upper bool
	// Value is whether the digest is a little-endian integer value whose
	// hex is printed most significant byte first (CRC32, CRC64, XXH64),
	// as opposed to a byte string printed in order (SHA1, SHA256).
	Value bool
}

var crc64Table = crc64.MakeTable(crc64.ECMA)

// crcLE wraps a hash whose Sum writes big-endian so that the digest
// bytes are the little-endian value, the order the 7-Zip hasher
// interface uses and the digest sums rely on.
type crcLE struct {
	hash.Hash
}

func (c crcLE) Sum(b []byte) []byte {
	s := c.Hash.Sum(nil)
	for _, v := range slices.Backward(s) {
		b = append(b, v)
	}
	return b
}

// Algorithms are the hashers in the order `7za i` lists them (and the
// column order of -scrc*).
var Algorithms = []Algorithm{
	{Name: "CRC32", DigestSize: 4, New: func() hash.Hash { return crcLE{crc32.NewIEEE()} }, Upper: true, Value: true},
	{Name: "CRC64", DigestSize: 8, New: func() hash.Hash { return crcLE{crc64.New(crc64Table)} }, Upper: true, Value: true},
	{Name: "SHA256", DigestSize: 32, New: sha256.New},
	{Name: "SHA1", DigestSize: 20, New: sha1.New},
	{Name: "XXH64", DigestSize: 8, New: NewXXH64, Upper: true, Value: true},
}

// Lookup returns the algorithm named name, case-insensitively (the SoT
// accepts -scrcsha256).
func Lookup(name string) (Algorithm, bool) {
	for _, a := range Algorithms {
		if strings.EqualFold(a.Name, name) {
			return a, true
		}
	}
	return Algorithm{}, false
}

// FormatDigest prints a digest the way the report does.
func (a Algorithm) FormatDigest(d []byte) string {
	if a.Value {
		r := make([]byte, len(d))
		for i := range d {
			r[i] = d[len(d)-1-i]
		}
		d = r
	}
	s := hex.EncodeToString(d)
	if a.Upper {
		s = strings.ToUpper(s)
	}
	return s
}

// Sum is a running digest sum with its carry count (observed: the
// report's totals are the per-item digests added as little-endian
// integers, with the number of overflows appended as -XXXXXXXX).
type Sum struct {
	Digest []byte
	Carry  uint32
}

func newSum(size int) Sum { return Sum{Digest: make([]byte, size)} }

// Add adds a digest to the sum.
func (s *Sum) Add(d []byte) {
	var c uint32
	for i := range s.Digest {
		v := uint32(s.Digest[i]) + uint32(d[i]) + c
		s.Digest[i] = byte(v)
		c = v >> 8
	}
	s.Carry += c
}

// Format prints the sum; withCount appends the carry count (observed:
// when the number of items summed is not 1).
func (s Sum) Format(a Algorithm, withCount bool) string {
	out := a.FormatDigest(s.Digest)
	if withCount {
		out += fmt.Sprintf("-%08X", s.Carry)
	}
	return out
}

// Entry is one hashed item of a report.
type Entry struct {
	Name    string // as printed (backslashes; directories end in one)
	IsDir   bool
	Size    uint64
	Digests [][]byte // one per algorithm of the bundle; nil for a directory
}

// Bundle accumulates the report's totals for a set of algorithms.
type Bundle struct {
	Algorithms []Algorithm
	NumFiles   int
	NumDirs    int
	TotalSize  uint64
	Data       []Sum // "for data": the file digests summed
	DataNames  []Sum // "for data and names": see AddEntry
	Entries    []Entry
}

// NewBundle returns an empty bundle for the algorithms.
func NewBundle(algs []Algorithm) *Bundle {
	b := &Bundle{Algorithms: algs}
	for _, a := range algs {
		b.Data = append(b.Data, newSum(a.DigestSize))
		b.DataNames = append(b.DataNames, newSum(a.DigestSize))
	}
	return b
}

// HashBytes hashes data with every algorithm of the bundle.
func (b *Bundle) HashBytes(data []byte) [][]byte {
	out := make([][]byte, len(b.Algorithms))
	for i, a := range b.Algorithms {
		h := a.New()
		h.Write(data)
		out[i] = h.Sum(nil)
	}
	return out
}

// AddFile adds a file with its data digests (HashBytes or a streamed
// equivalent).
func (b *Bundle) AddFile(name string, size uint64, digests [][]byte) {
	b.NumFiles++
	b.TotalSize += size
	for i := range b.Algorithms {
		b.Data[i].Add(digests[i])
		b.DataNames[i].Add(b.nameDigest(i, false, digests[i], name))
	}
	b.Entries = append(b.Entries, Entry{Name: name, Size: size, Digests: digests})
}

// AddDir adds a directory (name printed with its trailing backslash).
func (b *Bundle) AddDir(name string) {
	b.NumDirs++
	for i, a := range b.Algorithms {
		b.DataNames[i].Add(b.nameDigest(i, true, make([]byte, a.DigestSize), name))
	}
	b.Entries = append(b.Entries, Entry{Name: name, IsDir: true})
}

// nameDigest is one item's contribution to "for data and names"
// (observed on both SoTs, confirmed for all four byte-string hashers
// and CRC32): the hash of 16 bytes (the first 1 for a directory, the
// rest 0), the item's data digest (zeros for a directory), and the
// item's path in UTF-16LE with '/' separators and no trailing
// separator.
func (b *Bundle) nameDigest(i int, isDir bool, digest []byte, name string) []byte {
	h := b.Algorithms[i].New()
	var pre [16]byte
	if isDir {
		pre[0] = 1
	}
	h.Write(pre[:])
	h.Write(digest)
	p := strings.ReplaceAll(name, "\\", "/")
	p = strings.TrimSuffix(p, "/")
	var u []byte
	for _, r := range p {
		if r >= 0x10000 {
			r -= 0x10000
			u = binary.LittleEndian.AppendUint16(u, uint16(0xD800+(r>>10)))
			u = binary.LittleEndian.AppendUint16(u, uint16(0xDC00+(r&0x3FF)))
		} else {
			u = binary.LittleEndian.AppendUint16(u, uint16(r))
		}
	}
	h.Write(u)
	return h.Sum(nil)
}
