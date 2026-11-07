package sevenzip

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"io"
	"sync"
	"unicode/utf16"
)

// aes.go is the 7zAES coder (method 06F10701): AES-256 in CBC mode with
// a key derived by SHA-256 from the password. There is no public-domain
// source for the coder itself (the C++ 7zAes.cpp is LGPL); the cipher
// and hash are the standard library's, and the coder's properties, key
// derivation, padding and placement in the folder are observed on both
// SoTs (2026-11-07):
//
//   - Properties: byte 0 = NumCyclesPower (19) | 0x80 if a salt is
//     present | 0x40 if an IV is present; byte 1 = (saltSize-1)<<4 |
//     (ivSize-1); then the salt, then the IV. The SoT writes 53 0F and a
//     16-byte random IV, no salt.
//   - Key = SHA-256 over 2^NumCyclesPower rounds of (salt, password as
//     UTF-16LE, 8-byte little-endian round counter).
//   - Each pack stream is encrypted separately with zero padding to a
//     multiple of 16; an empty stream stays empty. The coder's unpack
//     size is the unpadded length, the pack size the padded one.
//   - In the folder record the 7zAES coders come first, one per pack
//     stream in reverse stored order, each bound to the coder that read
//     that pack stream; the new pack streams are the 7zAES in-streams in
//     reverse coder order, so the stored order is unchanged.

// ErrPassword is returned when an encrypted folder is read without a
// password.
var ErrPassword = errors.New("sevenzip: archive is encrypted; a password is required")

const (
	aesDefaultCycles = 19
	aesBlock         = 16
)

// aesProps returns the 7zAES coder properties for one IV (no salt).
func aesProps(iv [aesBlock]byte) []byte {
	b := make([]byte, 2+aesBlock)
	b[0] = aesDefaultCycles | 0x40
	b[1] = aesBlock - 1
	copy(b[2:], iv[:])
	return b
}

// parseAESProps decodes the coder properties (7zAesDecoder::SetDecoderProperties2).
func parseAESProps(props []byte) (cycles int, salt, iv []byte, err error) {
	if len(props) == 0 {
		return 0, nil, nil, ErrUnsupported
	}
	b0 := props[0]
	cycles = int(b0 & 0x3f)
	if b0&0xc0 == 0 {
		if len(props) != 1 {
			return 0, nil, nil, ErrUnsupported
		}
		return cycles, nil, nil, nil
	}
	if len(props) < 2 {
		return 0, nil, nil, ErrUnsupported
	}
	b1 := props[1]
	saltSize := int(b0>>7) + int(b1>>4)
	ivSize := int(b0>>6&1) + int(b1&0x0f)
	if len(props) != 2+saltSize+ivSize || cycles > 24 {
		return 0, nil, nil, ErrUnsupported
	}
	salt = props[2 : 2+saltSize]
	iv = make([]byte, aesBlock)
	copy(iv, props[2+saltSize:])
	return cycles, salt, iv, nil
}

var aesKeyCache sync.Map // string(cycles, salt, password) -> [32]byte

// aesKey derives the AES-256 key for the password.
func aesKey(password string, salt []byte, cycles int) [32]byte {
	cacheKey := string(rune(cycles)) + "\x00" + string(salt) + "\x00" + password
	if v, ok := aesKeyCache.Load(cacheKey); ok {
		return v.([32]byte)
	}
	var pw []byte
	for _, u := range utf16.Encode([]rune(password)) {
		pw = append(pw, byte(u), byte(u>>8))
	}
	var key [32]byte
	if cycles == 0x3f {
		// 7-Zip: NumCyclesPower 0x3F means the key is the salt and
		// password bytes themselves (no hashing); not written by the SoT.
		n := copy(key[:], salt)
		copy(key[n:], pw)
	} else {
		h := sha256.New()
		var ctr [8]byte
		rounds := uint64(1) << uint(cycles)
		for i := uint64(0); i < rounds; i++ {
			h.Write(salt)
			h.Write(pw)
			binary.LittleEndian.PutUint64(ctr[:], i)
			h.Write(ctr[:])
		}
		copy(key[:], h.Sum(nil))
	}
	aesKeyCache.Store(cacheKey, key)
	return key
}

// aesDecrypt decrypts one pack stream (a multiple of 16 bytes) and
// returns its first outSize bytes.
func aesDecrypt(props []byte, password string, in []byte, outSize uint64) ([]byte, error) {
	cycles, salt, iv, err := parseAESProps(props)
	if err != nil {
		return nil, err
	}
	if len(in)%aesBlock != 0 || outSize > uint64(len(in)) || (outSize+aesBlock-1)/aesBlock*aesBlock != uint64(len(in)) {
		return nil, ErrData
	}
	key := aesKey(password, salt, cycles)
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(in))
	if len(in) > 0 {
		cipher.NewCBCDecrypter(blk, iv).CryptBlocks(out, in)
	}
	return out[:outSize], nil
}

// aesWriter encrypts what is written to it in CBC mode and writes the
// ciphertext to w; Close pads the last block with zeros. plain counts
// the bytes written, the coder's unpack size.
type aesWriter struct {
	w     io.Writer
	mode  cipher.BlockMode
	buf   []byte // partial block
	block [aesBlock]byte
	plain uint64
}

func newAESWriter(w io.Writer, key [32]byte, iv [aesBlock]byte) (*aesWriter, error) {
	blk, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}
	return &aesWriter{w: w, mode: cipher.NewCBCEncrypter(blk, iv[:])}, nil
}

func (a *aesWriter) Write(p []byte) (int, error) {
	n := len(p)
	a.plain += uint64(n)
	if len(a.buf) > 0 {
		take := aesBlock - len(a.buf)
		if take > len(p) {
			take = len(p)
		}
		a.buf = append(a.buf, p[:take]...)
		p = p[take:]
		if len(a.buf) < aesBlock {
			return n, nil
		}
		a.mode.CryptBlocks(a.block[:], a.buf)
		a.buf = a.buf[:0]
		if _, err := a.w.Write(a.block[:]); err != nil {
			return 0, err
		}
	}
	full := len(p) &^ (aesBlock - 1)
	if full > 0 {
		out := make([]byte, full)
		a.mode.CryptBlocks(out, p[:full])
		if _, err := a.w.Write(out); err != nil {
			return 0, err
		}
	}
	if full < len(p) {
		a.buf = append(a.buf[:0], p[full:]...)
	}
	return n, nil
}

// Close writes the zero-padded final block, if any.
func (a *aesWriter) Close() error {
	if len(a.buf) == 0 {
		return nil
	}
	var last [aesBlock]byte
	copy(last[:], a.buf)
	a.buf = a.buf[:0]
	a.mode.CryptBlocks(a.block[:], last[:])
	_, err := a.w.Write(a.block[:])
	return err
}
