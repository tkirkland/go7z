package sevenzip

import (
	"bytes"

	"github.com/tkirkland/go7z/lzma"
)

// EncodeHeaderWith compresses a raw header with explicit LZMA
// properties (for pinning the SoT's header coder parameters).
func EncodeHeaderWith(header []byte, props lzma.EncProps, setDataSize bool) ([]byte, [5]byte, error) {
	enc := lzma.NewEncoder()
	if err := enc.SetProps(&props); err != nil {
		return nil, [5]byte{}, err
	}
	if setDataSize {
		enc.SetDataSize(uint64(len(header)))
	}
	var out bytes.Buffer
	if err := enc.Encode(&out, bytes.NewReader(header)); err != nil {
		return nil, [5]byte{}, err
	}
	return out.Bytes(), enc.WriteProperties(), nil
}

// HeaderEncProps exposes the header coder parameters in use.
func HeaderEncProps() (lzma.EncProps, bool) { return headerEncProps, headerSetDataSize }
