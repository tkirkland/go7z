package bra

import "io"

// delta.go is the port of C/Delta.c, the Delta filter: every byte is
// replaced by its difference from the byte `delta` positions earlier,
// with the last `delta` bytes of each call carried in the state for the
// next call (DELTA_STATE_SIZE = 256). The 7z coder property is one byte,
// delta - 1; delta is 1..256, default 1.

// DeltaStateSize is DELTA_STATE_SIZE.
const DeltaStateSize = 256

// DeltaState is the filter's carried state: the last delta bytes seen.
type DeltaState [DeltaStateSize]byte

// Init is Delta_Init.
func (s *DeltaState) Init() { *s = DeltaState{} }

// Encode is Delta_Encode: converts data in place and carries the state.
func (s *DeltaState) Encode(delta int, data []byte) {
	size := len(data)
	if size == 0 {
		return
	}
	var temp DeltaState
	copy(temp[:delta], s[:delta])

	if size <= delta {
		for i := 0; i < size; i++ {
			b := data[i]
			data[i] = b - temp[i]
			temp[i] = b
		}
		i := size
		for k := 0; k < delta; k++ {
			if i == delta {
				i = 0
			}
			s[k] = temp[i]
			i++
		}
		return
	}

	copy(s[:delta], data[size-delta:])
	p := size // the state copy leaves p at data + size
	if (size-delta)&1 != 0 {
		p--
		data[p] -= data[p-delta]
	}
	for p != delta {
		p--
		data[p] -= data[p-delta]
		p--
		data[p] -= data[p-delta]
	}
	for d := delta; d != 0; {
		p--
		d--
		data[p] -= temp[d]
	}
}

// Decode is Delta_Decode: the inverse of Encode in place, carrying the
// state.
func (s *DeltaState) Decode(delta int, data []byte) {
	size := len(data)
	if size == 0 {
		return
	}
	if size <= delta {
		for i := 0; i < size; i++ {
			data[i] += s[i]
		}
		// for (; delta != i; state++, delta--) *state = state[i];
		for k := 0; k < delta-size; k++ {
			s[k] = s[k+size]
		}
		copy(s[delta-size:delta], data)
		return
	}
	for i := 0; i < delta; i++ {
		data[i] += s[i]
	}
	for i := delta; i < size; i++ {
		data[i] += data[i-delta]
	}
	copy(s[:delta], data[size-delta:])
}

// DeltaEncode converts a whole buffer in place as the 7z Delta coder
// does (a fresh state).
func DeltaEncode(delta int, data []byte) {
	var s DeltaState
	s.Encode(delta, data)
}

// DeltaDecode is the inverse of DeltaEncode in place (7zDec.c:
// Delta_Init then Delta_Decode over the whole unpacked folder).
func DeltaDecode(delta int, data []byte) {
	var s DeltaState
	s.Decode(delta, data)
}

// DeltaEncodeBytes returns a converted copy of data.
func DeltaEncodeBytes(delta int, data []byte) []byte {
	out := append([]byte(nil), data...)
	DeltaEncode(delta, out)
	return out
}

// DeltaDecodeBytes returns a decoded copy of data.
func DeltaDecodeBytes(delta int, data []byte) []byte {
	out := append([]byte(nil), data...)
	DeltaDecode(delta, out)
	return out
}

// NewDeltaEncodeReader returns a reader that yields r's bytes converted
// by the Delta encoder, chunk by chunk with the state carried as 7-Zip's
// filter coder does.
func NewDeltaEncodeReader(delta int, r io.Reader) io.Reader {
	var s DeltaState
	return newConvReader(r, func(data []byte, _ uint32) int {
		s.Encode(delta, data)
		return len(data)
	})
}

// NewDeltaDecodeReader returns a reader that yields r's bytes converted
// by the Delta decoder.
func NewDeltaDecodeReader(delta int, r io.Reader) io.Reader {
	var s DeltaState
	return newConvReader(r, func(data []byte, _ uint32) int {
		s.Decode(delta, data)
		return len(data)
	})
}
