package sottest

// LargeCase is one large single-file input run against both lanes at a
// level where the builds differ: above 256 MB the x64 build's default
// dictionaries at mx7..9 (2^27, 2^28, 2^28) are not reduced to the input,
// and at mx6 and above the default thread count decides whether the
// LZMA2 stream is one solid block or split into blocks of 4 x dict
// (sevenzip.Threads).
type LargeCase struct {
	Name  string
	Level int
	Input func() []byte
}

// LargeCases returns the large inputs: 300 MB of zeros at mx6..9. Zeros
// keep the SoT runs and the module runs short while still reaching the
// unreduced dictionaries and the block layout.
func LargeCases() []LargeCase {
	zeros := func() []byte { return make([]byte, 300<<20) }
	var out []LargeCase
	for _, level := range []int{6, 7, 8, 9} {
		out = append(out, LargeCase{Name: "zeros300m", Level: level, Input: zeros})
	}
	return out
}
