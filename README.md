# go7z

A pure Go implementation of 7-Zip's LZMA, LZMA2, the BCJ, BCJ2, ARM, ARMT,
ARM64, Swap2, Swap4 and Delta filters, PPMd, 7zAES encryption and the 7z
container,
written to be
byte-identical to
7-Zip itself.

The source of truth (SoT, the word used throughout this repo) is a pinned
pair of 7-Zip 26.05 binaries, the 32-bit and the 64-bit `7za.exe` from
`7z2605-extra.7z` (SHA-256 verified). Every feature is proven by
comparing the module's output with each binary's output on the same
input, byte for byte. There is no other definition of correct.

## Status

Parity is tracked as a scoreboard over the 96 codecs, formats, hashers,
commands and switches that `7za` lists, proven in two lanes: against the
32-bit build and against the 64-bit build of `7za.exe` from
`7z2605-extra.7z`. The two builds differ where the source branches
on `sizeof(size_t)`: the default dictionary at mx7 and above, and the
LZMA2 block layout on inputs of hundreds of MB. Four codecs (PPC, IA64,
SPARC, RISCV) are omitted by decision, leaving 92 lines. Current state:
**32-bit lane 19 of 92; 64-bit lane 19 of 92**. Six lines (Deflate,
Deflate64, BZip2, Cab, gzip, bzip2) have no public-domain source and
are counted as blocked.

| Line (both lanes) | Proof                                                    |
| ----------------- | -------------------------------------------------------- |
| codec/Copy        | `copycoder`: 13 cases identical to the SoT               |
| codec/LZMA        | `lzma`: encoder and decoder, 26 cases identical          |
| codec/LZMA2       | `lzma`: encoder and decoder, 42 cases identical          |
| codec/BCJ         | `bra`: x86 converter, 37 cases identical                 |
| codec/BCJ2        | `bra`: four-stream x86 converter, 44 cases identical     |
| codec/ARM         | `bra`: ARM BL converter, 39 cases identical              |
| codec/ARMT        | `bra`: Thumb BL converter, 48 cases identical            |
| codec/ARM64       | `bra`: AArch64 BL/ADRP converter, 51 cases identical     |
| codec/Swap2       | `bra`: byte-pair swap, 32 cases identical                |
| codec/Swap4       | `bra`: four-byte reverse, 32 cases identical             |
| codec/Delta       | `bra`: Delta filter, 194 cases identical                 |
| codec/7zAES       | `sevenzip`: 49 archives identical given the SoT's IVs    |
| codec/PPMD        | `ppmd`: encoder and decoder, 46 cases identical          |
| hasher/CRC32      | `hasher`: h report identical, 21 cases x 3 forms         |
| hasher/CRC64      | `hasher`: h report identical, 21 cases                   |
| hasher/SHA256     | `hasher`: h report identical, 21 cases                   |
| hasher/SHA1       | `hasher`: h report identical, 21 cases                   |
| hasher/XXH64      | `hasher`: h report identical, 21 cases                   |
| format/7z         | `sevenzip`: 327 archives identical, all read back        |

Everything else (AES256CBC, the filter automation, xz/lzma formats, the CLI
commands and switches) is not done. See `HANDOFF.md`
for the full checklist and the order of work.

## Packages

- `lzma`: LZMA and LZMA2 encoders and decoders, ported from the
  public-domain LZMA SDK sources in 7-Zip 26.05 (`LzmaEnc.c`, `LzFind.c`,
  `Lzma2Enc.c`, `LzmaDec.c`, `Lzma2Dec.c`).
- `copycoder`: the Copy (store) coder.
- `hasher`: the CRC32, CRC64, SHA256, SHA1 and XXH64 hashers, the digest
  sums and the text of the `h` report.
- `ppmd`: the PPMd var.H (Ppmd7z) encoder and decoder, ported from
  `Ppmd7.c`, `Ppmd7Enc.c` and `Ppmd7Dec.c`.
- `bra`: the branch converters: BCJ (x86), ported from `Bra86.c`, and
  ARM, ARMT and ARM64, ported from `Bra.c`, and the Swap2 and Swap4 byte
  swaps (observed, no public-domain source) and Delta (ported from
  `Delta.c`), as whole-buffer functions and as
  streaming readers; BCJ2, ported from `Bcj2Enc.c` and `Bcj2.c`, as the SDK's
  state machines plus whole-buffer and streaming four-stream encoders
  and a decoder.
- `sevenzip`: the 7z container. The reader is a port of `7zArcIn.c` and
  `7zDec.c`. The writer has no public-domain source; it is built from
  `DOC/7zFormat.txt` and from observing what `7za` writes.
- `parity`: the scoreboard test.
- `internal/sot`, `internal/sottest`: locating and running the
  pinned binary, and the comparison helpers.

## Usage

```go
import "github.com/tkirkland/go7z/sevenzip"

// Create an archive the way "7zr a out.7z in/a.txt in/dir" would.
err := sevenzip.Create("out.7z", []string{"in/a.txt", "in/dir"}, sevenzip.Options{})

// Read one back.
f, _ := os.Open("out.7z")
fi, _ := f.Stat()
a, err := sevenzip.Open(f, fi.Size())
for i, e := range a.Entries {
    data, err := a.Extract(i)
    _ = data
}
```

`Options` covers the method (LZMA2, LZMA, Copy, or the filter alone),
the BCJ, BCJ2, ARM, ARMT, ARM64, Swap2, Swap4 and Delta filters (with the
Delta distance), the 7zAES password and header encryption, level, solid mode
and block size,
header
compression, threads and which timestamps to store.
Raw codec streams are available through `lzma.EncodeBytes`,
`lzma.Lzma2Encoder`, `lzma.DecodeOneShot` and `lzma.Lzma2DecodeOneShot`.

## Running the parity tests

The SoT binaries are not in the repository. Fetch and verify them once:

```
powershell tools/fetch-sot.ps1
```

Then:

```
go test -tags sot ./...
go test -tags sot -run TestParity ./parity/
```

`TestParity` prints `parity 32: N of 92` and `parity 64: N of 92` and
fails until both are 92. The tests run the SoTs for every case, so they
need Windows.

The pinned sources used for the ports are git tag `26.05` of
`github.com/ip7z/7zip`, cloned to `reference/7zip` (ignored by git).

## Licensing of the ported code

The C sources ported here (`C/Lzma*.c`, `C/LzFind.c`, `C/Bra86.c`,
`C/Bra.c`, `C/Bcj2Enc.c`, `C/Bcj2.c`, `C/7zArcIn.c`, `C/7zDec.c`) are public
domain, as marked in each file. The C++ archive
layer of 7-Zip is LGPL and is not ported; the 7z writer reproduces its
output from the format documentation and from observation.

## License

MIT. See `LICENSE`.
