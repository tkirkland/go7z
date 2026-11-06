# go7z

A pure Go implementation of 7-Zip's LZMA, LZMA2, BCJ filter and 7z
container, written to be byte-identical to 7-Zip itself.

The reference is a pinned copy of 7-Zip 26.05 (`7zr.exe`, SHA-256
verified). Every feature is proven by comparing the module's output with
that binary's output on the same input, byte for byte. There is no other
definition of correct.

## Status

Parity is tracked as a scoreboard over the 84 codecs, formats, hashers,
commands and switches that `7zr` lists. Current state: **5 of 84**.

| Line          | Proof                                                   |
| ------------- | ------------------------------------------------------- |
| codec/Copy    | `copycoder`: 13 cases identical to the oracle           |
| codec/LZMA    | `lzma`: encoder and decoder, 26 cases identical         |
| codec/LZMA2   | `lzma`: encoder and decoder, 42 cases identical         |
| codec/BCJ     | `bra`: x86 converter, 37 cases identical                |
| format/7z     | `sevenzip`: 89 archives identical, all read back        |

Everything else (the other branch filters, BCJ2, Delta, encryption,
xz/lzma formats, the CLI commands and switches) is not done. See `HANDOFF.md`
for the full checklist and the order of work.

## Packages

- `lzma`: LZMA and LZMA2 encoders and decoders, ported from the
  public-domain LZMA SDK sources in 7-Zip 26.05 (`LzmaEnc.c`, `LzFind.c`,
  `Lzma2Enc.c`, `LzmaDec.c`, `Lzma2Dec.c`).
- `copycoder`: the Copy (store) coder.
- `bra`: the x86 branch converter (BCJ), ported from `Bra86.c`, as
  whole-buffer functions and as streaming readers.
- `sevenzip`: the 7z container. The reader is a port of `7zArcIn.c` and
  `7zDec.c`. The writer has no public-domain source; it is built from
  `DOC/7zFormat.txt` and from observing what `7zr` writes.
- `parity`: the scoreboard test.
- `internal/oracle`, `internal/oracletest`: locating and running the
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
the BCJ filter, level, solid mode and block size, header compression, threads and which timestamps to store.
Raw codec streams are available through `lzma.EncodeBytes`,
`lzma.Lzma2Encoder`, `lzma.DecodeOneShot` and `lzma.Lzma2DecodeOneShot`.

## Running the parity tests

The oracle binary is not in the repository. Fetch and verify it once:

```
powershell tools/fetch-oracle.ps1
```

Then:

```
go test -tags oracle ./...
go test -tags oracle -run TestParity ./parity/
```

`TestParity` prints `parity: N of 84` and fails until N is 84. The tests
run the oracle for every case, so they need Windows.

The pinned sources used for the ports are git tag `26.05` of
`github.com/ip7z/7zip`, cloned to `reference/7zip` (ignored by git).

## Licensing of the ported code

The C sources ported here (`C/Lzma*.c`, `C/LzFind.c`, `C/Bra86.c`,
`C/7zArcIn.c`, `C/7zDec.c`) are public domain, as marked in each file. The C++ archive
layer of 7-Zip is LGPL and is not ported; the 7z writer reproduces its
output from the format documentation and from observation.

## License

MIT. See `LICENSE`.
