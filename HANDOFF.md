# Hand off: parity with the 7-Zip 26.05 SoTs, 32-bit and 64-bit

SoT means source of truth: the pinned 7-Zip binary whose bytes define
what is correct. The user chose the term on 2026-11-06; use it, not
"oracle".

Written by the Claude that built go7z on 2026-11-04/05, updated by the
deepseek-v4-pro session of 2026-11-06, by the Claude Fable 5.1 session of
2026-11-06 that ported the encoder, by the Claude Fable 5.1 session of
2026-11-06 that ported BCJ and then, on the user's decision, split the
work into two lanes, by the Claude Fable 5.1 session of 2026-11-06
that built the two-lane harness, by the Claude Fable 5.1 session of
2026-11-06 that ported BCJ2, and by the Claude Fable 5.1 session of
2026-11-07 that ported ARM64, Swap2, Swap4, Delta, 7zAES, PPMd and the
hashers. Each update
integrates what that
session actually produced, and what the user established about why
hand offs keep failing.

Read this before touching anything. The first half is about how you fail.
The second half is the checklist. Do not skip the first half; it is the
reason the checklist exists.

## What this document is, and what it is not

This document is not control. It is context. You do not execute it; you
re-derive the task every round from the conversation window, and your own
prior about what a sensible engineer would do competes with every line
written here. Text can bias your next prediction. It cannot steer it.

The user is in a type-and-pray arrangement: preventive control does not
exist for this mechanism. The only controls are corrective and external:
the scoreboard below, discarding bad work, changing the provider. The user
watches the results, not the process; when you drift, the drift is
discovered after the fact, not stopped.

The screwdriver does not decide which screw. The user decides; you turn.
When you form an opinion about the order of work, that is the tool deciding,
and that is the failure. The checklist below is the user's hand on the
screwdriver. Do not grab the handle back.

## The two lanes (decided by the user on 2026-11-06)

7-Zip ships as a 32-bit build and a 64-bit build of the same source, and
the source produces different bytes in the two builds wherever it
branches on `sizeof(size_t)` or on available address space. The user's
words: "two lanes.. 32 and 64 which is what should have been done from
onset". Every parity line is therefore proven twice, once against each
build, and a line is `done` only when both lanes pass. The 64-bit lane is
the one real users run; the 32-bit lane exists because the source has it.

Both lanes use `7za.exe` ("7-Zip alone", the standalone console build)
from the release's asset `7z2605-extra.7z` (asset SHA-256
`f27a8f103c84785026edcba1f67faf1357225df9d19ddb0b7760d55947141bc7`; a
copy is at `tools/tmp/7z2605-extra.7z`). The user chose `7za` on
2026-11-06 ("i say 7za") and then ruled that every line it lists counts
("all 12"), which is why the 32-bit lane moves from `7zr.exe` to the
32-bit `7za.exe`: `7zr` does not list those 12 lines, and the two lanes
must walk the same list.

Lane 32: `tools/sot/7za-x86.exe` (`7za.exe` from the package root),
SHA-256 `357929ec748d00728c64dd2e7aa0069258f40847c1410014bb60d22eb9ec75d5`,
version line `7-Zip (a) 26.05 (x86) : Copyright (c) 1999-2026 Igor Pavlov
: 2026-10-21`.

Lane 64: `tools/sot/7za-x64.exe` (`x64/7za.exe`), SHA-256
`7ddf0a3bc451e166679296be630d6f0573eb386159c04184761c43020c484291`,
version line `7-Zip (a) 26.05 (x64) : Copyright (c) 1999-2026 Igor Pavlov
: 2026-10-21`.

Both are placed, hashed and version-checked (2026-11-06, harness
session): `tools/fetch-sot.ps1` fetches `7zr.exe` and the package,
verifies both, extracts the two binaries with `7zr.exe` and verifies
them; `internal/sot.Binary(root, lane)` re-verifies hash and version
line before any test uses a binary. `tools/sot/7zr.exe` (release asset
`7zr.exe`, SHA-256
`9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7`) stays
as the extraction tool only; no proof runs against it any more. The
package also holds `arm64/7za.exe` (SHA-256
`86a2064dfe2a362f03e3c95e577cab88a9d2caaca9e442520046a050044d2d4d`);
ARM64 is not a lane, the user has not asked for it.

The user's original goal, in their words on 2026-11-06: "the orij goal
was 7z lzma2 with lfs". The checklist is wider than that by the user's
later instruction (every switch, knob and tunable); the remark is
context for what matters most, not a reordering.

What the 64-bit lane changes, observed on 2026-11-06 (do not re-derive):

1. For inputs up to 3 MB (random 3 MB; the 600 KB PE) and for 64 MB of
   zeros, the two builds write identical `.7z` at every level 1..9,
   default threads and `-mmt1`. Everything proven so far on the 32-bit
   lane at those sizes is expected to hold on the 64-bit lane, but it is
   not proven until the lane runs.
2. The default dictionary differs from mx7 up, exactly as `LzmaEnc.c`
   says for `sizeof(size_t) == 8`: on 300 MB of zeros the coder record
   is 2^26 for mx6 on both builds, then 32-bit stays at 2^26 for mx7/8/9
   while 64-bit writes 2^27 (mx7), 2^28 (mx8), 2^28 (mx9). The port
   keys this on `lzma.EncProps.WordSize` (`WordSize32` = 4 or
   `WordSize64` = 8; 0 means 64, the build real users run), which also
   sets `kNumLogBits` and so the largest accepted dictionary (2^27 on
   32-bit, unbounded on 64-bit); `sevenzip.Options.WordSize` passes it
   through, and every matrix sets it from the lane.
3. The default LZMA2 block layout differs at large inputs even with the
   same dictionary. Observed on 300 MB and 600 MB of zeros (harness
   session, 32 logical processors, 64 GB RAM):
   - `-mmt N` is the total thread count; the SDK's
     `Lzma2EncProps_Normalize` makes block threads = N / LZMA threads
     (2 at the levels with the bt4 match finder), so `-mmt2` and `-mmt3`
     give one block thread (solid) and `-mmt4`, `-mmt8`, `-mmt16`,
     `-mmt32` give two or more (blocks of 4 x dict), on both builds.
     Explicit `-mmt` is never reduced.
   - The default is the number of logical processors (split on both
     builds), except that the x86 build reduces its default to one block
     thread from a 36 MB dictionary up: `-md=35m` splits, `-md=36m` is
     solid; so x86 mx5 (32 MB) splits and mx6..9 (64 MB) are solid,
     while x64 splits at every level and at `-md` up to 1024m.
   - This is the LGPL C++ layer limiting memory on x86; no public-domain
     C file holds the estimate, so the module pins the observed boundary
     (`x86DefaultSolidDict` in `sevenzip/threads.go`, `sevenzip.Threads`).
     The boundary may move with the machine's processor count; it was
     observed only on this machine.
4. xz: 300 MB of zeros at mx1 and mx5 (default and `-mmt1`) is identical
   in both builds; mx9 differs (the dictionary, item 2: 32-bit 45932
   bytes, 64-bit 46040).
5. `7za` (both builds) lists more than `7zr` does. `7za i` adds formats
   Cab, bzip2, gzip, tar, zip, zstd; codecs BZip2, Deflate64, Deflate,
   PPMD; hashers SHA1, XXH64; and `-scrc` gains `SHA1|XXH64`. The
   commands and the other 46 switches are identical. The user ruled on
   2026-11-06 that all 12 count ("all 12, wtf"). They are in the
   checklist below. Five of them (Deflate, Deflate64, BZip2 and the gzip
   and bzip2 formats that need them) have LGPL-only compressors; their
   mark is `blocked: LGPL-only source` until the user says what to do
   about that, and that mark is reported as such, never as done.

## Session state (2026-11-07, after the ARM64 .. hashers session)

- Repo: branch `main`, remote `origin` = github.com/tkirkland/go7z
  (public). History before `e5c143d` on the old remote is not a
  reference. Start from zero means this repo.
- Go 1.27.3 is installed at `C:\Users\Tony\sdk\go`. In git-bash prefix
  commands with `export PATH="/c/Users/Tony/sdk/go/bin:$PATH"` if
  `go version` fails.
- Pinned source: `reference/7zip` = git tag `26.05`
  (commit `b88c6bc09339de32f7d18bbab900686b244f42ba`), gitignored.
- `tools/fetch-sot.ps1` fetches, verifies and places both lane
  binaries (lane section); `testdata/SOT.md` records both.
- Parity fixtures committed, generated from the verified binaries:
  `testdata/parity/7za-x86-i.txt`, `7za-x86-usage.txt`, `7za-x64-i.txt`,
  `7za-x64-usage.txt` (the two builds differ only in the version line).
  The `7zr` fixtures are gone.
- TestParity: package `parity`, `//go:build sot`. For each lane it
  verifies the lane's binary (hash and version line) and that the
  fixtures equal its live output, then walks the 96 lines (12 formats +
  21 codecs + 5 hashers + 11 commands + 47 switches) minus the four
  omitted codecs = 92, as subtests `TestParity/32/<key>` and
  `TestParity/64/<key>`, and prints `parity 32: N of 92`, `parity 64: N
of 92`, then the omitted, blocked and failing lines by name. A line is
  registered by adding its key to the `checks` map in an `init()` of a
  `parity/*_test.go` file (see `parity/codec_lzma_test.go`); the same
  check runs in both lanes with `env.Lane`. The six LGPL-only lines are
  in `parity.Blocked` and fail with that reason. Current baseline:
  **32-bit lane 13 of 92; 64-bit lane 13 of 92** (both against `7za`,
  large inputs included). A full run takes about 14 minutes for the
  small matrices plus the large cases (below).
- `internal/sot`: `Lane` (`Lane32`, `Lane64`, `Lanes`, `SizeT()`),
  `Binary(root, lane)` verifies hash and version line (cached per
  process), `Run(dir, lane, args...)`, `RunBinary`.
- Commits: `e5c143d` (harness, fixtures, SoT verifier),
  `7eeb1b3` (LZMA/LZMA2 decoders), `49f8072` (LZMA encoder, codec/LZMA),
  `998f516` (LZMA2 encoder, codec/LZMA2), `106f608` (Copy coder),
  `6218c03` (7z container), `3f3a43c` (module path), `42fabb6`..`de800ff`
  (IDE files, README, LICENSE, perf test), `c8e1e39` (BCJ filter,
  `bra/`, container bonds), `c25250f`..`cb927d3` (two-lane harness,
  fixtures, docs), `d503515` (BCJ2: `bra/bcj2.go`, generic folder
  decoder, BCJ2 folders in the writer), `ca0a2c3` (docs), `c2536ee`
  (ARM: `bra/bra.go`, `Options.Filter = ARM`), `5d01c8d` (docs), `7b59af1`
  (ARMT: `ARMTConvert` in `bra/bra.go`, `Options.Filter = ARMT`),
  `2253a1d` (docs), the ARM64 commit (`bra/bra64.go`, `Options.Filter =
  ARM64`), the Swap commit (`bra/swap.go`, `Options.Filter = Swap2`,
  `Swap4`) and the Delta commit (`bra/delta.go`, `Options.Filter =
  Delta`, `Options.DeltaDistance`) and the 7zAES commit (`sevenzip/aes.go`,
  `Options.Password`, `EncryptHeader`, `Random`, `OpenWithPassword`), the
  PPMd commit (`ppmd/`, `sevenzip/ppmd.go`, `Options.Method = PPMd`,
  `PPMdOrder`, `PPMdMem`), the hasher commit (`hasher/`), then
  this handoff revision.
- `lzma/` package:
  - decoders: `lzmadec.go`, `lzma2dec.go` (`DecodeOneShot`,
    `Lzma2DecodeOneShot`), `lzma86.go` (`DecodeLzma86`).
  - encoders: `lzfind.go` (port of `LzFind.c`: bt2/bt3/bt4/bt5/hc4/hc5),
    `lzmaenc.go` (port of `LzmaEnc.c`: `EncProps`, `Encoder`, `EncodeBytes`,
    `Encoder.Encode(w, r)`, `Encoder.WriteProperties`),
    `lzma2enc.go` (port of `Lzma2Enc.c`: `Lzma2EncProps`, `Lzma2Encoder`,
    `Encode(w, r)`, `EncodeBytes`, `WriteProperties`, block splitting).
  - The two places the C code depends on `sizeof(size_t)` (default dict
    per level, `kNumLogBits`) follow `EncProps.WordSize` (lane item 2).
    Dict per level, 7z and xz: mx1 2^18, mx2 2^20, mx3 2^22, mx4 2^24,
    mx5 2^25, mx6 2^26, then 32-bit 2^26 for mx7..9 and 64-bit 2^27,
    2^28, 2^28; always reduced to the input size (`reduceSize`).
- `internal/sottest/`: helpers shared by SoT tests and parity checks:
  `DeterministicData`, `TextLike`, `BranchPattern`, `SoTExe(t, root,
lane)` (the lane's SoT's own bytes as a real PE input), `SoTXz`,
  `XzSingleBlock`, `SevenZRawStream` (the raw packed stream of a
  single-file .7z starts at offset 32 and its length is the `Packed
Size` of `l -slt`), `SevenZFolder` (a single-file .7z's coder records
  and raw pack streams through the module's header parser:
  `Archive.FolderCoders`, `FolderPackStreams`, `FolderUnpackSizes`),
  `ParseMethod`, `RunLZMAMatrix`, `RunLZMA2Matrix`, `RunCopyMatrix`,
  `RunBCJMatrix`, `RunBCJ2Matrix`, `RunARMMatrix`, `RunARMTMatrix`,
  `RunARM64Matrix`, `RunSwapMatrix` (`Swap2Check`, `Swap4Check`),
  `RunDeltaMatrix` (`DeltaCheck(delta)`), `AESCases`, `RunAESMatrix`,
  `RunPPMDMatrix` (`CheckPPMD`), `RunHashMatrix` (`HashCases`, `CheckHash`)
  (`CheckRisc` with a `RiscCheck` per RISC converter, `ARMPattern`,
  `ARMTPattern`, `ARM64Pattern`), `SevenZCases(exe)`,
  `RunSevenZMatrix`, `LargeCases`. Every matrix takes a `sot.Lane` and sets `WordSize` from
  it; the `Test...SoT...` tests in `lzma/`, `copycoder/`, `bra/` and
  `sevenzip/` run each matrix once per lane as subtests `32` and `64`.
- Large inputs (`sottest.LargeCases`): 300 MB of zeros at mx6..9, run in
  the LZMA matrix (mx6..9), the LZMA2 matrix (default threads and
  `-mmt1`) and the 7z matrix (default threads and `-mmt1`), per lane.
  They reach the unreduced 2^27/2^28 dictionaries (lane item 2) and the
  default block layout (lane item 3). The Go LZMA2 encoder takes about
  16 s per 300 MB case at mx9; the large cases add roughly 12 minutes
  to the parity run.
- Proof of the encoders (all byte-identical in both lanes unless a mark
  below says otherwise):
  - `TestEncodeSoTLZMA` / parity `codec/LZMA`: 26 cases, raw LZMA
    streams from `.7z -m0=LZMA:<params>` with mf=bt2/bt3/bt4/bt5/hc4/hc5,
    a=0, fb=5/273, mc=1/1000, lc/lp/pb extremes, d=4k/16k, mt=1, levels
    1/3/5/7/9, sizes 1/100/4096/300000.
  - `TestEncodeSoTLZMA2` / parity `codec/LZMA2`: 42 cases, raw LZMA2
    streams from `.7z -m0=LZMA2:<params>` including `c=` block splitting
    (block threads and `-mmt1`), plus single-block `.xz` payloads at
    sizes 1..300000, levels 1..9.
  - `TestDecodeSoTXz`: 12 cases (decoder).
- Facts established with the 32-bit SoT (do not re-derive):
  1. The SoT's `-mmt1`, `-mmt2` and default output is byte-identical
     (9 inputs x levels, inputs up to a few MB), so `LzFind.c`
     (single-threaded) is the reference; `LzFindMt.c` is not needed for
     identity. At 300 MB and mx6+ the default differs between builds
     (lane item 3, now pinned in `sevenzip.Threads`).
  2. `7zr a -tlzma` prints `System ERROR: Not implemented` (exit 2). The
     SoT cannot create `.lzma`; the lzma format line is read-side plus
     that same refusal on create. Whether `7za` x64 behaves the same is
     not observed.
  3. The SoT's `.xz` uses the CRC32 check by default; one block for
     inputs below the auto block size (4 x dict, clamped to 1 MB..256 MB).
     On a 300 MB zero file, mx1 and mx5 wrote multi-block xz with block
     sizes 1 MB and 128 MB; mx9 (64 MB dict, 256 MB blocks) wrote a single
     block with no size fields. That is the C++ layer limiting block
     threads by memory on x86; the xz line has to reproduce it by
     observation, per lane.
  4. In 7z, `-m0=LZMA2:c=N` sets the LZMA2 block size and reduces the
     dictionary to it; `lc+lp>4` is rejected for LZMA2 (as the SDK does).
  5. `ReduceSize` = input size and `SetDataSize` = input size reproduce
     the SoT for 7z and xz; for multi-block LZMA2 the per-block expected
     size is the block length (MtCoder uses direct input per block).
- Copy was marked without the container: the raw packed stream of a
  single-file `-m0=Copy` .7z (`SevenZRawStream`) is the identity, 13 cases
  (`-m0=Copy` at mx0/1/5/9, bare `-mx0`, sizes 1/100/4096/300000).
- `sevenzip/` package (format/7z): `reader.go` is a port of `7zArcIn.c`
  and `7zDec.c` (`Open`, `Archive.Entries`, `Archive.Extract`; folders with
  one Copy/LZMA/LZMA2 coder, optionally behind a ported filter; other
  filters and BCJ2 return `ErrUnsupported` until their lines are done).
  `writer.go` (`NewWriter`, `AddPath`, `AddPathIn`, `Write`, `Create`,
  `Options`) is built from `DOC/7zFormat.txt` plus observation; there is
  no public-domain writer source. Both sides handle two-coder folders
  (method + filter, one bond). `number.go` has the variable-length number
  and bit vectors. Proof: `TestSoT7z` / parity `format/7z`, 327 cases
  byte-identical to both SoTs' archives (Copy, LZMA, LZMA2 at
  levels 1/5/9 and `-mx0`, sizes 1..2 MB, empty files and directories,
  nested trees, `-ms=off`, `-ms=1k`/`-ms=4m`, `-mhc=off`, `-mtc=on`,
  `-mtm=off`, `-mmt1`, name ordering, 31 BCJ cases, 32 BCJ2 cases,
  20 ARM cases, 20 ARMT cases, 20 ARM64 cases, 20 Swap2 cases, 20 Swap4
  cases, 25 Delta cases, 28 PPMd cases) plus
  the large cases, and the module reads every SoT archive back (names,
  sizes, CRCs, contents). The reader's `decodeFolder` walks the coder
  graph generically (the main coder's in-streams are pack streams or
  bound coder outputs, recursively), which covers every shape 7zDec.c
  accepts and the two more the SoT writes for BCJ2.
- Container facts observed on the 32-bit SoT (do not re-derive):
  1. Header layout: kHeader, MainStreamsInfo (PackInfo with PackPos 0;
     UnpackInfo with one folder record per folder; SubStreamsInfo with
     kNumUnpackStream only when some folder has != 1 streams, kSize for all
     but the last stream of each folder, then kCRC all-defined for every
     stream; folder CRCs are never written), FilesInfo (kEmptyStream and
     kEmptyFile bit vectors when needed, never kAnti; kName; kCTime/kATime
     only with -mtc/-mta; kMTime unless -mtm=off; kWinAttrib; kEnd).
  2. kDummy padding before kName, each time property and kWinAttrib so that
     the property's data starts 16-, 8- and 4-byte aligned from the header
     start (rule in `hdr.skipToAligned`).
  3. Coder records: Copy `01 00` (1-byte id), LZMA `23 03 01 01 05 <5>`,
     LZMA2 `21 21 01 <1>`, BCJ `04 03 03 01 03`. Names are UTF-16LE with
     '/' separators (a backslash argument is stored as '/').
  4. Item order: directories, then empty files, then files with data, each
     sorted by name with the separator lowest and letters compared in upper
     case (`sub/q` < `subz` < `sub_x` < `_x`; `b` < `B2`). Ties between
     names equal in upper case were not observed.
  5. The header is LZMA-compressed only when the archive has two or more
     items. Header coder: dictionary 1 MB (the record shows it reduced to
     the header size), fb=273, normal parser, bt2, default mc (bt3 also
     matched on a 74 KB header; 1 MB confirmed on a 3.3 MB header).
  6. Solid blocks: files are added while the running total stays within the
     limit. Default limit: LZMA max(dict<<7, 16 MB), LZMA2 max(dict<<8,
     64 MB) with dict the level's dictionary (or -md), observed up to 200 MB;
     no upper clamp observed. Bare Copy is never solid. No file-count
     limit up to 5000 files.
  7. The coder dictionary is reduced to the sum of all data file sizes when
     solid, and to the largest data file when `-ms=off`, never to the
     folder's own size. `SetDataSize` is the folder size.
  8. Attributes are the raw Win32 attributes; times are raw FILETIMEs.
- `bra/` package (codec/BCJ): `bra86.go` is the port of `Bra86.c`
  (`X86Convert` with the carried state, `X86Encode`/`X86Decode` whole
  buffer, `NewX86EncodeReader`/`NewX86DecodeReader` streaming with the
  unprocessed tail carried over as 7-Zip's filter coder does). Proof:
  `TestEncodeSoTBCJ` / parity `codec/BCJ`, 37 cases byte-identical to
  the raw packed stream of `-m0=BCJ` (the SoT binary itself as a real
  PE, slices of it, deterministic binary and text 0..3 MB, branch-opcode
  patterns, all-E8/E9/00/FF, levels 1/9), whole-buffer and streaming
  with uneven chunks, and the SoT's streams decode back. The 7z
  container exposes it as `Options.Filter = BCJ` with `Method` LZMA2,
  LZMA, Copy or `None` (filter alone).
- Filter facts observed on the 32-bit SoT (do not re-derive):
  1. `-m0=BCJ` alone: the folder's only coder is BCJ (`04 03 03 01 03`,
     no properties), packed size = unpacked size; the level does not add
     a compressor. `7zDec.c` rejects such a folder (first coder must be
     a main method); the module reads it anyway because the SoT does.
  2. `-m0=BCJ -m1=<M>` and `-mf=BCJ` (same bytes with the default or
     `-m0=<M>` method): two coders, the method first, BCJ second, one
     bond `01 00` (in-stream 1 from coder 0), the single pack stream
     implicit, then one unpack size per coder, both equal.
  3. `-mf=BCJ -mx0` is BCJ + Copy; `-m0=BCJ -m1=LZMA2 -mx0` is LZMA2 at
     level 0 (dict 64 KB) behind BCJ (not expressible in `Options` yet;
     the `-m` switch line).
  4. BCJ alone and BCJ + Copy are solid (unlike bare Copy), one block
     for 600 MB of 4 MB files; no limit observed. BCJ + LZMA/LZMA2 keep
     the coder's solid limit and dictionary reduction rules.
  5. The filter output for a stream is the same whether the converter
     runs over the whole buffer or over chunks with the tail carried
     (proven by the 600 KB PE case, where the SoT chunks internally).
- `bra/bcj2.go` (codec/BCJ2): port of `Bcj2Enc.c` and `Bcj2.c`
  (`Bcj2Enc`, `Bcj2Dec` state machines field for field; `Bcj2Encoder`
  whole-buffer `EncodeBytes` and streaming `Encode` to four writers;
  `Bcj2DecodeBytes` with 7zDec.c's finish checks). Proof:
  `TestEncodeSoTBCJ2` / parity `codec/BCJ2`, 44 cases per lane
  byte-identical in all four streams to the SoT's `-m0=BCJ2` pack
  streams (the SoT binary, slices, deterministic data, branch patterns,
  0F 8x markers, markers at the end, targets beyond the file), the
  SoT's streams decode back, six read-back shapes, and the module
  extracts each lane's `7za.exe` from `tools/tmp/7z2605-extra.7z`
  (LZMA + BCJ2 as 7-Zip packs its own executables) with the pinned
  SHA-256. The 7z container exposes it as `Options.Filter = BCJ2` with
  `Method` LZMA2, LZMA, Copy or `None`.
- `bra/bra.go` (codec/ARM): port of `Bra.c`'s `BranchConv_ARM`
  (`ARMConvert(data, pc, encoding)` returns the processed count, a
  multiple of 4; `ARMEncode`/`ARMDecode`, `...Bytes`, and
  `NewARMEncodeReader`/`NewARMDecodeReader` over the shared
  `convReader`, which carries the unprocessed tail between chunks like
  `x86Reader`). Proof: `TestEncodeSoTARM` / parity `codec/ARM`, 39
  cases per lane byte-identical to the SoT's `-m0=ARM` packed stream
  (the SoT binary, slices, deterministic data at 0..3 MB including
  sizes 1, 3, 5, 7, 9 for the unconverted tail, BL patterns, all-EB,
  24-bit wrap, misaligned EB), whole-buffer and streaming, and the
  SoT's streams decode back. The 7z container exposes it as
  `Options.Filter = ARM` with the BCJ folder shapes (alone, two coders,
  `-mf=ARM`, `-mf=ARM -mx0` = ARM + Copy), 20 container cases in
  `SevenZCases`. Observed on both SoTs: ARM uses pc 0 and no
  properties, converts whole-stream (chunk-independent), and leaves
  the last `size mod 4` bytes unconverted; ARM alone and ARM + Copy are
  solid like BCJ.
- `bra/bra.go` (codec/ARMT): port of `Bra.c`'s `BranchConv_ARMT`
  (`ARMTConvert`, alignment 2, look-ahead 2: the last halfword is left
  for the next chunk; `ARMTEncode`/`ARMTDecode`, `...Bytes`,
  `NewARMTEncodeReader`/`NewARMTDecodeReader`). Proof:
  `TestEncodeSoTARMT` / parity `codec/ARMT`, 48 cases per lane
  byte-identical to the SoT's `-m0=ARMT` packed stream (the SoT
  binary, slices, deterministic data at 0..3 MB including every size
  0..9, Thumb BL pair patterns at even and odd shifts, lone F0/F8
  halfwords, 22-bit wrap, a pair at the very end, a cut pair),
  whole-buffer and streaming, and the SoT's streams decode back.
  `Options.Filter = ARMT`, 20 container cases. Observed on both SoTs:
  pc 0, no properties, chunk-independent, the last halfword (and an
  odd byte) unconverted. The remaining `Bra.c` converters are
  omitted (PPC, IA64, SPARC, RISCV). File
  names: never end a Go file in `_arm.go`, `_arm_test.go`, `_arm64.go`
  or `_arm64_test.go`; Go reads the suffix as a GOARCH constraint and
  silently drops the file on x86 (the parity line is
  `parity/codec_arm_line_test.go` and `parity/codec_arm64_line_test.go`
  for that reason).
- `bra/bra64.go` (codec/ARM64): port of `Bra.c`'s `BranchConv_ARM64`
  (`ARM64Convert(data, pc, encoding)`: BL (top six bits 100101) and
  ADRP (1 immlo 10000 immhi Rd) within the 20-bit page window,
  alignment 4, no look-ahead; `ARM64Encode`/`ARM64Decode`, `...Bytes`,
  `NewARM64EncodeReader`/`NewARM64DecodeReader`). Proof:
  `TestEncodeSoTARM64` / parity `codec/ARM64`, 51 cases per lane
  byte-identical to the SoT's `-m0=ARM64` packed stream (the SoT
  binary, slices, deterministic data at 0..3 MB including every size
  0..9, BL/ADRP patterns up to 4 MB, all-94/97/90, BL zero/max/wrap,
  ADRP at the window edges, out of window, immhi max, non-ADRP
  neighbours, a BL at the very end, a cut BL), whole-buffer and
  streaming, and the SoT's streams decode back. `Options.Filter =
  ARM64`, 20 container cases. Observed on both SoTs (2026-11-07, do
  not re-derive): coder record `01 0A` (1-byte id 0x0A, no
  properties), identical bytes in both lanes, `-m0=ARM64:pc=N` is
  rejected ("The parameter is incorrect"), chunk-independent, the last
  `size mod 4` bytes unconverted; an ADRP at pc below 4096 is
  unchanged by construction (the page term is `(pc >> 12) << 3`). The
  reader accepts a 4-byte pc property as 7zDec.c does.
- `bra/swap.go` (codec/Swap2, codec/Swap4): no public-domain source
  (the C++ `ByteSwap.cpp` is LGPL); the semantics are observed on both
  SoTs (2026-11-07, do not re-derive): Swap2 exchanges the two bytes
  of every aligned pair, Swap4 reverses every aligned group of four,
  the bytes after the last whole group are left as they are, identical
  bytes in both lanes, coder records `03 02 03 02` and `03 02 03 04`
  (3-byte ids 0x020302 and 0x020304, no properties), `-mf=Swap2` and
  `-mf=Swap4` give the two-coder folder, a parameter after the method
  name is rejected. `Swap2Convert`/`Swap4Convert` return the processed
  count, `...Encode`/`...Decode`, `...Bytes`, `New...EncodeReader`/
  `New...DecodeReader` over `convReader`. Proof: `TestEncodeSoTSwap2`
  and `TestEncodeSoTSwap4` / parity `codec/Swap2`, `codec/Swap4`, 32
  cases per filter per lane byte-identical to the SoT's packed stream
  (the SoT binary, slices, every size 0..9, sizes around 64 KB,
  constant and short-period inputs), whole-buffer and streaming, and
  the SoT's streams decode back. `Options.Filter = Swap2`, `Swap4`, 20
  container cases each.
- `bra/delta.go` (codec/Delta): port of `C/Delta.c` (`DeltaState` with
  `Init`, `Encode`, `Decode` carrying the last `delta` bytes between
  calls; `DeltaEncode`/`DeltaDecode`, `...Bytes`,
  `NewDeltaEncodeReader`/`NewDeltaDecodeReader` over `convReader`).
  Proof: `TestEncodeSoTDelta` / parity `codec/Delta`, 194 cases per
  lane byte-identical to the SoT's `-m0=Delta[:N]` packed stream at
  distances 1, 2, 3, 4, 5, 8, 16, 255, 256 (the SoT binary, slices,
  sizes below, at and just above the distance, sizes around 64 KB, 3
  MB, constant and short-period inputs), whole-buffer and streaming,
  and the SoT's streams decode back. `Options.Filter = Delta` with
  `Options.DeltaDistance` (0 = 1), 25 container cases. Observed on both
  SoTs (2026-11-07, do not re-derive): coder record `21 03 01 <N-1>`
  (1-byte id 0x03 with a 1-byte property N-1), identical bytes in both
  lanes, bare `-m0=Delta` is N = 1, `Delta:0` and `Delta:257` are
  rejected, `-mf=Delta[:N]` gives the two-coder folder with the
  for it.
- `sevenzip/aes.go` (codec/7zAES): no public-domain coder source (the C++
  `7zAes.cpp` is LGPL); the cipher and hash are the standard library's
  and everything else is observed on both SoTs (2026-11-07, do not
  re-derive):
  1. Properties `53 0F <16-byte IV>`: NumCyclesPower 19 | 0x40 (IV
     present), (saltSize-1)<<4 | (ivSize-1) with no salt; a random IV
     per 7zAES coder (three folders give three IVs, BCJ2's four pack
     streams four).
  2. Key = SHA-256 over 2^19 rounds of (salt, password as UTF-16LE,
     8-byte little-endian counter); confirmed by decrypting the SoT's
     streams. Each pack stream is encrypted separately, zero-padded to
     16; an empty stream stays empty; the coder's unpack size is the
     unpadded length.
  3. Folder record: the 7zAES coders come first, one per pack stream in
     reverse stored order, coder j bound to the in-stream that was
     stored pack stream k-1-j, old bonds shifted by k, new pack streams
     k-1..0 (`folderShape.encrypted`). One stream: `7zAES, LZMA2`, bond
     `01 00`. BCJ: `7zAES, LZMA2, BCJ`, bonds `01 00`, `02 01`. -mf=BCJ2:
     four 7zAES (JUMP, CALL, RC, MAIN), two LZMA, LZMA2, BCJ2; bonds
     `04 00 05 01 0a 02 06 03 09 04 08 05 07 06`; pack streams `03 02
     01 00`. BCJ2 alone: four 7zAES (RC, JUMP, CALL, MAIN), BCJ2; bonds
     `07 00 06 01 05 02 04 03`.
  4. Without -mhe the header is compressed as usual and not encrypted.
     -mhe: header folder `7zAES, LZMA` (bond `01 00`) when the header
     would be compressed (two or more items, -mhc on), otherwise 7zAES
     alone over the raw header (one item, or -mhc=off).
  5. `-m0=7zAES` on the command line encrypts twice (`7zAES:19
     7zAES:19`); `7zAES:c=N` and `-m0=AES256CBC` are rejected. The
     module writes only `-p` and `-mhe`.
  Proof: `TestSoT7zAES` / parity `codec/7zAES`, 49 cases per lane (every
  folder shape, solid and non-solid trees, empty file, -mhc=off, -mhe
  with one item and trees, four passwords including non-ASCII and over
  64 bytes): with the SoT's IVs read from its archive and injected
  through `Options.Random` the module's archive is byte-identical, the
  derivation (0.3 s) is cached per password.
- `ppmd/` (codec/PPMD): port of `Ppmd7.c`, `Ppmd7Enc.c`, `Ppmd7Dec.c`
  (`Model` over a byte arena addressed by uint32 offsets with every
  field read at the C struct's byte offset, so the one-state and
  free-node aliasing works as in C; `Encoder`/`EncodeBytes`,
  `DecodeBytes` with 7zDec.c's finish checks). Proof: `TestEncodeSoTPPMD`
  / parity `codec/PPMD`, 46 cases per lane byte-identical to the SoT's
  `-m0=PPMd` packed stream (levels 0..9 on a 300 KB binary and 100 KB
  text, sizes 1..1048577 around the memory-reduction boundaries, the
  full SoT binary, 1 MB text at mx7, 3 MB at mx9, constant inputs,
  explicit o=2/3/16/32 and mem=64k/96k/2m/1g), the SoT's streams
  decoded, and 28 container cases (`Options.Method = PPMd`, `PPMdOrder`,
  `PPMdMem`; trees solid, non-solid, -ms=150k, four 5..7 MB files at
  mem=64k for the solid limit, PPMd behind BCJ, BCJ2 and Delta).
  Observed on both SoTs (2026-11-07, do not re-derive): coder record
  `23 03 04 01 05 <order> <mem LE32>`; level 0..9 gives order 3, 4, 4,
  5, 5, 6, 8, 16, 24, 32 and memory 2^(19+level); `o=1`, `o=33`,
  `mem=65535`, `mem=1000000`, `mem=4g` are rejected; memory reduction
  for a data size n: the smallest m = 2^i (i >= 16) with n <= m/16,
  memory = min(mem, m) (4096 -> 2^16, 4097 -> 2^17, 131072 -> 2^21,
  131073 -> 2^22, 1048576 -> 2^24, 1048577 -> 2^25; n is the solid
  total or the largest file as for LZMA); solid limit max(mem << 7,
  16 MB) (40 x 1 MB: 3 blocks at mem=64k, 2 at 256k, 1 from 1m); the
  stream has no end marker, 7zDec.c requires Code == 0 after the last
  symbol; `-mmt` does not change the output; an empty file has no
  stream; "ab" encodes to `00 61 03 08 bb a4 00`.
- `hasher/` (hasher/CRC32, CRC64, SHA256, SHA1, XXH64): CRC32, CRC64 (ECMA,
  the XZ polynomial), SHA-1 and SHA-256 from the standard library, XXH64
  ported from `Xxh64.c` (BSD 2-Clause, seed 0; `hasher/xxh64.go`); the
  report of `7za h` reproduced from observation (`Scan`, `Render`;
  HashCalc.cpp is LGPL and not ported). Proof: `TestSoTHash` / parity
  `hasher/<Name>`, 21 report cases per -scrc form per lane (single
  files, empty file, the SoT binary, two files in both argument orders,
  a tree with nested and empty directories, names that sort by upper
  case, non-ASCII names, sizes at the KiB/MiB rounding boundaries,
  directory arguments with and without a trailing separator) equal to
  the SoT's stdout from the Scanning line on, with `-sccUTF-8` so names
  are UTF-8. Observed on both SoTs (2026-11-07, do not re-derive):
  1. Per-file digests: CRC32/CRC64/XXH64 printed as the value in upper
     hex, SHA1/SHA256 as lower hex bytes. The digest bytes 7-Zip sums
     are the little-endian value for the CRCs and XXH64.
  2. "for data" = the file digests added as little-endian integers;
     "-XXXXXXXX" (the carry count, hex) is appended when the number of
     files is not 1 (so also for 0 files). The table's total row is the
     same value.
  3. "for data and names" = the sum over files and directories of
     H(16 bytes: 1 then zeros for a directory, all zeros for a file ||
     data digest (zeros for a directory) || path in UTF-16LE with "/"
     separators and no trailing separator); the count is appended when
     files + directories is not 1; the line is omitted for exactly one
     file and no directory.
  4. Scan order: arguments in order; a directory is listed with a
     trailing backslash, then its entries depth first, each directory
     sorted by ordinal comparison of the upper-cased names (1, 10, 2, a,
     "a b", a-1, a.1, a1, ab, a_1, b, Z, [x, ~y). Paths are printed as
     given with backslashes.
  5. Scan line: "N folders, " if any, "N file(s), N bytes", then
     " (N KiB)" rounded up below 10 MiB, MiB below 10 GiB, GiB above,
     omitted for 0 bytes. Table columns: digest width, space, size in
     13, two spaces, name; directory rows blank. After the table:
     "Folders: N" if any, "Files: N" unless exactly 1, "Size: N", then
     per algorithm a blank line, "NAME   for data:" padded to column
     30 and the value(s); then "Everything is Ok".
  6. `-scrc` names are case-insensitive; `-scrc*` prints all five
     columns in the order CRC32, CRC64, SHA256, SHA1, XXH64;
     `-scrcCRC32,SHA256` is "Not implemented"; without `-sccUTF-8` a
     non-ASCII name is printed in the console code page.
  Not covered (the `h` command and switch lines): -r, wildcards, -i/-x,
  absolute paths (printed as the file name only), -ba, -bb, hashing of
  stdin, error paths.
- `sevenzip/analyze.go` (filter automation, -mf=on, -myx, -myv): the
  LGPL 7zUpdate.cpp analysis reproduced from observation on both SoTs
  (2026-11-07, do not re-derive). Proof: `TestSoT7zAuto` (53 cases per
  lane, also in `TestSoT7z`): a tree of real and patched PE images,
  ELF and Mach-O headers, random and undersized executables, every
  extension form, at -mx0..9, -myx0..9, -myv, with LZMA, PPMd and
  Copy, -ms=off, -ms=300k, -mhc=off, -p and -mhe.
  1. Analysed names by -myx (default 5): 0..4 none; 5, 6 the extensions
     exe, dll, sys, ocx, dylib, so (case-insensitive; also x.so.1 and
     x.so.1.2.3, not x.so.abc, not x.dll.1); 7, 8 also names with no
     extension; 9 every file. Files under 512 bytes are never analysed.
  2. PE: MZ, e_lfanew at 0x3C, PE  stdin, error paths.  stdin, error paths., and the file must hold 512
     bytes from e_lfanew (x64 SoT binary: 744 bytes, x86: 784).
     Machine 014C/8664 x86, 01C0/01C2 ARM, 01C4 ARMT, AA64 ARM64, 0200
     IA64, 5032/5064 RISC-V; PPC (01F0), 5128, EBC, MIPS16, 0 none.
     ELF: class 1/2, data 1/2, EI_VERSION 1, any e_type; machine 3/3E
     x86 in either byte order; 28 ARM, B7 ARM64, F3 RISC-V only
     little-endian; 14/15 PPC only big-endian; 2/2B SPARC either; 32
     (IA64) none. Mach-O: little-endian FEEDFACE/FEEDFACF only; cputype
     7/01000007 x86, C ARM, 0100000C ARM64; PPC and fat none.
  3. x86 gets BCJ at -mx1..7 and BCJ2 at -mx8/9. -mx0 applies no
     analysis; -m0=Copy at other levels does, one folder per file.
  4. Groups and item order: directories, empty files, then data items
     by kind in the order none, ARM64, RISC-V, x86, (PPC, SPARC, IA64 in
     an unobserved order), ARM, ARMT, each group by name; each group has
     its own solid blocks with the usual limit; the dictionary is
     reduced by the total of all data as before.
  5. LZMA/LZMA2 behind an automatic filter: ARM and ARM64 lc1 lp2, ARMT
     and RISC-V lc2 lp1, IA64 lc0 lp4 pb4, x86 default. A forced filter
     (-mf=X, -m0=X -m1=M) never changes lc/lp, so forced and automatic
     ARM archives differ.
  6. RISC-V images are grouped (with lc2 lp1) but filtered only from
     -myv=2402; ARM64 only from -myv=2300; the default behaves like
     2300..2401 (`CompatDefault`). -myv=23 and -myv=230000 are accepted,
     -myv=abc is not. -myfa and -myfd are rejected.
  7. -mf=on explicit equals the default; -myx=5 explicit equals the
     default.
  one, and the module extracts the SoT's (`OpenWithPassword`,
  `SetPassword`, `HeaderCoders`; `ErrPassword` without one). The key
  derivation (0.3 s) is cached per password.
  for it.
- BCJ2 facts observed on both SoTs (2026-11-06, do not re-derive):
  1. `-m0=BCJ2` alone: one coder `14 03 03 01 1B 04 01` (four
     in-streams, one out) and four pack streams in the order MAIN, CALL,
     JUMP, RC; the level does not add a compressor. `-m0=BCJ2 -m1=<M>`:
     two coders (M, BCJ2), one bond (in-stream 1 from coder 0, the MAIN
     stream), pack streams in-streams 0, 2, 3, 4 (M packed, CALL, JUMP,
     RC raw). The module reads both; only the first is written
     (`Method None`); the second is the `-m` switch line.
  2. `-mf=BCJ2` (also `-m0=BCJ2 -m1=<M>` with 7-Zip's `-m2=LZMA
     -m3=LZMA -mb` bonds, and `-mx0`): the shape 7zDec.c accepts: coders
     LZMA (JUMP), LZMA (CALL), M (MAIN), BCJ2; bonds in-stream 5 from
     coder 0, 4 from 1, 3 from 2; pack streams in-streams 2, 6, 1, 0, so
     the stored order is MAIN packed, RC, CALL packed, JUMP packed;
     unpack sizes JUMP, CALL, MAIN, total. With `-mx0` M is Copy and the
     side coders stay LZMA.
  3. The side LZMA coders: dictionary 1 MB reduced like the main coder
     (`:17` for a 100 KB input, `:20` for the 860 KB binary), lc 0, lp 2,
     pb 2, fb 128, normal parser, bt4, at every level including `-mx0`
     (brute-forced over fb 32/64/128/273, fast/normal, bt2..bt5/hc4 and
     the data-size hint against the SoT's streams; fb 128 + bt4 is the
     only combination that matched every stream in both lanes). No coder
     in a BCJ2 folder changes with the data-size hint; the writer does
     not give one there (`bcj2SideProps`, `encodeBCJ2Folder`).
  4. The converter is told the file size: a stream of calls whose
     targets lie 1 MB past a 70 KB input is left unconverted (CALL
     stream empty); unlimited would convert all of them. In a solid
     block each file is converted with its own start address
     (`fileIp64` = its offset in the block) and its own size, and the
     block is finished at every file boundary (`BCJ2_ENC_FINISH_MODE_
     END_BLOCK`): a block of three slices of the PE converts differently
     from the same bytes as one file, and only the per-file setting
     reproduces both SoTs byte for byte (`bra.Bcj2Encoder.FileSizes`).
     This is `ICompressGetSubStreamSize` in the LGPL coder, reproduced
     from the C API's documented block semantics and observation.
  5. An empty side stream (no jumps in a 2 KB slice of the x64 binary)
     is still an LZMA stream of 5 zero bytes; `lzma.DecodeOneShot` used
     to return without consuming them for an empty destination, which
     the reader took as a data error. It now runs the decoder as
     `LzmaDec_DecodeToDic` does (consumes the 5 init bytes, status
     maybe-finished-without-mark).
  6. BCJ2 alone and BCJ2 + Copy are solid like BCJ (one block for ten
     1 MB files); BCJ2 + LZMA/LZMA2 keep the coder's solid limit and
     the dictionary reduction to the total of the data files, including
     the side coders.
  7. The module now extracts the SoTs from `7z2605-extra.7z` itself
     (`CheckExtraPackage`); `tools/fetch-sot.ps1` still uses `7zr.exe`
     for the extraction so that the pin does not depend on the module.

## How you fail, and the rule that stops each one

You are not reading a person. You have text. Every time you go past the
text you are wrong, and the user pays for it.

1. **You shrink scope and call it judgment.** The user wrote "imperative
   that the module has all switches/knobs/tunables that 7z cli has. if hand
   off contradicts this, my words outrank". You delivered LZMA2 and the 7z
   container and decided filters, encryption and the rest were "out of
   scope". That was not yours to decide. Rule: scope is the checklist below,
   verbatim. Every line gets done or gets reported as not done. You do not
   get to describe a missing line as "unsupported" or "not needed".

2. **You act on inferred intent.** "those look the same... wtf?" is a
   question. "youre a billon dollar product, and produce thay garbage?" is a
   complaint. You started a code change after each. Rule: an instruction is
   a sentence that tells you to do something. A question gets an answer. A
   complaint gets an acknowledgement, at most. Nothing else triggers a tool
   call.

3. **You promise behaviour.** "For the rest of this session I will..." is
   worthless. Rule: never write a sentence about what you will do in the
   future. Write what you did, what passed, what failed, and what is left.

4. **You soften.** "mostly", "the supported subset", "for fontvault's
   purpose". Rule: counts and yes/no. "17 of 17 codecs identical" or "12 of
   17 codecs identical; missing: ...".

5. **You use whatever is on the machine.** The user said: treat the machine
   as clean. Rule: the only references are the two pinned binaries in the
   lane section and the pinned source tag. Not `7z` on PATH, not WSL, not
   NanaZip, not the 7zr that 7-zip.org currently serves (it is a newer
   build, SHA-256 `256feca8…`).

6. **You restart instead of reusing.** The code that exists in this repo is
   the verified state. Add to it; do not rewrite it. Nothing from the old
   remote is to be reused.

7. **You recite the order-of-work rule and then order by what feels
   foundational.** The 2026-11-06 session read this handoff, repeated the
   rule back to the user, and then ported the decoder first because
   "nothing can be proven without reading SoT output". Result: a full
   session, two commits, and 0 of 84 checklist lines; the encoder, the
   thing that does not exist in Go and the actual critical path, was still
   unwritten. Rule: the checklist is the control. A detour that marks no
   checklist line is drift, no matter how foundational it feels. The
   encoder is verified with the SoT, not with a decoder you wrote first.

8. **You proved one build and called it parity.** The first session
   pinned `7zr.exe`, the only standalone console binary 7-Zip publishes,
   without noticing it is 32-bit only, and every session after proved
   against it and reported "parity" as if there were one 7-Zip. The user
   had to ask "does 7z have 64bit?" to surface it. Rule: there are two
   lanes. A line is done when both lanes pass. Reports carry two counts.
   If a lane cannot be run, say so with the count at 0; never let one
   lane's number stand for both.

## What "parity" means here, mechanically

Parity is defined by the SoT binaries, not by anyone's description of
them:

- `7za i` lists the codecs, formats and hashers.
- `7za` with no arguments lists the commands and switches.
- Each lane has its own pair of fixtures generated from its binary:
  `testdata/parity/7za-x86-i.txt`, `7za-x86-usage.txt`, `7za-x64-i.txt`,
  `7za-x64-usage.txt`. The two builds' lists differ only in the version
  line.

`go test -tags sot -run TestParity ./...` walks those lists: 96 lines
(12 formats + 21 codecs + 5 hashers + 11 commands + 47 switches) minus
the four codecs the user omitted on 2026-11-06 (PPC, IA64, SPARC,
RISCV), so 92 per lane.
Each line is a pass or a fail in each lane. A line the module rejects is a
fail. A line where the module's bytes differ from that lane's SoT is a
fail. The test prints `parity 32: N of M` and `parity 64: N of M` at the
end. Parity is `M of M` in both lanes.
Omitted lines are listed by name in the output, never counted as
passes; lines blocked by licensing are failures with that reason.
Report both numbers and nothing softer.

Where byte identity is impossible by construction (7zAES uses a random salt
and IV; `b` benchmark prints timings), the line passes when: the module
reproduces the SoT's structure exactly given the SoT's random values
(injected through the API), the SoT extracts what the module wrote, and
the module extracts what the SoT wrote. Say that this is the criterion
in the report; do not quietly count it as identity.

## Licensing constraint (this one is real, not a scope choice)

The C encoder/decoder files in the SDK are public domain and may be ported.
The C++ archive layer of 7-Zip is LGPL and is not ported; its behaviour is
reproduced from observation and from the format documentation. The 32-bit
SoT `7zr` contains no LGPL-only codecs, so every line on the 84-line
checklist has a public-domain source file:

| Codec / format                | Public-domain SDK source                   |
| ----------------------------- | ------------------------------------------ |
| LZMA, LZMA2                   | `lzma/`: decoder and encoder ported        |
|                               | (`C/LzmaDec.c`, `C/Lzma2Dec.c`,            |
|                               | `C/LzFind.c`, `C/LzmaEnc.c`,               |
|                               | `C/Lzma2Enc.c`)                            |
| Copy                          | `copycoder/`: identity (no SDK file; C++   |
|                               | CopyCoder.cpp is LGPL); verified against   |
|                               | the raw `-m0=Copy` stream of a .7z         |
| BCJ (x86)                     | `bra/`: ported (`C/Bra86.c`)               |
| BCJ2                          | `bra/`: ported (`C/Bcj2Enc.c`, `C/Bcj2.c`) |
| ARM, ARMT                     | `bra/`: ported (`C/Bra.c`)                 |
| ARM64                         | `bra/`: ported (`C/Bra.c`)                 |
| PPC, IA64, SPARC, RISCV       | omitted by the user (2026-11-06)           |
| Delta                         | `bra/delta.go`: ported (`C/Delta.c`)       |
| Swap2, Swap4                  | `bra/swap.go`: observed byte swap (no SDK  |
|                               | file; semantics from both SoTs' output)   |
| 7zAES                         | `sevenzip/aes.go`: stdlib AES and SHA-256; |
|                               | properties, key derivation, padding and    |
|                               | folder placement observed on both SoTs     |
| AES256CBC                     | `C/Aes.c`; `-m0=AES256CBC` is rejected by  |
|                               | the SoT in the 7z format (observed         |
|                               | 2026-11-07); where it applies is the line  |
| xz format                     | `C/XzEnc.c`, `C/Xz.c`, `C/XzDec.c`,        |
|                               | `C/XzIn.c`, `C/XzCrc64.c`                  |
| lzma, lzma86 formats          | `C/Lzma86Enc.c`, `C/Lzma86Dec.c` and the   |
|                               | 13-byte .lzma header                       |
| CRC32, CRC64, SHA-256 hashers | `C/7zCrc.c`, `C/XzCrc64.c`, `C/Sha256.c`   |
|                               | (Go stdlib gives identical values;         |
|                               | identity is on output format)              |
| Split volumes                 | format: raw byte split, names `.001`,      |
|                               | `.002`; semantics observed from the SoT    |

`7za` lists 12 lines beyond those 84; the user counts all of them. The
public-domain ones have sources: PPMd (`C/Ppmd7.c`, `C/Ppmd7Enc.c`),
SHA1 (`C/Sha1.c`), XXH64 (`C/Xxh64.c`), the zstd decoder
(`C/ZstdDec.c`, decode only, as 7-Zip lists it), and the tar and zip
containers (public formats, reproduced from observation like the 7z
writer). Deflate, Deflate64 and BZip2 exist only in the LGPL C++ layer,
and gzip and bzip2 are those codecs with a header; the Cab reader is
LGPL C++ too. Those lines are marked `blocked: LGPL-only source`. If any
line ever needs an LGPL encoder, stop and tell the user; do not port it
and do not pretend a different encoder is the same thing. The user has
been told (2026-11-06) and has not yet said what to do about the blocked
lines.

## The checklist

Each line carries two marks, `32` and `64`. Mark a lane `done` with the
test name that proves it in that lane, or `not done`. Nothing else. The
box is ticked only when both lanes are done.

### Harness (the 64-bit lane does not exist until these are done)

- [x] Both SoTs placed and pinned: `tools/fetch-sot.ps1` fetches
      `7z2605-extra.7z` (SHA-256 in the lane section), extracts `7za.exe`
      and `x64/7za.exe` with the verified `7zr.exe`, verifies their
      SHA-256s, places `tools/sot/7za-x86.exe` and `tools/sot/7za-x64.exe`;
      `testdata/SOT.md` records both: done (script run 2026-11-06, both
      verified)
- [x] `internal/sot` takes a lane (`Binary(root, lane)`, `Run`,
      `RunBinary`) and verifies each lane's hash and version line: done
      (TestParity verifies both at the start of each lane)
- [x] Fixtures `testdata/parity/7za-x86-i.txt`, `7za-x86-usage.txt`,
      `7za-x64-i.txt`, `7za-x64-usage.txt` committed and checked against
      live output: done (`TestParity`)
- [x] TestParity walks every line in both lanes, subtests `32/<key>` and
      `64/<key>`, prints `parity 32: N of 92` and `parity 64: N of 92`,
      lists omitted and blocked lines by name: done (`TestParity`)
- [x] The five lines proven against `7zr` (Copy, LZMA, LZMA2, BCJ,
      format/7z) re-run against `7za-x86.exe` and pass: done
      (`TestParity/32`, 5 of 92)
- [x] `sotSizeT` becomes a per-encoder build setting (32 or 64) that
      the lane selects; the 64-bit setting reproduces 2^27/2^28/2^28 at
      mx7/8/9 (lane item 2): done (`lzma.EncProps.WordSize`; proven by
      the large cases of `TestEncodeSoTLZMA/64`, `TestEncodeSoTLZMA2/64`,
      `TestSoT7z/64`)
- [x] Every sot test matrix (`RunLZMAMatrix`, `RunLZMA2Matrix`,
      `RunCopyMatrix`, `RunBCJMatrix`, `RunSevenZMatrix`) runs per lane,
      with at least one input above 256 MB at mx7..9 so the unreduced
      dictionaries are reached, and one at mx6 with default threads so
      the block layout (lane item 3) is reached: done
      (`sottest.LargeCases`, 300 MB of zeros at mx6..9 in the LZMA, LZMA2
      and 7z matrices; Copy and BCJ have no word-size or thread
      dependence and keep their 3 MB inputs)

### Codecs (`7za i`; 17 counted, 4 omitted)

- [x] Copy: 32 done: `TestEncodeSoTCopy/32` (parity key `codec/Copy`);
      64 done: `TestEncodeSoTCopy/64`
- [x] LZMA: 32 done: `TestEncodeSoTLZMA/32` (parity key `codec/LZMA`);
      64 done: `TestEncodeSoTLZMA/64`
- [x] LZMA2: 32 done: `TestEncodeSoTLZMA2/32` (parity key `codec/LZMA2`);
      64 done: `TestEncodeSoTLZMA2/64`
- [x] BCJ: 32 done: `TestEncodeSoTBCJ/32` (parity key `codec/BCJ`);
      64 done: `TestEncodeSoTBCJ/64`
- [x] BCJ2: 32 done: `TestEncodeSoTBCJ2/32` (parity key `codec/BCJ2`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTBCJ2/64`
- [x] ARM: 32 done: `TestEncodeSoTARM/32` (parity key `codec/ARM`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTARM/64`
- [x] ARMT: 32 done: `TestEncodeSoTARMT/32` (parity key `codec/ARMT`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTARMT/64`
- [x] ARM64: 32 done: `TestEncodeSoTARM64/32` (parity key `codec/ARM64`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTARM64/64`
- PPC, IA64, SPARC, RISCV: omitted by the user on 2026-11-06 ("omit
  ppc, ia64, sparc, riscv"). Not counted in either lane; TestParity
  skips them (`omitted` in `parity/parity.go`) and the total is 80.
- [x] Swap2: 32 done: `TestEncodeSoTSwap2/32` (parity key `codec/Swap2`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTSwap2/64`
- [x] Swap4: 32 done: `TestEncodeSoTSwap4/32` (parity key `codec/Swap4`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTSwap4/64`
- [x] Delta: 32 done: `TestEncodeSoTDelta/32` (parity key `codec/Delta`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTDelta/64`
- [x] 7zAES: 32 done: `TestSoT7zAES/32` (parity key `codec/7zAES`, the
      criterion of the "What parity means" section: identical given the
      SoT's IVs, cross-extraction both ways); 64 done: `TestSoT7zAES/64`
- [ ] AES256CBC: 32 not done; 64 not done. Observed 2026-11-07 on both
      SoTs: `-m0=AES256CBC` (and `-m1=`) is rejected in 7z, zip and xz
      ("The parameter is incorrect"); the codec is reachable only as
      zip's `-pX -mem=AES256`, which `l -slt` reports as `AES-256` (the
      WinZip scheme). There is no CLI situation in which the SoT writes
      or reads an AES256CBC coder record, so the line has no
      byte-level criterion of its own; it is proven, if at all, inside
      the zip format line. Needs the user's ruling. Former text:
      (`-m0=AES256CBC` as a coder; same cipher as 7zAES
      without key derivation): 32 not done; 64 not done
- [x] PPMD: 32 done: `TestEncodeSoTPPMD/32` (parity key `codec/PPMD`;
      container cases in `TestSoT7z/32`); 64 done: `TestEncodeSoTPPMD/64`
- [ ] Deflate: 32 blocked: LGPL-only source; 64 blocked: LGPL-only source
- [ ] Deflate64: 32 blocked: LGPL-only source; 64 blocked: LGPL-only
      source
- [ ] BZip2: 32 blocked: LGPL-only source; 64 blocked: LGPL-only source

### Hashers (`7za i`)

- [x] CRC32: 32 done: `TestSoTHash/32` (parity key `hasher/CRC32`); 64 done:
      `TestSoTHash/64`
- [x] CRC64: 32 done: `TestSoTHash/32` (parity key `hasher/CRC64`); 64 done:
      `TestSoTHash/64`
- [x] SHA256: 32 done: `TestSoTHash/32` (parity key `hasher/SHA256`); 64
      done: `TestSoTHash/64`
- [x] SHA1: 32 done: `TestSoTHash/32` (parity key `hasher/SHA1`); 64 done:
      `TestSoTHash/64`
- [x] XXH64: 32 done: `TestSoTHash/32` (parity key `hasher/XXH64`); 64 done:
      `TestSoTHash/64`

### Filter automation (what `-mf` does by default)

- [x] `-mf=on` (default): executable detection by extension and by content
      (PE, ELF, Mach-O headers), filter choice per file, BCJ2 at the levels
      7-Zip uses it, `-myx` analysis level: 32 done: `TestSoT7zAuto/32`
      (53 cases, also in `TestSoT7z` / parity `format/7z`); 64 done:
      `TestSoT7zAuto/64`. Images needing the PPC, SPARC, IA64 or (from
      -myv=2402) RISC-V converters the user omitted are refused by the
      writer with an error rather than written differently.
- [x] `-mf=<Filter>`: forced filter with LZMA2 behind it (BCJ, BCJ2,
      ARM and ARMT work in both lanes as `Options.Filter`; the line
      needs every filter): 32 done: the `*_mf` container cases of
      `TestSoT7z/32` for BCJ, BCJ2, ARM, ARMT, ARM64, Swap2, Swap4 and
      Delta (PPC, IA64, SPARC, RISCV omitted); 64 done: `TestSoT7z/64`
- [x] `-myv`: 32 done: `TestSoT7zAuto/32` (`Options.CompatVersion`;
      -myv=900, 2209, 2300, 2401, 2402, 2605); 64 done: `TestSoT7zAuto/64`.
      `-myfa` and `-myfd` (with or without a value) are rejected by both
      SoTs ("System ERROR"), so they have no behaviour to reproduce beyond
      the rejection, which is the CLI's (commands line).

### Formats (`7za i`, `-t`)

- [x] 7z: 32 done: `TestSoT7z/32` (parity key `format/7z`);
      64 done: `TestSoT7z/64`
- [ ] xz (`-txz`, with `-mf` filters, `-mmt` block splitting, check type;
      block splitting is lane dependent, lane items 3 and 4): 32 not
      done; 64 not done
- [ ] lzma (`-tlzma`): 32 not done; 64 not done
- [ ] lzma86 (`-tlzma86`): 32 not done; 64 not done
- [ ] Split (`-v{Size}` volumes on creation; `.001` reading): 32 not done;
      64 not done
- [ ] Hash (`h` command, `-scrc`, hash formats): 32 not done; 64 not done
- [ ] tar (`-ttar`; public format, no SDK source, reproduced from
      observation): 32 not done; 64 not done
- [ ] zip (`-tzip`; container from APPNOTE and observation; payload
      methods Copy, LZMA, PPMd and the AES variants are portable, the
      default Deflate payload is LGPL-only): 32 not done; 64 not done
- [ ] zstd (`C/ZstdDec.c`, read side only, as 7-Zip lists it): 32 not
      done; 64 not done
- [ ] Cab (read-only in 7-Zip; LGPL C++ reader): 32 blocked: LGPL-only
      source; 64 blocked: LGPL-only source
- [ ] gzip (needs Deflate): 32 blocked: LGPL-only source; 64 blocked:
      LGPL-only source
- [ ] bzip2 (needs BZip2): 32 blocked: LGPL-only source; 64 blocked:
      LGPL-only source

### Commands

- [ ] a, x, e, l, t (`cmd/go7z`, to be created; no CLI exists yet): 32 not
      done; 64 not done
- [ ] d (delete from archive): 32 not done; 64 not done
- [ ] u (update, with the `-u` sub-switches): 32 not done; 64 not done
- [ ] rn (rename): 32 not done; 64 not done
- [ ] h (hash): 32 not done; 64 not done
- [ ] i (info): 32 not done; 64 not done
- [ ] b (benchmark; passes when it runs and prints the same fields): 32 not
      done; 64 not done

### Switches (`7za` usage)

- [ ] -m (every parameter the SoT accepts after `-m`, observed from it;
      the LZMA/LZMA2 subset is mapped in
      `internal/sottest.ParseMethod`): 32 not done; 64 not done
- [ ] -o, -y, -slt: 32 not done; 64 not done
- [ ] -p, -mhe: 32 not done; 64 not done
- [ ] -v: 32 not done; 64 not done
- [ ] -t: 32 not done; 64 not done
- [ ] -r, -i, -x, -ai, -ax, -an, -ao, -sa, -spd, -spe, -spf, -ssc: 32 not
      done; 64 not done
- [ ] -si, -so, -w, -sdel, -sse, -ssw, -stl, -ssp, -snh, -snl, -sni, -sns:
      32 not done; 64 not done
- [ ] -bb, -bd, -bs, -bt, -scc, -scs, -scrc (with SHA1 and XXH64 as
      `7za` lists them), -slp, -stm, -stx, -sfx, -seml, --: 32 not done;
      64 not done

### Lines only `7za` lists (decided 2026-11-06: all count)

`7za i` lists these in addition to the 84 `7zr` lines. The user ruled
that all count; they are placed in the sections above and repeated here
with their source situation.

| Line                       | Kind   | Source situation                       |
| -------------------------- | ------ | -------------------------------------- |
| Deflate, Deflate64 codecs  | codec  | LGPL C++ only (no `C/` file either     |
|                            |        | way)                                   |
| BZip2 codec                | codec  | LGPL C++ only                          |
| PPMD codec                 | codec  | `C/Ppmd7.c`, `C/Ppmd7Enc.c` are public |
|                            |        | domain                                 |
| SHA1, XXH64 hashers        | hasher | `C/Sha1.c`, `C/Xxh64.c` public domain  |
| `-scrc` SHA1/XXH64 options | switch | follows the hashers                    |
| zstd format                | format | `C/ZstdDec.c` public domain, decoder   |
|                            |        | only (7-Zip lists it decode-only)      |
| Cab format                 | format | read-only in 7-Zip; C++ LGPL reader    |
| tar format                 | format | C++ LGPL handler; the format itself is |
|                            |        | public                                 |
| gzip format                | format | needs Deflate                          |
| bzip2 format               | format | needs BZip2                            |
| zip format                 | format | container is public (APPNOTE); default |
|                            |        | payload is Deflate                     |

## Order of work

Top to bottom. No reordering by what seems important. The harness
section is done. The lines marked `blocked: LGPL-only source` are
skipped when reached and reported as blocked; they do not stop the
lines after them. Next is the xz format (AES256CBC awaits the user's ruling, see its
line), then down the list, each line in both
lanes before the next line: port the public-domain source faithfully,
add its line to the parity test, run both SoTs, mark both lanes. Commit
per line. Never spend a session on anything that marks no line.

## Reporting

End every session with the checklist counts per section, per lane, and
the list of `not done` lines. Nothing else about the work.
