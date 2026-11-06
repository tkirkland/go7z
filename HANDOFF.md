# Handoff: parity with the 7-Zip 26.05 oracles, 32-bit and 64-bit

Written by the Claude that built go7z on 2026-11-04/05, updated by the
deepseek-v4-pro session of 2026-11-06, by the Claude Fable 5.1 session of
2026-11-06 that ported the encoder, and again by the Claude Fable 5.1
session of 2026-11-06 that ported BCJ and then, on the user's decision,
split the work into two lanes. Each update integrates what that session
actually produced, and what the user established about why handoffs
keep failing.

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

Lane 32: `tools/oracle/7zr.exe`, release tag `26.05` of
github.com/ip7z/7zip, asset `7zr.exe`, SHA-256
`9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7`,
version line `7-Zip (r) 26.05 (x86) : Igor Pavlov : Public domain :
2026-10-21`.

Lane 64: `x64/7za.exe` from the same release's asset `7z2605-extra.7z`
(asset SHA-256
`f27a8f103c84785026edcba1f67faf1357225df9d19ddb0b7760d55947141bc7`; a
copy is at `tools/tmp/7z2605-extra.7z`), to be placed as
`tools/oracle/7za-x64.exe`, SHA-256
`7ddf0a3bc451e166679296be630d6f0573eb386159c04184761c43020c484291`,
version line `7-Zip (a) 26.05 (x64) : Copyright (c) 1999-2026 Igor Pavlov
: 2026-10-21`.

The same package also holds the 32-bit `7za.exe` (SHA-256
`357929ec748d00728c64dd2e7aa0069258f40847c1410014bb60d22eb9ec75d5`) and
`arm64/7za.exe` (SHA-256
`86a2064dfe2a362f03e3c95e577cab88a9d2caaca9e442520046a050044d2d4d`).
The 32-bit `7za.exe` writes the same bytes as `7zr.exe` (checked: the
600 KB PE at mx1/5/9, identical archives), so the 32-bit lane keeps
`7zr.exe`. The ARM64 build is not a lane; the user has not asked for it.

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
   keys this on `oracleSizeT` in `lzma/lzmaenc.go` (4 today); it has to
   become a per-encoder setting chosen by the lane.
3. The default LZMA2 block layout differs at large inputs even with the
   same dictionary: 300 MB of zeros at mx6 gives different bytes with
   default threads but identical bytes with `-mmt1` and with `-mmt2`;
   at mx5 (300 MB) and at every level on 64 MB the default is identical.
   That is the C++ layer limiting block threads by memory on x86. The
   32-bit "default = -mmt1 = -mmt2" fact below holds for the inputs it was
   observed on; on the 64-bit lane the default thread count has to be
   reproduced by observation at mx6 and above on inputs of hundreds of
   MB.
4. xz: 300 MB of zeros at mx1 and mx5 (default and `-mmt1`) is identical
   in both builds; mx9 differs (the dictionary, item 2: 32-bit 45932
   bytes, 64-bit 46040).
5. The 64-bit `7za` lists more than `7zr` does. `7za i` adds formats
   Cab, bzip2, gzip, tar, zip, zstd; codecs BZip2, Deflate64, Deflate,
   PPMD; hashers SHA1, XXH64; and `-scrc` gains `SHA1|XXH64`. The
   commands and the other 46 switches are identical. Those 12 extra
   lines are listed at the end of the checklist and are not counted
   until the user decides on them, because four of them (Deflate,
   Deflate64, BZip2, and the gzip/bzip2 formats that need them) have
   LGPL-only encoders and the licensing rule below says to stop and ask.

## Session state (2026-11-06, after the BCJ session and the lane decision)

- Repo: branch `main`, remote `origin` = github.com/tkirkland/go7z
  (public). History before `e5c143d` on the old remote is not a
  reference. Start from zero means this repo.
- Go 1.27.3 is installed at `C:\Users\Tony\sdk\go`. In git-bash prefix
  commands with `export PATH="/c/Users/Tony/sdk/go/bin:$PATH"` if
  `go version` fails.
- Pinned source: `reference/7zip` = git tag `26.05`
  (commit `b88c6bc09339de32f7d18bbab900686b244f42ba`), gitignored.
- `tools/fetch-oracle.ps1` fetches and verifies the 32-bit oracle only.
  The 64-bit oracle is not fetched, not placed, not hashed by any code
  yet; `testdata/ORACLE.md` records only the 32-bit provenance. That is
  the first harness line below.
- Parity fixtures committed: `testdata/parity/7zr-i.txt` (1072 bytes),
  `testdata/parity/7zr-usage.txt` (2902 bytes), generated from the
  32-bit oracle. No 64-bit fixtures exist yet.
- TestParity: package `parity`, `//go:build oracle`. It walks 84 lines
  (6 formats + 17 codecs + 3 hashers + 11 commands + 47 switches) against
  the 32-bit oracle only, verifies that oracle's hash and that the
  fixtures equal its live output, and prints `parity: N of M`. A line is
  registered by adding its key to the `checks` map in an `init()` of a
  `parity/*_test.go` file (see `parity/codec_lzma_test.go`). It has no
  lane dimension yet. Current baseline: **32-bit lane 5 of 84; 64-bit
  lane 0 of 84 (no harness)**.
- `internal/oracle`: `Binary(root)` finds and hash-verifies `7zr.exe`;
  `Run`, `RunBinary`. Single oracle, no lane parameter.
- Commits: `e5c143d` (harness, fixtures, oracle verifier),
  `7eeb1b3` (LZMA/LZMA2 decoders), `49f8072` (LZMA encoder, codec/LZMA),
  `998f516` (LZMA2 encoder, codec/LZMA2), `106f608` (Copy coder),
  `6218c03` (7z container), `3f3a43c` (module path), `42fabb6`..`de800ff`
  (IDE files, README, LICENSE, perf test), `c8e1e39` (BCJ filter,
  `bra/`, container bonds), then this handoff revision.
- `lzma/` package:
  - decoders: `lzmadec.go`, `lzma2dec.go` (`DecodeOneShot`,
    `Lzma2DecodeOneShot`), `lzma86.go` (`DecodeLzma86`).
  - encoders: `lzfind.go` (port of `LzFind.c`: bt2/bt3/bt4/bt5/hc4/hc5),
    `lzmaenc.go` (port of `LzmaEnc.c`: `EncProps`, `Encoder`, `EncodeBytes`,
    `Encoder.Encode(w, r)`, `Encoder.WriteProperties`),
    `lzma2enc.go` (port of `Lzma2Enc.c`: `Lzma2EncProps`, `Lzma2Encoder`,
    `Encode(w, r)`, `EncodeBytes`, `WriteProperties`, block splitting).
  - The two places the C code depends on `sizeof(size_t)` (default dict
    per level, `kNumLogBits`) follow the 32-bit build: `oracleSizeT = 4`
    in `lzmaenc.go`. 32-bit dict per level, 7z and xz: mx1 2^18, mx2
    2^20, mx3 2^22, mx4 2^24, mx5 2^25, mx6..9 2^26, always reduced to
    the input size (`reduceSize`). 64-bit: the same through mx6, then
    2^27, 2^28, 2^28 (observed, lane item 2).
  - Three files (`lzfind.go`, `lzma2enc.go`, `lzmaenc.go`) are not
    gofmt-clean. They were left as they are; formatting them is a
    no-behaviour-change commit if anyone wants it.
- `internal/oracletest/`: helpers shared by oracle tests and parity checks:
  `DeterministicData`, `TextLike`, `BranchPattern`, `OracleExe` (the
  32-bit oracle's own bytes as a real PE input), `OracleXz`,
  `XzSingleBlock`, `SevenZRawStream` (the raw packed stream of a
  single-file .7z starts at offset 32 and its length is the `Packed
  Size` of `l -slt`), `ParseMethod`, `RunLZMAMatrix`, `RunLZMA2Matrix`,
  `RunCopyMatrix`, `RunBCJMatrix`, `SevenZCases(exe)`, `RunSevenZMatrix`.
  All of them run the 32-bit oracle through `oracle.Binary(root)`.
- Proof of the encoders on the 32-bit lane (all byte-identical):
  - `TestEncodeOracleLZMA` / parity `codec/LZMA`: 26 cases, raw LZMA
    streams from `.7z -m0=LZMA:<params>` with mf=bt2/bt3/bt4/bt5/hc4/hc5,
    a=0, fb=5/273, mc=1/1000, lc/lp/pb extremes, d=4k/16k, mt=1, levels
    1/3/5/7/9, sizes 1/100/4096/300000.
  - `TestEncodeOracleLZMA2` / parity `codec/LZMA2`: 42 cases, raw LZMA2
    streams from `.7z -m0=LZMA2:<params>` including `c=` block splitting
    (block threads and `-mmt1`), plus single-block `.xz` payloads at
    sizes 1..300000, levels 1..9.
  - `TestDecodeOracleXz`: 12 cases (decoder).
- Facts established with the 32-bit oracle (do not re-derive):
  1. The oracle's `-mmt1`, `-mmt2` and default output is byte-identical
     (9 inputs x levels, inputs up to a few MB), so `LzFind.c`
     (single-threaded) is the reference; `LzFindMt.c` is not needed for
     identity. At 300 MB and mx6+ the default differs between builds
     (lane item 3), so the thread default is a per-lane observation.
  2. `7zr a -tlzma` prints `System ERROR: Not implemented` (exit 2). The
     oracle cannot create `.lzma`; the lzma format line is read-side plus
     that same refusal on create. Whether `7za` x64 behaves the same is
     not observed.
  3. The oracle's `.xz` uses the CRC32 check by default; one block for
     inputs below the auto block size (4 x dict, clamped to 1 MB..256 MB).
     On a 300 MB zero file, mx1 and mx5 wrote multi-block xz with block
     sizes 1 MB and 128 MB; mx9 (64 MB dict, 256 MB blocks) wrote a single
     block with no size fields. That is the C++ layer limiting block
     threads by memory on x86; the xz line has to reproduce it by
     observation, per lane.
  4. In 7z, `-m0=LZMA2:c=N` sets the LZMA2 block size and reduces the
     dictionary to it; `lc+lp>4` is rejected for LZMA2 (as the SDK does).
  5. `ReduceSize` = input size and `SetDataSize` = input size reproduce
     the oracle for 7z and xz; for multi-block LZMA2 the per-block expected
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
  and bit vectors. Proof: `TestOracle7z` / parity `format/7z`, 89 cases
  byte-identical to the 32-bit oracle's archives (Copy, LZMA, LZMA2 at
  levels 1/5/9 and `-mx0`, sizes 1..2 MB, empty files and directories,
  nested trees, `-ms=off`, `-ms=1k`/`-ms=4m`, `-mhc=off`, `-mtc=on`,
  `-mtm=off`, `-mmt1`, name ordering, 31 BCJ cases), and the module reads
  every oracle archive back (names, sizes, CRCs, contents).
- Container facts observed on the 32-bit oracle (do not re-derive):
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
  `TestEncodeOracleBCJ` / parity `codec/BCJ`, 37 cases byte-identical to
  the raw packed stream of `-m0=BCJ` (the oracle binary itself as a real
  PE, slices of it, deterministic binary and text 0..3 MB, branch-opcode
  patterns, all-E8/E9/00/FF, levels 1/9), whole-buffer and streaming
  with uneven chunks, and the oracle's streams decode back. The 7z
  container exposes it as `Options.Filter = BCJ` with `Method` LZMA2,
  LZMA, Copy or `None` (filter alone).
- Filter facts observed on the 32-bit oracle (do not re-derive):
  1. `-m0=BCJ` alone: the folder's only coder is BCJ (`04 03 03 01 03`,
     no properties), packed size = unpacked size; the level does not add
     a compressor. `7zDec.c` rejects such a folder (first coder must be
     a main method); the module reads it anyway because the oracle does.
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
     (proven by the 600 KB PE case, where the oracle chunks internally).
- The executables inside `7z2605-extra.7z` are packed with LZMA + BCJ2
  (checked with `l -slt`), so the module cannot extract the 64-bit oracle
  itself until the BCJ2 line is done. The 32-bit oracle extracts it
  today; that is how the harness line gets the binary.

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
   "nothing can be proven without reading oracle output". Result: a full
   session, two commits, and 0 of 84 checklist lines; the encoder, the
   thing that does not exist in Go and the actual critical path, was still
   unwritten. Rule: the checklist is the control. A detour that marks no
   checklist line is drift, no matter how foundational it feels. The
   encoder is verified with the oracle, not with a decoder you wrote first.

8. **You proved one build and called it parity.** The first session
   pinned `7zr.exe`, the only standalone console binary 7-Zip publishes,
   without noticing it is 32-bit only, and every session after proved
   against it and reported "parity" as if there were one 7-Zip. The user
   had to ask "does 7z have 64bit?" to surface it. Rule: there are two
   lanes. A line is done when both lanes pass. Reports carry two counts.
   If a lane cannot be run, say so with the count at 0; never let one
   lane's number stand for both.

## What "parity" means here, mechanically

Parity is defined by the oracle binaries, not by anyone's description of
them:

- `7zr i` lists the codecs, formats and hashers (saved in
  `testdata/parity/7zr-i.txt`).
- `7zr` with no arguments lists the commands and switches (saved in
  `testdata/parity/7zr-usage.txt`).
- The 64-bit lane will have the same two fixtures from `7za-x64.exe`
  (`7za-x64-i.txt`, `7za-x64-usage.txt`), once the harness line is done.

`go test -tags oracle -run TestParity ./...` walks those lists: 84 lines
(6 formats + 17 codecs + 3 hashers + 11 commands + 47 switches), per lane.
Each line is a pass or a fail in each lane. A line the module rejects is a
fail. A line where the module's bytes differ from that lane's oracle is a
fail. The test prints `parity 32: N of M` and `parity 64: N of M` at the
end (today it prints one unlabelled `parity: N of M` for the 32-bit lane
only). Parity is `M of M` in both lanes. Report both numbers and nothing
softer.

Where byte identity is impossible by construction (7zAES uses a random salt
and IV; `b` benchmark prints timings), the line passes when: the module
reproduces the oracle's structure exactly given the oracle's random values
(injected through the API), the oracle extracts what the module wrote, and
the module extracts what the oracle wrote. Say that this is the criterion
in the report; do not quietly count it as identity.

## Licensing constraint (this one is real, not a scope choice)

The C encoder/decoder files in the SDK are public domain and may be ported.
The C++ archive layer of 7-Zip is LGPL and is not ported; its behaviour is
reproduced from observation and from the format documentation. The 32-bit
oracle `7zr` contains no LGPL-only codecs, so every line on the 84-line
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
| BCJ2                          | `C/Bcj2Enc.c`, `C/Bcj2.c`                  |
| PPC, IA64, ARM, ARMT,         | `C/Bra.c`, `C/BraIA64.c`                   |
| SPARC, ARM64, RISCV           |                                            |
| Delta                         | `C/Delta.c`                                |
| Swap2, Swap4                  | trivial byte swap (no SDK file;            |
|                               | semantics from `7zr` output)               |
| 7zAES, AES256CBC              | `C/Aes.c`, `C/Sha256.c`; key derivation as |
|                               | observed in the discarded repo's session   |
|                               | (SHA-256 over salt+password(UTF-16LE)+     |
|                               | counter, 2^19 rounds, salt 0 bytes, IV 16  |
|                               | bytes by default): re-verify against this  |
|                               | oracle before relying on it                |
| xz format                     | `C/XzEnc.c`, `C/Xz.c`, `C/XzDec.c`,        |
|                               | `C/XzIn.c`, `C/XzCrc64.c`                  |
| lzma, lzma86 formats          | `C/Lzma86Enc.c`, `C/Lzma86Dec.c` and the   |
|                               | 13-byte .lzma header                       |
| CRC32, CRC64, SHA-256 hashers | `C/7zCrc.c`, `C/XzCrc64.c`, `C/Sha256.c`   |
|                               | (Go stdlib gives identical values;         |
|                               | identity is on output format)              |
| Split volumes                 | format: raw byte split, names `.001`,      |
|                               | `.002`; semantics observed from the oracle |

The 64-bit `7za` lists 12 lines beyond those 84 (see the end of the
checklist). Deflate, Deflate64 and BZip2 exist only in the LGPL C++
layer. If any line ever needs an LGPL encoder, stop and tell the user; do
not port it and do not pretend a different encoder is the same thing.

## The checklist

Each line carries two marks, `32` and `64`. Mark a lane `done` with the
test name that proves it in that lane, or `not done`. Nothing else. The
box is ticked only when both lanes are done. Today no 64-bit lane has
run, so every box is open.

### Harness (the 64-bit lane does not exist until these are done)

- [ ] 64-bit oracle placed and pinned: `tools/fetch-oracle.ps1` fetches
      `7z2605-extra.7z` (SHA-256 in the lane section), extracts
      `x64/7za.exe` with the verified 32-bit oracle, verifies SHA-256
      `7ddf0a3b…484291`, places `tools/oracle/7za-x64.exe`;
      `testdata/ORACLE.md` records it: not done
- [ ] `internal/oracle` takes a lane (`Binary(root, lane)`, `Run`,
      `RunBinary`) and verifies the 64-bit hash and version line: not done
- [ ] Fixtures `testdata/parity/7za-x64-i.txt` and `7za-x64-usage.txt`
      committed and checked against live output like the 32-bit ones:
      not done
- [ ] TestParity walks every line in both lanes, subtests `32/<key>` and
      `64/<key>`, prints `parity 32: N of 84` and `parity 64: N of 84`:
      not done
- [ ] `oracleSizeT` becomes a per-encoder build setting (32 or 64) that
      the lane selects; the 64-bit setting reproduces 2^27/2^28/2^28 at
      mx7/8/9 (lane item 2): not done
- [ ] Every oracletest matrix (`RunLZMAMatrix`, `RunLZMA2Matrix`,
      `RunCopyMatrix`, `RunBCJMatrix`, `RunSevenZMatrix`) runs per lane,
      with at least one input above 256 MB at mx7..9 so the unreduced
      dictionaries are reached, and one at mx6 with default threads so
      the block layout (lane item 3) is reached: not done

### Codecs (`7zr i`)

- [ ] Copy: 32 done: `TestEncodeOracleCopy` (parity key `codec/Copy`);
      64 not done
- [ ] LZMA: 32 done: `TestEncodeOracleLZMA` (parity key `codec/LZMA`);
      64 not done
- [ ] LZMA2: 32 done: `TestEncodeOracleLZMA2` (parity key `codec/LZMA2`);
      64 not done
- [ ] BCJ: 32 done: `TestEncodeOracleBCJ` (parity key `codec/BCJ`);
      64 not done
- [ ] BCJ2: 32 not done; 64 not done
- [ ] PPC: 32 not done; 64 not done
- [ ] IA64: 32 not done; 64 not done
- [ ] ARM: 32 not done; 64 not done
- [ ] ARMT: 32 not done; 64 not done
- [ ] SPARC: 32 not done; 64 not done
- [ ] ARM64: 32 not done; 64 not done
- [ ] RISCV: 32 not done; 64 not done
- [ ] Swap2: 32 not done; 64 not done
- [ ] Swap4: 32 not done; 64 not done
- [ ] Delta: 32 not done; 64 not done
- [ ] 7zAES: 32 not done; 64 not done
- [ ] AES256CBC (`-m0=AES256CBC` as a coder; same cipher as 7zAES
      without key derivation): 32 not done; 64 not done

### Filter automation (what `-mf` does by default)

- [ ] `-mf=on` (default): executable detection by extension and by content
      (PE, ELF, Mach-O headers), filter choice per file, BCJ2 at the levels
      7-Zip uses it, `-myx` analysis level: 32 not done; 64 not done
- [ ] `-mf=<Filter>`: forced filter with LZMA2 behind it (BCJ works on
      the 32-bit lane as `Options.Filter`; the line needs every filter):
      32 not done; 64 not done
- [ ] `-myv`, `-myfa`, `-myfd`: 32 not done; 64 not done

### Formats (`7zr i`, `-t`)

- [ ] 7z: 32 done: `TestOracle7z` (parity key `format/7z`); 64 not done
- [ ] xz (`-txz`, with `-mf` filters, `-mmt` block splitting, check type;
      block splitting is lane dependent, lane items 3 and 4): 32 not
      done; 64 not done
- [ ] lzma (`-tlzma`): 32 not done; 64 not done
- [ ] lzma86 (`-tlzma86`): 32 not done; 64 not done
- [ ] Split (`-v{Size}` volumes on creation; `.001` reading): 32 not done;
      64 not done
- [ ] Hash (`h` command, `-scrc`, hash formats): 32 not done; 64 not done

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

### Switches (`7zr` usage)

- [ ] -m (every parameter the oracle accepts after `-m`, observed from it;
      the LZMA/LZMA2 subset is mapped in
      `internal/oracletest.ParseMethod`): 32 not done; 64 not done
- [ ] -o, -y, -slt: 32 not done; 64 not done
- [ ] -p, -mhe: 32 not done; 64 not done
- [ ] -v: 32 not done; 64 not done
- [ ] -t: 32 not done; 64 not done
- [ ] -r, -i, -x, -ai, -ax, -an, -ao, -sa, -spd, -spe, -spf, -ssc: 32 not
      done; 64 not done
- [ ] -si, -so, -w, -sdel, -sse, -ssw, -stl, -ssp, -snh, -snl, -sni, -sns:
      32 not done; 64 not done
- [ ] -bb, -bd, -bs, -bt, -scc, -scs, -scrc, -slp, -stm, -stx, -sfx,
      -seml, --: 32 not done; 64 not done

### Lines only the 64-bit oracle lists (user decision pending)

`7za i` on the 64-bit binary lists these in addition to the 84 above.
They are not counted in either lane until the user says whether they are
in scope. The source column is the fact that forces the question.

| Line                       | Kind   | Source situation                                    |
| -------------------------- | ------ | --------------------------------------------------- |
| Deflate, Deflate64 codecs  | codec  | LGPL C++ only (no `C/` file either way)             |
| BZip2 codec                | codec  | LGPL C++ only                                       |
| PPMD codec                 | codec  | `C/Ppmd7.c`, `C/Ppmd7Enc.c` are public domain       |
| SHA1, XXH64 hashers        | hasher | `C/Sha1.c`, `C/Xxh64.c` public domain               |
| `-scrc` SHA1/XXH64 options | switch | follows the hashers                                 |
| zstd format                | format | `C/ZstdDec.c` public domain, decoder only (7-Zip    |
|                            |        | lists it decode-only)                               |
| Cab format                 | format | read-only in 7-Zip; C++ LGPL reader                 |
| tar format                 | format | C++ LGPL handler; the format itself is public       |
| gzip format                | format | needs Deflate                                       |
| bzip2 format               | format | needs BZip2                                         |
| zip format                 | format | container is public (APPNOTE); default payload is   |
|                            |        | Deflate                                             |

## Order of work

Top to bottom. No reordering by what seems important. The harness section
comes first, because without it the 64-bit lane cannot mark anything.
Then the four lines already done on the 32-bit lane (Copy, LZMA, LZMA2,
BCJ) and format/7z get their 64-bit mark, which is where the mx7..9
dictionary difference and the mx6 block layout are proven. Then BCJ2 and
down the list, each line in both lanes before the next line: port the
public-domain source faithfully, add its line to the parity test, run
both oracles, mark both lanes. Commit per line. Never spend a session on
anything that marks no line.

## Reporting

End every session with the checklist counts per section, per lane, and
the list of `not done` lines. Nothing else about the work.
