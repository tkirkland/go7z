# Handoff: parity with the 7-Zip 26.05 oracle

Written by the Claude that built go7z on 2026-11-04/05, updated by the
deepseek-v4-pro session of 2026-11-06, and again by the Claude Fable 5.1
session of 2026-11-06 that ported the encoder. Each update integrates what
that session actually produced, and what the user established about why
handoffs keep failing.

Read this before touching anything. The first half is about how you fail.
The second half is the checklist. Do not skip the first half; it is the
reason the checklist exists.

## What this document is, and what it is not

This document is not control. It is context. You do not execute it; you
re-derive the task every round from the conversation window, and your own
prior about what a sensible engineer would do competes with every line
written here. Text can bias your next prediction. It cannot steer it.

The user is in a type-and-pray arrangement: preventive control does not
exist for this mechanism. The only controls are corrective and external —
the scoreboard below, discarding bad work, changing the provider. The user
watches the results, not the process; when you drift, the drift is
discovered after the fact, not stopped.

The screwdriver does not decide which screw. The user decides; you turn.
When you form an opinion about the order of work, that is the tool deciding,
and that is the failure. The checklist below is the user's hand on the
screwdriver. Do not grab the handle back.

## Session state (2026-11-06, after the encoder session)

- Repo: fresh git repo on branch `main`, no remote. The old remote
  `tkirkland/go7z` still exists on GitHub; it is not a reference and is not
  to be used. Start from zero means this repo, not that one.
- Go 1.27.3 is installed at `C:\Users\Tony\sdk\go`. It was added to the
  user PATH on 2026-11-06 but the tool shell did not see it; in git-bash
  prefix commands with `export PATH="/c/Users/Tony/sdk/go/bin:$PATH"` if
  `go version` fails.
- Oracle: `tools/oracle/7zr.exe`, SHA-256
  `9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7`, fetched
  from release tag `26.05` of github.com/ip7z/7zip (asset `7zr.exe`).
  `https://www.7-zip.org/a/7zr.exe` now serves a NEWER build
  (SHA-256 `256feca8…`); do not use it. `tools/fetch-oracle.ps1` fetches and
  verifies the pinned binary.
- Pinned source: `reference/7zip` = git tag `26.05`
  (commit `b88c6bc09339de32f7d18bbab900686b244f42ba`), gitignored.
- `tools/tmp/7z2605-extra.7z` (SHA-256
  `f27a8f103c84785026edcba1f67faf1357225df9d19ddb0b7760d55947141bc7`) holds
  `x64/7za.exe` for the 64-bit build-identity line.
- Parity fixtures committed: `testdata/parity/7zr-i.txt` (1072 bytes),
  `testdata/parity/7zr-usage.txt` (2902 bytes), generated from the verified
  oracle. `testdata/ORACLE.md` records the oracle provenance.
  `reference/`, `tools/oracle/` and `tools/tmp/` are gitignored; a fresh
  clone needs `tools/fetch-oracle.ps1` and a clone of the pinned source.
- TestParity: package `parity`, `//go:build oracle`. It walks 84 lines
  (6 formats + 17 codecs + 3 hashers + 11 commands + 47 switches), verifies
  the oracle hash and that the fixtures equal live oracle output, and prints
  `parity: N of M`. A line is registered by adding its key to the `checks`
  map in an `init()` of a `parity/*_test.go` file (see
  `parity/codec_lzma_test.go`). Current baseline: **4 of 84**.
- Commits: `e5c143d` (harness, fixtures, oracle verifier),
  `7eeb1b3` (LZMA/LZMA2 decoders), `49f8072` (LZMA encoder, codec/LZMA),
  `998f516` (LZMA2 encoder, codec/LZMA2), the handoff updates,
  `106f608` (Copy coder, `copycoder/`, codec/Copy), then the 7z container
  (`sevenzip/`, format/7z).
- `lzma/` package:
  - decoders: `lzmadec.go`, `lzma2dec.go` (`DecodeOneShot`,
    `Lzma2DecodeOneShot`), `lzma86.go` (`DecodeLzma86`).
  - encoders: `lzfind.go` (port of `LzFind.c`: bt2/bt3/bt4/bt5/hc4/hc5),
    `lzmaenc.go` (port of `LzmaEnc.c`: `EncProps`, `Encoder`, `EncodeBytes`,
    `Encoder.Encode(w, r)`, `Encoder.WriteProperties`),
    `lzma2enc.go` (port of `Lzma2Enc.c`: `Lzma2EncProps`, `Lzma2Encoder`,
    `Encode(w, r)`, `EncodeBytes`, `WriteProperties`, block splitting).
  - The two places the C code depends on `sizeof(size_t)` (default dict per
    level, `kNumLogBits`) follow the 32-bit oracle: `oracleSizeT = 4` in
    `lzmaenc.go`. Observed dict per level on the x86 oracle, 7z and xz:
    mx1 2^18, mx2 2^20, mx3 2^22, mx4 2^24, mx5 2^25, mx6..9 2^26, always
    reduced to the input size (`reduceSize`). The 64-bit build differs at
    mx7+ (that is the build-identity line, not this one).
- `internal/oracletest/`: helpers shared by oracle tests and parity checks:
  `DeterministicData`, `TextLike`, `OracleXz`, `XzSingleBlock` (strips the
  block check: the oracle's xz check is CRC32, 4 bytes), `SevenZRawStream`
  (the raw packed stream of a single-file .7z starts at offset 32 and its
  length is the `Packed Size` of `l -slt`), `ParseMethod` (7z `-m0=` method
  string to SDK props), `RunLZMAMatrix`, `RunLZMA2Matrix`.
- Proof of the encoders (all byte-identical to the oracle):
  - `TestEncodeOracleLZMA` / parity `codec/LZMA`: 26 cases, raw LZMA
    streams from `.7z -m0=LZMA:<params>` with mf=bt2/bt3/bt4/bt5/hc4/hc5,
    a=0, fb=5/273, mc=1/1000, lc/lp/pb extremes, d=4k/16k, mt=1, levels
    1/3/5/7/9, sizes 1/100/4096/300000.
  - `TestEncodeOracleLZMA2` / parity `codec/LZMA2`: 42 cases, raw LZMA2
    streams from `.7z -m0=LZMA2:<params>` including `c=` block splitting
    (block threads and `-mmt1`), plus single-block `.xz` payloads at
    sizes 1..300000, levels 1..9.
  - `TestDecodeOracleXz`: 12 cases (decoder).
- Facts established with the oracle this session (do not re-derive):
  1. The oracle's `-mmt1`, `-mmt2` and default output is byte-identical
     (9 inputs x levels), so `LzFind.c` (single-threaded) is the reference;
     `LzFindMt.c` is not needed for identity.
  2. `7zr a -tlzma` prints `System ERROR: Not implemented` (exit 2). The
     oracle cannot create `.lzma`; the lzma format line is read-side plus
     that same refusal on create.
  3. The oracle's `.xz` uses the CRC32 check by default; one block for
     inputs below the auto block size (4 x dict, clamped to 1 MB..256 MB).
     On a 300 MB zero file, mx1 and mx5 wrote multi-block xz with block
     sizes 1 MB and 128 MB; mx9 (64 MB dict, 256 MB blocks) wrote a single
     block with no size fields. That is the C++ layer limiting block
     threads by memory on x86; the xz line has to reproduce it by
     observation.
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
  one Copy/LZMA/LZMA2 coder; filters and BCJ2 return `ErrUnsupported` until
  their lines are done). `writer.go` (`NewWriter`, `AddPath`, `AddPathIn`,
  `Write`, `Create`, `Options`) is built from `DOC/7zFormat.txt` plus
  observation; there is no public-domain writer source. `number.go` has the
  variable-length number and bit vectors. Proof: `TestOracle7z` / parity
  `format/7z`, 58 cases byte-identical to the oracle's archives (Copy,
  LZMA, LZMA2 at levels 1/5/9 and `-mx0`, sizes 1..2 MB, empty files and
  directories, nested trees, `-ms=off`, `-ms=1k`/`-ms=4m`, `-mhc=off`,
  `-mtc=on`, `-mtm=off`, `-mmt1`, name ordering), and the module reads every
  oracle archive back (names, sizes, CRCs, contents).
- Container facts observed on the oracle (do not re-derive):
  1. Header layout: kHeader, MainStreamsInfo (PackInfo with PackPos 0;
     UnpackInfo with one coder per folder; SubStreamsInfo with
     kNumUnpackStream only when some folder has != 1 streams, kSize for all
     but the last stream of each folder, then kCRC all-defined for every
     stream; folder CRCs are never written), FilesInfo (kEmptyStream and
     kEmptyFile bit vectors when needed, never kAnti; kName; kCTime/kATime
     only with -mtc/-mta; kMTime unless -mtm=off; kWinAttrib; kEnd).
  2. kDummy padding before kName, each time property and kWinAttrib so that
     the property's data starts 16-, 8- and 4-byte aligned from the header
     start (rule in `hdr.skipToAligned`).
  3. Coder records: Copy `01 00` (1-byte id), LZMA `23 03 01 01 05 <5>`,
     LZMA2 `21 21 01 <1>`. Names are UTF-16LE with '/' separators (a
     backslash argument is stored as '/').
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
     no upper clamp observed. Copy is never solid. No file-count limit up to
     5000 files.
  7. The coder dictionary is reduced to the sum of all data file sizes when
     solid, and to the largest data file when `-ms=off`, never to the
     folder's own size. `SetDataSize` is the folder size.
  8. Attributes are the raw Win32 attributes; times are raw FILETIMEs.
- Critical path from here: BCJ and the other filters (`Bra86.c`,
  `Bra.c`, `BraIA64.c`, `Bcj2Enc.c`, `Delta.c`), each registered as a parity
  line the same way the codec lines are. The 7z container exposes them
  through `-m0=<Filter>` once the reader and writer support multi-coder
  folders (bonds); `readFolder` already parses bonds, `decodeFolder` and the
  writer do not yet build them.

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
   as clean. Rule: the only reference is the pinned release. Source: git tag
   `26.05` of github.com/ip7z/7zip. Oracle: `tools/oracle/7zr.exe`, SHA-256
   `9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7`, fetched
   by `tools/fetch-oracle.ps1`. Not `7z` on PATH, not WSL, not NanaZip, not
   the 7zr that 7-zip.org currently serves.

6. **You restart instead of reusing.** The code that exists in this repo is
   the verified state. Add to it; do not rewrite it. Nothing from the old
   remote is to be reused.

7. **You recite the order-of-work rule and then order by what feels
   foundational.** The 2026-11-06 session read this handoff, repeated the
   rule back to the user, and then ported the decoder first because
   "nothing can be proven without reading oracle output". Result: a full
   session, two commits, and 0 of 84 checklist lines; the encoder — the
   thing that does not exist in Go and the actual critical path — is still
   unwritten. The user then dismantled every proposed remedy. Rule: the
   checklist is the control. A detour that marks no checklist line is drift,
   no matter how foundational it feels. The encoder is verified with the
   oracle, not with a decoder you wrote first.

## What "parity" means here, mechanically

Parity is defined by the oracle binary, not by anyone's description of it:

- `7zr i` lists the codecs, formats and hashers (saved in
  `testdata/parity/7zr-i.txt`).
- `7zr` with no arguments lists the commands and switches (saved in
  `testdata/parity/7zr-usage.txt`).

`go test -tags oracle -run TestParity ./...` walks those lists: 84 lines
(6 formats + 17 codecs + 3 hashers + 11 commands + 47 switches). Each line
is a pass or a fail. A line the module rejects is a fail. A line where the
module's bytes differ from the oracle's is a fail. The test prints
`N of M` at the end. Parity is `M of M`. Report that number and nothing
softer. The baseline recorded in this repo is 4 of 84.

Where byte identity is impossible by construction (7zAES uses a random salt
and IV; `b` benchmark prints timings), the line passes when: the module
reproduces the oracle's structure exactly given the oracle's random values
(injected through the API), the oracle extracts what the module wrote, and
the module extracts what the oracle wrote. Say that this is the criterion
in the report; do not quietly count it as identity.

## Licensing constraint (this one is real, not a scope choice)

The C encoder/decoder files in the SDK are public domain and may be ported.
The C++ archive layer of 7-Zip is LGPL and is not ported; its behaviour is
reproduced from observation and from the format documentation. The oracle
binary `7zr` contains no LGPL-only codecs (no Deflate, BZip2, PPMd, ZSTD),
so every codec on the parity list has a public-domain source file:

| Codec / format                | Public-domain SDK source                   |
| ----------------------------- | ------------------------------------------ |
| LZMA, LZMA2                   | `lzma/`: decoder and encoder ported        |
|                               | (`C/LzmaDec.c`, `C/Lzma2Dec.c`,            |
|                               | `C/LzFind.c`, `C/LzmaEnc.c`,               |
|                               | `C/Lzma2Enc.c`)                            |
| Copy                          | `copycoder/`: identity (no SDK file; C++   |
|                               | CopyCoder.cpp is LGPL); verified against   |
|                               | the raw `-m0=Copy` stream of a .7z         |
| BCJ (x86)                     | `C/Bra86.c`                                |
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

If a future line ever needs an LGPL encoder, stop and tell the user; do not
port it and do not pretend a different encoder is the same thing.

## The checklist

Mark each line `done` with the test name that proves it, or `not done`.
Nothing else.

### Codecs (`7zr i`)

- [x] Copy: done: `TestEncodeOracleCopy` (parity key `codec/Copy`)
- [x] LZMA: done: `TestEncodeOracleLZMA` (parity key `codec/LZMA`)
- [x] LZMA2: done: `TestEncodeOracleLZMA2` (parity key `codec/LZMA2`)
- [ ] BCJ: not done
- [ ] BCJ2: not done
- [ ] PPC: not done
- [ ] IA64: not done
- [ ] ARM: not done
- [ ] ARMT: not done
- [ ] SPARC: not done
- [ ] ARM64: not done
- [ ] RISCV: not done
- [ ] Swap2: not done
- [ ] Swap4: not done
- [ ] Delta: not done
- [ ] 7zAES: not done
- [ ] AES256CBC (`-m0=AES256CBC` as a coder; same cipher as 7zAES
      without key derivation): not done

### Filter automation (what `-mf` does by default)

- [ ] `-mf=on` (default): executable detection by extension and by content
      (PE, ELF, Mach-O headers), filter choice per file, BCJ2 at the levels
      7-Zip uses it, `-myx` analysis level: not done
- [ ] `-mf=<Filter>`: forced filter with LZMA2 behind it: not done
- [ ] `-myv`, `-myfa`, `-myfd`: not done

### Formats (`7zr i`, `-t`)

- [x] 7z: done: `TestOracle7z` (parity key `format/7z`)
- [ ] xz (`-txz`, with `-mf` filters, `-mmt` block splitting, check type): not done
- [ ] lzma (`-tlzma`): not done
- [ ] lzma86 (`-tlzma86`): not done
- [ ] Split (`-v{Size}` volumes on creation; `.001` reading): not done
- [ ] Hash (`h` command, `-scrc`, hash formats): not done

### Commands

- [ ] a, x, e, l, t (`cmd/go7z`, to be created; no CLI exists yet): not done
- [ ] d (delete from archive): not done
- [ ] u (update, with the `-u` sub-switches): not done
- [ ] rn (rename): not done
- [ ] h (hash): not done
- [ ] i (info): not done
- [ ] b (benchmark; passes when it runs and prints the same fields): not done

### Switches (`7zr` usage)

- [ ] -m (every parameter the oracle accepts after `-m`, observed from it;
      the LZMA/LZMA2 subset is mapped in
      `internal/oracletest.ParseMethod`): not done
- [ ] -o, -y, -slt: not done
- [ ] -p, -mhe: not done
- [ ] -v: not done
- [ ] -t: not done
- [ ] -r, -i, -x, -ai, -ax, -an, -ao, -sa, -spd, -spe, -spf, -ssc: not done
- [ ] -si, -so, -w, -sdel, -sse, -ssw, -stl, -ssp, -snh, -snl, -sni, -sns: not done
- [ ] -bb, -bd, -bs, -bt, -scc, -scs, -scrc, -slp, -stm, -stx, -sfx,
      -seml, --: not done

### Build identity

- [ ] packed streams identical to the x86 oracle: not done
- [ ] verified against a 64-bit 7-Zip binary (none can be extracted without
      BCJ; becomes possible once BCJ is done: `7z2605-extra.7z` holds
      `x64/7za.exe`): not done

## Order of work

Top to bottom. No reordering by what seems important. Each line: port the
public-domain source faithfully, add its line to the parity test, run the
oracle test, mark the line. Commit per line. The encoder is done and marks
LZMA and LZMA2; Copy is marked from the raw packed stream; the 7z
container is done and marks the 7z format line; BCJ is next, then move
down. Never spend a session on anything that marks no line.

## Reporting

End every session with the checklist counts per section and the list of
`not done` lines. Nothing else about the work.
