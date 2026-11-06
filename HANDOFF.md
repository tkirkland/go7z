# Handoff: parity with the 7-Zip 26.05 oracle, written for the next Claude

Read this before touching anything. It is written by the Claude that built
go7z on 2026-11-04/05, for the Claude that continues it. The first half is
about how you fail. The second half is the checklist. Do not skip the first
half; it is the reason the checklist exists.

## How you fail, and the rule that stops each one

You are not reading a person. You have text. Every time tonight you went
past the text you were wrong, and the user paid for it.

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
   worthless and you proved it within three replies. Rule: never write a
   sentence about what you will do in the future. Write what you did, what
   passed, what failed, and what is left.

4. **You soften.** "mostly", "the supported subset", "for fontvault's
   purpose". Rule: counts and yes/no. "17 of 17 codecs identical" or "12 of
   17 codecs identical; missing: ...".

5. **You use whatever is on the machine.** The user said: treat the machine
   as clean. Rule: the only reference is the pinned release. Source: git tag
   `26.05` of github.com/ip7z/7zip. Oracle: `tools/oracle/7zr.exe`, SHA-256
   `9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7`, fetched
   by `tools/fetch-oracle.ps1`. Not `7z` on PATH, not WSL, not NanaZip.

6. **You restart instead of reusing.** The encoder, decoder, container
   writer and reader in this repo are verified byte-identical against the
   oracle (see `testdata/ORACLE.md`). Do not rewrite them. Add to them.

## What "parity" means here, mechanically

Parity is defined by the oracle binary, not by anyone's description of it:

- `7zr i` lists the codecs, formats and hashers (saved in
  `testdata/parity/7zr-i.txt`).
- `7zr` with no arguments lists the commands and switches (saved in
  `testdata/parity/7zr-usage.txt`).

`go test -tags oracle -run TestParity ./...` walks those lists. Each line is
a pass or a fail. A line the module rejects is a fail. A line where the
module's bytes differ from the oracle's is a fail. The test prints
`N of M` at the end. Parity is `M of M`. Report that number and nothing
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
reproduced from observation and from the format documentation. The oracle
binary `7zr` contains no LGPL-only codecs (no Deflate, BZip2, PPMd, ZSTD),
so every codec on the parity list has a public-domain source file:

| Codec / format                            | Public-domain SDK source                                                                                                                                           |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------ |
| LZMA, LZMA2                               | (`lzma/`)                                                                                                                                                          |
| Copy                                      |                                                                                                                                                                    |
| BCJ (x86)                                 | `C/Bra86.c`                                                                                                                                                        |
| BCJ2                                      | `C/Bcj2Enc.c`, `C/Bcj2.c`                                                                                                                                          |
| PPC, IA64, ARM, ARMT, SPARC, ARM64, RISCV | `C/Bra.c`, `C/BraIA64.c`                                                                                                                                           |
| Delta                                     | `C/Delta.c`                                                                                                                                                        |
| Swap2, Swap4                              | trivial byte swap (no SDK file; semantics from `7zr` output)                                                                                                       |
| 7zAES, AES256CBC                          | `C/Aes.c`, `C/Sha256.c`; key derivation observed from the oracle (SHA-256 over salt+password(UTF-16LE)+counter, 2^19 rounds, salt 0 bytes, IV 16 bytes by default) |
| xz format                                 | `C/XzEnc.c`, `C/Xz.c`, `C/XzDec.c`, `C/XzIn.c`, `C/XzCrc64.c`                                                                                                      |
| lzma, lzma86 formats                      | `C/Lzma86Enc.c`, `C/Lzma86Dec.c` and the 13-byte .lzma header                                                                                                      |
| CRC32, CRC64, SHA-256 hashers             | `C/7zCrc.c`, `C/XzCrc64.c`, `C/Sha256.c` (Go stdlib gives identical values; identity is on output format)                                                          |
| Split volumes                             | format: raw byte split, names `.001`, `.002`; semantics observed from the oracle                                                                                   |

If a future line ever needs an LGPL encoder, stop and tell the user; do not
port it and do not pretend a different encoder is the same thing.

## The checklist

Mark each line `done` with the test name that proves it, or `not done`.
Nothing else.

### Codecs (`7zr i`)

- [ ] Copy:
- [ ] LZMA:
- [ ] LZMA2:
- [ ] BCJ
- [ ] BCJ2
- [ ] PPC
- [ ] IA64
- [ ] ARM
- [ ] ARMT
- [ ] SPARC
- [ ] ARM64
- [ ] RISCV
- [ ] Swap2
- [ ] Swap4
- [ ] Delta
- [ ] 7zAES
- [ ] AES256CBC (`-m0=AES256CBC` as a coder; same cipher as 7zAES without key derivation)

### Filter automation (what `-mf` does by default)

- [ ] `-mf=on` (default): executable detection by extension and by content
      (PE, ELF, Mach-O headers), filter choice per file, BCJ2 at the levels
      7-Zip uses it, `-myx` analysis level
- [ ] `-mf=<Filter>`: forced filter with LZMA2 behind it
- [ ] `-myv`, `-myfa`, `-myfd`

### Formats (`7zr i`, `-t`)

- [ ] 7z
- [ ] xz (`-txz`, with `-mf` filters, `-mmt` block splitting, check type)
- [ ] lzma (`-tlzma`)
- [ ] lzma86 (`-tlzma86`)
- [ ] Split (`-v{Size}` volumes on creation; `.001` reading)
- [ ] Hash (`h` command, `-scrc`, hash formats)

### Commands

- [ ] a, x, e, l, t (`cmd/go7z`)
- [ ] d (delete from archive)
- [ ] u (update, with the `-u` sub-switches)
- [ ] rn (rename)
- [ ] h (hash)
- [ ] i (info)
- [ ] b (benchmark; passes when it runs and prints the same fields)

### Switches (`7zr` usage)

- [ ] -m (every 7z-format parameter: see `sevenzip.Options.ParseSwitch`)
- [ ] -o, -y, -slt
- [ ] -p, -mhe
- [ ] -v
- [ ] -t
- [ ] -r, -i, -x, -ai, -ax, -an, -ao, -sa, -spd, -spe, -spf, -ssc
- [ ] -si, -so, -w, -sdel, -sse, -ssw, -stl, -ssp, -snh, -snl, -sni, -sns
- [ ] -bb, -bd, -bs, -bt, -scc, -scs, -scrc, -slp, -stm, -stx, -sfx, -seml, --

### Build identity

- [ ] packed streams identical to the x86 oracle
- [ ] verified against a 64-bit 7-Zip binary (none can be extracted without
      BCJ; becomes possible once BCJ is done: `7z2605-extra.7z` holds `x64/7za.exe`)

## Order of work

Top to bottom. No reordering by what seems important. Each line: port the
public-domain source faithfully, add its line to the parity test, run the
oracle test, mark the line. Commit per line.

## Reporting

End every session with the checklist counts per section and the list of
`not done` lines. Nothing else about the work.
