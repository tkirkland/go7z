# SoT (source of truth)

Pinned SoT: `tools/sot/7zr.exe`

- Source: release tag `26.05` of `github.com/ip7z/7zip` (asset `7zr.exe`)
- SHA-256: `9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7`
- Version line: `7-Zip (r) 26.05 (x86) : Igor Pavlov : Public domain : 2026-10-21`
- Fetched by `tools/fetch-sot.ps1`

Pinned source: `reference/7zip` — git tag `26.05` of `github.com/ip7z/7zip`
(commit `b88c6bc09339de32f7d18bbab900686b244f42ba`).

Parity fixtures (generated from the verified SoT, committed):

- `testdata/parity/7zr-i.txt` — output of `7zr i`
- `testdata/parity/7zr-usage.txt` — output of `7zr` with no arguments

`7z2605-extra.7z` from the same release (SHA-256
`f27a8f103c84785026edcba1f67faf1357225df9d19ddb0b7760d55947141bc7`)
holds `x64/7za.exe` for the 64-bit build-identity check.

Byte-identity exceptions (stated, never counted as identity):

- 7zAES: random salt and IV. Pass = identical structure given the SoT's
  random values injected through the API, plus the SoT extracts what the
  module wrote and the module extracts what the SoT wrote.
- `b` benchmark: prints timings. Pass = it runs and prints the same fields.
