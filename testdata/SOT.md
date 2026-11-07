# SoT (source of truth)

7-Zip ships a 32-bit and a 64-bit build of the same source, and the two
write different bytes wherever the source branches on `sizeof(size_t)`
or on available memory. Every parity line is therefore proven twice,
once per lane, against the standalone console build `7za.exe` ("7-Zip
alone") of release tag `26.05` of `github.com/ip7z/7zip`, asset
`7z2605-extra.7z` (SHA-256
`f27a8f103c84785026edcba1f67faf1357225df9d19ddb0b7760d55947141bc7`).

| Lane | Binary                 | In the package | SHA-256                                                            | Version line                                                           |
| ---- | ---------------------- | -------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------- |
| 32   | `tools/sot/7za-x86.exe` | `7za.exe`      | `357929ec748d00728c64dd2e7aa0069258f40847c1410014bb60d22eb9ec75d5` | `7-Zip (a) 26.05 (x86) : Copyright (c) 1999-2026 Igor Pavlov : 2026-10-21` |
| 64   | `tools/sot/7za-x64.exe` | `x64/7za.exe`  | `7ddf0a3bc451e166679296be630d6f0573eb386159c04184761c43020c484291` | `7-Zip (a) 26.05 (x64) : Copyright (c) 1999-2026 Igor Pavlov : 2026-10-21` |

The package also holds `arm64/7za.exe` (SHA-256
`86a2064dfe2a362f03e3c95e577cab88a9d2caaca9e442520046a050044d2d4d`).
ARM64 is not a lane.

`tools/fetch-sot.ps1` fetches the package and the release's `7zr.exe`
(asset `7zr.exe`, SHA-256
`9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7`,
version line `7-Zip (r) 26.05 (x86) : Igor Pavlov : Public domain :
2026-10-21`), verifies both, extracts the two lane binaries with `7zr.exe`
(the package is packed with LZMA + BCJ2, which the module cannot read
until the BCJ2 line is done), verifies their SHA-256s and places them
under `tools/sot/`. `7zr.exe` stays there as the extraction tool only;
no proof runs against it since the lanes were split (2026-11-06).
`internal/sot.Binary(root, lane)` re-verifies the SHA-256 and the
version line of a lane's binary before any test uses it.

Pinned source: `reference/7zip` — git tag `26.05` of `github.com/ip7z/7zip`
(commit `b88c6bc09339de32f7d18bbab900686b244f42ba`).

Parity fixtures (generated from the verified binaries, committed, and
checked against live output by TestParity):

- `testdata/parity/7za-x86-i.txt`, `7za-x64-i.txt` — output of `7za i`
- `testdata/parity/7za-x86-usage.txt`, `7za-x64-usage.txt` — output of
  `7za` with no arguments

The two builds' lists differ only in the version line.

Byte-identity exceptions (stated, never counted as identity):

- 7zAES: random salt and IV. Pass = identical structure given the SoT's
  random values injected through the API, plus the SoT extracts what the
  module wrote and the module extracts what the SoT wrote.
- `b` benchmark: prints timings. Pass = it runs and prints the same fields.
