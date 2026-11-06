# Downloads the pinned 7-Zip 26.05 oracle (7zr.exe) and verifies its SHA-256.
# The only acceptable oracle is release tag 26.05 of github.com/ip7z/7zip.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$OutDir = Join-Path $Root "tools\oracle"
$Out = Join-Path $OutDir "7zr.exe"
$Url = "https://github.com/ip7z/7zip/releases/download/26.05/7zr.exe"
$Pinned = "9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7"

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
Invoke-WebRequest -Uri $Url -OutFile $Out

$Actual = (Get-FileHash -Algorithm SHA256 $Out).Hash.ToLowerInvariant()
if ($Actual -ne $Pinned) {
    Remove-Item $Out
    throw "SHA-256 mismatch: expected $Pinned, got $Actual"
}
Write-Host "oracle verified: $Out"
