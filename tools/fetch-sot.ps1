# Fetches and pins the 7-Zip 26.05 SoTs (sources of truth), one per lane:
#   tools/sot/7za-x86.exe  (lane 32: 7za.exe from 7z2605-extra.7z)
#   tools/sot/7za-x64.exe  (lane 64: x64/7za.exe from 7z2605-extra.7z)
# The package is extracted with the release's 7zr.exe, which is fetched
# and verified first and kept as tools/sot/7zr.exe (extraction tool only;
# it is not a lane). Every byte is verified against a pinned SHA-256.
# The only acceptable source is release tag 26.05 of github.com/ip7z/7zip.
$ErrorActionPreference = "Stop"
$Root = Split-Path -Parent $PSScriptRoot
$SotDir = Join-Path $Root "tools\sot"
$TmpDir = Join-Path $Root "tools\tmp"
$Release = "https://github.com/ip7z/7zip/releases/download/26.05"

$Pinned = @{
    "7zr.exe"         = "9bf582b894dfa665f852d7e9112b02290a1c303c2d95a21fcdc41ffcb03143b7"
    "7z2605-extra.7z" = "f27a8f103c84785026edcba1f67faf1357225df9d19ddb0b7760d55947141bc7"
    "7za-x86.exe"     = "357929ec748d00728c64dd2e7aa0069258f40847c1410014bb60d22eb9ec75d5"
    "7za-x64.exe"     = "7ddf0a3bc451e166679296be630d6f0573eb386159c04184761c43020c484291"
}

function Hash($Path) {
    return (Get-FileHash -Algorithm SHA256 $Path).Hash.ToLowerInvariant()
}

function Verify($Path, $Name) {
    $Actual = Hash $Path
    if ($Actual -ne $Pinned[$Name]) {
        Remove-Item $Path
        throw "SHA-256 mismatch for ${Name}: expected $($Pinned[$Name]), got $Actual"
    }
}

# Fetch downloads $Asset from the release into $Dest unless a verified
# copy is already there.
function Fetch($Asset, $Dest) {
    if ((Test-Path $Dest) -and ((Hash $Dest) -eq $Pinned[$Asset])) {
        Write-Host "present and verified: $Dest"
        return
    }
    Invoke-WebRequest -Uri "$Release/$Asset" -OutFile $Dest
    Verify $Dest $Asset
    Write-Host "fetched and verified: $Dest"
}

New-Item -ItemType Directory -Force -Path $SotDir | Out-Null
New-Item -ItemType Directory -Force -Path $TmpDir | Out-Null

$Sevenzr = Join-Path $SotDir "7zr.exe"
Fetch "7zr.exe" $Sevenzr

$Extra = Join-Path $TmpDir "7z2605-extra.7z"
Fetch "7z2605-extra.7z" $Extra

$ExtractDir = Join-Path $TmpDir "extra"
if (Test-Path $ExtractDir) { Remove-Item -Recurse -Force $ExtractDir }
& $Sevenzr x -y "-o$ExtractDir" $Extra "7za.exe" "x64\7za.exe" | Out-Null
if ($LASTEXITCODE -ne 0) { throw "7zr x failed with exit code $LASTEXITCODE" }

$Lanes = @(
    @{ Name = "7za-x86.exe"; From = (Join-Path $ExtractDir "7za.exe") },
    @{ Name = "7za-x64.exe"; From = (Join-Path $ExtractDir "x64\7za.exe") }
)
foreach ($Lane in $Lanes) {
    $Dest = Join-Path $SotDir $Lane.Name
    Copy-Item -Force $Lane.From $Dest
    Verify $Dest $Lane.Name
    $Version = (& $Dest | Where-Object { $_ -ne "" } | Select-Object -First 1)
    Write-Host "SoT verified: $Dest"
    Write-Host "  $Version"
}
Remove-Item -Recurse -Force $ExtractDir
