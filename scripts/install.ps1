# Install provguard on Windows (PowerShell 5.1 or 7):
#
#   irm https://raw.githubusercontent.com/durgavarapraveen/provguard/main/scripts/install.ps1 | iex
#
# It downloads the release binary for this machine, checks it against the
# release's SHA256SUMS, and starts the guided setup (provguard init), which
# copies the binary to ~\.provguard\bin and adds the Claude Code hooks.
#
# Environment:
#   PROVGUARD_VERSION   a release such as 0.2.0 (default: the latest)
#   PROVGUARD_DIST      install from this local folder instead of GitHub
#   PROVGUARD_NO_INIT   set to 1 to download and check only

$ErrorActionPreference = 'Stop'
$repo = 'durgavarapraveen/provguard'

# throw, not exit: under `irm | iex`, exit would close the user's window.
function Fail($msg) { throw "provguard install: $msg" }

$arch = switch ($env:PROCESSOR_ARCHITECTURE) {
    'AMD64' { 'amd64' }
    'ARM64' { 'arm64' }
    default { Fail "unsupported CPU $env:PROCESSOR_ARCHITECTURE" }
}

$tmp = Join-Path ([IO.Path]::GetTempPath()) ("provguard-" + [guid]::NewGuid())
New-Item -ItemType Directory -Path $tmp | Out-Null
try {
    $version = $env:PROVGUARD_VERSION
    if ($env:PROVGUARD_DIST) {
        if (-not $version) {
            $f = Get-ChildItem $env:PROVGUARD_DIST -Filter "provguard_*_windows_$arch.exe" | Select-Object -First 1
            if (-not $f) { Fail "no provguard_*_windows_$arch.exe in $env:PROVGUARD_DIST" }
            $version = $f.Name -replace '^provguard_(.*)_windows_.*$', '$1'
        }
        Copy-Item (Join-Path $env:PROVGUARD_DIST 'SHA256SUMS') $tmp
        Copy-Item (Join-Path $env:PROVGUARD_DIST "provguard_${version}_windows_$arch.exe") $tmp
    } else {
        [Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls12
        if (-not $version) {
            $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name -replace '^v', ''
            if (-not $version) { Fail 'could not find the latest release' }
        }
        $base = "https://github.com/$repo/releases/download/v$version"
        Write-Host "Downloading provguard $version for windows/$arch ..."
        Invoke-WebRequest "$base/SHA256SUMS" -OutFile (Join-Path $tmp 'SHA256SUMS') -UseBasicParsing
        Invoke-WebRequest "$base/provguard_${version}_windows_$arch.exe" -OutFile (Join-Path $tmp "provguard_${version}_windows_$arch.exe") -UseBasicParsing
    }

    $name = "provguard_${version}_windows_$arch.exe"
    $line = Get-Content (Join-Path $tmp 'SHA256SUMS') | Where-Object { $_ -match "\s\*?$([regex]::Escape($name))$" } | Select-Object -First 1
    if (-not $line) { Fail "$name is not listed in SHA256SUMS" }
    $want = ($line -split '\s+')[0].ToLower()
    $got = (Get-FileHash (Join-Path $tmp $name) -Algorithm SHA256).Hash.ToLower()
    if ($want -ne $got) { Fail "checksum mismatch for $name (expected $want, got $got); nothing installed" }
    Write-Host 'Checksum OK.'

    $bin = Join-Path $tmp 'provguard.exe'
    Move-Item (Join-Path $tmp $name) $bin

    if ($env:PROVGUARD_NO_INIT -eq '1') {
        & $bin version
        return
    }
    & $bin init
    if ($LASTEXITCODE -ne 0) { Fail "provguard init failed (exit $LASTEXITCODE)" }

    $dir = Join-Path $HOME '.provguard\bin'
    Write-Host ''
    Write-Host 'To run provguard commands from any folder, add it to your user PATH:'
    Write-Host "  [Environment]::SetEnvironmentVariable('Path', [Environment]::GetEnvironmentVariable('Path','User') + ';$dir', 'User')"
    Write-Host 'Then open a new terminal.'
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
