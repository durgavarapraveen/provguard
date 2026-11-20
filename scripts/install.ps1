# Install provguard on Windows (PowerShell 5.1 or 7):
#
#   irm https://raw.githubusercontent.com/durgavarapraveen/provguard/main/scripts/install.ps1 | iex
#
# It downloads the release binary for this machine, checks it against the
# release's SHA256SUMS (this catches a broken download, not a compromised
# release), and starts the guided setup (provguard init), which
# copies the binary to ~\.provguard\bin and adds the Claude Code hooks.
#
# Environment:
#   PROVGUARD_VERSION   a release such as 0.2.0 (default: the latest)
#   PROVGUARD_DIST      install from this local folder instead of GitHub
#   PROVGUARD_NO_INIT   set to 1 to download and check only

# Everything runs inside a script block, so `irm | iex` leaves the user's
# session as it was: no changed $ErrorActionPreference, no new functions.
& {
$ErrorActionPreference = 'Stop'
$ProgressPreference = 'SilentlyContinue' # the PS 5.1 progress bar slows downloads a lot
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
        [Net.ServicePointManager]::SecurityProtocol = [Net.ServicePointManager]::SecurityProtocol -bor [Net.SecurityProtocolType]::Tls12
        if (-not $version) {
            try {
                $version = (Invoke-RestMethod "https://api.github.com/repos/$repo/releases/latest").tag_name -replace '^v', ''
            } catch {
                Fail "no provguard release found at github.com/$repo/releases (or GitHub cannot be reached). Try again later, or build from source: go install github.com/$repo/cmd/provguard@latest"
            }
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

    # Build provenance (Sigstore) proves the binary was built from this repo
    # by its release workflow, which a checksum from the same release cannot.
    # Releases up to 0.5.1 have none. It needs the GitHub CLI, signed in.
    if (-not $env:PROVGUARD_DIST) {
        if ($version -match '^0\.([0-4]\.|5\.[01]$)') {
            Write-Host "Provenance: release $version has no signed provenance (releases after 0.5.1 do)."
        } elseif ((Get-Command gh -ErrorAction SilentlyContinue) -and ($null -ne (& gh auth token 2>$null))) {
            & gh attestation verify (Join-Path $tmp $name) --repo $repo *> $null
            if ($LASTEXITCODE -ne 0) { Fail "build provenance check failed for ${name}: it was not built by $repo's release workflow; nothing installed" }
            Write-Host "Provenance OK (built by $repo's release workflow)."
        } else {
            Write-Host "Provenance not checked: install the GitHub CLI (gh) and sign in, then run: gh attestation verify <file> --repo $repo"
        }
    }

    $bin = Join-Path $tmp 'provguard.exe'
    Move-Item (Join-Path $tmp $name) $bin

    if ($env:PROVGUARD_NO_INIT -eq '1') {
        & $bin version
        return
    }
    # The setup asks questions in a terminal. Without one (a CI job, a
    # script) it could only show the change, so install with the defaults.
    if ([Console]::IsInputRedirected) { & $bin init --yes } else { & $bin init }
    if ($LASTEXITCODE -ne 0) { Fail "provguard init failed (exit $LASTEXITCODE)" }

    # A terminal reads PATH when it starts, so the setup's change reaches
    # only new terminals. This script runs inside the user's terminal (irm |
    # iex), so give this one the folder too, if the user put it on PATH.
    $dir = Join-Path $HOME '.provguard\bin'
    $onUserPath = ([Environment]::GetEnvironmentVariable('Path', 'User') -split ';') -contains $dir
    $inSession = ($env:Path -split ';') -contains $dir
    if ($onUserPath -and -not $inSession -and (Test-Path (Join-Path $dir 'provguard.exe'))) {
        $env:Path = $env:Path.TrimEnd(';') + ';' + $dir
        Write-Host 'provguard works in this terminal too: try provguard status'
    }
} finally {
    Remove-Item -Recurse -Force $tmp -ErrorAction SilentlyContinue
}
}
