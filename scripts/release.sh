#!/usr/bin/env bash
# Build release binaries for Windows, macOS and Linux, with SHA-256 checksums.
# Usage: scripts/release.sh 0.1.0
# Output: dist/provguard_<version>_<os>_<arch>[.exe] and dist/SHA256SUMS
# Works in Git Bash on Windows, macOS and Linux. Needs Go 1.26+.
set -euo pipefail

version="${1:?usage: scripts/release.sh VERSION (e.g. 0.1.0)}"
cd "$(dirname "$0")/.."

# Refuse to build a release from untested code.
go vet ./...
go test ./... -count=1
go run ./cmd/provguard bench --check > /dev/null

rm -rf dist && mkdir -p dist
targets="windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64"
for t in $targets; do
  os="${t%/*}"; arch="${t#*/}"
  ext=""; [ "$os" = "windows" ] && ext=".exe"
  out="dist/provguard_${version}_${os}_${arch}${ext}"
  CGO_ENABLED=0 GOOS="$os" GOARCH="$arch" \
    go build -trimpath -ldflags "-s -w -X main.version=${version}" -o "$out" ./cmd/provguard
  echo "built $out"
done

( cd dist && if command -v sha256sum >/dev/null; then sha256sum provguard_*; else shasum -a 256 provguard_*; fi ) > dist/SHA256SUMS
echo "wrote dist/SHA256SUMS"
