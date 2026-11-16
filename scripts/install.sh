#!/bin/sh
# Install provguard on macOS, Linux or Windows (Git Bash):
#
#   curl -fsSL https://raw.githubusercontent.com/durgavarapraveen/provguard/main/scripts/install.sh | sh
#
# It downloads the release binary for this machine, checks it against the
# release's SHA256SUMS, and starts the guided setup (provguard init), which
# copies the binary to ~/.provguard/bin and adds the Claude Code hooks.
#
# Environment:
#   PROVGUARD_VERSION   a release such as 0.2.0 (default: the latest)
#   PROVGUARD_DIST      install from this local folder instead of GitHub
#                       (the folder scripts/release.sh writes)
#   PROVGUARD_NO_INIT   set to 1 to download and check only
set -eu

repo="durgavarapraveen/provguard"

say() { printf '%s\n' "$*"; }
fail() { say "provguard install: $*" >&2; exit 1; }

case "$(uname -s)" in
  Darwin) os=darwin ;;
  Linux) os=linux ;;
  MINGW* | MSYS* | CYGWIN*) os=windows ;;
  *) fail "unsupported system $(uname -s); build from source: go install github.com/$repo/cmd/provguard@latest" ;;
esac
case "$(uname -m)" in
  x86_64 | amd64) arch=amd64 ;;
  arm64 | aarch64) arch=arm64 ;;
  *) fail "unsupported CPU $(uname -m)" ;;
esac
ext=""
[ "$os" = windows ] && ext=".exe"

fetch() { # fetch URL FILE
  if command -v curl >/dev/null 2>&1; then
    curl -fsSL "$1" -o "$2"
  elif command -v wget >/dev/null 2>&1; then
    wget -q "$1" -O "$2"
  else
    fail "curl or wget is needed"
  fi
}

sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$1" | cut -d' ' -f1
  else
    shasum -a 256 "$1" | cut -d' ' -f1
  fi
}

tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT INT TERM

version="${PROVGUARD_VERSION:-}"
if [ -n "${PROVGUARD_DIST:-}" ]; then
  [ -n "$version" ] || version="$(ls "$PROVGUARD_DIST" | sed -n "s/^provguard_\(.*\)_${os}_${arch}${ext}\$/\1/p" | head -n 1)"
  [ -n "$version" ] || fail "no provguard_*_${os}_${arch}${ext} in $PROVGUARD_DIST"
  cp "$PROVGUARD_DIST/SHA256SUMS" "$tmp/SHA256SUMS"
  cp "$PROVGUARD_DIST/provguard_${version}_${os}_${arch}${ext}" "$tmp/"
else
  if [ -z "$version" ]; then
    fetch "https://api.github.com/repos/$repo/releases/latest" "$tmp/latest.json"
    version="$(sed -n 's/.*"tag_name": *"v\{0,1\}\([^"]*\)".*/\1/p' "$tmp/latest.json" | head -n 1)"
    [ -n "$version" ] || fail "could not find the latest release"
  fi
  base="https://github.com/$repo/releases/download/v$version"
  say "Downloading provguard $version for $os/$arch ..."
  fetch "$base/SHA256SUMS" "$tmp/SHA256SUMS"
  fetch "$base/provguard_${version}_${os}_${arch}${ext}" "$tmp/provguard_${version}_${os}_${arch}${ext}"
fi

name="provguard_${version}_${os}_${arch}${ext}"
want="$(grep " \*\{0,1\}$name\$" "$tmp/SHA256SUMS" | cut -d' ' -f1)"
[ -n "$want" ] || fail "$name is not listed in SHA256SUMS"
got="$(sha256 "$tmp/$name")"
[ "$want" = "$got" ] || fail "checksum mismatch for $name (expected $want, got $got); nothing installed"
say "Checksum OK."

bin="$tmp/provguard$ext"
mv "$tmp/$name" "$bin"
chmod +x "$bin"

if [ "${PROVGUARD_NO_INIT:-}" = 1 ]; then
  "$bin" version
  exit 0
fi

# The setup asks questions. When this script is piped into sh, stdin is the
# script itself, so read the answers from the terminal.
if [ -r /dev/tty ]; then
  "$bin" init </dev/tty
else
  "$bin" init --yes
fi

say ""
say "To run provguard commands from any folder, add it to your PATH:"
if [ "$os" = windows ]; then
  say "  export PATH=\"\$HOME/.provguard/bin:\$PATH\"   (Git Bash; for PowerShell use install.ps1)"
else
  say "  export PATH=\"\$HOME/.provguard/bin:\$PATH\"   (add this line to ~/.zshrc or ~/.bashrc)"
fi
