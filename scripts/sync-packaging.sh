#!/usr/bin/env bash
#
# Keep the in-repo packaging manifests pinned to the current release:
#   - Formula/tresor.rb         (Homebrew: version + per-arch sha256)
#   - packaging/scoop/tresor.json (version + url + hash)
#   - packaging/aur/PKGBUILD      (pkgver)
#
# release-please only bumps the crate version + CHANGELOG, so these files would
# drift otherwise. Invoked from .github/workflows/release-please.yml after a
# release is created; the workflow commits the result to main with `[skip ci]`.
#
# Homebrew renders from packaging/homebrew/tresor.rb.tmpl; the formula lives in
# this repo and is consumed via `brew tap njoerd114/tresor <repo-url>` (a tap is
# just a repo with a Formula/ dir — the separate homebrew-tresor repo is gone).
#
# Usage: scripts/sync-packaging.sh <version> <tag>
#
set -euo pipefail

version="${1:?usage: sync-packaging.sh <version> <tag>}"
tag="${2:?usage: sync-packaging.sh <version> <tag>}"

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
template="$repo_root/packaging/homebrew/tresor.rb.tmpl"
formula_out="$repo_root/Formula/tresor.rb"
scoop="$repo_root/packaging/scoop/tresor.json"
aur="$repo_root/packaging/aur/PKGBUILD"
base_url="https://github.com/njoerd114/tresor/releases/download/${tag}"
windows_asset="tresor-x86_64-pc-windows-msvc.zip"

if [[ ! -f "$template" ]]; then
  echo "error: formula template not found: $template" >&2
  exit 1
fi

# sha256 of a release asset, streamed so nothing is written to disk.
asset_sha() {
  local asset="$1"
  curl -fsSL "${base_url}/${asset}" | sha256sum | cut -d' ' -f1
}

sha_arm64_darwin="$(asset_sha tresor-aarch64-apple-darwin.tar.gz)"
sha_x86_64_darwin="$(asset_sha tresor-x86_64-apple-darwin.tar.gz)"
sha_arm64_linux="$(asset_sha tresor-aarch64-unknown-linux-gnu.tar.gz)"
sha_x86_64_linux="$(asset_sha tresor-x86_64-unknown-linux-gnu.tar.gz)"
sha_win="$(asset_sha "$windows_asset")"

mkdir -p "$(dirname "$formula_out")"
sed \
  -e "s|@@VERSION@@|${version}|g" \
  -e "s|@@BASE_URL@@|${base_url}|g" \
  -e "s|@@SHA_ARM64_DARWIN@@|${sha_arm64_darwin}|g" \
  -e "s|@@SHA_X86_64_DARWIN@@|${sha_x86_64_darwin}|g" \
  -e "s|@@SHA_ARM64_LINUX@@|${sha_arm64_linux}|g" \
  -e "s|@@SHA_X86_64_LINUX@@|${sha_x86_64_linux}|g" \
  "$template" > "$formula_out"

python3 - "$scoop" "$version" "$base_url" "$windows_asset" "$sha_win" <<'PY'
import json
import sys

path, version, base_url, asset, sha = sys.argv[1:6]
with open(path) as fh:
    manifest = json.load(fh)
manifest["version"] = version
manifest["architecture"]["64bit"]["url"] = f"{base_url}/{asset}"
manifest["architecture"]["64bit"]["hash"] = sha
with open(path, "w") as fh:
    json.dump(manifest, fh, indent=2)
    fh.write("\n")
PY

# AUR builds from the tag tarball and uses `sha256sums=('SKIP')`, so only pkgver
# needs to move; `source` follows `$pkgver`.
tmp="$(mktemp)"
trap 'rm -f "$tmp"' EXIT
sed -E "s|^pkgver=.*|pkgver=${version}|" "$aur" > "$tmp"
mv "$tmp" "$aur"

echo "synced Formula/tresor.rb + scoop + AUR manifests to ${version}"
