#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Fetch the PUBLISHED reference busbar binary the shadow oracle records its golden from, verify it
# against the digest pinned in golden-digests.tsv, and install it under the cache path selftest.sh
# and record.sh name. The golden's truth is the released artifact — never a local build of the tag.
#
#   fetch-golden.sh [--version 1.5.5] [--check] [--cache-dir DIR]
#
#   --check   only verify the cached binary's digest (no network); exit 3 if absent or mismatched.
#
# Refuses (exit 3) on any digest mismatch and deletes the download. Also caches the release's
# openapi JSON (used by enumerate-cells.py) beside the binary.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
# shellcheck source=../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"

VERSION="1.5.5" CHECK=0 CACHE_ROOT="${BUSBAR_ORACLE_CACHE:-$HOME/.cache/busbar-oracle}"
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    --cache-dir) CACHE_ROOT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
DIGESTS="${here}/golden-digests.tsv"
CACHE="${CACHE_ROOT}/${VERSION}"
BIN="${CACHE}/busbar"

sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }

pinned() {  # pinned <asset> -> sha256 or empty
  awk -F'\t' -v v="$VERSION" -v a="$1" '$1==v && $2==a {print $3; exit}' "$DIGESTS"
}

case "$(uname -sm)" in
  "Darwin arm64") TRIPLE=aarch64-apple-darwin; EXT=tar.gz ;;
  "Darwin x86_64") TRIPLE=x86_64-apple-darwin; EXT=tar.gz ;;
  "Linux aarch64"|"Linux arm64") TRIPLE=aarch64-unknown-linux-gnu; EXT=tar.gz ;;
  "Linux x86_64") TRIPLE=x86_64-unknown-linux-gnu; EXT=tar.gz ;;
  *) echo "fetch-golden: unsupported host $(uname -sm)" >&2; exit 2 ;;
esac
ASSET="busbar-${TRIPLE}.${EXT}"
OPENAPI="busbar-openapi-v${VERSION}.json"
WANT="$(pinned "$ASSET")"; WANT_OPENAPI="$(pinned "$OPENAPI")"
[ -n "$WANT" ] || { echo "fetch-golden: no pinned digest for ${VERSION} ${ASSET} in ${DIGESTS}" >&2; exit 2; }

if [ "$CHECK" -eq 1 ]; then
  [ -x "$BIN" ] || { echo "fetch-golden: cached binary absent: $BIN" >&2; exit 3; }
  have="$(cat "${CACHE}/.asset-digest" 2>/dev/null || true)"
  [ "$have" = "$WANT" ] || { echo "fetch-golden: cached asset digest ${have:-none} != pinned ${WANT}" >&2; exit 3; }
  "$BIN" --version >/dev/null 2>&1 || { echo "fetch-golden: cached binary does not run" >&2; exit 3; }
  echo "ok  ${BIN}  $("$BIN" --version 2>/dev/null | head -1)  asset ${ASSET} ${WANT:0:12}"
  exit 0
fi

if [ -x "$BIN" ] && [ "$(cat "${CACHE}/.asset-digest" 2>/dev/null || true)" = "$WANT" ] && [ -s "${CACHE}/openapi.json" ]; then
  echo "cached  ${BIN}  asset ${ASSET} ${WANT:0:12}"
  exit 0
fi

mkdir -p "$CACHE"
DL="$(mktemp -d "${TMPDIR:-/tmp}/busbar-golden-dl.XXXXXX")"
trap 'rm -rf "$DL"' EXIT
URL="https://github.com/GetBusbar/busbar/releases/download/v${VERSION}"

fetch() {  # fetch <asset> <dest>
  if command -v gh >/dev/null 2>&1; then
    gh release download "v${VERSION}" --repo GetBusbar/busbar --pattern "$1" --dir "$(dirname "$2")" --clobber >/dev/null 2>&1 && [ -s "$2" ] && return 0
  fi
  curl -fsSL -m 300 -o "$2" "${URL}/$1"
}

fetch "$ASSET" "${DL}/${ASSET}" || { echo "fetch-golden: download failed for ${ASSET}" >&2; exit 4; }
got="$(sha256_of "${DL}/${ASSET}")"
if [ "$got" != "$WANT" ]; then
  echo "fetch-golden: DIGEST MISMATCH for ${ASSET}" >&2
  echo "  expected ${WANT}" >&2
  echo "  actual   ${got}" >&2
  rm -f "${DL}/${ASSET}"
  exit 3
fi

if [ -n "$WANT_OPENAPI" ]; then
  fetch "$OPENAPI" "${DL}/${OPENAPI}" || { echo "fetch-golden: download failed for ${OPENAPI}" >&2; exit 4; }
  got_o="$(sha256_of "${DL}/${OPENAPI}")"
  [ "$got_o" = "$WANT_OPENAPI" ] || { echo "fetch-golden: DIGEST MISMATCH for ${OPENAPI}: expected ${WANT_OPENAPI} actual ${got_o}" >&2; exit 3; }
  cp "${DL}/${OPENAPI}" "${CACHE}/openapi.json"
fi

tar -xzf "${DL}/${ASSET}" -C "$DL" || { echo "fetch-golden: extract failed" >&2; exit 4; }
found="$(find "$DL" -type f -name busbar -perm -u+x | head -1)"
[ -n "$found" ] || found="$(find "$DL" -type f -name busbar | head -1)"
[ -n "$found" ] || { echo "fetch-golden: no 'busbar' in ${ASSET}" >&2; exit 4; }
install -m 0755 "$found" "$BIN"
declaw "$BIN"
printf '%s\n' "$WANT" >"${CACHE}/.asset-digest"
printf 'v%s\t%s\t%s\n' "$VERSION" "$ASSET" "$WANT" >"${CACHE}/.provenance"
"$BIN" --version >/dev/null 2>&1 || { echo "fetch-golden: installed binary does not run" >&2; exit 4; }
echo "installed  ${BIN}  $("$BIN" --version 2>/dev/null | head -1)  asset ${ASSET} ${WANT:0:12}"
