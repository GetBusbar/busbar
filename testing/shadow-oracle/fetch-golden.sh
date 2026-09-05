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
#
#   --check-golden <dir>   verify that <dir>/meta.json's `binary_sha256` (the exact binary record.sh
#                           used to make that recording) matches the sha256 of the binary this script
#                           has cached/pinned for that recording's version — i.e. the golden on disk
#                           was really produced by the binary we still believe is "the golden binary",
#                           not some other build that happens to share a version string. Exit 3 on
#                           mismatch or a meta.json with no binary_sha256 (an unproven golden).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
# shellcheck source=../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"
# shellcheck source=harness-rev.sh
source "${here}/harness-rev.sh"

VERSION="1.5.5" CHECK=0 CACHE_ROOT="${BUSBAR_ORACLE_CACHE:-$HOME/.cache/busbar-oracle}" CHECK_GOLDEN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --version) VERSION="$2"; shift 2 ;;
    --check) CHECK=1; shift ;;
    --check-golden) CHECK_GOLDEN="$2"; shift 2 ;;
    --cache-dir) CACHE_ROOT="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done
DIGESTS="${here}/golden-digests.tsv"
CACHE="${CACHE_ROOT}/${VERSION}"
BIN="${CACHE}/busbar"

pinned() {  # pinned <asset> -> sha256 or empty
  awk -F'\t' -v v="$VERSION" -v a="$1" '$1==v && $2==a {print $3; exit}' "$DIGESTS"
}

if [ -n "$CHECK_GOLDEN" ]; then
  meta_path="${CHECK_GOLDEN}/meta.json"
  [ -s "$meta_path" ] || { echo "fetch-golden --check-golden: no meta.json at ${meta_path}" >&2; exit 3; }
  want_bin_sha="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("binary_sha256") or "")' "$meta_path" 2>/dev/null)"
  [ -n "$want_bin_sha" ] || { echo "fetch-golden --check-golden: ${meta_path} has no binary_sha256 (an unproven golden — re-record it)" >&2; exit 3; }
  meta_ver="$(python3 -c 'import json,sys; print(json.load(open(sys.argv[1])).get("version") or "")' "$meta_path" 2>/dev/null)"
  [ -x "$BIN" ] || { echo "fetch-golden --check-golden: no cached binary at ${BIN} (version ${VERSION}; golden reports version ${meta_ver:-unknown}) — run fetch-golden.sh first" >&2; exit 3; }
  have_bin_sha="$(binary_sha256 "$BIN")"
  if [ "$have_bin_sha" != "$want_bin_sha" ]; then
    echo "fetch-golden --check-golden: MISMATCH — ${meta_path} was recorded with binary_sha256 ${want_bin_sha} but the cached ${BIN} is ${have_bin_sha}" >&2
    exit 3
  fi
  echo "ok  ${CHECK_GOLDEN}  binary_sha256 ${want_bin_sha:0:12} matches cached ${BIN}"
  exit 0
fi

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
