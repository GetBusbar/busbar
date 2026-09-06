#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Fetch a PUBLISHED 1.5.5-era plugin tarball by pinned digest (plugin-digests.tsv) into the oracle
# cache. The oracle drives BOTH binaries with the same published plugin: a 1.5.5 operator's plugin
# must load in 1.6.0 unchanged (PB-11/37/93), and that is only provable with the real artifact.
#
#   fetch-plugin.sh <repo> [--check]      e.g. fetch-plugin.sh store-sqlite
#   prints the cached tarball path on success. Exit 3 on digest mismatch (download deleted).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
# shellcheck source=../fleet-fixtures/lib.sh
source "${repo}/testing/fleet-fixtures/lib.sh"
NAME="${1:?plugin repo name (e.g. store-sqlite)}"; shift || true
CHECK=0; [ "${1:-}" = "--check" ] && CHECK=1
CACHE_ROOT="${BUSBAR_ORACLE_CACHE:-$HOME/.cache/busbar-oracle}"
case "$(uname -sm)" in
  "Darwin arm64") TRIPLE=aarch64-apple-darwin ;; "Darwin x86_64") TRIPLE=x86_64-apple-darwin ;;
  "Linux aarch64"|"Linux arm64") TRIPLE=aarch64-unknown-linux-gnu ;; "Linux x86_64") TRIPLE=x86_64-unknown-linux-gnu ;;
  *) echo "fetch-plugin: unsupported host" >&2; exit 2 ;;
esac
row="$(awk -F'\t' -v n="$NAME" -v t="$TRIPLE" '$1==n && index($3,t) {print; exit}' "${here}/plugin-digests.tsv")"
[ -n "$row" ] || { echo "fetch-plugin: no pinned asset for ${NAME} on ${TRIPLE}" >&2; exit 2; }
TAG="$(printf '%s' "$row" | cut -f2)"; ASSET="$(printf '%s' "$row" | cut -f3)"; WANT="$(printf '%s' "$row" | cut -f4)"
DIR="${CACHE_ROOT}/plugins/${NAME}/${TAG}"; OUT="${DIR}/${ASSET}"
sha256_of() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
if [ -s "$OUT" ] && [ "$(sha256_of "$OUT")" = "$WANT" ]; then echo "$OUT"; exit 0; fi
[ "$CHECK" -eq 0 ] || { echo "fetch-plugin: not cached or digest mismatch: $OUT" >&2; exit 3; }
mkdir -p "$DIR"; tmp="$(mktemp -d "${TMPDIR:-/tmp}/busbar-plugin-dl.XXXXXX")"; trap 'rm -rf "$tmp"' EXIT
if command -v gh >/dev/null 2>&1; then gh release download "$TAG" --repo "GetBusbar/${NAME}" --pattern "$ASSET" --dir "$tmp" --clobber >/dev/null 2>&1; fi
[ -s "${tmp}/${ASSET}" ] || curl -fsSL -m 300 -o "${tmp}/${ASSET}" "https://github.com/GetBusbar/${NAME}/releases/download/${TAG}/${ASSET}" || { echo "fetch-plugin: download failed" >&2; exit 4; }
got="$(sha256_of "${tmp}/${ASSET}")"
[ "$got" = "$WANT" ] || { echo "fetch-plugin: DIGEST MISMATCH for ${ASSET}: expected ${WANT} actual ${got}" >&2; exit 3; }
# PUBLISH BY RENAME. `install` into $OUT writes the bytes in place, so a reader arriving mid-write
# sees a SHORT tarball at the path the cache-hit test above accepts — and the oracle runs its cells
# concurrently against a shared cache, so that reader exists. The cache-hit test would reject the
# partial file on digest, but the cell that opens it directly gets a truncated archive and reports a
# plugin defect. Write beside the target, then rename: on the same filesystem that is atomic, so the
# path either holds nothing or holds the whole verified tarball. The digest is still checked BEFORE
# the rename, so what becomes visible is only ever the asset that matched the pin.
install -m 0644 "${tmp}/${ASSET}" "${OUT}.tmp.$$" && mv -f "${OUT}.tmp.$$" "$OUT" || {
  rm -f "${OUT}.tmp.$$"; echo "fetch-plugin: could not publish ${OUT}" >&2; exit 4; }
declaw "$OUT"; echo "$OUT"
