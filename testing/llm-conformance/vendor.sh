#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Fetch the providers' PUBLIC machine-readable API specifications the LLM-plane conformance gate
# validates against, verify each against the digest pinned in spec-digests.tsv, and install it under
#   ~/.cache/busbar-llm-specs/<spec>/<digest>/spec.<yaml|json>
# The specs are NOT vendored into the repository (about 7 MB across five files); the digest file is what
# is tracked, exactly as testing/shadow-oracle/fetch-golden.sh + golden-digests.tsv pin the 1.5.5
# binary rather than committing it. A cached copy whose digest matches is used without any network.
#
#   vendor.sh                 fetch whatever is not cached; verify; exit 0 when all five are present
#   vendor.sh --check         verify the cache only (no network); exit 3 if anything is absent/wrong
#   vendor.sh --repin <spec>  fetch the current upstream document and PRINT the row you would pin
#                             (nothing is installed; paste the row into spec-digests.tsv on purpose).
#                             For a VENDORED spec the download is kept and its path printed, so the
#                             reviewed bytes are the ones that get committed.
#   vendor.sh --paths         print "<spec>\t<path>" for every pinned spec (what validate.py reads)
#   vendor.sh --drift         THE LIVE-DRIFT DETECTOR, separate from the judge: for every VENDORED
#                             spec, fetch the live upstream document and compare it (same digest
#                             format) with the committed copy's pin. Exit 5 and say DRIFT when they
#                             differ, 4 when upstream cannot be fetched, 0 when live == committed.
#   --digests <file>          read pins from <file> instead of spec-digests.tsv (the selftest plants
#                             drift this way); vendored paths resolve relative to that file.
#
# VENDORED specs (url column `vendored:<path>`, fifth column = the live upstream URL). Some
# upstreams cannot be pinned by URL: Google serves only the LIVE discovery document and bumps its
# `revision` field every few days, so a URL pin went RED on every branch at every bump (item 116)
# and the judge could judge nothing. Those documents are committed under specs/ after review; the
# digest pins the committed file, the judge installs it from the tree with NO network, and
# `--drift` is the separate, loud check that upstream has moved on from what was reviewed.
#
# Refuses (exit 3) on any digest mismatch and deletes the download: a spec that silently changed
# under the gate would change what "conformant" means without anyone reviewing the change.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
DIGESTS="${here}/spec-digests.tsv"
CACHE_ROOT="${BUSBAR_LLM_SPEC_CACHE:-$HOME/.cache/busbar-llm-specs}"
MODE=fetch REPIN=""
while [ $# -gt 0 ]; do
  case "$1" in
    --check) MODE=check; shift ;;
    --paths) MODE=paths; shift ;;
    --repin) MODE=repin; REPIN="$2"; shift 2 ;;
    --cache-dir) CACHE_ROOT="$2"; shift 2 ;;
    --drift) MODE=drift; shift ;;
    --digests) DIGESTS="$2"; shift 2 ;;
    *) echo "unknown arg: $1" >&2; exit 2 ;;
  esac
done

sha256_raw() { if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1; else shasum -a 256 "$1" | cut -d' ' -f1; fi; }
# json-canonical: digest of the document re-serialized with sorted keys and no whitespace, so a
# server that varies key order per request (Google's discovery endpoint does) still pins.
sha256_canonical() {
  python3 - "$1" <<'PY'
import hashlib, json, sys
with open(sys.argv[1], "rb") as f:
    doc = json.load(f)
print(hashlib.sha256(json.dumps(doc, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()).hexdigest())
PY
}
digest_of() {  # digest_of <format> <file>
  case "$1" in
    raw) sha256_raw "$2" ;;
    json-canonical) sha256_canonical "$2" 2>/dev/null || echo "unparseable-json" ;;
    *) echo "bad-format"; return 1 ;;
  esac
}
ext_for() { case "$1" in *.json|*'$discovery'*|*'?version='*) echo json ;; *) echo yaml ;; esac; }

rows() { awk -F'\t' '!/^#/ && NF>=4 {print}' "$DIGESTS"; }
[ -s "$DIGESTS" ] || { echo "vendor: no digest file at $DIGESTS" >&2; exit 2; }
DIGESTS_DIR="$(cd "$(dirname "$DIGESTS")" && pwd)"
# vendored_src <url-column> -> absolute path of the committed copy, or empty when not vendored
vendored_src() { case "$1" in vendored:*) printf '%s/%s' "$DIGESTS_DIR" "${1#vendored:}" ;; esac; }

if [ "$MODE" = drift ]; then
  drifted=0 unreachable=0 checked=0
  while IFS=$'\t' read -r spec fmt want url upstream; do
    [ -n "$spec" ] || continue
    [ -n "$(vendored_src "$url")" ] || continue
    checked=$((checked+1))
    if [ -z "$upstream" ]; then
      echo "vendor: ${spec} is vendored but names no upstream URL (fifth column); drift cannot be measured" >&2
      unreachable=$((unreachable+1)); continue
    fi
    tmp="$(mktemp "${TMPDIR:-/tmp}/busbar-llm-drift.XXXXXX")"
    if ! curl -fsSL -m 300 -o "$tmp" "$upstream"; then
      echo "vendor: LIVE DRIFT UNMEASURED for ${spec}: download failed for ${upstream}" >&2
      rm -f "$tmp"; unreachable=$((unreachable+1)); continue
    fi
    live="$(digest_of "$fmt" "$tmp")"; rm -f "$tmp"
    if [ "$live" = "$want" ]; then
      echo "in-sync    ${spec}  ${want:0:12}  live upstream == the committed, reviewed copy"
    else
      echo "::error title=llm spec LIVE DRIFT (${spec})::upstream ${upstream} is no longer the reviewed copy ${url#vendored:}" >&2
      echo "vendor: LIVE DRIFT for ${spec} (${fmt})" >&2
      echo "  upstream  ${upstream}" >&2
      echo "  committed ${want}  (${url#vendored:})" >&2
      echo "  live      ${live}" >&2
      echo "  The judge still validates against the committed copy. Review the change, then: vendor.sh --repin ${spec}" >&2
      drifted=$((drifted+1))
    fi
  done < <(rows)
  [ "$checked" -gt 0 ] || { echo "vendor: --drift found no vendored spec to measure" >&2; exit 2; }
  [ "$drifted" -eq 0 ] || exit 5
  [ "$unreachable" -eq 0 ] || exit 4
  exit 0
fi

if [ "$MODE" = repin ]; then
  row="$(rows | awk -F'\t' -v s="$REPIN" '$1==s{print; exit}')"
  [ -n "$row" ] || { echo "vendor: no row for spec '$REPIN' in $DIGESTS" >&2; exit 2; }
  fmt="$(printf '%s' "$row" | cut -f2)"; url="$(printf '%s' "$row" | cut -f4)"; upstream="$(printf '%s' "$row" | cut -f5)"
  if [ -n "$(vendored_src "$url")" ]; then
    # keep the download: it is the candidate to diff against the committed copy and, once reviewed,
    # to commit in its place under a new name, with this row pointing at it
    tmp="$(mktemp "${TMPDIR:-/tmp}/busbar-llm-spec-${REPIN}.XXXXXX")"
    curl -fsSL -m 300 -o "$tmp" "$upstream" || { echo "vendor: download failed for $upstream" >&2; rm -f "$tmp"; exit 4; }
    echo "vendor: candidate kept at $tmp — diff it against ${url#vendored:}, commit it under specs/, point the row at it" >&2
    printf '%s\t%s\t%s\t%s\t%s\n' "$REPIN" "$fmt" "$(digest_of "$fmt" "$tmp")" "vendored:specs/<new file>" "$upstream"
    exit 0
  fi
  tmp="$(mktemp "${TMPDIR:-/tmp}/busbar-llm-spec.XXXXXX")"; trap 'rm -f "$tmp"' EXIT
  curl -fsSL -m 300 -o "$tmp" "$url" || { echo "vendor: download failed for $url" >&2; exit 4; }
  printf '%s\t%s\t%s\t%s\n' "$REPIN" "$fmt" "$(digest_of "$fmt" "$tmp")" "$url"
  exit 0
fi

fails=0
while IFS=$'\t' read -r spec fmt want url upstream; do
  [ -n "$spec" ] || continue
  src="$(vendored_src "$url")"
  ext="$(ext_for "${src:-$url}")"
  dir="${CACHE_ROOT}/${spec}/${want}"
  file="${dir}/spec.${ext}"
  if [ "$MODE" = paths ]; then printf '%s\t%s\n' "$spec" "$file"; continue; fi

  # A CACHE HIT IS MEASURED, NOT REMEMBERED. This used to compare the `.digest` sidecar this very
  # script wrote with the digest it was about to check — a note comparing itself, which says nothing
  # about the bytes in spec.<ext> and is still true after those bytes change. `--check`, whose whole
  # job is "verify the cache only", therefore printed `cached` for a document that was no longer the
  # one the pin names, and fetch mode declined to re-download it. The file itself is digested here:
  # 2 ms for the largest spec, and the difference between a pin and a note about a pin.
  if [ -s "$file" ]; then
    have="$(digest_of "$fmt" "$file")"
    if [ "$have" = "$want" ]; then
      rm -f "${dir}/spec.parsed.json"   # a pre-parse of this document that nothing measures; validate.py no longer reads it
      printf '%s\n' "$want" >"${dir}/.digest"
      echo "cached     ${spec}  ${want:0:12}  ${file}"
      continue
    fi
    echo "vendor: CACHE DRIFT for ${spec} (${fmt}): ${file}" >&2
    echo "  expected ${want}" >&2
    echo "  actual   ${have}" >&2
    echo "  The cached document is not the one this digest names. Nothing may be validated against it." >&2
    if [ "$MODE" = check ]; then fails=$((fails+1)); continue; fi
    echo "  re-fetching from ${url}" >&2
  fi
  if [ "$MODE" = check ]; then
    echo "MISSING    ${spec}  ${want:0:12}  (run vendor.sh to fetch)"; fails=$((fails+1)); continue
  fi

  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.download.XXXXXX")"
  if [ -n "$src" ]; then
    # VENDORED: the committed, reviewed copy is the source. No network, ever; the same digest check
    # below refuses it if the committed bytes are not the ones the pin names.
    if ! cp "$src" "$tmp" 2>/dev/null; then
      echo "vendor: vendored copy for ${spec} is missing: ${src}" >&2; rm -f "$tmp"; fails=$((fails+1)); continue
    fi
  elif ! curl -fsSL -m 300 -o "$tmp" "$url"; then
    echo "vendor: download failed for ${spec}: ${url}" >&2; rm -f "$tmp"; fails=$((fails+1)); continue
  fi
  got="$(digest_of "$fmt" "$tmp")"
  if [ "$got" != "$want" ]; then
    echo "vendor: DIGEST MISMATCH for ${spec} (${fmt})" >&2
    echo "  url      ${url}" >&2
    echo "  expected ${want}" >&2
    echo "  actual   ${got}" >&2
    if [ -n "$src" ]; then
      echo "  The COMMITTED copy ${src} is not the document the pin names. Nothing may be validated against it." >&2
    else
      echo "  The upstream document changed since it was pinned. Review it, then: vendor.sh --repin ${spec}" >&2
    fi
    rm -f "$tmp"; fails=$((fails+1)); continue
  fi
  mv "$tmp" "$file"
  printf '%s\n' "$want" >"${dir}/.digest"
  printf '%s\t%s\t%s\t%s\n' "$spec" "$fmt" "$want" "$url" >"${dir}/.provenance"
  echo "installed  ${spec}  ${want:0:12}  ${file}"
done < <(rows)

[ "$MODE" = paths ] && exit 0
if [ "$fails" -ne 0 ]; then echo "vendor: ${fails} spec(s) not verified" >&2; exit 3; fi
