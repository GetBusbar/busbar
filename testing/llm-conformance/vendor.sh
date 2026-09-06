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
#                             (nothing is installed; paste the row into spec-digests.tsv on purpose)
#   vendor.sh --paths         print "<spec>\t<path>" for every pinned spec (what validate.py reads)
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
# FLOOR: `-s` above only proves the file has BYTES, and this file is mostly comment lines -- a
# digest file reduced to its header, or one whose columns were edited to spaces instead of tabs,
# satisfies `-s` and yields ZERO data rows. The loop below then iterates nothing, `fails` stays 0,
# and every mode exits 0 reporting success over nothing pinned at all. Nothing is pinned unless at
# least one row survives the parse.
n_rows="$(rows | grep -c . || true)"
[ "$n_rows" -gt 0 ] || {
  echo "vendor: $DIGESTS parsed to ZERO pinned spec(s) -- nothing would be verified, so nothing is" >&2
  echo "        pinned. Rows are TAB-separated with at least 4 columns: <spec> <format> <digest> <url>." >&2
  exit 2
}

if [ "$MODE" = repin ]; then
  row="$(rows | awk -F'\t' -v s="$REPIN" '$1==s{print; exit}')"
  [ -n "$row" ] || { echo "vendor: no row for spec '$REPIN' in $DIGESTS" >&2; exit 2; }
  fmt="$(printf '%s' "$row" | cut -f2)"; url="$(printf '%s' "$row" | cut -f4)"
  tmp="$(mktemp "${TMPDIR:-/tmp}/busbar-llm-spec.XXXXXX")"; trap 'rm -f "$tmp"' EXIT
  curl -fsSL -m 300 -o "$tmp" "$url" || { echo "vendor: download failed for $url" >&2; exit 4; }
  printf '%s\t%s\t%s\t%s\n' "$REPIN" "$fmt" "$(digest_of "$fmt" "$tmp")" "$url"
  exit 0
fi

fails=0
while IFS=$'\t' read -r spec fmt want url; do
  [ -n "$spec" ] || continue
  ext="$(ext_for "$url")"
  dir="${CACHE_ROOT}/${spec}/${want}"
  file="${dir}/spec.${ext}"
  if [ "$MODE" = paths ]; then printf '%s\t%s\n' "$spec" "$file"; continue; fi

  # A CACHED SPEC IS RE-HASHED, NEVER TAKEN ON THE WORD OF A SIDECAR. This used to accept the cache
  # whenever `${dir}/.digest` happened to contain $want -- but that sidecar is an ordinary file this
  # script wrote once, and its required content is the expected digest itself, so any process that
  # can write the cache can mint a matching pair. The bytes the gate actually validates against were
  # never hashed after install. The header's promise ("refuses on any digest mismatch") only held on
  # the download path; on every subsequent offline run -- which is every CI run, since the cache is
  # restored from an artifact -- the pin was not enforced at all. Now the pinned digest is compared
  # to the digest OF THE FILE, every time, in every mode.
  if [ -s "$file" ]; then
    have="$(digest_of "$fmt" "$file")"
    if [ "$have" = "$want" ]; then
      echo "cached     ${spec}  ${want:0:12}  ${file}"
      continue
    fi
    echo "vendor: CACHED SPEC DOES NOT MATCH ITS PIN for ${spec} (${fmt})" >&2
    echo "  file     ${file}" >&2
    echo "  expected ${want}" >&2
    echo "  actual   ${have}" >&2
    echo "  The cached bytes are not the pinned document. Delete the cache entry and re-vendor; if" >&2
    echo "  upstream genuinely changed, review it and: vendor.sh --repin ${spec}" >&2
    rm -f "${dir}/.digest"
    fails=$((fails+1))
    continue
  fi
  if [ "$MODE" = check ]; then
    echo "MISSING    ${spec}  ${want:0:12}  (run vendor.sh to fetch)"; fails=$((fails+1)); continue
  fi

  mkdir -p "$dir"
  tmp="$(mktemp "${dir}/.download.XXXXXX")"
  if ! curl -fsSL -m 300 -o "$tmp" "$url"; then
    echo "vendor: download failed for ${spec}: ${url}" >&2; rm -f "$tmp"; fails=$((fails+1)); continue
  fi
  got="$(digest_of "$fmt" "$tmp")"
  if [ "$got" != "$want" ]; then
    echo "vendor: DIGEST MISMATCH for ${spec} (${fmt})" >&2
    echo "  url      ${url}" >&2
    echo "  expected ${want}" >&2
    echo "  actual   ${got}" >&2
    echo "  The upstream document changed since it was pinned. Review it, then: vendor.sh --repin ${spec}" >&2
    rm -f "$tmp"; fails=$((fails+1)); continue
  fi
  mv "$tmp" "$file"
  printf '%s\n' "$want" >"${dir}/.digest"
  printf '%s\t%s\t%s\t%s\n' "$spec" "$fmt" "$want" "$url" >"${dir}/.provenance"
  echo "installed  ${spec}  ${want:0:12}  ${file}"
done < <(rows)

[ "$MODE" = paths ] && exit 0
if [ "$fails" -ne 0 ]; then echo "vendor: ${fails} spec(s) not verified" >&2; exit 3; fi
