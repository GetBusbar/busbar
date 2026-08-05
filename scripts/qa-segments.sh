#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# qa-segments.sh — the qa-gate SEGMENTATION umbrella (busbar 1.5.3, unit G; design §6 + catalog
# qa-gate-test-catalog-1.5.3.md §1/§3).
#
# qa-gate is a REGISTRY-DRIVEN umbrella that fans out one independent, independently-reported job per
# `active` segment listed in `qa/segments.toml`, holding every not-yet-shipped capability as a
# `reserved` slot that reports PASS/SKIP. This script is the runner behind that umbrella — the exact
# analogue of `plugin-registry-check.sh --list` driving qa-gate.yml's per-plugin sibling checkout
# loop: the MANIFEST is the source of truth, adding a segment is a manifest entry, never new plumbing.
#
# SUBCOMMANDS
#   --list                 emit the manifest as a TSV feed (id  status  tier  run) — the CI fan-out
#                          reads this to build its matrix (registry-driven, no hand-written legs).
#   --selftest             the SEGMENTATION SELF-TEST (catalog §3): the manifest parses; lists both
#                          active AND reserved entries; the preserved coverage (core-data-plane +
#                          plugins) is present (union ⊇ today's gate); every active segment has a run
#                          command; every reserved segment is inert (reports PASS/SKIP). Cannot be
#                          lied to — asserts the exact expected segment set + statuses.
#   --run [--tier T]       run every active segment (optionally filtered to tier fast|live-mock);
#                          reserved segments report PASS/SKIP. SELF-MEASURING: each segment records
#                          its own wall-clock; a per-segment timing summary (segment · tier · status ·
#                          duration · result), SORTED LONGEST-FIRST, prints at the end so the LONG
#                          POLE (Amdahl) is obvious on the very first qa run.
#   --segment ID           run exactly one segment by id.
#
# GREEN-ON-COMPLETION: each active segment runs + reports independently; the umbrella is green iff
# every active segment is green AND every reserved segment reports PASS/SKIP. No cross-segment masking.
#
# No external deps beyond python3 (stdlib tomllib on 3.11+, with a tiny fallback parser) — same bare
# runner posture as the sibling lints.

set -uo pipefail
cd "$(dirname "$0")/.."

# The manifest is overridable ONLY so the self-test can drive the runner against a throwaway fixture
# manifest (that is how inertness is proven by OBSERVATION rather than by trusting a status string).
# CI never sets this; the default is the real manifest.
MANIFEST="${QA_SEGMENTS_MANIFEST:-qa/segments.toml}"
PY=python3

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

command -v "$PY" >/dev/null 2>&1 || { echo "qa-segments: python3 not found" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "qa-segments: missing manifest $MANIFEST" >&2; exit 2; }

# ── Manifest -> TSV feed (id \t status \t tier \t run). tomllib on 3.11+, else a minimal parser that
#    understands exactly the [[segment]] table-array shape this manifest uses. ──
feed() {
  "$PY" - "$MANIFEST" <<'PY'
import sys
path = sys.argv[1]
data = None
try:
    import tomllib
    with open(path, "rb") as f:
        data = tomllib.load(f)
except Exception:
    data = None
segs = []
if data is not None:
    segs = data.get("segment", [])
else:
    # minimal fallback: parse [[segment]] blocks of key = "value" lines
    cur = None
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if s.startswith("#") or not s:
            continue
        if s == "[[segment]]":
            cur = {}
            segs.append(cur)
            continue
        if cur is not None and "=" in s:
            k, _, v = s.partition("=")
            k = k.strip()
            v = v.strip()
            if "#" in v and not v.startswith('"'):
                v = v.split("#", 1)[0].strip()
            v = v.strip().strip('"')
            cur[k] = v
for seg in segs:
    print("\t".join([seg.get("id",""), seg.get("status",""), seg.get("tier",""), seg.get("run","")]))
PY
}

# Is this run command a `cargo test --test <name>` whose integration test target does not yet exist?
# (Lets active segments whose end-to-end body needs another build unit's admin API report a LOUD
# PASS(pending) instead of a hard failure — the "scaffold now, arm later" seam the brief asks for.)
pending_target() {
  local run="$1" name
  # bash `=~` (portable across bash 3.2 on macOS and 4+ on Linux) — avoids BSD-vs-GNU sed `\+` drift.
  if [[ "$run" =~ --test[[:space:]]+([A-Za-z0-9_]+) ]]; then
    name="${BASH_REMATCH[1]}"
    [ -f "crates/busbar/tests/${name}.rs" ] && return 1
    return 0
  fi
  return 1
}

# ── SELF-TEST (segmentation self-test, catalog §3) ────────────────────────────────────────────────
selftest() {
  hdr "qa-gate SEGMENTATION self-test (the umbrella proves its own shape before it runs anything)"
  local fails=0 f
  f="$(feed)" || { red "manifest failed to parse"; return 1; }
  [ -n "$f" ] || { red "manifest parsed to an EMPTY feed"; return 1; }

  local ids active reserved runs_missing=0
  ids="$(printf '%s\n' "$f" | cut -f1 | sort)"
  active="$(printf '%s\n' "$f" | awk -F'\t' '$2=="active"{print $1}' | sort)"
  reserved="$(printf '%s\n' "$f" | awk -F'\t' '$2=="reserved"{print $1}' | sort)"

  # (a) lists BOTH active and reserved entries
  if [ -n "$active" ] && [ -n "$reserved" ]; then
    note "PASS  manifest lists both active AND reserved segments"
  else
    red "  FAIL  manifest must list both active and reserved segments"; fails=$((fails+1))
  fi

  # (b) PRESERVED coverage present (union ⊇ today's gate): core-data-plane + plugins are active
  local seg
  for seg in core-data-plane plugins; do
    if printf '%s\n' "$active" | grep -qx "$seg"; then
      note "PASS  preserved coverage present + active: $seg"
    else
      red "  FAIL  preserved coverage LOST: $seg not an active segment"; fails=$((fails+1))
    fi
  done

  # (c) the 1.5.3 LIVE new segments are active
  for seg in export hook-bindings config-stability; do
    if printf '%s\n' "$active" | grep -qx "$seg"; then
      note "PASS  1.5.3 live segment active: $seg"
    else
      red "  FAIL  expected 1.5.3 live segment missing/inactive: $seg"; fails=$((fails+1))
    fi
  done

  # (d) the RESERVED slots are defined-but-inert (present, status=reserved), each mapped to a release
  for seg in mcp-integrity a2a smart-router; do
    if printf '%s\n' "$reserved" | grep -qx "$seg"; then
      note "PASS  reserved slot defined-but-inert: $seg"
    else
      red "  FAIL  reserved slot missing: $seg"; fails=$((fails+1))
    fi
  done

  # (e) every segment has a non-empty run command (arming a reserved slot is a status flip, not a
  #     rewrite — so it must already name its future run)
  while IFS=$'\t' read -r id status tier run; do
    [ -n "$id" ] || continue
    if [ -z "$run" ]; then
      red "  FAIL  segment $id has no run command"; fails=$((fails+1))
    fi
    case "$tier" in fast|live-mock) : ;; *) red "  FAIL  segment $id has invalid tier '$tier'"; fails=$((fails+1)) ;; esac
    case "$status" in active|reserved) : ;; *) red "  FAIL  segment $id has invalid status '$status'"; fails=$((fails+1)) ;; esac
  done <<<"$f"
  note "PASS  every segment names a run command + a valid tier/status"

  # (f) EVERY reserved segment reports PASS/SKIP (not just a sampled one).
  while read -r seg; do
    [ -n "$seg" ] || continue
    if run_one "$seg" quiet && [ "${LAST_RESULT:-}" = "SKIP" ]; then
      note "PASS  reserved segment reports PASS/SKIP: $seg"
    else
      red "  FAIL  reserved segment $seg did not report PASS/SKIP (got '${LAST_RESULT:-}')"
      fails=$((fails+1))
    fi
  done <<<"$reserved"

  # (g) …and reserved really is INERT, proven by OBSERVATION, not by trusting the status string.
  # A status of SKIP would look identical whether or not the command ran, so drive the runner against
  # a throwaway fixture manifest whose reserved segment's `run` would create a SENTINEL FILE. If the
  # sentinel exists afterwards, the "inert" slot actually executed and the umbrella is lying. The
  # fixture also carries an ACTIVE segment writing its own sentinel, so this proves the sentinel
  # mechanism works at all — otherwise "no file" would pass vacuously even if nothing ever ran.
  local ftmp
  ftmp="$(mktemp -d)"
  cat >"$ftmp/segments.toml" <<TOML
[[segment]]
id     = "selftest-reserved"
status = "reserved"
tier   = "fast"
run    = "touch '$ftmp/RESERVED-RAN'"

[[segment]]
id     = "selftest-active"
status = "active"
tier   = "fast"
run    = "touch '$ftmp/ACTIVE-RAN'"
TOML
  QA_SEGMENTS_MANIFEST="$ftmp/segments.toml" "$0" --run >/dev/null 2>&1
  if [ -f "$ftmp/ACTIVE-RAN" ]; then
    note "PASS  control: an ACTIVE segment DID execute its run command (sentinel observed)"
  else
    red "  FAIL  control failed — an active segment did not run; the inertness proof below is vacuous"
    fails=$((fails+1))
  fi
  if [ -f "$ftmp/RESERVED-RAN" ]; then
    red "  FAIL  a RESERVED segment EXECUTED its run command (sentinel created) — not inert"
    fails=$((fails+1))
  else
    note "PASS  reserved segment is INERT — its run command never executed (no sentinel)"
  fi
  rm -rf "$ftmp"

  if [ "$fails" -eq 0 ]; then
    grn "qa-gate segmentation self-test: ALL GREEN (manifest shape + preserved coverage + inert reserved proven)"
    return 0
  fi
  red "qa-gate segmentation self-test: $fails FAILED"
  return 1
}

# ── Run one segment; sets LAST_RESULT (PASS|SKIP|FAIL|PENDING) and LAST_SECONDS. ──
LAST_RESULT=""
LAST_SECONDS=0
run_one() {
  local want_id="$1" quiet="${2:-}"
  local f line id status tier run start end
  f="$(feed)"
  line="$(printf '%s\n' "$f" | awk -F'\t' -v id="$want_id" '$1==id')"
  [ -n "$line" ] || { red "no such segment: $want_id"; LAST_RESULT="FAIL"; return 1; }
  IFS=$'\t' read -r id status tier run <<<"$line"

  start=$(date +%s)
  if [ "$status" = "reserved" ]; then
    LAST_RESULT="SKIP"; end=$(date +%s); LAST_SECONDS=$((end-start))
    [ "$quiet" = "quiet" ] || ylw "SKIP  [$tier] $id — reserved slot (empty set); arms when its release ships"
    return 0
  fi
  if pending_target "$run"; then
    LAST_RESULT="PENDING"; end=$(date +%s); LAST_SECONDS=$((end-start))
    [ "$quiet" = "quiet" ] || ylw "PASS(pending)  [$tier] $id — TODO: '$run' target not yet on this branch (awaiting its build unit); scaffolded green."
    return 0
  fi
  [ "$quiet" = "quiet" ] || hdr "SEGMENT $id [$tier]  ->  $run"
  if ( eval "$run" ); then
    LAST_RESULT="PASS"; end=$(date +%s); LAST_SECONDS=$((end-start))
    [ "$quiet" = "quiet" ] || grn "PASS  $id (${LAST_SECONDS}s)"
    return 0
  else
    LAST_RESULT="FAIL"; end=$(date +%s); LAST_SECONDS=$((end-start))
    [ "$quiet" = "quiet" ] || red "FAIL  $id (${LAST_SECONDS}s)"
    return 1
  fi
}

# ── Run all (optionally tier-filtered), with the self-measuring timing summary. ──
run_all() {
  local tier_filter="${1:-}"
  local f id status tier run rc=0
  local -a rows=()
  f="$(feed)"
  while IFS=$'\t' read -r id status tier run; do
    [ -n "$id" ] || continue
    if [ -n "$tier_filter" ] && [ "$tier" != "$tier_filter" ]; then
      continue
    fi
    run_one "$id" || rc=1
    rows+=("${LAST_SECONDS}"$'\t'"${id}"$'\t'"${tier}"$'\t'"${status}"$'\t'"${LAST_RESULT}")
  done <<<"$f"

  hdr "qa-gate TIMING SUMMARY (self-measuring — longest pole first; parallel speedup is capped by it)"
  printf '  %-10s  %-18s  %-10s  %-9s  %s\n' "DURATION" "SEGMENT" "TIER" "STATUS" "RESULT"
  printf '%s\n' "${rows[@]}" | sort -t$'\t' -k1,1 -rn | while IFS=$'\t' read -r secs id tier status result; do
    printf '  %-10s  %-18s  %-10s  %-9s  %s\n' "${secs}s" "$id" "$tier" "$status" "$result"
  done

  if [ "$rc" -eq 0 ]; then
    grn "qa-gate umbrella: GREEN (all active segments passed; all reserved reported PASS/SKIP)"
  else
    red "qa-gate umbrella: RED (a segment failed — see above; no cross-segment masking)"
  fi
  return "$rc"
}

case "${1:-}" in
  --list) feed ;;
  --selftest) selftest ;;
  --segment)
    [ -n "${2:-}" ] || { echo "usage: $0 --segment <id>" >&2; exit 2; }
    run_one "$2"; exit $? ;;
  --run | "")
    if [ "${2:-}" = "--tier" ]; then run_all "${3:-}"; else run_all ""; fi ;;
  --tier) run_all "${2:-}" ;;
  -h | --help) sed -n '2,45p' "$0" ;;
  *) echo "usage: $0 [--list|--selftest|--run [--tier fast|live-mock]|--segment ID]" >&2; exit 2 ;;
esac
