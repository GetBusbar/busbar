#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# config-stability-gate.sh — the CONFIG-STABILITY CI GATE.
#
# 1.5.3 is the LAST config-breaking release. After it, the config grammar is FROZEN and every future
# feature may add only NEW OPTIONAL keys/sections/enum-variants. This gate ENFORCES that, per-PR, the
# same way the admin-API openapi.json drift guard enforces the served contract — READ a committed
# snapshot, REGENERATE from the source, DIFF — plus the mechanic the openapi guard does NOT have: an
# ADDITIVE-ONLY classifier that fails RED on any breaking delta.
#
# TWO checks, mirroring `openapi_json_matches_committed_file` + a new additive test:
#
#   1. DRIFT GUARD  — the committed `config-schema.snapshot.json` must byte-equal a fresh render of
#                     the config surface. A config-type change that forgets to regenerate the snapshot
#                     fails LOUD with the exact `UPDATE_CONFIG_SCHEMA=1` regen command — identical
#                     ergonomics to `UPDATE_OPENAPI=1`.
#
#   2. ADDITIVE-ONLY — the committed BASELINE (read from a git ref, NEVER the working tree) vs the
#                     fresh render, classified node-by-node: new optional field / new section / enum
#                     append = GREEN; field removed/retyped, newly-required, enum-variant dropped =
#                     RED. Because the baseline is a git ref, refreshing the snapshot file CANNOT
#                     launder a break through a snapshot rewrite.
#
# SELF-TEST (`--selftest`, run FIRST in CI like every other scripts/*-lint.sh): drives the classifier
# against fixture snapshot pairs whose verdict is known, proving the gate RED-flags a removal / retype
# / newly-required / enum-drop and GREEN-passes an additive add / new-section / enum-append / reorder
# — and that a snapshot "refresh" does not launder a break. The self-test cannot be lied to: it feeds
# the classifier known inputs and asserts the exact exit codes.
#
# No external deps beyond python3 (stdlib only) + git — the same bare-runner posture as the sibling
# lints. `UPDATE_CONFIG_SCHEMA=1` regenerates the snapshot (the reviewed-intentional-change path).

set -uo pipefail
cd "$(dirname "$0")/.."

PY=python3
GEN="scripts/config-schema.py"
CONFIG_SRC="crates/busbar/src/config"
SNAPSHOT="crates/busbar/src/config/config-schema.snapshot.json"
# The per-path break-waiver file (see config-schema.py load_waivers). A COMMITTED file, deliberately
# not an env var: every excused break is a reviewable line in the PR diff. Empty by default.
WAIVERS="crates/busbar/src/config/config-schema.waivers"
BASELINE_REF="${CONFIG_SCHEMA_BASELINE_REF:-HEAD}"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

command -v "$PY" >/dev/null 2>&1 || { echo "config-stability-gate: python3 not found" >&2; exit 2; }

# ── SELF-TEST ──────────────────────────────────────────────────────────────────────────────────────
selftest() {
  hdr "config-stability gate SELF-TEST (the gate proves itself before it judges the tree)"
  local tmp rc fails=0
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN

  # A tiny baseline fingerprint the fixtures mutate. Shapes mirror the REAL 1.5.3 grammar surface:
  # a named-definition map alias (`hooks:` = HookDefs), its definition struct, and the `phase:` stage
  # enum. There is deliberately NO `plane`/`bindings`/`principal` fixture — that grammar was DELETED
  # in the 1.5.3 audit (audit-decisions §1) and must not survive even as a test fixture.
  cat >"$tmp/base.json" <<'JSON'
{
  "_meta": {"frozen_at": "1.5.3"},
  "types": {
    "Root": {"kind": "struct", "fields": {
      "keep":     {"type": "String", "optional": false},
      "opt":      {"type": "String", "optional": true}
    }},
    "HookStage": {"kind": "enum", "variants": ["request", "response"]},
    "type HookDefs": {"kind": "alias", "target": "indexmap::IndexMap<String, HookDefCfg>"}
  }
}
JSON

  # Each case: name · expected-exit(0=green,3=red,4=stale-waiver) · a python mutation producing
  # fresh.json · OPTIONAL waiver-file body (4th arg) fed to the classifier.
  run_case() {
    local name="$1" want="$2" mut="$3" waiver_body="${4-}"
    "$PY" - "$tmp/base.json" "$tmp/fresh.json" <<PY
import json, sys
d = json.load(open(sys.argv[1]))
$mut
json.dump(d, open(sys.argv[2], "w"))
PY
    if [ -n "$waiver_body" ]; then
      printf '%s\n' "$waiver_body" >"$tmp/waivers"
      "$PY" "$GEN" classify "$tmp/base.json" "$tmp/fresh.json" "$tmp/waivers" >/dev/null 2>&1
    else
      "$PY" "$GEN" classify "$tmp/base.json" "$tmp/fresh.json" >/dev/null 2>&1
    fi
    rc=$?
    if [ "$rc" -eq "$want" ]; then
      note "PASS  $name (exit $rc)"
    else
      red  "  FAIL  $name (want exit $want, got $rc)"
      fails=$((fails + 1))
    fi
  }

  # ── GREEN (additive) cases — catalog CFG-09/CFG-10/CFG-11 ──
  run_case "additive: new OPTIONAL field is GREEN"        0 'd["types"]["Root"]["fields"]["added"]={"type":"String","optional":True}'
  run_case "additive: new whole section is GREEN"         0 'd["types"]["NewSection"]={"kind":"struct","fields":{"x":{"type":"u32","optional":True}}}'
  run_case "additive: enum-variant append is GREEN"       0 'd["types"]["HookStage"]["variants"].append("candidate")'
  run_case "additive: required->optional relax is GREEN"  0 'd["types"]["Root"]["fields"]["keep"]["optional"]=True'
  run_case "no-op: key reorder / reformat is GREEN"       0 'd["types"]={k:d["types"][k] for k in sorted(d["types"],reverse=True)}'

  # ── RED (breaking) cases — catalog CFG-05..CFG-08 ──
  run_case "breaking: field REMOVAL is RED"               3 'del d["types"]["Root"]["fields"]["keep"]'
  run_case "breaking: field RETYPE is RED"                3 'd["types"]["Root"]["fields"]["keep"]["type"]="u32"'
  run_case "breaking: newly-REQUIRED field is RED"        3 'd["types"]["Root"]["fields"]["opt"]["optional"]=False'
  run_case "breaking: new REQUIRED field is RED"          3 'd["types"]["Root"]["fields"]["added"]={"type":"String","optional":False}'
  run_case "breaking: enum-variant DROP is RED"           3 'd["types"]["HookStage"]["variants"]=["request"]'
  run_case "breaking: enum-variant RENAME is RED"         3 'd["types"]["HookStage"]["variants"]=["request","respond"]'
  run_case "breaking: whole-section REMOVAL is RED"       3 'del d["types"]["HookStage"]'
  run_case "breaking: kind change (struct->enum) is RED"  3 'd["types"]["Root"]={"kind":"enum","variants":["a"]}'

  # The named-definition-map aliases ARE the `hooks:`/`export:`/`identity-providers:` grammar shape
  # Retargeting a map alias to a list breaks every config using the map form.
  run_case "breaking: def-map alias RETARGET is RED"      3 'd["types"]["type HookDefs"]["target"]="Vec<HookDefCfg>"'
  run_case "additive: NEW def-map alias is GREEN"         0 'd["types"]["type ExportDefs"]={"kind":"alias","target":"indexmap::IndexMap<String, ExportDefCfg>"}'

  # ── CFG-13 anti-launder: a snapshot "refresh" must NOT launder a break. The classifier's baseline
  # is the git-ref fingerprint (here base.json), independent of any working-tree snapshot rewrite:
  # even when the fresh render already dropped the field (exactly what a laundered snapshot looks
  # like), classify(baseline, fresh) still sees base.json's field and fails RED.
  run_case "anti-launder: refreshed snapshot still RED"   3 'del d["types"]["Root"]["fields"]["keep"]'

  # ── WAIVER discipline: the escape hatch must be NARROW, and must not become a blanket override. ──
  run_case "waiver: exact-path waiver excuses ITS break"  0 \
    'del d["types"]["Root"]["fields"]["keep"]' \
    'Root.keep = reviewed 1.5.3 break (self-test fixture)'
  # The decisive one: a waiver for path A must NOT suppress an unrelated break at path B.
  run_case "waiver: does NOT excuse an UNWAIVED break"    3 \
    'del d["types"]["Root"]["fields"]["keep"]; del d["types"]["HookStage"]' \
    'Root.keep = reviewed 1.5.3 break (self-test fixture)'
  # A waiver that no longer matches anything is dead standing permission to break that path later.
  run_case "waiver: STALE waiver is itself an error"      4 \
    'd["types"]["Root"]["fields"]["added"]={"type":"String","optional":True}' \
    'Root.keep = stale — the break it excused is gone'
  # A wildcard would turn the hatch into a rubber stamp; it must be refused outright (exit 1 from
  # SystemExit, i.e. neither a silent pass (0) nor a normal RED (3)).
  run_case "waiver: WILDCARD waiver is refused"           1 \
    'del d["types"]["Root"]["fields"]["keep"]' \
    'Root.* = wildcards must be refused'
  # An empty/absent waiver file must not weaken anything.
  run_case "waiver: empty waiver file changes nothing"    3 \
    'del d["types"]["Root"]["fields"]["keep"]' \
    '# no waivers'

  if [ "$fails" -eq 0 ]; then
    grn "config-stability gate self-test: ALL GREEN (classifier RED/GREEN discipline proven)"
    return 0
  fi
  red "config-stability gate self-test: $fails FAILED"
  return 1
}

# ── DRIFT GUARD ─────────────────────────────────────────────────────────────────────────────────────
check() {
  local tmp fresh rc
  tmp="$(mktemp -d)"
  trap 'rm -rf "$tmp"' RETURN
  fresh="$tmp/fresh.json"

  "$PY" "$GEN" gen "$CONFIG_SRC" >"$fresh" || { red "config-schema gen failed"; return 2; }

  # UPDATE path: the reviewed-intentional-change escape hatch (identical role to UPDATE_OPENAPI=1).
  if [ "${UPDATE_CONFIG_SCHEMA:-}" = "1" ]; then
    cp "$fresh" "$SNAPSHOT"
    grn "UPDATE_CONFIG_SCHEMA=1: rewrote $SNAPSHOT"
    note "the additive check below STILL runs against the committed baseline — a refresh cannot launder a break."
  fi

  hdr "DRIFT GUARD — committed snapshot vs fresh render"
  if [ ! -f "$SNAPSHOT" ]; then
    red "missing committed snapshot: $SNAPSHOT"
    note "seed it with:  UPDATE_CONFIG_SCHEMA=1 scripts/config-stability-gate.sh"
    return 1
  fi
  if diff -u "$SNAPSHOT" "$fresh" >"$tmp/drift.diff" 2>&1; then
    grn "no drift — committed config-schema.snapshot.json matches the config source"
  else
    red "config-schema.snapshot.json is STALE — the config surface changed but the snapshot was not regenerated."
    sed 's/^/    /' "$tmp/drift.diff" | head -60
    echo
    note "regenerate (reviewed, intentional change) with:"
    note "    UPDATE_CONFIG_SCHEMA=1 scripts/config-stability-gate.sh"
    return 1
  fi

  # ── ADDITIVE-ONLY — baseline from a git ref (NEVER the working tree) ──
  hdr "ADDITIVE-ONLY — baseline ($BASELINE_REF) vs fresh render"

  # FIRST: does the ref itself resolve? This distinction is load-bearing. A single `cat-file` on
  # `<ref>:<path>` cannot tell "valid ref, snapshot not committed there yet" (a legitimate one-time
  # bootstrap) apart from "that ref does not exist at all" (a shallow clone, a missing `fetch-depth:
  # 0`, or a typo'd CONFIG_SCHEMA_BASELINE_REF). Collapsing both into a friendly "skipped" would hand
  # anyone a silent bypass: point the gate at a nonexistent ref and every breaking change sails
  # through green. An unresolvable ref is therefore a HARD ERROR, never a skip.
  if ! git rev-parse --verify --quiet "${BASELINE_REF}^{commit}" >/dev/null 2>&1; then
    red "config-stability gate: baseline ref '$BASELINE_REF' does NOT resolve — refusing to run."
    note "the additive check is the whole gate; silently skipping it would be a free bypass."
    note "in CI this almost always means the checkout was shallow — use actions/checkout with"
    note "    with: { fetch-depth: 0 }   (and for a PR, fetch the base branch)"
    note "locally, set CONFIG_SCHEMA_BASELINE_REF to a ref that exists (default: HEAD)."
    return 2
  fi

  if git cat-file -e "$BASELINE_REF:$SNAPSHOT" 2>/dev/null; then
    git show "$BASELINE_REF:$SNAPSHOT" >"$tmp/baseline.json" 2>/dev/null
    if "$PY" "$GEN" classify "$tmp/baseline.json" "$fresh" "$WAIVERS"; then
      grn "additive-only: every config-surface delta is additive (or no change)"
    else
      rc=$?
      red "config-stability gate: NON-ADDITIVE config change (see above)."
      return "$rc"
    fi
  else
    # The ref resolves but carries no snapshot: the genuine one-time bootstrap, i.e. the very commit
    # that introduces this gate. Narrow and self-extinguishing — true only until the snapshot lands.
    ylw "baseline $BASELINE_REF resolves but has no committed snapshot yet (ONE-TIME bootstrap: the"
    ylw "commit that introduces this gate) — additive check has nothing to diff against this run."
    note "every later commit/PR IS diffed against the committed snapshot. If you see this after the"
    note "snapshot is committed, the baseline ref is wrong — investigate, do not ignore."
  fi
  return 0
}

case "${1:-}" in
  --selftest) selftest ;;
  --check | "") check ;;
  -h | --help)
    sed -n '2,40p' "$0"
    ;;
  *) echo "usage: $0 [--selftest|--check]" >&2; exit 2 ;;
esac
