#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# qa-segments.sh — the qa-gate SEGMENTATION umbrella (busbar 1.5.3, unit G; design §6 + catalog
# qa-gate-test-catalog-1.5.3.md §1/§3).
#
# qa-gate is a REGISTRY-DRIVEN umbrella that fans out one independent, independently-reported job per
# `active` segment, holding every not-yet-shipped capability as a `reserved` slot that is INERT and
# EXCLUDED FROM THE GREEN CLAIM. The MANIFEST (qa/segments.toml) is the source of truth: adding a
# segment is a manifest entry, never new plumbing — the exact analogue of plugin-registry-check.sh
# --list driving qa-gate.yml's per-plugin sibling checkout loop.
#
# ── WHAT CHANGED IN THIS REVISION, AND WHY (the honesty fix) ──────────────────────────────────────
# This runner used to have a `PASS(pending)` outcome: an `active` segment whose `cargo test --test
# <target>` did not exist reported GREEN with a "scaffolded green" marker. Measured against the live
# tree, TWO of the three active fast segments were in exactly that state — `export` named
# `qa_export` and `hook-bindings` named `qa_hook_bindings`, NEITHER of which has ever existed in
# crates/busbar/tests/. The umbrella completed in ten seconds and reported GREEN having executed
# almost nothing.
#
# A segment reporting GREEN having run nothing is indistinguishable from one that passed. That is the
# reports-success-while-doing-nothing defect class this release exists to kill, and it was living
# inside the gate meant to catch it. So:
#
#   * PASS(pending) IS DELETED. There is no longer any outcome by which an `active` segment can be
#     green without executing its command. An active segment whose run target does not exist is a
#     HARD FAIL naming the segment and the missing target (see missing_test_target).
#   * `export` and `hook-bindings` now point at coverage that GENUINELY EXISTS in this tree (in-crate
#     unit tests under `--bin busbar`, since `busbar` is a binary-only package). Nothing was
#     manufactured to satisfy the manifest; the manifest was corrected to match the tree.
#   * THE GREEN CLAIM CARRIES ITS SCOPE. `--run`'s final block NAMES every reserved segment it did
#     not cover, every segment a --tier filter excluded, and whether the per-plugin fan-out was live.
#     "GREEN" with no scope is how a partial gate reads as a full one.
#   * EVERY ACTIVE SEGMENT IS FAIL-INJECTED by --selftest: its failure is injected and the umbrella
#     is asserted to exit non-zero and name it. A segment never observed red is not known to work.
#
# ── RECOMMENDED TO scripts/release-check.sh (NOT edited here — a sibling owns that file) ──────────
# The per-plugin fan-out below is what turns the serial fleet soak into a parallel matrix. It needs
# two additive things from release-check.sh:
#
#   1. `--list-segments`: print, one per line, the segment tokens this script accepts, and exit 0.
#      Emit the literal token `plugin-*` to advertise that per-plugin segments are supported. This is
#      the CAPABILITY PROBE this runner uses; it must be cheap and side-effect-free (no docker, no
#      build), like the existing arg-validation path.
#   2. `--segment plugin-<repo>`: run only that one plugin's phases (boot its `service` container,
#      run its gate) rather than the full fleet.
#
# This runner does NOT depend on either landing. It probes; if `plugin-*` is not advertised it falls
# back to the aggregate `plugins` segment (today's preserved coverage) and SAYS SO in the scope line.
# Coverage is identical either way; only the wall clock differs.
#
# SUBCOMMANDS
#   --list                 emit the manifest as a TSV feed (id  status  tier  run) — the CI fan-out
#                          reads this to build its matrix (registry-driven, no hand-written legs).
#                          CONTRACT: four tab-separated columns in that order. Per-plugin segments
#                          appear as ordinary rows. The workflow depends on this shape.
#   --selftest             the SEGMENTATION SELF-TEST (catalog §3): the manifest parses; lists both
#                          active AND reserved entries; the preserved coverage is present; every
#                          active segment has a run command; reserved segments are INERT (proven by
#                          observation); the per-plugin expansion matches the registry EXACTLY; the
#                          missing-target hard fail actually fails; and EVERY active segment is
#                          fail-injected red then restored green. Hermetic — no network, no docker.
#   --run [--tier T]       run every active segment (optionally filtered to tier fast|live-mock),
#                          then print the longest-first timing summary and the SCOPE block.
#   --segment ID           run exactly one segment by id.
#
# GREEN-ON-COMPLETION: each active segment runs + reports independently; the umbrella is green iff
# every active segment is green. No cross-segment masking. Reserved segments make no claim at all.
#
# No external deps beyond python3 (stdlib tomllib on 3.11+, with a tiny fallback parser) — same bare
# runner posture as the sibling lints.

set -uo pipefail
cd "$(dirname "$0")/.." || { echo "qa-segments: cannot cd to repo root" >&2; exit 2; }

# The manifest is overridable ONLY so the self-test can drive the runner against throwaway fixture
# manifests (that is how inertness, the missing-target fail, and per-segment fail-injection are proven
# by OBSERVATION rather than by trusting a status string). CI never sets this.
MANIFEST="${QA_SEGMENTS_MANIFEST:-qa/segments.toml}"
PY=python3
REGISTRY_CMD="./scripts/plugin-registry-check.sh"
RELEASE_CHECK="./scripts/release-check.sh"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

command -v "$PY" >/dev/null 2>&1 || { echo "qa-segments: python3 not found" >&2; exit 2; }
[ -f "$MANIFEST" ] || { echo "qa-segments: missing manifest $MANIFEST" >&2; exit 2; }

# ── Manifest -> RAW rows (KIND \t id \t status \t tier \t run \t extra). tomllib on 3.11+, else a
#    minimal parser understanding exactly the [[segment]] / [[segment_template]] shape used here. ──
raw_feed() {
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

def emit(kind, ident, status, tier, run, extra):
    print("\t".join([kind, ident, status, tier, run, extra]))

if data is not None:
    segs = data.get("segment", [])
    tpls = data.get("segment_template", [])
else:
    # minimal fallback: parse [[segment]] / [[segment_template]] blocks of key = "value" lines
    segs, tpls = [], []
    cur = None
    for line in open(path, encoding="utf-8"):
        s = line.strip()
        if s.startswith("#") or not s:
            continue
        if s == "[[segment]]":
            cur = {}
            segs.append(cur)
            continue
        if s == "[[segment_template]]":
            cur = {}
            tpls.append(cur)
            continue
        if cur is not None and "=" in s:
            k, _, v = s.partition("=")
            k = k.strip()
            v = v.strip()
            if "#" in v and not v.startswith('"'):
                v = v.split("#", 1)[0].strip()
            v = v.strip().strip('"')
            cur[k] = v

for s in segs:
    emit("SEG", s.get("id", ""), s.get("status", ""), s.get("tier", ""),
         s.get("run", ""), s.get("fallback_for", ""))
for t in tpls:
    emit("TPL", t.get("id_prefix", ""), t.get("status", ""), t.get("tier", ""),
         t.get("run", ""), t.get("source", ""))
PY
}

# ── The plugin registry feed (plugins.yaml, via the gate that keeps its consumers honest). ────────
# A parse failure or an EMPTY feed is fatal, never a silent zero-plugin expansion — a fan-out that
# quietly covers nothing is the same lie as a segment that quietly runs nothing.
registry_feed() {
  local out
  out="$("$REGISTRY_CMD" --list 2>/dev/null)" || {
    echo "qa-segments: plugin registry feed FAILED ($REGISTRY_CMD --list)" >&2; return 1; }
  [ -n "$out" ] || { echo "qa-segments: plugin registry feed is EMPTY — refusing to expand a per-plugin fan-out that would cover nothing" >&2; return 1; }
  printf '%s\n' "$out"
}

# ── CAPABILITY PROBE: does release-check.sh support per-plugin segments? ──────────────────────────
# Declarative, not a grep of that script's source: we ask it what segments it accepts. Today it does
# not implement --list-segments (unknown arg -> exit 2, no output, no side effects), so this is false
# and the aggregate `plugins` fallback carries plugin coverage. It flips to true, with no change
# here, the moment the sibling change advertises `plugin-*`. Overridable for the self-test only.
PLUGIN_FANOUT_CACHE=""
plugin_fanout_available() {
  if [ -n "${QA_SEGMENTS_FORCE_FANOUT:-}" ]; then
    [ "$QA_SEGMENTS_FORCE_FANOUT" = "1" ] && return 0 || return 1
  fi
  if [ -z "$PLUGIN_FANOUT_CACHE" ]; then
    if [ -x "$RELEASE_CHECK" ] && "$RELEASE_CHECK" --list-segments 2>/dev/null | grep -qx 'plugin-\*'; then
      PLUGIN_FANOUT_CACHE=yes
    else
      PLUGIN_FANOUT_CACHE=no
    fi
  fi
  [ "$PLUGIN_FANOUT_CACHE" = yes ]
}

# ── feed(): the resolved 4-column TSV (id \t status \t tier \t run). ──────────────────────────────
# Expands each [[segment_template]] against its registry, and SUPPRESSES any [[segment]] whose
# `fallback_for` names a template that expanded. Exactly one of {aggregate fallback, expanded set} is
# ever emitted for a given prefix — never neither (coverage hole), never both (double spend).
#
# ALL-OR-NOTHING: the resolved feed is accumulated and printed only once every source has been read
# successfully. A registry failure must not leave a PARTIAL feed on stdout — that feed would be a
# perfectly well-formed segment list with the plugin legs silently missing, and a consumer that built
# its matrix from it (ignoring the exit code) would run a smaller gate and report green. Same defect
# class as PASS(pending), one layer down. On any failure this prints NOTHING and returns non-zero.
feed() {
  local raw fanout=no out="" reg=""
  raw="$(raw_feed)" || return 1
  [ -n "$raw" ] || return 1

  local has_tpl=""
  has_tpl="$(printf '%s\n' "$raw" | awk -F'\t' '$1=="TPL"{print $2}')"
  if [ -n "$has_tpl" ] && plugin_fanout_available; then
    fanout=yes
  fi

  # Resolve the registry BEFORE emitting anything, so a registry failure yields an empty feed.
  if [ "$fanout" = yes ]; then
    reg="$(registry_feed)" || return 1
  fi

  local kind id status tier run extra
  # 1. plain segments (suppressing fallbacks whose template is live)
  while IFS=$'\t' read -r kind id status tier run extra; do
    [ "$kind" = "SEG" ] || continue
    [ -n "$id" ] || continue
    if [ -n "$extra" ] && [ "$fanout" = yes ] && printf '%s\n' "$has_tpl" | grep -qx "$extra"; then
      continue   # aggregate stand-in suppressed: its per-item fan-out is carrying the coverage
    fi
    out+="$(printf '%s\t%s\t%s\t%s' "$id" "$status" "$tier" "$run")"$'\n'
  done <<<"$raw"

  # 2. template expansion (only when the fan-out can actually run)
  if [ "$fanout" != yes ]; then
    printf '%s' "$out"
    return 0
  fi
  local p_repo p_dir p_alias p_kind p_service p_gate_req p_gate erun
  while IFS=$'\t' read -r kind id status tier run extra; do
    [ "$kind" = "TPL" ] || continue
    # registry feed fields: repo dir alias kind service release_gate gate checkout_ref — the trailing
    # checkout_ref is a clone-time knob (qa-gate.yml's checkout loop) and is not templated here.
    while IFS=$'\t' read -r p_repo p_dir p_alias p_kind p_service p_gate_req p_gate _; do
      [ -n "$p_repo" ] || continue
      erun="$run"
      erun="${erun//\{repo\}/$p_repo}"
      erun="${erun//\{dir\}/$p_dir}"
      erun="${erun//\{alias\}/$p_alias}"
      erun="${erun//\{kind\}/$p_kind}"
      erun="${erun//\{service\}/$p_service}"
      erun="${erun//\{release_gate\}/$p_gate_req}"
      erun="${erun//\{gate\}/$p_gate}"
      out+="$(printf '%s-%s\t%s\t%s\t%s' "$id" "$p_repo" "$status" "$tier" "$erun")"$'\n'
    done <<<"$reg"
  done <<<"$raw"
  printf '%s' "$out"
}

# ── THE HONESTY CHECK ─────────────────────────────────────────────────────────────────────────────
# If a run command names `cargo test --test <target>`, that integration target must EXIST. Prints the
# missing target name and returns 0 when it is absent; returns 1 when there is nothing missing.
# This is what replaced PASS(pending): the same condition that used to print "scaffolded green" now
# makes the segment RED.
missing_test_target() {
  local run="$1" name
  # bash `=~` (portable across bash 3.2 on macOS and 4+ on Linux) — avoids BSD-vs-GNU sed `\+` drift.
  if [[ "$run" =~ --test[[:space:]]+([A-Za-z0-9_]+) ]]; then
    name="${BASH_REMATCH[1]}"
    [ -f "crates/busbar/tests/${name}.rs" ] && return 1
    printf '%s\n' "$name"
    return 0
  fi
  return 1
}

# ── Run one segment; sets LAST_RESULT (PASS|SKIP|FAIL) and LAST_SECONDS. ──────────────────────────
LAST_RESULT=""
LAST_SECONDS=0
run_one() {
  local want_id="$1" quiet="${2:-}"
  local f line id status tier run start end miss
  f="$(feed)"
  line="$(printf '%s\n' "$f" | awk -F'\t' -v id="$want_id" '$1==id')"
  [ -n "$line" ] || { red "no such segment: $want_id"; LAST_RESULT="FAIL"; return 1; }
  IFS=$'\t' read -r id status tier run <<<"$line"

  start=$(date +%s)
  if [ "$status" = "reserved" ]; then
    LAST_RESULT="SKIP"; end=$(date +%s); LAST_SECONDS=$((end-start))
    [ "$quiet" = "quiet" ] || ylw "SKIP  [$tier] $id — reserved slot: INERT, executes nothing, makes NO green claim"
    return 0
  fi

  # An active segment that cannot execute its command is RED. Never green, never "pending".
  if miss="$(missing_test_target "$run")"; then
    LAST_RESULT="FAIL"; end=$(date +%s); LAST_SECONDS=$((end-start))
    [ "$quiet" = "quiet" ] || {
      red "FAIL  [$tier] $id — ACTIVE segment names a run target that DOES NOT EXIST"
      note "run:            $run"
      note "missing target: crates/busbar/tests/${miss}.rs"
      note "An active segment must execute something. Point it at coverage that exists, or set"
      note "status = \"reserved\" so it is excluded from the green claim instead of faking it."
    }
    return 1
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

# ── Run all (optionally tier-filtered), with the timing summary AND the mandatory scope block. ────
run_all() {
  local tier_filter="${1:-}"
  local f id status tier run rc=0
  local -a rows=()
  local covered="" reserved="" tierskipped="" failedset="" plugins_covered=no
  f="$(feed)" || { red "qa-gate umbrella: RED (manifest/registry feed failed)"; return 1; }
  while IFS=$'\t' read -r id status tier run; do
    [ -n "$id" ] || continue
    if [ "$status" = "reserved" ]; then
      reserved="${reserved:+$reserved, }$id"
    fi
    if [ -n "$tier_filter" ] && [ "$tier" != "$tier_filter" ]; then
      tierskipped="${tierskipped:+$tierskipped, }$id"
      continue
    fi
    if run_one "$id"; then
      if [ "$status" != "reserved" ]; then
        # COVERED means: active, executed, AND passed. A segment that failed is listed separately —
        # calling it "covered" would be the same category error as the old PASS(pending).
        covered="${covered:+$covered, }$id"
        case "$id" in plugins|plugin-*) plugins_covered=yes ;; esac
      fi
    else
      rc=1
      failedset="${failedset:+$failedset, }$id"
    fi
    rows+=("${LAST_SECONDS}"$'\t'"${id}"$'\t'"${tier}"$'\t'"${status}"$'\t'"${LAST_RESULT}")
  done <<<"$f"

  hdr "qa-gate TIMING SUMMARY (self-measuring — longest pole first; parallel speedup is capped by it)"
  printf '  %-10s  %-22s  %-10s  %-9s  %s\n' "DURATION" "SEGMENT" "TIER" "STATUS" "RESULT"
  printf '%s\n' "${rows[@]}" | sort -t$'\t' -k1,1 -rn | while IFS=$'\t' read -r secs id tier status result; do
    printf '  %-10s  %-22s  %-10s  %-9s  %s\n' "${secs}s" "$id" "$tier" "$status" "$result"
  done

  # ── THE SCOPE BLOCK. A green claim that does not say what it covered is how a partial gate reads
  #    as a full one. Every reserved segment is NAMED as not covered.
  hdr "qa-gate SCOPE (what this result does and does NOT claim)"
  note "COVERED (active, executed, PASSED): ${covered:-<none>}"
  [ -z "$failedset" ] || note "FAILED (active, executed, RED): $failedset"
  note "NOT COVERED — reserved (inert, no claim made): ${reserved:-<none>}"
  [ -z "$tier_filter" ] || note "NOT COVERED — excluded by --tier '$tier_filter': ${tierskipped:-<none>}"
  if plugin_fanout_available; then
    note "plugin fan-out: LIVE — one segment per plugins.yaml entry, expanded from the registry."
  else
    note "plugin fan-out: UNAVAILABLE — $RELEASE_CHECK does not advertise 'plugin-*' via --list-segments."
    note "                plugin coverage is carried by the aggregate 'plugins' segment instead."
  fi
  if [ "$plugins_covered" = no ]; then
    note "PLUGINS NOT COVERED BY THIS RUN — no plugin segment passed here; this result makes NO"
    note "                claim about any plugin."
    [ "$tier_filter" != "fast" ] || note "                (Expected on --tier fast: plugin segments are live-mock.)"
  fi

  if [ "$rc" -eq 0 ]; then
    grn "qa-gate umbrella: GREEN — for the COVERED set named above, and nothing else."
  else
    red "qa-gate umbrella: RED (a segment failed — see above; no cross-segment masking)"
  fi
  return "$rc"
}

# ── SELF-TEST (segmentation self-test, catalog §3) ────────────────────────────────────────────────
# Hermetic: no network, no docker, no cargo. Every assertion that matters is proven by OBSERVATION
# against a throwaway fixture manifest, not by trusting a status string in the real one.
selftest() {
  hdr "qa-gate SEGMENTATION self-test (the umbrella proves its own shape before it runs anything)"
  local fails=0 f
  f="$(feed)" || { red "manifest failed to parse / registry feed failed"; return 1; }
  [ -n "$f" ] || { red "manifest parsed to an EMPTY feed"; return 1; }

  local active reserved
  active="$(printf '%s\n' "$f" | awk -F'\t' '$2=="active"{print $1}' | sort)"
  reserved="$(printf '%s\n' "$f" | awk -F'\t' '$2=="reserved"{print $1}' | sort)"

  # (a) lists BOTH active and reserved entries
  if [ -n "$active" ] && [ -n "$reserved" ]; then
    note "PASS  manifest lists both active AND reserved segments"
  else
    red "  FAIL  manifest must list both active and reserved segments"; fails=$((fails+1))
  fi

  # (b) PRESERVED coverage present (union ⊇ today's gate). `plugins` is deliberately NOT asserted
  # here: it is the aggregate stand-in that (g) below suppresses when the per-plugin fan-out is live.
  # (g) asserts plugin coverage exists in exactly one of the two forms, which is the real invariant.
  local seg
  seg=core-data-plane
  if printf '%s\n' "$active" | grep -qx "$seg"; then
    note "PASS  preserved coverage present + active: $seg"
  else
    red "  FAIL  preserved coverage LOST: $seg not an active segment"; fails=$((fails+1))
  fi

  # (c) the 1.5.3 LIVE segments are active
  for seg in export hook-bindings config-stability; do
    if printf '%s\n' "$active" | grep -qx "$seg"; then
      note "PASS  1.5.3 live segment active: $seg"
    else
      red "  FAIL  expected 1.5.3 live segment missing/inactive: $seg"; fails=$((fails+1))
    fi
  done

  # (d) the RESERVED slots are defined-but-inert, each mapped to a release
  for seg in mcp-integrity a2a smart-router; do
    if printf '%s\n' "$reserved" | grep -qx "$seg"; then
      note "PASS  reserved slot defined-but-inert: $seg"
    else
      red "  FAIL  reserved slot missing: $seg"; fails=$((fails+1))
    fi
  done

  # (e) every segment has a non-empty run command + valid tier/status
  local id status tier run
  while IFS=$'\t' read -r id status tier run; do
    [ -n "$id" ] || continue
    [ -n "$run" ] || { red "  FAIL  segment $id has no run command"; fails=$((fails+1)); }
    case "$tier" in fast|live-mock) : ;; *) red "  FAIL  segment $id has invalid tier '$tier'"; fails=$((fails+1)) ;; esac
    case "$status" in active|reserved) : ;; *) red "  FAIL  segment $id has invalid status '$status'"; fails=$((fails+1)) ;; esac
  done <<<"$f"
  note "PASS  every segment names a run command + a valid tier/status"

  # (f) NO ACTIVE SEGMENT NAMES A MISSING TEST TARGET. This is the regression guard for the exact
  #     defect that motivated this revision: `export`/`hook-bindings` were active while naming
  #     qa_export/qa_hook_bindings, neither of which exists.
  local miss
  while IFS=$'\t' read -r id status tier run; do
    [ "$status" = "active" ] || continue
    if miss="$(missing_test_target "$run")"; then
      red "  FAIL  active segment $id names a NON-EXISTENT test target '$miss'"; fails=$((fails+1))
    fi
  done <<<"$f"
  note "PASS  no active segment names a non-existent cargo test target"

  # (g) PLUGIN COVERAGE IS UNCONDITIONAL, and the fan-out (when live) matches the registry EXACTLY.
  #     This is the anti-drift assertion: the manifest carries no plugin names, so the only way the
  #     expanded set can disagree with plugins.yaml is a broken expansion — which fails here, loudly,
  #     rather than quietly covering fewer plugins.
  local reg_repos exp_repos
  if plugin_fanout_available; then
    reg_repos="$(registry_feed | cut -f1 | sort)"
    exp_repos="$(printf '%s\n' "$f" | cut -f1 | sed -n 's/^plugin-//p' | sort)"
    if [ "$reg_repos" = "$exp_repos" ]; then
      note "PASS  per-plugin fan-out expands to EXACTLY the plugins.yaml repo set"
    else
      red "  FAIL  per-plugin fan-out does NOT match the registry (drift):"
      diff <(printf '%s\n' "$reg_repos") <(printf '%s\n' "$exp_repos") | sed 's/^/        /'
      fails=$((fails+1))
    fi
    if printf '%s\n' "$f" | cut -f1 | grep -qx 'plugins'; then
      red "  FAIL  aggregate 'plugins' segment emitted ALONGSIDE the fan-out (double spend)"; fails=$((fails+1))
    else
      note "PASS  aggregate 'plugins' stand-in correctly suppressed while the fan-out is live"
    fi
  else
    if printf '%s\n' "$active" | grep -qx 'plugins'; then
      note "PASS  fan-out unavailable -> aggregate 'plugins' segment active (plugin coverage NOT dropped)"
    else
      red "  FAIL  fan-out unavailable AND no aggregate 'plugins' segment — plugin coverage is a HOLE"
      fails=$((fails+1))
    fi
  fi
  # …and prove the expansion itself works, here, without depending on the sibling's flags landing:
  # force the probe true against a fixture and check the set matches the registry.
  local fo_ids fo_expect
  fo_ids="$(QA_SEGMENTS_FORCE_FANOUT=1 "$0" --list | cut -f1 | sed -n 's/^plugin-//p' | sort)"
  fo_expect="$(registry_feed | cut -f1 | sort)"
  if [ "$fo_ids" = "$fo_expect" ] && [ -n "$fo_ids" ]; then
    note "PASS  forced fan-out expands to exactly the registry set (expansion proven, not assumed)"
  else
    red "  FAIL  forced fan-out did not reproduce the registry set"; fails=$((fails+1))
  fi
  if QA_SEGMENTS_FORCE_FANOUT=1 "$0" --list | cut -f1 | grep -qx 'plugins'; then
    red "  FAIL  forced fan-out still emitted the aggregate 'plugins' stand-in"; fails=$((fails+1))
  else
    note "PASS  forced fan-out suppresses the aggregate stand-in (exactly one, never both)"
  fi

  # (h) reserved really is INERT, proven by OBSERVATION rather than by trusting the status string.
  # A SKIP looks identical whether or not the command ran, so drive the runner against a fixture whose
  # reserved segment's `run` would create a SENTINEL FILE. The fixture also carries an ACTIVE segment
  # writing its own sentinel, so the mechanism is proven to work at all — otherwise "no file" would
  # pass vacuously even if nothing ever ran.
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

  # (i) THE MISSING-TARGET HARD FAIL CAN ACTUALLY FAIL (and does not fire on a target that exists).
  # This is the replacement for PASS(pending) proven red. crates/busbar/tests/cli_validate.rs exists
  # on this branch and is the control; qa_export is the exact target that used to print
  # "scaffolded green" and must now be RED.
  local mtmp
  mtmp="$(mktemp -d)"
  cat >"$mtmp/segments.toml" <<'TOML'
[[segment]]
id     = "selftest-missing-target"
status = "active"
tier   = "fast"
run    = "cargo test -p busbar --test qa_export"
TOML
  if QA_SEGMENTS_MANIFEST="$mtmp/segments.toml" "$0" --run >"$mtmp/out" 2>&1; then
    red "  FAIL  an active segment naming the non-existent 'qa_export' target reported GREEN"
    fails=$((fails+1))
  elif grep -q 'DOES NOT EXIST' "$mtmp/out" && grep -q 'qa_export' "$mtmp/out"; then
    note "PASS  missing run target is a HARD FAIL naming the segment and the target (PASS(pending) is gone)"
  else
    red "  FAIL  missing-target run failed but did not name the segment/target"; fails=$((fails+1))
  fi
  if missing_test_target "cargo test -p busbar --test cli_validate" >/dev/null; then
    red "  FAIL  missing-target check fired on 'cli_validate', which DOES exist (false positive)"
    fails=$((fails+1))
  else
    note "PASS  missing-target check does NOT fire on a target that exists (cli_validate)"
  fi
  rm -rf "$mtmp"

  # (j) FAIL INJECTION, PER ACTIVE SEGMENT. A segment never observed red is not known to work: for
  # each active segment id, inject a known failure into that segment's run and assert the umbrella
  # exits NON-ZERO and NAMES it; then restore it and assert it goes back to green. Hermetic — the
  # injected/restored commands are `exit 7` / `true`, so no cargo, docker, or network is touched.
  local itmp seg_id seg_tier
  itmp="$(mktemp -d)"
  while IFS=$'\t' read -r id status tier run; do
    [ "$status" = "active" ] || continue
    seg_id="$id"; seg_tier="$tier"
    # RED: this segment's command fails.
    cat >"$itmp/segments.toml" <<TOML
[[segment]]
id     = "$seg_id"
status = "active"
tier   = "$seg_tier"
run    = "exit 7"
TOML
    if QA_SEGMENTS_MANIFEST="$itmp/segments.toml" "$0" --run >"$itmp/out" 2>&1; then
      red "  FAIL  fail-injection: segment '$seg_id' failed but the umbrella reported GREEN"
      fails=$((fails+1))
      continue
    fi
    if ! grep -q "FAIL  $seg_id" "$itmp/out"; then
      red "  FAIL  fail-injection: umbrella went red for '$seg_id' but did not NAME it"
      fails=$((fails+1))
      continue
    fi
    # GREEN restored: same segment, passing command.
    cat >"$itmp/segments.toml" <<TOML
[[segment]]
id     = "$seg_id"
status = "active"
tier   = "$seg_tier"
run    = "true"
TOML
    if QA_SEGMENTS_MANIFEST="$itmp/segments.toml" "$0" --run >"$itmp/out" 2>&1; then
      note "PASS  fail-injection proven red then restored green: $seg_id"
    else
      red "  FAIL  fail-injection: '$seg_id' stayed red after restoring a passing command"
      fails=$((fails+1))
    fi
  done <<<"$f"
  rm -rf "$itmp"

  # (k) THE GREEN CLAIM CARRIES ITS SCOPE — the umbrella's own output must name its reserved set.
  local stmp
  stmp="$(mktemp -d)"
  cat >"$stmp/segments.toml" <<'TOML'
[[segment]]
id     = "selftest-scope-active"
status = "active"
tier   = "fast"
run    = "true"

[[segment]]
id     = "selftest-scope-reserved"
status = "reserved"
tier   = "fast"
run    = "false"
TOML
  QA_SEGMENTS_MANIFEST="$stmp/segments.toml" "$0" --run >"$stmp/out" 2>&1
  if grep -q 'NOT COVERED — reserved' "$stmp/out" && grep -q 'selftest-scope-reserved' "$stmp/out"; then
    note "PASS  the green claim NAMES the reserved segments it did not cover"
  else
    red "  FAIL  the umbrella printed a green claim without naming its reserved (uncovered) set"
    fails=$((fails+1))
  fi
  rm -rf "$stmp"

  if [ "$fails" -eq 0 ]; then
    grn "qa-gate segmentation self-test: ALL GREEN (shape + preserved coverage + inert reserved + registry-exact fan-out + every active segment proven red-then-green)"
    return 0
  fi
  red "qa-gate segmentation self-test: $fails FAILED"
  return 1
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
  -h | --help) sed -n '2,72p' "$0" ;;
  *) echo "usage: $0 [--list|--selftest|--run [--tier fast|live-mock]|--segment ID]" >&2; exit 2 ;;
esac
