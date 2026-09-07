# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# shellcheck shell=bash
# shellcheck disable=SC2034  # LEG_KIND/LEG_STATUS/LEG_SLICES are read by voice-conformance.sh on source
#
# LEG: spec-per-dialect — the voice conformance spec, run once PER DIALECT.
#
# The matrix is the two dialects busbar's voice plane will speak: openai and gemini. Each slice runs
# the full spec battery against that dialect's peer and holds it to the dialect's own required
# scenario set (set equality, never a floor — see the sibling MCP `assert_covered`).
#
# STATUS: ready. Wired against the `busbar-voice` plane. Each slice drives EVERY captured fixture in
# `testing/voice-conformance/fixtures/$dialect/` through the dialect's real codec
# (`OpenAiRealtimeCodec` / `GeminiLiveCodec`) as wire JSON → IR → wire JSON, and asserts round-trip
# stability at the level the codec guarantees (IR-fixpoint; some families are also byte-stable, and
# an atomic Gemini `toolCall` that decodes to a streamed triple is held to the correlation
# fingerprint, since the stateless writer re-frames per event). A fixture that decodes to NOTHING is
# only accepted when it is a documented drop+warn; anything else fails RED. One fixture — the Gemini
# `realtimeInput.audio{}` uplink shape the shipped codec does not read — stays an HONEST PENDING
# sub-item (printed, never dressed as a pass), not a reason to weaken the whole leg.

# shellcheck source=../lib/conform-bin.sh disable=SC1091
. "$(dirname "${BASH_SOURCE[0]}")/../lib/conform-bin.sh"

LEG_KIND=conformance
LEG_STATUS=ready
LEG_SLICES=(openai gemini)

# THE REQUIRED SCENARIO SET, HELD TO SET EQUALITY — which the header above has claimed since this
# leg was written and nothing did. `voice-conform spec` enumerates whatever `.json` files it finds in
# the dialect directory and asserts only that the list is not EMPTY, so the leg's subject was
# whatever happened to be on disk. Planted: thirteen of the fourteen openai fixtures deleted. The leg
# reported one PASS row and exited 0 — thirteen scenarios stopped being exercised and not one row
# said so.
#
# `fixtures/scenario-census.tsv` is the declared set. Equality is checked in BOTH directions and
# BEFORE the harness runs: a censused scenario with no file is a scenario that silently stopped being
# tested; a file with no census line is a scenario nobody decided to test. Both are FAIL rows on this
# leg's own slice, so they travel the ordinary RESULT path and the runner folds them like any other
# conformance finding.
spec_census_rows() {  # spec_census_rows <dialect> — prints RESULT rows; 0 rows means the census holds
  local dialect="$1" census="$VC_FIXTURES/scenario-census.tsv" declared present missing extra
  if [ ! -s "$census" ]; then
    echo "RESULT $dialect FAIL the scenario census $census is missing or empty, so the required scenario set cannot be checked and this slice would judge whatever is on disk"
    return 0
  fi
  declared="$(awk -F'\t' -v d="$dialect" '$1==d && $2!=""{print $2}' "$census" | sort -u)"
  if [ -z "$declared" ]; then
    echo "RESULT $dialect FAIL the scenario census names no scenario for dialect '$dialect'; a dialect with an empty required set is one nothing can be missing from"
    return 0
  fi
  present="$(cd "$VC_FIXTURES/$dialect" 2>/dev/null && ls -1 ./*.json 2>/dev/null | sed 's|^\./||' | sort -u)"
  missing="$(comm -23 <(printf '%s\n' "$declared") <(printf '%s\n' "$present"))"
  extra="$(comm -13 <(printf '%s\n' "$declared") <(printf '%s\n' "$present"))"
  [ -n "$missing" ] && echo "RESULT $dialect FAIL scenario(s) the census requires but the tree no longer carries: $(printf '%s' "$missing" | tr '\n' ' ')— they stopped being exercised without a single red; restore them, or strike them from scenario-census.tsv in the commit that retires them"
  [ -n "$extra" ] && echo "RESULT $dialect FAIL fixture file(s) present but absent from the census: $(printf '%s' "$extra" | tr '\n' ' ')— a scenario nobody declared is one nobody decided to test; add it to scenario-census.tsv"
  return 0
}

leg_execute() {
  local dialect="$1"
  local bin census_rows
  census_rows="$(spec_census_rows "$dialect")"
  if [ -n "$census_rows" ]; then
    # The census FAILs are printed and the harness is not run: its per-fixture rows would be a
    # report on a scenario set nobody agreed to, and printing them beside a census failure invites
    # a reader to weigh thirty greens against one red. The slice is already RED.
    printf '%s\n' "$census_rows"
    return 0
  fi
  bin="$(voice_conform_bin)" || { echo "RESULT $dialect FAIL harness build failed"; return 0; }
  "$bin" spec "$dialect" "$VC_FIXTURES/$dialect"
}
