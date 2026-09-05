#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# VOICE (4th-plane) CONFORMANCE BATTERY — the runner, at structural parity with the MCP and A2A
# batteries. The voice runtime now exists and all four legs are LEG_STATUS=ready, so the legs assert
# real conformance. This file (and its PENDING/ready machinery below) stays in place so a future leg or
# slice can still land as a drop-in rather than a rebuild, exercised by --selftest.
#
# WHY A SCAFFOLD IS A LEGITIMATE GREEN, AND WHERE THE LINE IS.
#
#   The sibling MCP/A2A batteries make `NOT ARMED, SO NOT RUN` a RED state, because for those planes
#   the runtime EXISTS: a disarmed subject leg renders as the identical green tick a leg that judged
#   busbar and passed would produce, and that false green is the whole disease those batteries treat.
#
#   The runtime now exists and every shipped leg is armed (LEG_STATUS=ready): "armed and vacuous" is
#   exactly the failure mode the ready-leg anti-vacuity check below guards against. The PENDING path
#   stays live for any future leg/slice that isn't armed yet — stated loudly, per leg, and never
#   dressed up as a conformance pass. The self-test's job is to keep the transition from PENDING to a
#   real, armed-or-red leg a DROP-IN, and to prove — via `--selftest` — that the moment a leg claims
#   to be READY it is held to exactly the anti-vacuity discipline the other batteries use: a ready
#   leg that produces no result is RED, not green.
#
#   That is the difference the header of `mcp-conformance.yml` is about, applied one plane over: the
#   transition is EXERCISED by `--selftest`, not asserted by a real run that cannot happen yet.
#
# THE TWO-LEG RULE, inherited unchanged and enforced the day the legs light up:
#
#   CONTROL runs ALWAYS. A battery that cannot judge a known-good third-party dialect peer cannot be
#   trusted to judge busbar.
#
#   SUBJECT IS ARMED OR RED. Once a leg is READY, an armed run that executed nothing is RED. The
#   `--selftest` drives that transition in both directions so the rule is one somebody has watched
#   work before the first real leg depends on it.
#
# THE DECLARED LEGS (discovered from `legs/*.sh`, never enumerated here — the same rule
# `verdict-covers-every-leg.py` applies to the workflow, one level in):
#
#   spec-per-dialect   the voice spec battery, per dialect. MATRIX: openai, gemini.
#   replay             captured-transcript replay: a recorded session must re-derive identically.
#   cross-parity       the 4 ORDERED OpenAI<->Gemini pairs (oo, og, go, gg) must agree where the
#                      cross-dialect mapping says they must.
#   provider-credential the realtime provider credential the mint / SDP passes dial under, composed
#                      from the deployment's own provider catalog + secret resolver.
#   metering-lease     a session's money hop is the HOST's reserve-then-settle lease, capped by the
#                      presenting principal's own remaining budget.
#   session-scope      the plane's declared `session` scope kind, enforced at session open.
#   gemini-live-route  (K4) the Gemini Live dialect has a MOUNTED WS-accept route (claim, admission,
#                      arrival, and the wire handshake itself), not just a codec the spec/cross-parity
#                      legs exercise off to the side.
#   provider-dial      (K5) a session actually DIALS the composed provider through a real (loopback)
#                      socket via `topology::dial_provider`, and its D2 metering lease settles the
#                      usage that arrived over it — the WS legs' upstream dial is no longer uncomposed.
#   admit-refusal      a key whose budget is already spent is refused AT THE DOOR
#                      (`StartError::BudgetRefused`) before any host-side lease is opened and before
#                      any ledger posting — no provider dial has anything left to reach.
#   route-failover     a hard-down provider dial trips the breaker cell on its first strike, and the
#                      tripped cell refuses every FURTHER dial before any socket/URL work — the
#                      documented terminal outcome, with no repeated egress once the cell is open.
#   audit-record       one governed session lands EXACTLY ONE new admin-audit entry, carrying the
#                      plane's own action literal (`voice.session.open`) and outcome (`applied`).
#   exit-terminal      one session ends ONCE: a metering lease settles exactly once under a double
#                      close, and a session's one admin-audit row survives being torn down before it
#                      ever runs a frame.
#   governance         the 5 vision checkpoints (incl. D2 hard-close-on-exhaustion). GOVERNANCE IS
#                      NOT A CONFORMANCE RESULT — it can never move the conformance verdict, exactly
#                      as `testing/a2a-governance/` can never contribute to the A2A verdict.
#
# THE INPUTS LATER LEGS CONSUME (authored by another agent; referenced, not created, here):
#   testing/voice-conformance/fixtures/{openai,gemini}/   captured transcripts + spec fixtures
#   docs/design/voice-cross-dialect-mapping.*             the OpenAI<->Gemini equivalence the
#                                                         cross-parity leg is judged against
#
# MODES
#   --selftest                 prove the scaffold's OWN accounting bites (coverage, floor, the
#                              pending/ready transition, governance-never-counts), then exit 0.
#   --leg NAME [--slice S]     run one leg (all slices, or one). PENDING legs report and exit 0.
#   --verdict                  run every leg and emit the honest verdict (the default).
#   --list                     print the declared legs, their kind, status and slices.
#   --help
#
# HOW A LEG GETS FILLED (the drop-in): edit `legs/<name>.sh` — flip `LEG_STATUS=ready` and implement
# `leg_execute <slice>` so it prints one `RESULT <slice> <PASS|FAIL> <detail>` line per assertion.
# Nothing in this runner, in the verdict emitter, or in the workflow changes.
#
#   VOICE_RESULT_LOG   optional: a file path. When set, every RESULT line (and every vacuous
#                       "NO RESULT" slice) is ALSO appended there as one machine-readable TSV row
#                       (`<leg>\t<slice>\t<verdict-or-NORESULT>\t<detail>`), in addition to — never
#                       instead of — the human `say` lines above. Written for
#                       testing/shadow-oracle/rigs-ledger.sh, which folds this battery's per-leg
#                       verdicts into the shadow oracle's own ledger; nothing else reads it, and the
#                       default (unset) run is byte-for-byte what it always was.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# DISCOVERED, NOT ENUMERATED. Overridable so `--selftest` can point the exact same accounting code
# at fixture leg directories instead of the real ones.
VOICE_LEGS_DIR="${VOICE_LEGS_DIR:-$HERE/legs}"

# A FLOOR on the declared-leg count, for the same reason the python verdict linter has one: every
# equality below would hold for a battery that had been gutted to a single leg, so the count is
# checked first. Thirteen legs ship today (spec-per-dialect, replay, cross-parity,
# provider-credential, metering-lease, session-scope, gemini-live-route, provider-dial,
# admit-refusal, route-failover, audit-record, exit-terminal, plus governance).
MIN_LEGS="${VOICE_MIN_LEGS:-3}"

say()  { printf '%s\n' "$*"; }
warn() { printf '%s\n' "$*" >&2; }
die()  { printf 'FAIL: %s\n' "$*" >&2; exit 1; }

# The whole leading comment block, read to wherever it now ends rather than to a line number a later
# edit to the header would silently walk past.
usage() { sed -n '2,/^set -euo pipefail$/p' "${BASH_SOURCE[0]}" | sed '$d' | sed 's/^# \{0,1\}//'; }

# ── the leg contract ────────────────────────────────────────────────────────────────────────────
#
# Each `legs/<name>.sh`, when sourced, sets LEG_KIND / LEG_STATUS / LEG_SLICES and defines
# `leg_execute`. `_load_leg` RESETS the contract before every source so one leg's declaration can
# never bleed into the next, and rejects a leg that fails to declare itself — an under-declared leg
# is exactly the silent gap this whole file is arranged to refuse.
_load_leg() {
  local file="$1"
  LEG_KIND=""; LEG_STATUS=""; LEG_SLICES=()
  leg_execute() { die "leg '$1' declares no leg_execute"; }
  # shellcheck disable=SC1090
  . "$file"
  case "$LEG_KIND" in
    conformance|governance) ;;
    *) die "$(basename "$file"): LEG_KIND must be 'conformance' or 'governance', got '${LEG_KIND:-}'" ;;
  esac
  case "$LEG_STATUS" in
    pending|ready) ;;
    *) die "$(basename "$file"): LEG_STATUS must be 'pending' or 'ready', got '${LEG_STATUS:-}'" ;;
  esac
  [ "${#LEG_SLICES[@]}" -ge 1 ] || die "$(basename "$file"): LEG_SLICES must name at least one slice"
}

declared_legs() {
  local f
  for f in "$VOICE_LEGS_DIR"/*.sh; do
    [ -e "$f" ] || continue
    basename "$f" .sh
  done | sort
}

leg_file() { printf '%s/%s.sh' "$VOICE_LEGS_DIR" "$1"; }

# ── processing one leg ──────────────────────────────────────────────────────────────────────────
#
# Prints the leg's per-slice lines and returns:
#   0  pending, or ready and every slice PASS
#   1  ready and at least one slice FAIL (a real conformance finding)
#   2  ready but a slice produced NO result — the vacuous-ready trap, the scaffold's version of
#      "armed and executed nothing". This is the fault the drop-in must never introduce silently.
# A governance leg NEVER returns 1: its findings are observations, never a conformance verdict.
_process_leg() {
  local name="$1" only_slice="${2:-}" rc=0
  _load_leg "$(leg_file "$name")"
  # An optional single-slice filter, applied AFTER the (re)load so it is not clobbered by it. This
  # is how the workflow's matrix job runs exactly one dialect slice.
  [ -n "$only_slice" ] && LEG_SLICES=("$only_slice")
  local kindtag="conformance"; [ "$LEG_KIND" = governance ] && kindtag="governance (NOT a conformance result)"

  if [ "$LEG_STATUS" = pending ]; then
    say "  leg $name [$kindtag]: PENDING — scaffolded, no voice runtime yet"
    local s
    for s in "${LEG_SLICES[@]}"; do say "      · $s : PENDING"; done
    return 0
  fi

  # READY. Each slice must yield at least one RESULT line, or the leg is vacuous.
  local s out results
  for s in "${LEG_SLICES[@]}"; do
    out="$(leg_execute "$s" || true)"
    results="$(printf '%s\n' "$out" | grep -E '^RESULT ' || true)"
    if [ -z "$results" ]; then
      say "      · $s : NO RESULT — a READY leg that executed nothing is RED"
      # Additive, machine-readable mirror for testing/shadow-oracle/rigs-ledger.sh: it needs a
      # per-leg/per-slice record it can turn into a ledger row without re-parsing the human log
      # above. Written ONLY when VOICE_RESULT_LOG is set, so nothing about the existing stdout/log
      # shape changes for anyone not asking for it.
      if [ -n "${VOICE_RESULT_LOG:-}" ]; then
        printf '%s\t%s\tNORESULT\tREADY leg executed nothing\n' "$name" "$s" >>"$VOICE_RESULT_LOG"
      fi
      rc=2; continue
    fi
    if [ -n "${VOICE_RESULT_LOG:-}" ]; then
      printf '%s\n' "$results" | while IFS=' ' read -r _ slice verdict detail; do
        printf '%s\t%s\t%s\t%s\n' "$name" "$slice" "$verdict" "${detail:-}" >>"$VOICE_RESULT_LOG"
      done
    fi
    printf '%s\n' "$results" | while IFS=' ' read -r _ slice verdict detail; do
      say "      · $slice : $verdict ${detail:-}"
    done
    if [ "$LEG_KIND" != governance ] && printf '%s\n' "$results" | grep -qE '^RESULT [^ ]+ FAIL'; then
      [ "$rc" -eq 2 ] || rc=1
    fi
  done
  say "  leg $name [$kindtag]: $([ "$rc" -eq 0 ] && echo READY/ok || echo READY/RED)"
  return "$rc"
}

# ── the verdict emitter ─────────────────────────────────────────────────────────────────────────
#
# MIRRORS `verdict-covers-every-leg.py`, one level in: it holds the set of legs it REPORTED ON to
# equality with the set DISCOVERED, so a leg cannot be added to the tree and then silently dropped
# from the verdict. `VOICE_SELFTEST_DROP` injects exactly that fault, through this real code path,
# so `--selftest` can watch the coverage check bite.
emit_verdict() {
  local -a declared covered
  mapfile -t declared < <(declared_legs)
  [ "${#declared[@]}" -ge "$MIN_LEGS" ] \
    || die "FLOOR: the battery declares only ${#declared[@]} leg(s) (minimum $MIN_LEGS). A gutted battery satisfies every equality below, so the count is checked first."

  say "== VOICE conformance battery — verdict =="
  say "   (pending legs are honest, not passing; a READY leg asserts real conformance or is RED)"
  say ""

  local name rc problems=0 pending=0 ready_ok=0 conformance_fail=0 governance_legs=0
  for name in "${declared[@]}"; do
    if [ "${VOICE_SELFTEST_DROP:-}" = "$name" ]; then
      continue    # injected coverage fault: this leg is discovered but never reported
    fi
    covered+=("$name")
    _load_leg "$(leg_file "$name")"
    [ "$LEG_KIND" = governance ] && governance_legs=$((governance_legs+1))
    rc=0; _process_leg "$name" || rc=$?
    case "$rc" in
      0) [ "$LEG_STATUS" = pending ] && pending=$((pending+1)) || ready_ok=$((ready_ok+1)) ;;
      1) conformance_fail=$((conformance_fail+1)) ;;
      2) problems=$((problems+1)) ;;
    esac
  done

  # COVERAGE: every discovered leg must have been reported on. Set equality, not a floor.
  local missing
  missing="$(comm -23 <(printf '%s\n' "${declared[@]}" | sort -u) <(printf '%s\n' "${covered[@]}" | sort -u) || true)"
  if [ -n "$missing" ]; then
    warn ""
    warn "UNREPORTED LEG(S): the verdict discovered these legs but never judged them:"
    # Deliberate word-splitting: one leg name per line.
    # shellcheck disable=SC2086
    printf '  %s\n' $missing >&2
    warn "A verdict that skips a declared leg is the false green this battery exists to refuse."
    problems=$((problems+1))
  fi

  say ""
  say "  legs declared:       ${#declared[@]}  (governance: $governance_legs, not counted toward conformance)"
  say "  pending:             $pending"
  say "  ready & passing:     $ready_ok"
  say "  conformance failures:$conformance_fail"
  say "  accounting problems: $problems"

  if [ "$problems" -gt 0 ]; then
    die "the battery's own accounting failed above — no verdict about busbar can be believed."
  fi
  if [ "$conformance_fail" -gt 0 ]; then
    die "$conformance_fail conformance leg(s) failed. This IS a finding about busbar."
  fi
  say ""
  if [ "$ready_ok" -eq 0 ]; then
    say "VOICE verdict: SCAFFOLD self-test PASS, $pending leg(s) pending. NOT a conformance pass —"
    say "no voice leg asserts real conformance yet; the shape is enforced and every leg is accounted for."
  else
    say "VOICE verdict: $ready_ok ready leg(s) passed, $pending pending. Conformance holds for the ready legs."
  fi
}

# ── one leg on demand (the workflow's per-leg jobs call this) ─────────────────────────────────────
run_one_leg() {
  local name="$1" only_slice="${2:-}"
  local file; file="$(leg_file "$name")"
  [ -f "$file" ] || die "no such leg '$name' (declared legs: $(declared_legs | paste -sd' ' -))"
  say "== VOICE conformance battery — leg '$name' =="
  _load_leg "$file"
  local rc=0; _process_leg "$name" "$only_slice" || rc=$?
  case "$rc" in
    0) [ "$LEG_STATUS" = pending ] \
         && say "leg '$name': PENDING (scaffold) — exiting 0; this is not a conformance pass" \
         || say "leg '$name': READY and passing" ;;
    1) die "leg '$name': conformance FAIL — a finding about busbar" ;;
    2) die "leg '$name': READY but executed nothing — RED, not green" ;;
  esac
}

# ── --selftest: prove the accounting BITES before any verdict is believed ─────────────────────────
#
# The same discipline the sibling batteries use: plant runs the checks MUST refuse, plus runs they
# MUST accept, so a green here cannot be produced by an emitter that refuses everything or accepts
# everything. Every fixture drives the REAL `emit_verdict`/`_process_leg` code, against fixture leg
# directories, so nothing here is a parallel re-implementation that could pass while the real thing
# is broken.
selftest() {
  say "== voice-conformance SELF-TEST (the scaffold's accounting cannot be lied to) =="
  local tmp failures=0
  tmp="$(mktemp -d)"
  # Path expanded at trap-set time: a RETURN trap fires after the function's locals are gone, so a
  # `$tmp` referenced inside it would be unbound under `set -u`.
  # shellcheck disable=SC2064
  trap "rm -rf '$tmp'" RETURN

  # Fixture leg writers. `_pending`, `_ready_pass`, `_ready_fail`, `_ready_vacuous`, `_gov` each
  # write a leg file honouring the contract, so the fixtures exercise the loader too.
  _pending()       { printf 'LEG_KIND=conformance\nLEG_STATUS=pending\nLEG_SLICES=(%s)\nleg_execute(){ :; }\n' "$2" >"$1"; }
  _ready_pass()    { printf 'LEG_KIND=conformance\nLEG_STATUS=ready\nLEG_SLICES=(%s)\nleg_execute(){ echo "RESULT $1 PASS ok"; }\n' "$2" >"$1"; }
  _ready_fail()    { printf 'LEG_KIND=conformance\nLEG_STATUS=ready\nLEG_SLICES=(%s)\nleg_execute(){ echo "RESULT $1 FAIL boom"; }\n' "$2" >"$1"; }
  _ready_vacuous() { printf 'LEG_KIND=conformance\nLEG_STATUS=ready\nLEG_SLICES=(%s)\nleg_execute(){ echo "no result at all"; }\n' "$2" >"$1"; }
  _gov_fail()      { printf 'LEG_KIND=governance\nLEG_STATUS=ready\nLEG_SLICES=(%s)\nleg_execute(){ echo "RESULT $1 FAIL observed"; }\n' "$2" >"$1"; }

  probe() { ( VOICE_LEGS_DIR="$1" VOICE_MIN_LEGS="${3:-3}" ${VOICE_SELFTEST_DROP:+VOICE_SELFTEST_DROP="$VOICE_SELFTEST_DROP"} emit_verdict ) >/dev/null 2>&1; }
  check() {  # check <name> <legsdir> <want:accept|refuse> [minlegs]
    local name="$1" dir="$2" want="$3" min="${4:-3}"
    if ( VOICE_LEGS_DIR="$dir" VOICE_MIN_LEGS="$min" emit_verdict ) >/dev/null 2>&1; then got=accept; else got=refuse; fi
    if [ "$got" = "$want" ]; then say "  ok: $name -> $got"; else say "  MISS: $name -> $got (wanted $want)"; failures=$((failures+1)); fi
  }

  # GREEN: an all-PENDING scaffold of the required shape is accepted and exits 0. This is the state
  # the battery ships in today; if it were refused, every RED below would prove only that the
  # emitter refuses everything.
  local d1="$tmp/all-pending"; mkdir -p "$d1"
  _pending "$d1/spec-per-dialect.sh" "openai gemini"
  _pending "$d1/replay.sh" "default"
  _pending "$d1/cross-parity.sh" "oo og go gg"
  check "an all-pending scaffold" "$d1" accept

  # RED: a READY leg that produces NO result. The vacuous-ready trap — the scaffold's own version of
  # "armed and executed nothing", and the fault a careless drop-in would introduce.
  local d2="$tmp/vacuous-ready"; mkdir -p "$d2"
  _pending "$d2/replay.sh" "default"
  _pending "$d2/cross-parity.sh" "oo og go gg"
  _ready_vacuous "$d2/spec-per-dialect.sh" "openai gemini"
  check "a READY leg that executed nothing" "$d2" refuse

  # RED: a READY conformance leg with a FAIL slice is a real finding and must fail the verdict.
  local d3="$tmp/ready-fail"; mkdir -p "$d3"
  _pending "$d3/replay.sh" "default"
  _pending "$d3/cross-parity.sh" "oo og go gg"
  _ready_fail "$d3/spec-per-dialect.sh" "openai"
  check "a READY leg with a FAIL slice" "$d3" refuse

  # GREEN: a READY leg whose slices all PASS is accepted — otherwise the two REDs above prove only
  # that any READY leg is refused.
  local d4="$tmp/ready-pass"; mkdir -p "$d4"
  _pending "$d4/replay.sh" "default"
  _pending "$d4/cross-parity.sh" "oo og go gg"
  _ready_pass "$d4/spec-per-dialect.sh" "openai"
  check "a READY leg whose slices all pass" "$d4" accept

  # RED: below the floor. A battery gutted to one leg satisfies every equality, so the count is
  # checked first — with min set to 3 against a single-leg tree.
  local d5="$tmp/gutted"; mkdir -p "$d5"
  _pending "$d5/only.sh" "x"
  check "a gutted battery below the leg floor" "$d5" refuse 3

  # RED: coverage. A leg is discovered but the emitter drops it from the verdict. Injected through
  # the REAL emitter via VOICE_SELFTEST_DROP, exactly the fault verdict-covers-every-leg.py catches
  # in the workflow one level out.
  if ( VOICE_LEGS_DIR="$d1" VOICE_MIN_LEGS=3 VOICE_SELFTEST_DROP=replay emit_verdict ) >/dev/null 2>&1; then
    say "  MISS: a dropped (unreported) leg was accepted"; failures=$((failures+1))
  else
    say "  ok: a leg discovered but dropped from the verdict is refused"
  fi

  # GOVERNANCE NEVER COUNTS. A governance leg that FAILs must NOT fail the conformance verdict — it
  # is an observation, not a conformance result, the same separation a2a-governance is held to.
  local d6="$tmp/gov-fails"; mkdir -p "$d6"
  _pending "$d6/spec-per-dialect.sh" "openai gemini"
  _pending "$d6/replay.sh" "default"
  _pending "$d6/cross-parity.sh" "oo og go gg"
  _gov_fail "$d6/governance.sh" "D2-hard-close-on-exhaustion"
  check "a governance leg that FAILs does not fail conformance" "$d6" accept

  # RED: an under-declared leg (no LEG_KIND) must be refused by the loader, not silently skipped.
  local d7="$tmp/malformed"; mkdir -p "$d7"
  _pending "$d7/spec-per-dialect.sh" "openai gemini"
  _pending "$d7/replay.sh" "default"
  printf 'LEG_STATUS=pending\nLEG_SLICES=(x)\n' >"$d7/broken.sh"
  check "a leg that fails to declare its kind" "$d7" refuse

  [ "$failures" -eq 0 ] || die "$failures self-test fixture(s) did not behave as declared"

  # And finally: the REAL legs on disk must load and account cleanly right now (whatever mix of
  # ready/pending they currently declare).
  say ""
  say "-- the shipped legs, accounted for --"
  local shipped; shipped="$(declared_legs | paste -sd' ' -)"
  ( emit_verdict ) >/dev/null 2>&1 || die "the shipped scaffold does not self-account cleanly: $shipped"
  local n; n="$(declared_legs | grep -c . || true)"
  say ""
  say "self-test PASS, $n legs accounted for: $shipped"
}

main() {
  case "${1:---verdict}" in
    --selftest) selftest ;;
    --verdict)  emit_verdict ;;
    --list)
      local name
      for name in $(declared_legs); do
        _load_leg "$(leg_file "$name")"
        printf '  %-18s kind=%-11s status=%-7s slices=[%s]\n' "$name" "$LEG_KIND" "$LEG_STATUS" "${LEG_SLICES[*]}"
      done ;;
    --leg)
      shift; [ $# -ge 1 ] || die "--leg needs a leg name"
      local legname="$1" slice=""; shift || true
      while [ $# -gt 0 ]; do
        case "$1" in
          --slice) slice="${2:-}"; shift 2 ;;
          *) die "unknown argument to --leg: $1" ;;
        esac
      done
      run_one_leg "$legname" "$slice" ;;
    --help|-h) usage ;;
    *) die "unknown mode: $1 (try --help)" ;;
  esac
}

main "$@"
