#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# verify-1.6.0-done.sh — THE 1.6.0 DONE-ORACLE. A single, re-runnable, un-gameable proof that
# "busbar 1.6.0 is done." Per docs/design/playbook/00-MASTER-PLAN.md ("DONE = scripts/verify-1.6.0-done.sh
# green") and the gate designs (gate-no-deferral.md, gate-isomorphism.md).
#
# WHAT "DONE" MEANS HERE — the umbrella asserts, as ONE verdict, that every sub-gate is green:
#   build            the full-gate cargo battery (`cargo xtask full-gate`, driven by qa/full-gate.toml).
#                    No register, no battery: BUILD is RED, never a silent downgrade to plain builds.
#   plane-purity     cargo xtask gate plane-purity  (neutral crates 0 side channels / 0 backwards),
#                    plus the strict ratchet, which nothing invoked while it was a shell flag.
#   plane-delete     scripts/plane-delete-test.sh --all, plus a roster-coverage check that the
#                    LOCKED 5-plane roster (llm/mcp/a2a/streaming/decisions, BUSBAR-1.6.0 #18/#48)
#                    has no plane left untested on disk.
#   byte-identity    the MONEY PATH is byte-stable: openapi_json_matches_committed_file,
#                    resolved_billing_and_limits_config_is_byte_stable, and the 6 busbar-llm-codec
#                    same-proto byte-exact oracles. Bless/regen env vars MUST be empty first (else the
#                    check is a no-op that regenerates the goldens instead of comparing to them), and
#                    every filtered step declares its test count so a filter that selects nothing is
#                    RED rather than vacuously green (see filtered_cargo_test).
#   config-stability cargo xtask gate config-schema (config-schema.snapshot.json byte-stable).
#   test             cargo test --workspace  +  cargo test -p busbar-voice --features runtime.
#   conformance      the conformance rigs' selftests + verdict-covers-every-leg.py + the voice legs =ready.
#   teller-steps     the H2 matrix holds on BOTH its columns: every rig cell id still resolves to the
#                    scenario/script/leg/suite that owns it, and the rigs behind them RUN and pass
#                    (testing/shadow-oracle/rigs-ledger.sh, driven from the TELLER-STEPS group
#                    rather than from the gate runner, which segregation forbids), and every
#                    root-leg cell it calls proven runs over the loop.
#   no-deferral      cargo xtask gate no-deferral-strict-done (nothing deferred; voice markers CLEARED).
#   config-noun      scripts/plane-config-noun-gate.sh armed (GREP_GATE_REPORT_ONLY=0). Its residual is
#                    a LOCKED-legitimate floor, not zero and not a done condition, so what is asserted
#                    is the floor itself: the run must PRODUCE a count (a gate that errored, or whose
#                    verdict line moved, is RED) and that count must not RISE above CONFIG_NOUN_FLOOR.
#                    A fall is green and says so — lower the floor when it lands.
#   equality         scripts/capability-equality-summary.py reports 0 missing cells (LLM==MCP==A2A true),
#                    AND the ledger's root column holds with all five root-* legs on and every cell it
#                    calls `proven` over the loop actually runs and passes.
#   isomorphism      the crates/busbar/tests/plane_isomorphism.rs gate is present and green.
#   parity           testing/shadow-oracle: this build vs the PUBLISHED 1.5.5 binary, 0 divergences
#                    across every recorded cell family (wire, admin, boot, CLI, config, billing,
#                    failover, plugins); golden gaps are named, never passes. Both ENDS of that
#                    comparison are pinned by digest and the group REFUSES rather than reports when
#                    either is unproven: the subject is BOTH legs the release claims (the default
#                    all-planes build AND the LLM-only build, two different binaries), each the
#                    artefact its release build itself names (never a relative path something else
#                    can occupy), each recording must carry its artefact's sha256; the golden is the
#                    COMMITTED 1.5.5 recording, never re-recorded here, checked whole and carrying a
#                    sha256 this repository commits for 1.5.5; every in-scope cell without a golden
#                    is named in accepted-gaps.json; and the verdict is read out of the report — so
#                    a run that compared the wrong binary, or compared nothing at all, is a refusal.
#   design           cargo xtask gate design-bindings --strict: every ARCHITECTURE.md Appendix B
#                    binding is mapped to a check that still exists in the tree (test, oracle cell,
#                    lint, gate). An unmapped binding is a named gap and is RED here -- "done" means
#                    nothing we designed is unproven. Existence only; the checks run in their own tiers.
#   changelog        cargo xtask gate changelog-register: EVERY entry in
#                    testing/shadow-oracle/accepted-differences.json -- improvement as well as
#                    breaking, per ARCHITECTURE.md's owner rule -- has its `changelog` field's exact
#                    line present, verbatim, in CHANGELOG.md, or an explicit null with a written
#                    reason. A difference the owner accepted cannot silently fall out of the release
#                    notes, and a break may never waive its line.
# Every sub-gate runs its own `--selftest` FIRST where it has one, then its `--check`, so a gate that
# could not fire is refused before its verdict is trusted (the house rule).
#
# LOCKED EXCLUSION (00-MASTER-PLAN "RECONCILED DECISIONS"): the done-oracle DELIBERATELY does NOT
# require scripts/plane-noun-gate.sh / scripts/plane-grep-gate.sh == 0. Those meter LLM BILLING VOCAB
# that STAYS in the neutral crates by the LOCKED invariant — an orthogonal axis, not a done condition.
# Including them would gate the release on a debt the owner ruled out of scope; they are not here.
#
# PROGRESS METER. This is fail-SOFT across groups: it RUNS EVERY sub-gate, collects every RED, prints a
# grouped readout, and exits non-zero if ANY group is RED. So on an unfinished tree it doubles as a
# checklist of what is left — never aborting at the first red.
#
# FLAGS:
#   --fast   substitute `cargo build --workspace` for the heavy full-gate battery in the BUILD group
#            (for a quick progress read); every other group still runs in full. Without it, BUILD runs
#            the full `cargo xtask full-gate` — the real DONE claim. A --fast run that comes out clean
#            reports PROVISIONAL and exits 3, never the DONE banner and never exit 0: the banner and
#            the exit code are all a wrapper, a CI step or the proof collator ever sees, so a
#            provisional answer must not be spendable as the real one.
#   --selftest  prove the verdict itself (the floor, the --fast demotion, red-group handling).
#
# bash 3.2 + POSIX, the same bare-runner posture as the sibling gates.
set -uo pipefail
# Resolved BEFORE the cd, because the floor below is counted out of this file and `$0` stops
# resolving the moment the working directory moves under a relative invocation.
SELF="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")"
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
bold() { printf '\033[1m%s\033[0m\n' "$*"; }
hdr()  { printf '\n\033[1m══ %s ══\033[0m\n' "$*"; }

# --help prints the WHOLE header comment -- every line from 2 up to the first non-comment line --
# rather than a hand-typed range. The range was `2,66`, and the header grew past it: the FLAGS block
# (--fast, --selftest, and the rule that a --fast run is PROVISIONAL and exits 3, the one contract a
# wrapper author most needs) sat below the cut and --help never showed it.
print_help() { awk 'NR == 1 { next } /^#/ { sub(/^# ?/, ""); print; next } { exit }' "$SELF"; }

FAST=0 SELFTEST=0
case "${1:-}" in --fast) FAST=1 ;; --selftest) SELFTEST=1 ;; "" ) ;; -h|--help) print_help; exit 0 ;; *) echo "usage: $0 [--fast|--selftest]" >&2; exit 2 ;; esac

# Results accumulators (parallel arrays — bash 3.2 has no assoc arrays).
G_NAME=(); G_STATE=(); G_NOTE=()
CUR_GROUP=""; CUR_RED=0; CUR_FIRST_NOTE=""
begin_group() { CUR_GROUP="$1"; CUR_RED=0; CUR_FIRST_NOTE=""; hdr "$1"; }
end_group() {
  G_NAME+=("$CUR_GROUP")
  if [ "$CUR_RED" -eq 0 ]; then G_STATE+=("GREEN"); G_NOTE+=(""); else G_STATE+=("RED"); G_NOTE+=("$CUR_FIRST_NOTE"); fi
}

# Run one step; print [ok]/[RED]; on RED, mark the current group red and remember the first reason.
step() {   # $1 = label ; rest = command
  local label="$1"; shift
  if "$@" >/tmp/done-oracle-step.$$ 2>&1; then
    printf '  \033[32m[ok]\033[0m   %s\n' "$label"
  else
    printf '  \033[31m[RED]\033[0m  %s\n' "$label"
    sed 's/^/          /' /tmp/done-oracle-step.$$ | tail -4
    CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="$label"
  fi
  rm -f /tmp/done-oracle-step.$$
}
# ── THE ONE VERDICT, as a function so --selftest can drive it ───────────────────────────────────
# It used to be a straight-line tail nobody could exercise without running every gate in the file
# for twenty minutes, which is why both of the defects it now refuses lived in it.
#
# THE FLOOR. `fail` starts at 0 and only a group can raise it, so an empty G_NAME — a refactor that
# moves the group definitions, an early `return` in a sourced fragment — walks straight past the
# loop and announces DONE having judged nothing. (On bash 3.2, the macOS bare runner this file
# targets, `${!G_NAME[@]}` on an empty array under `set -u` is a hard error instead; on Linux CI's
# bash 5 it is silently empty. The floor makes both hosts answer the same way.)
#
# --fast IS NOT A DONE CLAIM. It substitutes `cargo build --workspace` for the full ci battery, so
# the run never executed `clippy -D warnings` or the test tiers the BUILD group's name promises. It
# said so in one yellow line hundreds of lines earlier and then printed the SAME unqualified DONE
# banner and the SAME exit 0 as a full run — and the banner and the exit code are all a wrapper
# script, a CI step or the proof-manifest collator ever sees. A provisional answer must not be
# spendable as the real one.
# THE FLOOR IS COUNTED OUT OF THIS FILE, AND IT IS NOT LOWERABLE FROM THE ENVIRONMENT.
#
# It was a hand-maintained constant, `DONE_GROUP_FLOOR="${DONE_GROUP_FLOOR:-19}"`, and it had two
# holes that both end in the DONE banner and exit 0 — which is all a wrapper, a CI step or the proof
# collator ever reads:
#
#   * IT HAD FALLEN BEHIND THE FILE. This script defines TWENTY begin_group/end_group pairs; the
#     constant still said nineteen. So a run that lost a whole group — a `begin_group` moved inside
#     an `if` that did not fire, a sourced fragment that returned early, a group deleted in a
#     refactor and its constant left alone — reported "19 / 19 groups GREEN" and announced DONE. The
#     floor exists precisely to catch that, and it was one short of being able to.
#   * IT WAS AN ENVIRONMENT OVERRIDE. `DONE_GROUP_FLOOR=1 scripts/verify-1.6.0-done.sh` made one
#     green group a DONE claim. Every other operator-chosen repoint in this file is refused by
#     assert_bless_env_empty for exactly this reason; the floor on the verdict itself was the one
#     that could still be dialled down, and unlike a blessed golden it leaves nothing behind.
#
# So: the number of groups this file DEFINES is counted from the file, the declared constant must
# agree with it (a group added or removed is a two-place edit a reviewer sees), and the environment
# may only ever RAISE the floor. A count that cannot be taken is RED, never a floor of zero.
DONE_GROUPS_DECLARED=23
# awk, not `grep -c ... || echo 0`: `grep -c` on a file with no matches PRINTS 0 and EXITS 1, so the
# obvious fallback fires on top of grep's own output and the variable becomes the two-line string
# "0\n0" — which then fails every numeric comparison below and takes the honest-floor check with it.
# (gate.sh carries the same note over the same trap.) awk prints exactly one number, always.
DONE_GROUPS_DEFINED="$(awk '/^begin_group /{n++} END{print n+0}' "$SELF" 2>/dev/null)"
[ -n "$DONE_GROUPS_DEFINED" ] || DONE_GROUPS_DEFINED=0
DONE_GROUP_FLOOR="$DONE_GROUPS_DECLARED"
# An override may only tighten. `-gt` and not `-ne`: a caller raising the floor is asserting more,
# which is always safe to honour; a caller lowering it is un-owing groups from outside the file.
if [ -n "${DONE_GROUP_FLOOR_MIN:-}" ] && [ "${DONE_GROUP_FLOOR_MIN}" -gt "$DONE_GROUP_FLOOR" ] 2>/dev/null; then
  DONE_GROUP_FLOOR="$DONE_GROUP_FLOOR_MIN"
fi

# Checked at the top of the verdict rather than here, so --selftest can drive it.
floor_is_honest() {
  if [ "${DONE_GROUPS_DEFINED:-0}" -lt 1 ] 2>/dev/null; then
    red "══ done-oracle: could not count the begin_group definitions in ${SELF} — the floor would be"
    red "   whatever the constant happens to say, checked against nothing. Refusing to render a verdict. ══"
    return 1
  fi
  if [ "$DONE_GROUPS_DEFINED" != "$DONE_GROUPS_DECLARED" ]; then
    red "══ done-oracle: this file defines ${DONE_GROUPS_DEFINED} group(s) but declares a floor of"
    red "   ${DONE_GROUPS_DECLARED}. A group was added or removed and the declaration did not follow, so the"
    red "   floor no longer measures anything. Set DONE_GROUPS_DECLARED=${DONE_GROUPS_DEFINED}. ══"
    return 1
  fi
  return 0
}
final_verdict() {
  local fail=0 green=0 total=0 i
  floor_is_honest || return 1
  if [ "${#G_NAME[@]}" -gt 0 ]; then
    for i in $(seq 0 $(( ${#G_NAME[@]} - 1 ))); do
      total=$((total+1))
      if [ "${G_STATE[$i]}" = "GREEN" ]; then
        green=$((green+1)); printf '  \033[32m● GREEN\033[0m  %s\n' "${G_NAME[$i]}"
      else
        fail=1; printf '  \033[31m● RED  \033[0m  %s   — %s\n' "${G_NAME[$i]}" "${G_NOTE[$i]}"
      fi
    done
  fi
  printf '\n'
  bold "  $green / $total groups GREEN"
  if [ "$total" -lt "$DONE_GROUP_FLOOR" ]; then
    red "══ busbar 1.6.0 done-oracle: only ${total} group(s) reported, floor is ${DONE_GROUP_FLOOR} — groups went missing, so nothing here is a verdict. ══"
    return 1
  fi
  if [ "$fail" -eq 0 ]; then
    if [ "$FAST" -eq 1 ]; then
      ylw "══ busbar 1.6.0: PROVISIONAL — every sub-gate that RAN is green, but --fast substituted"
      ylw "   'cargo build --workspace' for the full ci battery, so the BUILD group proves much less"
      ylw "   than its name. Re-run without --fast before calling 1.6.0 done. ══"
      return 3
    fi
    grn "══ busbar 1.6.0 is DONE — every sub-gate is green. ══"
    return 0
  fi
  red "══ busbar 1.6.0 is NOT done — $((total-green)) group(s) RED (see above). This readout is the work queue. ══"
  return 1
}

if [ "$SELFTEST" -eq 1 ]; then
  _st_fails=0
  _st() {  # _st <label> <want-rc> <want-substring> <fast> <n-green> <n-red>
    local label="$1" want="$2" needle="$3" fast="$4" ng="$5" nr="$6" out rc j
    out="$(
      FAST="$fast"; G_NAME=(); G_STATE=(); G_NOTE=()
      for j in $(seq 1 "$ng"); do [ "$ng" -eq 0 ] || { G_NAME+=("g$j"); G_STATE+=("GREEN"); G_NOTE+=(""); }; done
      for j in $(seq 1 "$nr"); do [ "$nr" -eq 0 ] || { G_NAME+=("r$j"); G_STATE+=("RED"); G_NOTE+=("because"); }; done
      final_verdict; echo "RC=$?"
    )"
    rc="${out##*RC=}"
    if [ "$rc" = "$want" ] && printf '%s' "$out" | grep -q -- "$needle"; then
      printf 'PASS  %s\n' "$label"
    else
      printf 'FAIL  %s (rc=%s want=%s, looked for %s)\n' "$label" "$rc" "$want" "$needle"; _st_fails=$((_st_fails+1))
    fi
  }
  # THE COUNTS ARE TAKEN FROM THE FILE, NOT TYPED. They used to be the literal 19 the floor
  # happened to say, so the case that is supposed to prove "a lost group is refused" was passing a
  # number that WAS the floor rather than one below the groups this file actually defines — which is
  # how the floor came to sit one under reality with a green self-test over it.
  _n="$DONE_GROUPS_DEFINED"
  # A --fast run whose groups are all green must NOT be spendable as the DONE claim.
  _st "--fast + all green -> PROVISIONAL, non-zero"      3 "PROVISIONAL"    1 "$_n"           0
  _st "full run + all green -> DONE, exit 0"             0 "is DONE"        0 "$_n"           0
  _st "--fast + a red group -> NOT done"                 1 "is NOT done"    1 "$((_n - 1))"   1
  _st "full run + a red group -> NOT done"               1 "is NOT done"    0 "$((_n - 1))"   1
  # Zero groups is not DONE: nothing raised `fail`, because nothing ran.
  _st "zero groups -> RED, never DONE"                   1 "floor is"       0 0              0
  _st "groups went missing (below the floor) -> RED"     1 "floor is"       0 3              0
  # ONE group short of what this file DEFINES. The case the old literal could not express: with the
  # floor one under the group count, this run printed "19 / 19 groups GREEN" and the DONE banner.
  _st "one group short of the defined set -> RED"        1 "floor is"       0 "$((_n - 1))"   0

  # THE FLOOR ITSELF MUST BE HONEST, and it must not be dialled down from outside the file.
  if floor_is_honest >/dev/null 2>&1; then
    printf 'PASS  the declared floor matches the %s group(s) this file defines\n' "$_n"
  else
    printf 'FAIL  the declared floor (%s) does not match the %s group(s) defined\n' \
      "$DONE_GROUPS_DECLARED" "$_n"; _st_fails=$((_st_fails + 1))
  fi
  ( DONE_GROUPS_DECLARED=$((_n - 1)); floor_is_honest ) >/dev/null 2>&1 \
    && { printf 'FAIL  a declaration one under the defined group count was accepted\n'; _st_fails=$((_st_fails + 1)); } \
    || printf 'PASS  a declaration that has fallen behind the group count -> RED\n'
  ( DONE_GROUPS_DEFINED=0; floor_is_honest ) >/dev/null 2>&1 \
    && { printf 'FAIL  a group count that could not be taken was accepted as a floor\n'; _st_fails=$((_st_fails + 1)); } \
    || printf 'PASS  a group count that could not be taken -> RED, not a floor of zero\n'
  # The environment may raise the floor and may not lower it. Driven through a real re-read of the
  # floor block out of this file, so it is the shipped derivation under test and not a copy of it.
  _floor_under() {  # _floor_under <env assignment>  -> prints the floor the script would use
    env "$1" bash -c '
      SELF="$1"; shift
      eval "$(awk "/^DONE_GROUPS_DECLARED=/,/^fi\$/" "$SELF")"
      echo "$DONE_GROUP_FLOOR"' _ "$SELF"
  }
  if [ "$(_floor_under DONE_GROUP_FLOOR=1)" = "$_n" ]; then
    printf 'PASS  DONE_GROUP_FLOOR=1 in the environment cannot lower the floor\n'
  else
    printf 'FAIL  the environment lowered the floor to %s\n' "$(_floor_under DONE_GROUP_FLOOR=1)"
    _st_fails=$((_st_fails + 1))
  fi
  if [ "$(_floor_under DONE_GROUP_FLOOR_MIN=1)" = "$_n" ]; then
    printf 'PASS  DONE_GROUP_FLOOR_MIN below the floor cannot lower it\n'
  else
    printf 'FAIL  DONE_GROUP_FLOOR_MIN lowered the floor to %s\n' "$(_floor_under DONE_GROUP_FLOOR_MIN=1)"
    _st_fails=$((_st_fails + 1))
  fi
  if [ "$(_floor_under DONE_GROUP_FLOOR_MIN=$((_n + 5)))" = "$((_n + 5))" ]; then
    printf 'PASS  DONE_GROUP_FLOOR_MIN above the floor still raises it (a caller may owe more)\n'
  else
    printf 'FAIL  DONE_GROUP_FLOOR_MIN could not raise the floor\n'; _st_fails=$((_st_fails + 1))
  fi
  echo
fi

# A step that is RED simply because an artifact does not exist yet (a not-yet-built sub-gate).
absent_step() { printf '  \033[31m[RED]\033[0m  %s — NOT PRESENT YET (%s)\n' "$1" "$2"; CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="$1 (absent)"; }

# THE BUILD GROUP, as a function so --selftest can drive its arms. Without --fast the ONLY green
# BUILD is the full-gate battery. A missing qa/full-gate.toml used to fall through to three plain
# `cargo build`s -- no clippy, no test tier -- and still report GREEN, print the unqualified DONE
# banner and exit 0: the exact downgrade --fast was demoted to PROVISIONAL / exit 3 for, reachable by
# deleting one file. A missing register is now RED, named, like every other absent sub-gate.
run_build_group() {  # $1 = the full-gate register path
  local register="$1"
  if [ "$FAST" -eq 1 ]; then
    ylw "  --fast: substituting 'cargo build --workspace' for the full ci battery"
    step "cargo build --workspace" cargo build --workspace --quiet
  elif [ -f "$register" ]; then
    step "cargo xtask full-gate --selftest" cargo xtask full-gate --selftest
    step "cargo xtask full-gate"            cargo xtask full-gate
  else
    absent_step "full-gate register (BUILD without it is three plain builds: no clippy, no test tier)" "$register"
  fi
}

# THE VOICE LEGS ARE =READY, READ OFF THE RIG'S OWN --list. The CONFORMANCE group is titled
# "voice legs =ready", and its only voice step was the rig's --selftest, whose last check accepts a
# battery in which EVERY leg is LEG_STATUS=pending (it prints "NOT a conformance pass" to a stdout it
# then discards, and returns 0). So nothing compared LEG_STATUS to `ready` anywhere. This does.
# VOICE_LEGS_DIR is the rig's own fixture override; it is cleared for the real read so an operator
# cannot point the DONE run at a hand-made legs directory. --selftest passes a fixture dir.
voice_legs_all_ready() {  # $1 = runner ; $2 = legs dir (selftest fixture) or empty for the shipped legs
  local runner="$1" dir="${2:-}" out n notready
  if [ -n "$dir" ]; then
    out="$(VOICE_LEGS_DIR="$dir" bash "$runner" --list 2>&1)" || { printf '%s\n' "$out"; echo "the voice rig could not list its legs"; return 1; }
  else
    out="$(env -u VOICE_LEGS_DIR bash "$runner" --list 2>&1)" || { printf '%s\n' "$out"; echo "the voice rig could not list its legs"; return 1; }
  fi
  n="$(printf '%s\n' "$out" | grep -c ' status=' || true)"
  if [ "${n:-0}" -lt 1 ]; then
    printf '%s\n' "$out"; echo "the voice rig listed ZERO legs — nothing is =ready because nothing is there"; return 1
  fi
  notready="$(printf '%s\n' "$out" | grep ' status=' | grep -v ' status=ready ' || true)"
  if [ -n "$notready" ]; then
    echo "voice leg(s) NOT LEG_STATUS=ready — a pending leg asserts no conformance at all:"
    printf '%s\n' "$notready"
    return 1
  fi
  echo "all $n voice leg(s) are LEG_STATUS=ready"
}

# EVERY `cargo xtask gate <name>` THIS FILE RUNS IS A REGISTERED GATE, per the registry's own
# `--list` (the instrument, not a grep of its source). The AUDIT-LEDGER group ran
# `cargo xtask gate audit-ledger --selftest` for a gate deleted with its register; it
# was masked only because the `if` around it guarded on that deleted register too, so a restored
# register would have met a step that can only fail. Flags (`--all`, `--list`) are not gate names.
xtask_gates_invoked_are_registered() {  # $1 = file to scan
  local file="$1" listed invoked g bad=""
  listed="$(cargo xtask gate --list 2>/dev/null | awk '{print $1}')" || true
  [ -n "$listed" ] || { echo "cargo xtask gate --list printed nothing — the registry cannot be read, so nothing can be checked against it"; return 1; }
  invoked="$(grep -v '^[[:space:]]*#' "$file" | grep -oE 'cargo xtask gate [a-z0-9][a-z0-9-]*' | awk '{print $4}' | sort -u)"
  [ -n "$invoked" ] || { echo "found no \`cargo xtask gate <name>\` invocation in $file — the scan read nothing"; return 1; }
  for g in $invoked; do
    printf '%s\n' "$listed" | grep -qx -- "$g" || bad="${bad:+$bad }$g"
  done
  if [ -n "$bad" ]; then
    echo "invoked but NOT registered (cargo xtask gate --list): $bad"
    return 1
  fi
  echo "$(printf '%s\n' "$invoked" | grep -c .) gate name(s) invoked, every one registered"
}

# NON-VACUITY FOR A FILTERED `cargo test`. A name filter selects by substring across every target
# cargo builds, and a filter that matches NOTHING still exits 0 — "running 0 tests ... 0 passed; N
# filtered out" — so a step whose filter has drifted (wrong -p, a renamed test, a moved module) goes
# green while proving nothing at all. Every filtered step below therefore DECLARES how many tests it
# expects, and this wrapper refuses the run unless exactly that many actually passed. The declared
# number is part of the assertion: a test deleted out of the set is as red as a test that failed.
filtered_cargo_test() {  # $1 = expected passing count ; rest = the cargo argv
  local want="$1"; shift
  local out rc got
  out="$("$@" 2>&1)"; rc=$?
  if [ "$rc" -ne 0 ]; then printf '%s\n' "$out"; return "$rc"; fi
  got="$(printf '%s\n' "$out" \
    | sed -n 's/^test result: ok\. \([0-9][0-9]*\) passed.*/\1/p' \
    | awk '{ n += $1 } END { print n+0 }')"
  if [ "$got" != "$want" ]; then
    printf '%s\n' "$out"
    printf 'VACUITY: this filter was expected to run %s test(s); the run reported %s passed.\n' "$want" "$got"
    printf 'Either the filter no longer selects the intended tests, or the expected count is stale.\n'
    return 1
  fi
  printf '%s test(s) passed, exactly the expected set.\n' "$got"
}

# Assert the money-path bless/regen env vars are EMPTY — otherwise a byte-identity "check" silently
# REGENERATES the golden instead of comparing against it (a green that proves nothing).
#
# THE LIST IS "EVERY VARIABLE THAT CAN MAKE A COMPARISON COMPARE NOTHING", not "every variable with
# BLESS in its name", and three of them were missing:
#
#   * SHADOW_ORACLE_GOLDEN repoints the PARITY group's golden recording. Set it to
#     `$ORACLE_DIR/recordings/candidate` and replay.sh diffs the candidate against ITSELF: zero
#     divergences, every cell present, a perfect parity report that compared a build to a copy of
#     itself. It is a stronger bless than any of the four already listed here, because those at
#     least rewrite a golden a reviewer can then diff, while this one leaves no trace at all.
#   * SHADOW_ORACLE_DIR does the same thing one level up.
#   * CONFIG_SCHEMA_BASELINE_REF repoints the config-stability gate's additive-only baseline. That
#     gate's whole content is the diff against the baseline; pointing it at HEAD, or at any ref
#     carrying an older snapshot, makes every non-additive change additive.
#   * CONFIG_SCHEMA_BOOTSTRAP is that gate's declared one-run escape from having no baseline at all.
#     It exists so a missing baseline announces itself rather than passing silently — which makes it
#     exactly the kind of thing a DONE run must refuse.
#
# FOUR MORE, all PARITY-specific (BYTE-IDENTITY never shells to bin/oracle, so these four are inert
# there; they stay in this ONE shared list anyway, the same way SHADOW_ORACLE_GOLDEN/DIR above are —
# a variable that cannot fire in a group it also guards is a no-op there, not a hole):
#   * BUSBAR_ORACLE_DATA repoints bin/oracle's whole data dir — cells.json, the golden registers,
#     accepted-differences.json, accepted-gaps.json, owed-baseline.txt, the cell drivers. Point it at
#     a directory with a thinner cells.json or a pre-accepted diff and PARITY judges a corpus nobody
#     reviewed, however green the report reads.
#   * BUSBAR_ORACLE_PRODUCT_ROOT repoints the product bin/oracle records FROM. Set it off this
#     checkout and PARITY records and diffs some OTHER tree's candidate while this script's own
#     banner still says this tree is what was proven.
#   * BUSBAR_ORACLE_TOOL_DIR repoints where bin/oracle's generated record.sh/replay.sh shims (and any
#     caller that locates the harness through this var, e.g. the turnstile) are read from — an
#     operator-chosen tool dir is an operator-chosen judge.
#   * BUSBAR_ORACLE_CACHE repoints the cached golden `fetch-golden --check` verifies against
#     (default `$HOME/.cache/busbar-oracle`). Point it at a cache seeded with a hand-edited "1.5.5"
#     and `fetch-golden --check` calls it pinned.
#
# ELEVEN MORE (item 49), each with a reader in this tree:
#   * BUSBAR_ORACLE_RUST_BIN / BUSBAR_RELEASE_CHECKOUT pick the oracle's Rust binary (bin/oracle,
#     resolve step 1 and 2): a prebuilt path, or a checkout to build it from. That is the JUDGE
#     itself, chosen by the operator — stronger than repointing its data.
#   * BUSBAR_EMIT_OPENAPI makes `emit_openapi_artifact` (busbar-core-admin json tests) write the
#     served doc to any path. BYTE-IDENTITY's `openapi` filter runs that test next to the
#     json-matches-committed golden, so pointed at the committed openapi.json it rewrites the golden
#     the same run compares against.
#   * BUSBAR_UPDATE_GOLDEN (busbar-plugin tests/layout_golden.rs), UPDATE_KEYS_ERROR_GOLDEN
#     (busbar-core-admin keys error wire) and UPDATE_DIAGNOSTICS (busbar-a2a diagnostics markdown)
#     each write the fresh bytes over the committed golden and RETURN before asserting. The BUILD
#     group's full-gate runs all three.
#   * XTASK_INSN_EMIT_BASELINE / XTASK_PPB_EMIT_BASELINE switch instance-noun-neutrality and
#     plane-pricing-blindness into their baseline-regeneration mode (the census printed as the
#     qa/*.toml the gate compares against). The run is then a re-baselining run, not a DONE run.
#   * GREP_GATE_REPORT_ONLY (plane-grep/noun/config-noun gates) and SECRET_GATE_REPORT_ONLY
#     (secret-hygiene gate) turn a gate's RED into exit 0. This file pins GREP_GATE_REPORT_ONLY=0
#     inline where it runs the config-noun --check; refusing the exported value means a refactor
#     that drops the inline pin cannot quietly inherit a report-only gate.
# BUSBAR_ARM64_BASELINE is NOT here: scripts/pgo-build.sh reads it to pick an armv8.0 target CPU for
# a release artefact. No step in this file builds that artefact, and nothing compares against it.
#
# A DONE run means "this tree was measured against something outside itself". Any of these set means
# it was measured against something the operator chose, which is a different claim.
#
# UPDATE_CONFIG_SCHEMA IS GONE FROM THIS LIST, and its absence is a strengthening rather than a
# relaxation. The config-schema gate's regen path is now the `--write` FLAG, not an environment
# variable, and this script invokes the gate without it — so a DONE run structurally CANNOT
# regenerate the snapshot, where before it could only be asserted not to have. A flag has to be
# written at the call site, in a diff. The two CONFIG_SCHEMA_* variables stay: the gate still reads
# both, and both still defeat the claim this script makes.
assert_bless_env_empty() {
  local v bad=0
  for v in UPDATE_OPENAPI BLESS_BACKCOMPAT_CORPUS BUSBAR_BLESS_GOLDEN \
           SHADOW_ORACLE_GOLDEN SHADOW_ORACLE_DIR CONFIG_SCHEMA_BASELINE_REF CONFIG_SCHEMA_BOOTSTRAP \
           BUSBAR_ORACLE_DATA BUSBAR_ORACLE_PRODUCT_ROOT BUSBAR_ORACLE_TOOL_DIR BUSBAR_ORACLE_CACHE \
           BUSBAR_ORACLE_RUST_BIN BUSBAR_RELEASE_CHECKOUT BUSBAR_EMIT_OPENAPI \
           BUSBAR_UPDATE_GOLDEN UPDATE_KEYS_ERROR_GOLDEN UPDATE_DIAGNOSTICS \
           XTASK_INSN_EMIT_BASELINE XTASK_PPB_EMIT_BASELINE \
           GREP_GATE_REPORT_ONLY SECRET_GATE_REPORT_ONLY; do
    if [ -n "${!v:-}" ]; then echo "regen/repoint env var $v is SET ('${!v}') — the comparison would be against something the operator chose, not the pinned reference"; bad=1; fi
  done
  return "$bad"
}

# Assert SKIP_BOOT_LEG is EMPTY — a DIFFERENT kind of hole than the bless/repoint vars above (it does
# not make a byte comparison compare nothing; it makes PLANE-DELETE not run the comparison at all).
# scripts/plane-delete-test.sh reads it (its own `--skip-boot-leg` flag sets it) and, when set, skips
# Leg 3 — the boot+serve leg that proves the plane's route is actually GONE at runtime, on every plane
# — leaving only Leg 1/Leg 2 (the plane compiles out), which a DONE run must not silently accept as
# "the plane is deletable". This is checked in the PLANE-DELETE group itself, not folded into
# assert_bless_env_empty: that function's two callers are BYTE-IDENTITY and PARITY, neither of which
# runs plane-delete-test.sh, so a var only PLANE-DELETE reads has to be asserted where PLANE-DELETE
# actually runs or the refusal never fires.
assert_skip_boot_leg_empty() {
  if [ -n "${SKIP_BOOT_LEG:-}" ]; then
    echo "SKIP_BOOT_LEG is SET ('$SKIP_BOOT_LEG') — plane-delete-test.sh would skip the boot+serve leg, downgrading PLANE-DELETE to a compile-only check"
    return 1
  fi
  return 0
}

# ── PARITY'S SUBJECT — THE CANDIDATE MUST BE THE BINARY THIS RUN BUILT, OR THE RUN REFUSES ───────
# PARITY is the only group in this file that compares this tree with something it did not write: the
# binary published with the previous release. That is what makes its answer unmanufacturable by the
# work being measured, and it is exactly why its SUBJECT has to be pinned as hard as its baseline.
#
# IT WAS NOT, in two independent ways, and each one produces a confident number about the wrong file.
#
#   1. THE SUBJECT WAS A HARD-CODED RELATIVE PATH. `record --bin target/release/busbar` sat one line
#      under `cargo build -p busbar --release --locked`, and those two name the same file only when
#      cargo's output directory is `./target`. CARGO_TARGET_DIR or CARGO_BUILD_TARGET_DIR in the
#      environment, or a `[build] target-dir` in any .cargo/config.toml above this checkout, sends
#      the build elsewhere while the recorder still opens the relative path. If anything has left a
#      binary — or a symlink to one — at that path, the recorder takes THAT as the subject, and the
#      divergence count it reports reads as a statement about this tree. It cannot fail loudly,
#      because the path exists and is executable, which was the whole test it had to pass. That is
#      not a broken instrument; it is a worse thing, an instrument that answers about a subject
#      nobody asked about, confidently.
#      The repair is not a better relative path. It is to stop guessing. Under
#      `--message-format=json-render-diagnostics` cargo prints `"executable":"<path>"` for the bin
#      target, on a no-op build as well as a fresh one, so the artefact of THIS invocation in THIS
#      tree is a fact the build itself states. `bin/oracle` already resolves the JUDGE that way; this
#      resolves the SUBJECT the same way, and the two-path hole closes by construction.
#
#   2. NOTHING READ WHAT WAS ACTUALLY RECORDED. The recorder stamps the binary it executed into the
#      recording's own meta.json as `binary_sha256`, and no caller ever compared it with anything.
#      So even a correct `--bin` argument proved nothing about the bytes behind it.
#      `assert_recorded_subject` digests the resolved artefact BEFORE the record and requires the
#      recording to name that same digest AFTER — closing the hole from the far side, independently
#      of how the path was chosen, and putting the subject's identity in the run's own output.
#
# THE BASELINE GETS THE SAME TREATMENT. The golden used to be re-recorded here whenever its recording
# directory was empty, and trusted sight unseen whenever it was not. It is now the committed recording
# (parity_install_golden, TODO item 41), and `assert_golden_is_pinned` requires that recording's
# `binary_sha256` to be a digest this repository COMMITS for the baseline release in
# testing/shadow-oracle/golden-digests.tsv. A baseline nobody can identify is not an external
# baseline. It is load-bearing rather than decorative: the cached baseline binary a re-record would
# read from is not always present on the machine, and when it is gone the committed digest is the
# only thing left that says what the reused recording is.
#
# AND THE VERDICT IS READ FROM THE REPORT, NOT FROM THE EXIT CODE. The differ's rc is the verdict
# ONLY under `--strict`; without it the run prints its rows and exits 0 whatever they say. Measured
# on this corpus: the same recording pair exits 0 with eight unaccepted divergences, and — the worse
# half — exits 0 having compared ZERO cells when the id filter selects nothing, writing a report
# whose `diverging` is 0 because its `owed` is 0. A run that measured nothing and a run that found
# nothing are the same zero to any caller reading the exit status. `--strict` is passed below, and
# `assert_parity_verdict` re-derives both facts from the report itself so the claim does not rest on
# one flag in one pinned engine.
#
# The baseline release is a constant here, not an override: a variable an operator can set is one
# more way to choose what this group compares against.
PARITY_BASELINE_VERSION=1.5.5

sha256_of() {  # $1 = file ; prints the lowercase hex digest
  if command -v shasum >/dev/null 2>&1; then shasum -a 256 "$1" | awk '{print $1}'
  elif command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | awk '{print $1}'
  else echo "neither shasum nor sha256sum is on PATH — the subject cannot be identified" >&2; return 1; fi
}

# Read one dotted field out of a JSON file. A refusal that cannot be EVALUATED is a refusal that did
# not fire, so a missing python3 returns non-zero (refuse) rather than empty (accept).
json_field() {  # $1 = json file ; $2 = dotted path
  command -v python3 >/dev/null 2>&1 || { echo "python3 is not on PATH, so this refusal cannot be evaluated — refusing rather than passing" >&2; return 2; }
  python3 -c '
import json, sys
try:
    d = json.load(open(sys.argv[1]))
except Exception as e:
    sys.stderr.write("unreadable JSON %s: %s\n" % (sys.argv[1], e)); sys.exit(2)
for k in sys.argv[2].split("."):
    if not isinstance(d, dict) or k not in d:
        sys.stderr.write("missing field %s in %s\n" % (sys.argv[2], sys.argv[1])); sys.exit(3)
    d = d[k]
print(d)
' "$1" "$2"
}

# The path the build named must be a real, executable, NON-SYMLINK file. The symlink arm is not
# tidiness: a stray link at the recorder's path is exactly how a foreign build got in front of this
# instrument on this checkout, and it is the one shape that satisfies `-x` while pointing at another
# tree entirely.
assert_candidate_bin_sane() {  # $1 = candidate path
  local p="${1:-}"
  if [ -z "$p" ]; then
    echo "the release build named no executable artefact — there is no subject to record"; return 1
  fi
  if [ -L "$p" ]; then
    echo "the candidate path is a SYMLINK: $p -> $(readlink "$p")"
    echo "a link here records whatever tree it points at and reports the answer as this one's — refusing"
    return 1
  fi
  if [ ! -f "$p" ]; then echo "the candidate binary is not a regular file: $p"; return 1; fi
  if [ ! -x "$p" ]; then echo "the candidate binary is not executable: $p"; return 1; fi
  return 0
}

# The recording must name the binary we digested a moment ago. This is the check that would have
# caught the foreign build even with the old hard-coded path in place.
assert_recorded_subject() {  # $1 = recording dir ; $2 = expected sha256 ; $3 = what it is
  local dir="${1:-}" want="${2:-}" what="${3:-the recording}" got
  if [ -z "$want" ]; then
    echo "no expected digest was computed for $what — refusing rather than accepting any subject"; return 1
  fi
  if ! got="$(json_field "$dir/meta.json" binary_sha256 2>/dev/null)"; then
    echo "$what at $dir does not state which binary it executed (meta.json / binary_sha256 unreadable)"
    echo "a recording that cannot name its subject is not evidence about one — refusing"
    return 1
  fi
  if [ "$got" != "$want" ]; then
    echo "$what recorded a DIFFERENT binary than the one this run built:"
    echo "  built    sha256 $want"
    echo "  recorded sha256 $got   ($dir/meta.json)"
    echo "every number in the report would be about that other file — refusing"
    return 1
  fi
  return 0
}

# The golden must be the published artefact, and must prove it by a digest this repository commits.
assert_golden_is_pinned() {  # $1 = golden recording dir ; $2 = the committed digest table ; $3 = version
  local dir="${1:-}" tsv="${2:-}" ver="${3:-}" got
  if ! got="$(json_field "$dir/meta.json" binary_sha256 2>/dev/null)"; then
    echo "the golden recording at $dir does not name the binary it was taken from — refusing"; return 1
  fi
  if [ ! -f "$tsv" ]; then
    echo "no committed digest table at $tsv — nothing pins the baseline, so nothing makes it external"; return 1
  fi
  if ! awk -F'\t' -v d="$got" -v v="$ver" '$1==v && $3==d { found=1 } END { exit found ? 0 : 1 }' "$tsv"; then
    echo "the golden was recorded from a binary this repository does not pin for $ver: $got"
    echo "$tsv carries no row for that digest, so the baseline is whatever this machine happened to"
    echo "hold rather than the published artefact — refusing"
    return 1
  fi
  echo "golden binary sha256 $got is pinned in $tsv for $ver"
  return 0
}

# The verdict, taken from the report the differ wrote rather than from its exit status, and printed
# with the scope attached so a green can never be read as more than it is.
assert_parity_verdict() {  # $1 = report dir
  local rep="${1:-}" owed diverging accepted unbaselined scope
  if ! owed="$(json_field "$rep/report.json" totals.owed 2>/dev/null)"; then
    echo "no readable report at $rep/report.json — the replay left no verdict to read, so there is none"; return 1
  fi
  diverging="$(json_field "$rep/report.json" totals.diverging 2>/dev/null)" || return 1
  accepted="$(json_field "$rep/report.json" totals.accepted 2>/dev/null)" || return 1
  unbaselined="$(json_field "$rep/report.json" totals.unbaselined 2>/dev/null)" || return 1
  scope="$(json_field "$rep/report.json" totals.cells_in_scope 2>/dev/null)" || return 1
  case "$owed"      in ''|*[!0-9]*) echo "totals.owed is not a count ('$owed')"; return 1 ;; esac
  case "$diverging" in ''|*[!0-9]*) echo "totals.diverging is not a count ('$diverging')"; return 1 ;; esac
  echo "compared $owed owed cell(s) of a $scope-cell corpus: $diverging diverging, $accepted accepted, $unbaselined unbaselined"
  if [ "$owed" -eq 0 ]; then
    echo "the replay compared ZERO cells. A run that measured nothing and a run that found nothing"
    echo "print the same zero; this one measured nothing — refusing"
    return 1
  fi
  if [ "$diverging" -ne 0 ]; then
    echo "$diverging unaccepted divergence(s) over $owed owed cell(s) — see $rep/diverging.txt"
    return 1
  fi
  return 0
}

# ── THE SUBJECT IS TWO BUILDS, NOT ONE (TODO item 38) ────────────────────────────────────────────
# C3 is a claim about the LLM-ONLY build ("LLM-only 1.6.0 is byte-identical to published 1.5.5",
# BUSBAR-1.6.0.md C3), and the release ships the DEFAULT build, whose `default` list compiles in every
# non-LLM plane. This group used to run ONE plain `cargo build`, so every recording it ever took was
# of the all-planes binary and the LLM-only claim was never measured by it at all. Both legs are now
# built, digested, recorded and replayed strictly against the same golden, each under its own name,
# and the two digests must DIFFER — an llm-only leg that produced the default binary's bytes means
# the feature flags did not bite and the "second" leg is the first one measured twice.
#
# The LLM-only feature set is DERIVED from the manifest's own `default`, never restated here: drop
# every `plane-<x>` in `default` and the `root-<x>` of each dropped plane; keep the rest. A restated
# list goes stale the day a plane joins `default`, and a new plane left out of the rule would ride
# into the "LLM-only" leg unseen — so the derivation refuses if what is left names any `plane-*`, or
# lacks `proto-llm` or `root-llm` (TODO item 156: without `root-llm` rate-history answers 400).
PARITY_LEGS="default llm-only"
PARITY_MANIFEST=crates/busbar/Cargo.toml

manifest_default_features() {  # $1 = manifest ; prints the `default` feature list, one per line
  command -v python3 >/dev/null 2>&1 || { echo "python3 is not on PATH — the leg's feature set cannot be derived; refusing" >&2; return 2; }
  python3 - "$1" <<'PY'
import sys
try:
    import tomllib
except ImportError:
    sys.stderr.write("python3 has no tomllib (needs 3.11+) — refusing rather than guessing a feature set\n"); sys.exit(2)
try:
    d = tomllib.load(open(sys.argv[1], "rb"))
except Exception as e:
    sys.stderr.write("unreadable manifest %s: %s\n" % (sys.argv[1], e)); sys.exit(2)
feats = d.get("features", {}).get("default")
if not isinstance(feats, list) or not feats:
    sys.stderr.write("%s declares no [features] default list\n" % sys.argv[1]); sys.exit(3)
for f in feats:
    print(f)
PY
}

parity_llm_only_features() {  # $1 = manifest ; prints the comma-joined LLM-only feature set
  local all f x planes="" keep="" drop
  all="$(manifest_default_features "$1")" || return 1
  for f in $all; do case "$f" in plane-*) planes="$planes ${f#plane-}" ;; esac; done
  for f in $all; do
    drop=0
    for x in $planes; do [ "$f" = "plane-$x" ] || [ "$f" = "root-$x" ] && drop=1; done
    [ "$drop" -eq 1 ] || keep="${keep:+$keep,}$f"
  done
  case ",$keep," in *,plane-*) echo "the derived LLM-only set still names a plane feature: $keep" >&2; return 1 ;; esac
  case ",$keep," in *,proto-llm,*) ;; *) echo "the derived LLM-only set lacks proto-llm — it would not be an LLM build: $keep" >&2; return 1 ;; esac
  case ",$keep," in *,root-llm,*) ;; *) echo "the derived LLM-only set lacks root-llm (TODO item 156) — refusing: $keep" >&2; return 1 ;; esac
  printf '%s\n' "$keep"
}

parity_leg_args() {  # $1 = leg ; $2 = manifest ; prints the leg's extra cargo args, one per line
  local feats
  case "${1:-}" in
    default) return 0 ;;   # the shipped build IS the plain build: no flag may narrow it
    llm-only)
      feats="$(parity_llm_only_features "$2")" || return 1
      # Its own target dir, so the two legs never overwrite one artefact between build and record.
      printf '%s\n' --no-default-features --features "$feats" --target-dir target/parity-llm-only ;;
    *) echo "unknown parity leg '${1:-}' — the legs are: $PARITY_LEGS" >&2; return 1 ;;
  esac
}

# Build the subject and make the BUILD say where it put it. `step` is fail-soft by design, so the
# record must not be reachable from a build that failed: this returns non-zero and the group takes
# its refusal branch instead of recording whatever happens to be lying at a relative path.
parity_build_and_resolve() {  # $1 = leg ; prints the artefact path on stdout; diagnostics on stderr
  local leg="${1:-}" out path a
  local args=()
  if ! a="$(parity_leg_args "$leg" "$PARITY_MANIFEST")"; then return 1; fi
  while IFS= read -r path; do [ -n "$path" ] && args+=("$path"); done <<<"$a"
  if ! out="$(cargo build -p busbar --release --locked ${args[@]+"${args[@]}"} --message-format=json-render-diagnostics 2>&1)"; then
    printf '%s\n' "$out" >&2
    return 1
  fi
  path="$(printf '%s\n' "$out" | sed -n 's/.*"executable":"\([^"]*\)".*/\1/p' | tail -1)"
  if [ -z "$path" ]; then
    echo "the $leg release build succeeded but reported no executable artefact for -p busbar" >&2
    return 1
  fi
  printf '%s\n' "$path"
}

# The two legs must be two binaries. Equal digests mean the llm-only flags compiled nothing out.
assert_legs_distinct() {  # $1 = default sha256 ; $2 = llm-only sha256
  if [ -z "${1:-}" ] || [ -z "${2:-}" ]; then
    echo "a leg has no digest — both legs must be built and identified before either is believed"; return 1
  fi
  if [ "$1" = "$2" ]; then
    echo "the default and llm-only legs are the SAME binary ($1): the llm-only flags compiled nothing"
    echo "out, so one build was measured twice and the LLM-only claim was not measured at all — refusing"
    return 1
  fi
  return 0
}

# ── THE REFERENCE IS THE COMMITTED 1.5.5 GOLDEN, NEVER RE-RECORDED HERE (TODO item 41) ───────────
# This group used to re-record its own golden, from the cached 1.5.5 binary, whenever the golden
# directory was empty — on the machine under test, with no check that the recording was whole. That
# is the exact practice ci.yml's shadow-oracle job names as the thing that went wrong ("234 of 897
# cells failed to record on one run and the report read 'the golden no longer owes this id'"): a
# reference re-derived on the machine under test is not a reference. The golden is now the signed-off
# recording committed at testing/shadow-oracle/golden/1.5.5, COPIED in fresh on every run (a stale
# copy left in target/ from an earlier run is never trusted), and the copy is checked whole before
# anything is compared with it. The published binary itself is fetched by `./bin/oracle fetch-golden`
# (digest-pinned) and the recording must name that pinned digest (assert_golden_is_pinned).
PARITY_COMMITTED_GOLDEN="testing/shadow-oracle/golden/$PARITY_BASELINE_VERSION"

assert_golden_whole() {  # $1 = golden recording dir
  command -v python3 >/dev/null 2>&1 || { echo "python3 is not on PATH, so wholeness cannot be evaluated — refusing"; return 2; }
  python3 - "${1:-}" <<'PY'
import json, os, sys
g = sys.argv[1]
try:
    rec = json.load(open(os.path.join(g, "meta.json")))["recorded"]
except Exception as e:
    print("the golden at %s has no readable meta.json `recorded` count (%s) — refusing" % (g, e)); sys.exit(1)
try:
    rows = [l.rstrip("\n").split("\t") for l in open(os.path.join(g, "ledger.tsv")) if l.strip()]
except Exception as e:
    print("the golden at %s has no readable ledger.tsv (%s) — refusing" % (g, e)); sys.exit(1)
passed = [r[0] for r in rows if len(r) > 1 and r[1] == "PASS"]
if not isinstance(rec, int) or rec <= 0 or not passed:
    print("the golden owes NOTHING (meta recorded=%r, %d PASS rows) — every replay against it is vacuously green" % (rec, len(passed))); sys.exit(1)
if len(passed) != rec:
    print("the golden is NOT WHOLE: ledger.tsv has %d PASS rows, meta.json records %d" % (len(passed), rec)); sys.exit(1)
missing = [c for c in passed if not os.path.isfile(os.path.join(g, "cells", c.replace("|", "__") + ".json"))]
if missing:
    print("the golden is NOT WHOLE: %d PASS row(s) have no recorded cell file, e.g. %s" % (len(missing), missing[0])); sys.exit(1)
print("golden whole: %d PASS rows = meta recorded %d, every one with its cell file" % (len(passed), rec))
PY
}

parity_install_golden() {  # $1 = committed golden dir ; $2 = destination
  local src="${1:-}" dst="${2:-}"
  if [ ! -d "$src" ]; then echo "no committed golden at $src — there is no reference to compare with; refusing"; return 1; fi
  rm -rf "$dst" && mkdir -p "$(dirname "$dst")" && cp -R "$src" "$dst" || { echo "could not copy the committed golden to $dst"; return 1; }
  assert_golden_whole "$dst"
}

# The file itself may never re-record a golden. Scans non-comment lines for an oracle `record` whose
# --out is a golden or whose --bin is the cached baseline binary — the shape the old arm had.
assert_never_rerecords_golden() {  # $1 = file to scan
  local hits
  [ -f "${1:-}" ] || { echo "nothing to scan at ${1:-<empty>} — refusing"; return 1; }
  hits="$(grep -nE '^[^#]*oracle[[:space:]]+record([[:space:]]|$)' "$1" \
          | grep -iE -- '--out[[:space:]]+"?[^[:space:]]*golden|busbar-oracle/[^[:space:]]*/busbar|PARITY_BASELINE_VERSION/busbar' || true)"
  if [ -n "$hits" ]; then
    echo "this run would RE-RECORD its own reference on the machine under test:"
    printf '%s\n' "$hits" | sed 's/^/  /'
    echo "the golden is the committed $PARITY_BASELINE_VERSION recording, copied in and checked whole — refusing"
    return 1
  fi
  return 0
}

# ── EVERY IN-SCOPE CELL HAS A GOLDEN OR A NAMED REASON; THE BASELINE IS THE GOLDEN (TODO item 51) ─
# owed-baseline.txt is the ratchet the differ holds the golden to, so it must be EXACTLY the golden's
# PASS set — a duplicate line (it carried one: 917 lines for 916 cells) makes its line count a false
# statement of the owed denominator. And a cell that is in scope (every family outside the mcp/a2a
# conformance-rig families) but has no golden reference must be NAMED in accepted-gaps.json with an
# owner and a rationale; 22 were not, 14 of them named nowhere.
assert_golden_bookkeeping() {  # $1 = golden dir ; $2 = owed-baseline ; $3 = accepted-gaps ; $4 = cells.json
  command -v python3 >/dev/null 2>&1 || { echo "python3 is not on PATH, so the bookkeeping cannot be evaluated — refusing"; return 2; }
  python3 - "$@" <<'PY'
import json, os, re, sys, collections
g, base, gaps, cells = sys.argv[1:5]
bad = []
try:
    ledger = {}
    for l in open(os.path.join(g, "ledger.tsv")):
        r = l.rstrip("\n").split("\t")
        if r and r[0]:
            ledger[r[0]] = r
    ids = [c["id"] for c in json.load(open(cells))["cells"]]
    lines = [l.strip() for l in open(base) if l.strip() and not l.lstrip().startswith("#")]
    doc = json.load(open(gaps))
except Exception as e:
    print("unreadable bookkeeping input: %s — refusing" % e); sys.exit(1)
dups = [k for k, n in collections.Counter(lines).items() if n > 1]
if dups:
    bad.append("owed-baseline.txt repeats %d id(s): %s" % (len(dups), ", ".join(sorted(dups))))
passed = {k for k, r in ledger.items() if len(r) > 1 and r[1] == "PASS"}
extra, lost = set(lines) - passed, passed - set(lines)
if extra:
    bad.append("owed-baseline.txt owes %d id(s) the golden does not PASS, e.g. %s" % (len(extra), sorted(extra)[0]))
if lost:
    bad.append("the golden PASSes %d id(s) owed-baseline.txt does not name, e.g. %s" % (len(lost), sorted(lost)[0]))
entries = []
for e in doc.get("accepted", []):
    if not (e.get("cells") and str(e.get("owner", "")).strip() and str(e.get("rationale", "")).strip()):
        bad.append("accepted-gaps entry %r lacks cells, owner or rationale" % e.get("id")); continue
    try:
        entries.append(re.compile(e["cells"]))
    except re.error as err:
        bad.append("accepted-gaps entry %r has a bad regex: %s" % (e.get("id"), err))
def rig_proven(cid):
    r = ledger.get(cid)
    return cid.split("|", 1)[0] in ("mcp", "a2a") and r is not None and len(r) > 2 \
        and r[1] == "SKIP" and "proven by its conformance rig" in r[2]
unowed = [c for c in ids if c not in passed and not rig_proven(c)]
unnamed = [c for c in unowed if not any(rx.search(c) for rx in entries)]
if unnamed:
    bad.append("%d in-scope cell(s) have no golden reference and no accepted-gaps.json entry names them:\n    %s"
               % (len(unnamed), "\n    ".join(unnamed)))
if bad:
    print("\n".join(bad)); sys.exit(1)
print("bookkeeping whole: owed-baseline = the golden's %d PASS ids, no repeats; %d in-scope cell(s) without a golden, every one named"
      % (len(passed), len(unowed)))
PY
}

# ── --selftest: the DONE gate's own refusals, proven RED before any group runs ────────────────────
# This script's whole claim is "the tree was measured against something outside itself". Every
# variable named in assert_bless_env_empty defeats that claim in a different way, and two of them
# (SHADOW_ORACLE_GOLDEN, CONFIG_SCHEMA_BASELINE_REF) used to be exempt from it — the first can point
# PARITY at the candidate, the second can point config-stability at a baseline that makes every
# break additive. So each is planted here in turn and required to go red. Runs in seconds, builds
# nothing, and is what stops the list quietly shrinking back.
if [ "$SELFTEST" -eq 1 ]; then
  printf '== verify-1.6.0-done SELF-TEST (the DONE gate refuses a run that measures itself) ==\n'
  st_fail=0
  if assert_bless_env_empty >/dev/null 2>&1; then
    printf '  [ok]     a clean environment is accepted\n'
  else
    printf '  [FAILED] a clean environment was refused — the assertion is reading a variable this shell already carries\n'
    assert_bless_env_empty 2>&1 | sed 's/^/           /'
    st_fail=1
  fi
  # This list is typed out AGAIN rather than read from the function: it is the independent
  # expectation, so dropping a name from assert_bless_env_empty leaves it here and goes RED.
  for st_v in UPDATE_OPENAPI BLESS_BACKCOMPAT_CORPUS BUSBAR_BLESS_GOLDEN \
              SHADOW_ORACLE_GOLDEN SHADOW_ORACLE_DIR CONFIG_SCHEMA_BASELINE_REF CONFIG_SCHEMA_BOOTSTRAP \
              BUSBAR_ORACLE_DATA BUSBAR_ORACLE_PRODUCT_ROOT BUSBAR_ORACLE_TOOL_DIR BUSBAR_ORACLE_CACHE \
              BUSBAR_ORACLE_RUST_BIN BUSBAR_RELEASE_CHECKOUT BUSBAR_EMIT_OPENAPI \
              BUSBAR_UPDATE_GOLDEN UPDATE_KEYS_ERROR_GOLDEN UPDATE_DIAGNOSTICS \
              XTASK_INSN_EMIT_BASELINE XTASK_PPB_EMIT_BASELINE \
              GREP_GATE_REPORT_ONLY SECRET_GATE_REPORT_ONLY; do
    # A subshell so the plant cannot leak, driving the REAL assert_bless_env_empty — not a copy of
    # its rule, which would prove only that the copy agrees with itself.
    if ( export "$st_v=planted"; assert_bless_env_empty ) >/dev/null 2>&1; then
      printf '  [FAILED] %s was SET and the DONE gate accepted it\n' "$st_v"
      st_fail=1
    else
      printf '  [ok]     %s set -> the DONE run is REFUSED\n' "$st_v"
    fi
  done
  # SKIP_BOOT_LEG is its own function (see above) with its own proof, for the same reason it is
  # checked in PLANE-DELETE rather than folded into assert_bless_env_empty.
  if ( export SKIP_BOOT_LEG=1; assert_skip_boot_leg_empty ) >/dev/null 2>&1; then
    printf '  [FAILED] SKIP_BOOT_LEG was SET and the DONE gate accepted it\n'
    st_fail=1
  else
    printf '  [ok]     SKIP_BOOT_LEG set -> the DONE run is REFUSED\n'
  fi
  # ── PARITY'S SUBJECT AND VERDICT REFUSALS, each planted and required to go RED ────────────────
  # The bless/repoint loop above proves this run cannot be pointed at a baseline the operator chose.
  # These prove the other half: that it cannot be pointed at a SUBJECT nobody chose, and that it
  # cannot report a zero it did not earn. Every fixture is a file in a temp dir — no build, no
  # network, seconds — and every refusal is driven through the REAL function the group calls, not a
  # restatement of its rule.
  st_expect() {  # $1 = accept|refuse ; $2 = label ; rest = the command under test
    local want="$1" label="$2"; shift 2
    if "$@" >/dev/null 2>&1; then
      if [ "$want" = accept ]; then printf '  [ok]     %s\n' "$label"
      else printf '  [FAILED] %s — ACCEPTED, and this must be refused\n' "$label"; st_fail=1; fi
    else
      if [ "$want" = refuse ]; then printf '  [ok]     %s -> REFUSED\n' "$label"
      else printf '  [FAILED] %s — REFUSED, and this must be accepted (the guard fires on a clean case)\n' "$label"; st_fail=1; fi
    fi
  }
  st_tmp="$(mktemp -d "${TMPDIR:-/tmp}/done-parity-selftest.XXXXXX")"
  printf '#!/bin/sh\nexit 0\n' > "$st_tmp/busbar"; chmod +x "$st_tmp/busbar"
  st_sha="$(sha256_of "$st_tmp/busbar")"
  st_other=0000000000000000000000000000000000000000000000000000000000000000
  ln -s "$st_tmp/busbar" "$st_tmp/busbar-link"
  printf 'not a binary\n' > "$st_tmp/not-exec"
  mkdir -p "$st_tmp/rec-good" "$st_tmp/rec-wrong" "$st_tmp/rec-bare"
  printf '{"binary_sha256":"%s","recorded":3}\n' "$st_sha"   > "$st_tmp/rec-good/meta.json"
  printf '{"binary_sha256":"%s","recorded":3}\n' "$st_other" > "$st_tmp/rec-wrong/meta.json"
  printf '# version\tasset\tsha256\n%s\tbusbar-selftest\t%s\n' "$PARITY_BASELINE_VERSION" "$st_sha" > "$st_tmp/digests.tsv"
  mkdir -p "$st_tmp/rep-green" "$st_tmp/rep-diverging" "$st_tmp/rep-nothing"
  printf '{"totals":{"owed":913,"diverging":0,"accepted":289,"unbaselined":1405,"cells_in_scope":2318}}\n' > "$st_tmp/rep-green/report.json"
  printf '{"totals":{"owed":913,"diverging":8,"accepted":289,"unbaselined":1405,"cells_in_scope":2318}}\n' > "$st_tmp/rep-diverging/report.json"
  printf '{"totals":{"owed":0,"diverging":0,"accepted":0,"unbaselined":0,"cells_in_scope":0}}\n'           > "$st_tmp/rep-nothing/report.json"
  st_expect accept "a real, unlinked, executable artefact is the subject"        assert_candidate_bin_sane "$st_tmp/busbar"
  st_expect refuse "a SYMLINK standing where the candidate binary should be"     assert_candidate_bin_sane "$st_tmp/busbar-link"
  st_expect refuse "a candidate path that does not exist"                        assert_candidate_bin_sane "$st_tmp/absent"
  st_expect refuse "a build that named no artefact at all"                       assert_candidate_bin_sane ""
  st_expect refuse "a candidate that is not executable"                          assert_candidate_bin_sane "$st_tmp/not-exec"
  st_expect accept "a recording that names the binary this run built"            assert_recorded_subject "$st_tmp/rec-good"  "$st_sha" "fixture"
  st_expect refuse "a recording that names a DIFFERENT binary"                   assert_recorded_subject "$st_tmp/rec-wrong" "$st_sha" "fixture"
  st_expect refuse "a recording that names no binary at all"                     assert_recorded_subject "$st_tmp/rec-bare"  "$st_sha" "fixture"
  st_expect refuse "a subject with no digest to compare against"                 assert_recorded_subject "$st_tmp/rec-good"  ""        "fixture"
  st_expect accept "a golden whose digest this repository commits"               assert_golden_is_pinned "$st_tmp/rec-good"  "$st_tmp/digests.tsv" "$PARITY_BASELINE_VERSION"
  st_expect refuse "a golden whose digest this repository does not commit"       assert_golden_is_pinned "$st_tmp/rec-wrong" "$st_tmp/digests.tsv" "$PARITY_BASELINE_VERSION"
  st_expect refuse "a golden checked against a digest table that is not there"   assert_golden_is_pinned "$st_tmp/rec-good"  "$st_tmp/no-such.tsv" "$PARITY_BASELINE_VERSION"
  st_expect accept "a report with cells compared and none diverging"             assert_parity_verdict "$st_tmp/rep-green"
  st_expect refuse "a report carrying unaccepted divergences"                    assert_parity_verdict "$st_tmp/rep-diverging"
  st_expect refuse "a report that compared ZERO cells (the zero that is not one)" assert_parity_verdict "$st_tmp/rep-nothing"
  st_expect refuse "no report at all"                                            assert_parity_verdict "$st_tmp/rep-missing"

  # ── PARITY RECORDS BOTH LEGS (item 38) ────────────────────────────────────────────────────────
  st_legs_named() { case " $PARITY_LEGS " in *" default "*) ;; *) return 1 ;; esac
                    case " $PARITY_LEGS " in *" llm-only "*) ;; *) return 1 ;; esac; }
  st_expect accept "PARITY records BOTH legs: the default all-planes build and the LLM-only build" st_legs_named
  # ...and the group ITSELF iterates them: a list nothing loops over proves nothing about what ran.
  st_group_builds_each_leg() {
    grep -qE '^[[:space:]]*for PARITY_LEG in \$PARITY_LEGS; do' "$SELF" || return 1
    grep -qE '^[[:space:]]*if PARITY_BIN="\$\(parity_build_and_resolve "\$PARITY_LEG"' "$SELF"; }
  st_expect accept "the PARITY group builds, records and replays EACH leg (not one plain cargo build)" st_group_builds_each_leg
  st_default_is_plain() { [ -z "$(parity_leg_args default "$PARITY_MANIFEST")" ]; }
  st_expect accept "the default leg is the plain shipped build (no flag narrows it)" st_default_is_plain
  st_llm_real() { local f; f="$(parity_llm_only_features "$PARITY_MANIFEST")" || return 1
    case ",$f," in *,plane-*) return 1 ;; esac
    parity_leg_args llm-only "$PARITY_MANIFEST" | grep -qx -- '--no-default-features'; }
  st_expect accept "the llm-only leg derives from THIS manifest: --no-default-features, no plane-*" st_llm_real
  printf '[features]\ndefault = ["auth-admin-tokens", "proto-llm", "plane-mcp", "plane-voice", "root-admin", "root-voice", "root-llm"]\n' > "$st_tmp/Cargo-legs.toml"
  printf '[features]\ndefault = ["auth-admin-tokens", "proto-llm", "plane-mcp", "root-admin"]\n' > "$st_tmp/Cargo-noroot.toml"
  printf '[features]\nfoo = []\n' > "$st_tmp/Cargo-nodefault.toml"
  st_llm_fixture() { [ "$(parity_llm_only_features "$st_tmp/Cargo-legs.toml")" = "auth-admin-tokens,proto-llm,root-admin,root-llm" ]; }
  st_expect accept "a fixture manifest's LLM-only set drops every plane-<x> and its root-<x>, keeps the rest" st_llm_fixture
  st_expect refuse "an LLM-only set without root-llm (item 156: rate-history answers 400)" parity_llm_only_features "$st_tmp/Cargo-noroot.toml"
  st_expect refuse "a manifest with no default list (no leg can be derived)"               parity_llm_only_features "$st_tmp/Cargo-nodefault.toml"
  st_expect refuse "an unknown leg name"                                                  parity_leg_args all-planes "$PARITY_MANIFEST"
  st_expect accept "two legs that are two different binaries"                             assert_legs_distinct "$st_sha" "$st_other"
  st_expect refuse "two legs that are the SAME binary (the llm-only flags compiled nothing out)" assert_legs_distinct "$st_sha" "$st_sha"
  st_expect refuse "a leg with no digest"                                                 assert_legs_distinct "$st_sha" ""

  # ── THE REFERENCE IS THE COMMITTED GOLDEN, WHOLE, NEVER RE-RECORDED (item 41) ─────────────────
  # The planted line goes through %s so it is not itself a record line the real scan finds.
  printf '  step x ./bin/oracle %s --bin "$HOME/.cache/busbar-oracle/1.5.5/busbar" --plane all --out "$GOLDEN"\n' record > "$st_tmp/rerecord.sh"
  printf '  step x ./bin/oracle %s --bin "$PARITY_BIN" --plane all --out "$CAND"\n' record > "$st_tmp/candidate-only.sh"
  st_expect refuse "a DONE run that re-records its own golden on the machine under test" assert_never_rerecords_golden "$st_tmp/rerecord.sh"
  st_expect accept "a DONE run that records only the candidate"                          assert_never_rerecords_golden "$st_tmp/candidate-only.sh"
  st_expect accept "THIS file never re-records the golden"                               assert_never_rerecords_golden "$SELF"
  mkdir -p "$st_tmp/g-whole/cells" "$st_tmp/g-short/cells" "$st_tmp/g-empty/cells" "$st_tmp/g-nocell/cells"
  for st_g in g-whole g-short g-nocell; do
    printf 'a|x|ok\tPASS\t\t\nb|y|ok\tPASS\t\t\nmcp|z|ok\tSKIP\tUNSUPPORTED: mcp is proven by its conformance rig, not recorded here\tnamed gap\n' > "$st_tmp/$st_g/ledger.tsv"
    printf '{}\n' > "$st_tmp/$st_g/cells/a__x__ok.json"
  done
  printf '{}\n' > "$st_tmp/g-whole/cells/b__y__ok.json"; printf '{}\n' > "$st_tmp/g-short/cells/b__y__ok.json"
  printf '{"binary_sha256":"%s","recorded":2}\n' "$st_sha" > "$st_tmp/g-whole/meta.json"
  printf '{"binary_sha256":"%s","recorded":3}\n' "$st_sha" > "$st_tmp/g-short/meta.json"
  printf '{"binary_sha256":"%s","recorded":2}\n' "$st_sha" > "$st_tmp/g-nocell/meta.json"
  printf '{"binary_sha256":"%s","recorded":0}\n' "$st_sha" > "$st_tmp/g-empty/meta.json"; : > "$st_tmp/g-empty/ledger.tsv"
  st_expect accept "a whole golden (PASS rows = meta recorded, every cell file present)"  assert_golden_whole "$st_tmp/g-whole"
  st_expect refuse "a TRUNCATED golden (fewer PASS rows than meta recorded)"               assert_golden_whole "$st_tmp/g-short"
  st_expect refuse "a golden whose PASS row has no recorded cell file"                     assert_golden_whole "$st_tmp/g-nocell"
  st_expect refuse "a golden that owes nothing"                                            assert_golden_whole "$st_tmp/g-empty"
  st_expect refuse "installing a committed golden that is not there"                       parity_install_golden "$st_tmp/no-such-golden" "$st_tmp/g-dst"
  st_expect accept "the COMMITTED $PARITY_BASELINE_VERSION golden is whole"                assert_golden_whole "$PARITY_COMMITTED_GOLDEN"
  st_expect accept "the COMMITTED golden names a digest this repository pins"              assert_golden_is_pinned "$PARITY_COMMITTED_GOLDEN" testing/shadow-oracle/golden-digests.tsv "$PARITY_BASELINE_VERSION"

  # ── EVERY IN-SCOPE CELL HAS A GOLDEN OR A NAMED REASON; THE BASELINE IS THE GOLDEN (item 51) ──
  printf '{"cells":[{"id":"a|x|ok"},{"id":"b|y|ok"},{"id":"mcp|z|ok"},{"id":"c|w|ok"}]}\n' > "$st_tmp/cells.json"
  printf 'a|x|ok\nb|y|ok\n' > "$st_tmp/base-good.txt"
  printf 'a|x|ok\nb|y|ok\nb|y|ok\n' > "$st_tmp/base-dup.txt"
  printf 'a|x|ok\n' > "$st_tmp/base-short.txt"
  printf '{"accepted":[{"id":"c","cells":"^c\\\\|w\\\\|ok$","owner":"o","rationale":"why"}]}\n' > "$st_tmp/gaps-named.json"
  printf '{"accepted":[]}\n' > "$st_tmp/gaps-none.json"
  printf '{"accepted":[{"id":"c","cells":"^c\\\\|w\\\\|ok$","owner":"o","rationale":""}]}\n' > "$st_tmp/gaps-noreason.json"
  st_expect accept "baseline = golden PASS set and the one unowed in-scope cell is named" assert_golden_bookkeeping "$st_tmp/g-whole" "$st_tmp/base-good.txt"  "$st_tmp/gaps-named.json"    "$st_tmp/cells.json"
  st_expect refuse "owed-baseline.txt repeats an id (917 lines for 916 cells)"           assert_golden_bookkeeping "$st_tmp/g-whole" "$st_tmp/base-dup.txt"   "$st_tmp/gaps-named.json"    "$st_tmp/cells.json"
  st_expect refuse "owed-baseline.txt omits an id the golden PASSes"                     assert_golden_bookkeeping "$st_tmp/g-whole" "$st_tmp/base-short.txt" "$st_tmp/gaps-named.json"    "$st_tmp/cells.json"
  st_expect refuse "an in-scope cell with no golden that nothing names"                  assert_golden_bookkeeping "$st_tmp/g-whole" "$st_tmp/base-good.txt"  "$st_tmp/gaps-none.json"     "$st_tmp/cells.json"
  st_expect refuse "a gap entry with no rationale does not name anything"                assert_golden_bookkeeping "$st_tmp/g-whole" "$st_tmp/base-good.txt"  "$st_tmp/gaps-noreason.json" "$st_tmp/cells.json"
  st_expect accept "THIS tree: owed-baseline IS the golden, every in-scope gap is named" assert_golden_bookkeeping "$PARITY_COMMITTED_GOLDEN" testing/shadow-oracle/owed-baseline.txt testing/shadow-oracle/accepted-gaps.json testing/shadow-oracle/cells.json

  # ── THE MIGRATION CORPUS HAS SEEN EVERY SHIPPED RELEASE (item 48) ─────────────────────────────
  # v1.5.3/1.5.4/1.5.5 never joined it, so the migrator was never run over the configs the release
  # under comparison actually shipped. refresh.sh --check derives the shipped set from the release
  # tags and requires every file byte-identical; the plant removes the newest release's config.
  mkdir -p "$st_tmp/corpus"
  cp -R tests/migration-corpus/from-tags tests/migration-corpus/providers "$st_tmp/corpus/" 2>/dev/null || true
  rm -f "$st_tmp/corpus/from-tags/v${PARITY_BASELINE_VERSION}_config.yaml"
  st_expect refuse "a migration corpus missing the v$PARITY_BASELINE_VERSION config it shipped" bash tests/migration-corpus/refresh.sh --check --corpus-dir "$st_tmp/corpus"
  st_expect accept "THIS migration corpus holds every config every release tag shipped"     bash tests/migration-corpus/refresh.sh --check

  # ── BUILD: no full-gate register is RED, not three plain builds (item 529) ────────────────────
  # Driven through the REAL run_build_group with `step` stubbed to a recorder, so no cargo runs.
  st_build() {  # $1 = FAST ; $2 = register path  -> exit 0 iff the group came out GREEN
    ( FAST="$1"; CUR_RED=0; CUR_FIRST_NOTE=""; step() { echo "STEP $1"; }
      run_build_group "$2" >/dev/null 2>&1; [ "$CUR_RED" -eq 0 ] )
  }
  printf 'version = 1\n' > "$st_tmp/full-gate.toml"
  st_expect accept "BUILD with the full-gate register present runs the battery"   st_build 0 "$st_tmp/full-gate.toml"
  st_expect refuse "BUILD with NO full-gate register (the silent plain-build downgrade)" st_build 0 "$st_tmp/no-full-gate.toml"

  # ── the CONFORMANCE group's voice legs are =ready (item 530) ──────────────────────────────────
  if [ -f testing/voice-conformance/voice-conformance.sh ]; then
    mkdir -p "$st_tmp/legs-ready" "$st_tmp/legs-pending" "$st_tmp/legs-none"
    for st_l in a b c; do
      printf 'LEG_KIND=conformance\nLEG_STATUS=ready\nLEG_SLICES=(x)\nleg_execute(){ :; }\n' > "$st_tmp/legs-ready/$st_l.sh"
      printf 'LEG_KIND=conformance\nLEG_STATUS=ready\nLEG_SLICES=(x)\nleg_execute(){ :; }\n' > "$st_tmp/legs-pending/$st_l.sh"
    done
    printf 'LEG_KIND=conformance\nLEG_STATUS=pending\nLEG_SLICES=(x)\nleg_execute(){ :; }\n' > "$st_tmp/legs-pending/b.sh"
    # EVERY leg pending: the exact state the rig's --selftest accepts (its zero-ready branch returns 0).
    mkdir -p "$st_tmp/legs-allpending"
    for st_l in a b c; do
      printf 'LEG_KIND=conformance\nLEG_STATUS=pending\nLEG_SLICES=(x)\nleg_execute(){ :; }\n' > "$st_tmp/legs-allpending/$st_l.sh"
    done
    st_expect accept "voice legs all LEG_STATUS=ready"                  voice_legs_all_ready testing/voice-conformance/voice-conformance.sh "$st_tmp/legs-ready"
    st_expect refuse "a voice leg LEG_STATUS=pending under the '=ready' claim" voice_legs_all_ready testing/voice-conformance/voice-conformance.sh "$st_tmp/legs-pending"
    st_expect refuse "EVERY voice leg LEG_STATUS=pending (the rig's --selftest accepts this)" voice_legs_all_ready testing/voice-conformance/voice-conformance.sh "$st_tmp/legs-allpending"
    st_expect refuse "a voice rig with ZERO legs"                       voice_legs_all_ready testing/voice-conformance/voice-conformance.sh "$st_tmp/legs-none"
  else
    printf '  [FAILED] testing/voice-conformance/voice-conformance.sh is absent — the =ready check cannot be proven\n'; st_fail=1
  fi

  # ── every `cargo xtask gate <name>` this file runs is registered (item 468) ───────────────────
  # The planted name goes through %s so this line is not itself an invocation the real scan finds.
  printf 'step x cargo xtask gate %s --selftest\n' no-such-gate-planted > "$st_tmp/plant.sh"
  st_expect refuse "a planted unregistered gate name is caught"                   xtask_gates_invoked_are_registered "$st_tmp/plant.sh"
  st_expect accept "every gate name THIS file invokes is in cargo xtask gate --list" xtask_gates_invoked_are_registered "$SELF"

  # ── --help shows the FLAGS contract (item 551) ────────────────────────────────────────────────
  st_help() { local h; h="$(bash "$SELF" --help 2>&1)" || return 1
    case "$h" in *"--fast"*) ;; *) return 1 ;; esac
    case "$h" in *"--selftest"*) ;; *) return 1 ;; esac
    case "$h" in *"PROVISIONAL"*"exits 3"*) ;; *) return 1 ;; esac; }
  st_expect accept "--help prints --fast, --selftest and the PROVISIONAL / exit-3 rule" st_help
  rm -rf "$st_tmp"
  _st_fails=$((_st_fails + st_fail))
  if [ "$_st_fails" -eq 0 ]; then
    printf '\nverify-1.6.0-done selftest: GREEN (verdict proofs + every bless/repoint variable refused)\n'
    exit 0
  fi
  printf '\nverify-1.6.0-done selftest: RED (%s failure(s))\n' "$_st_fails"
  exit 1
fi

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "BUILD — the cargo battery"
run_build_group qa/full-gate.toml
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "PLANE-PURITY — neutral crates carry no side channel (0/0)"
step "plane-purity --selftest" cargo xtask gate plane-purity --selftest
step "plane-purity gate"       cargo xtask gate plane-purity
step "plane-purity --strict"   cargo xtask gate plane-purity-strict
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
# THE SHIP CRITERION (owner, 2026-09-07): the ~10 plugin kinds never cross-contaminate, and on the
# ship SHA that is ZERO — zero fused names, zero cross-kind edges, zero cross-kind vocabulary, one
# entry surface per kind and one shared conformance battery per kind, with no permanent exemptions.
# The four enforceable rows are BLOCKING on every push as `kind-isolation`; the strict twin adds the
# two rows that are red on HEAD by design, and this is where they have to reach zero.
begin_group "KIND-ISOLATION — the plugin kinds never cross-contaminate (ship criterion, 0 exemptions)"
step "kind-isolation --selftest" cargo xtask gate kind-isolation-ship --selftest
step "kind-isolation --ship"     cargo xtask gate kind-isolation-ship
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
# INSTANCE-NOUN NEUTRALITY — the burndown census that goes GREEN only when NO crate names a concrete
# plane/transport instance outside its own crate family. RED on HEAD by design (the plane extraction
# is in flight, and every remaining coupling is a tracked row in qa/instance-noun-neutrality.toml);
# this is the release-time question of whether that burndown has reached zero. A per-push red would
# only restate that the extraction is in flight, so it lives here, not in ci.yml.
begin_group "INSTANCE-NOUN NEUTRALITY — no concrete instance noun leaks across crate families (burndown to 0)"
step "instance-noun --selftest" cargo xtask gate instance-noun-neutrality --selftest
step "instance-noun gate"       cargo xtask gate instance-noun-neutrality
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
# REACHABILITY — every plane in #48's locked roster is served by a unit path the COMPOSITION ROOT
# ACTUALLY CONSTRUCTS. It exists because of the 2026-09-22 a2a money findings: three real faults in
# crates/busbar/src/root/units_a2a.rs that NO corpus cell and NO rig leg could have caught, because
# `A2aUnits::new`'s only call site in the workspace is under `#[cfg(test)]`. There is no behaviour to
# witness, so no behavioural witness can exist — the only instrument that sees that class is one that
# measures the ABSENCE of a caller. RED on HEAD by design, on named rows, and every unreached unit
# path either gets switched on or gets a written `[[dormant]]` row in qa/reachability.toml. Exactly
# the footing instance-noun-neutrality is on above: a per-push red would only restate that the plane
# switch-ons are in flight, so it lives here and not in ci.yml.
begin_group "REACHABILITY — every locked plane is served by a unit path the composition root constructs"
step "reachability --selftest" cargo xtask gate reachability --selftest
step "reachability gate"       cargo xtask gate reachability
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
# THE LOCKED ROSTER IS 5 PLANES, NOT 4, AND NOT {llm,mcp,a2a,voice}. docs/design/BUSBAR-1.6.0.md
# Part 2:
#   #18 — "The fourth plane is STREAMING, not voice. Voice is ONE capability/dialect inside the
#         streaming plane... No `voice` as a plane/kind/crate/feature name: the streaming plane's
#         crate is `busbar-plane-streaming`, feature `plane-streaming`..."
#   #48 — "jev is the `decisions` plane — planes = 5, not 4... The locked plane roster becomes 5:
#         llm, mcp, a2a, streaming, decisions(jev) — amending #18/#39's count of 4."
# So the group below is titled and asserted against {llm, mcp, a2a, streaming, decisions} — what
# the spec says the planes ARE — not the stale on-disk spelling. This is an ENUMERATION fix, not a
# claim the fold is finished: both `busbar-plane-voice` and `busbar-plane-streaming` exist in the
# tree today (the rename has not landed) and `busbar-plane-decision` exists but is deliberately
# unwired (no root Cargo.toml/main.rs entry, no on-disk `busbar-decision(s)` I/O crate) — the fold
# is tracked separately from this file.
begin_group "PLANE-DELETE — each locked plane (llm/mcp/a2a/streaming/decisions, BUSBAR-1.6.0 Part 2 #18/#48) is deletable"
if ! assert_skip_boot_leg_empty >/tmp/done-planedelete-env.$$ 2>&1; then
  printf '  \033[31m[RED]\033[0m  SKIP_BOOT_LEG is NOT empty — refusing PLANE-DELETE (would silently skip the boot+serve leg)\n'
  sed 's/^/          /' /tmp/done-planedelete-env.$$
  rm -f /tmp/done-planedelete-env.$$
  CUR_RED=1; CUR_FIRST_NOTE="SKIP_BOOT_LEG set (plane-delete)"
else
  rm -f /tmp/done-planedelete-env.$$
  # scripts/plane-delete-test.sh iterates $PLANE_KEYS (scripts/plane-keys.sh), which is still the
  # ON-DISK spelling {llm, mcp, a2a, voice} on purpose — it is a literal `crates/busbar-<key>`
  # directory suffix, and spelling it `streaming` before the crate rename lands would make the
  # harness open a directory that is not there (the exact silent-zero-files failure plane-keys.sh
  # exists to prevent). `--all`'s own `report_coverage` already computes the gap against
  # PLANE_KEYS_LOCKED (the same 5-plane roster #18/#48 lock) and prints it — but only as a yellow
  # informational note, never red, because a plane with literally nothing on disk yet (`decisions`)
  # has nothing for a strong-form removal test to prove either way. DONE, this file's own claim,
  # means the full 5-plane roster is provably deletable, so the step below promotes that gap to a
  # red HERE rather than letting a yellow note inside an exit-0 run keep it invisible.
  step "plane-delete-test --selftest" bash scripts/plane-delete-test.sh --selftest
  step "plane-delete-test --all"      bash scripts/plane-delete-test.sh --all
  step "locked 5-plane roster (llm/mcp/a2a/streaming/decisions) has no on-disk coverage gap" bash -c '
    . scripts/plane-keys.sh
    gaps=""
    for lp in $PLANE_KEYS_LOCKED; do
      od="$(plane_ondisk_key "$lp")"
      case " $PLANE_KEYS " in
        *" ${od:-__no_ondisk_key__} "*) : ;;
        *) gaps="${gaps:+$gaps }$lp" ;;
      esac
    done
    if [ -n "$gaps" ]; then
      echo "locked plane(s) with no on-disk crate this harness can strong-form test yet: $gaps"
      echo "(scripts/plane-delete-test.sh --all reports this same gap as an informational yellow note, never red — see report_coverage)"
      exit 1
    fi
    echo "all $(printf '%s' "$PLANE_KEYS_LOCKED" | wc -w | tr -d ' ') locked plane(s) are reachable on disk"
  '
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "BYTE-IDENTITY — the money path is byte-stable"
if assert_bless_env_empty >/tmp/done-oracle-step.$$ 2>&1; then
  printf '  \033[32m[ok]\033[0m   bless/regen/repoint env (every var in assert_bless_env_empty) is empty\n'
  # MUST carry --features openapi-schema AND -p busbar (unifies the feature graph-wide, so the plane
  # crates' `openapi-schema` reaches busbar-core-admin's dev-dep edges) — the golden tests are
  # cfg-gated on it, so without both the filter selects ZERO of them. The three byte-identity goldens
  # (json-matches-committed, served-equals-committed, error-enum-matches) live in busbar-core-admin
  # with the admin service (1.6.0; W4.a absorbed busbar-core into busbar-kernel, and #37 folded
  # busbar-plane-admin + busbar-admin into busbar-core-admin), so `-p busbar-core-admin` is REQUIRED:
  # `-p busbar -p busbar-kernel` alone selects just 1 test (busbar-kernel's
  # `a_plane_with_admin_verbs_documents_at_least_one_openapi_path`) against the expected 23 — a
  # vacuity the count check catches. With busbar-core-admin added the `openapi` filter runs the real
  # set (22 in busbar-core-admin + 1 in busbar-kernel = 23), so the oracle's byte-identity check is
  # real, matching cargo xtask full-gate. Thread-count-independent: every busbar-core-admin openapi
  # test installs the plane seam before reading `openapi_doc()` (see `openapi_doc_seamed` in that
  # crate's json tests), so no `--test-threads=1` pin is needed for determinism.
  step "openapi.json goldens match committed file"  filtered_cargo_test 23 cargo test -p busbar -p busbar-kernel -p busbar-core-admin --features openapi-schema --quiet openapi
  step "resolved billing+limits config byte-stable" filtered_cargo_test 1  cargo test -p busbar-kernel --quiet resolved_billing_and_limits_config_is_byte_stable
  # The six `*_round_trip_byte_exact` oracles live in busbar-llm-codec
  # (crates/busbar-llm-codec/src/tests/proto/same_proto_fidelity_tests.rs), not in busbar-llm.
  step "6 same-proto byte-exact oracles"            filtered_cargo_test 6  cargo test -p busbar-llm-codec --quiet round_trip_byte_exact
else
  printf '  \033[31m[RED]\033[0m  bless/regen env is NOT empty — refusing byte-identity (would regenerate goldens)\n'
  sed 's/^/          /' /tmp/done-oracle-step.$$; rm -f /tmp/done-oracle-step.$$
  CUR_RED=1; CUR_FIRST_NOTE="bless env not empty"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CONFIG-STABILITY — config-schema.snapshot.json is additive-only / byte-stable"
step "config-schema gate --selftest" cargo xtask gate config-schema --selftest
step "config-schema gate"            cargo xtask gate config-schema
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "TEST — full workspace + voice runtime"
step "cargo test --workspace"                    cargo test --workspace --quiet
step "cargo test -p busbar-voice --features runtime" cargo test -p busbar-voice --features runtime --quiet
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CONFORMANCE — rig selftests + verdict coverage + voice legs =ready"
[ -f scripts/mcp-conformance.sh ] && step "mcp-conformance --selftest" bash scripts/mcp-conformance.sh --selftest \
  || absent_step "mcp-conformance --selftest" "scripts/mcp-conformance.sh"
if [ -f testing/verdict-covers-every-leg.py ]; then
  step "verdict-covers-every-leg.py" python3 testing/verdict-covers-every-leg.py
else
  absent_step "verdict-covers-every-leg.py" "testing/verdict-covers-every-leg.py — T2 conformance coverage gate not built yet"
fi
if [ -f testing/verdict-covers-every-leg.py ]; then
  step "verdict-covers-every-leg.py --selftest" python3 testing/verdict-covers-every-leg.py --selftest
fi
if [ -f testing/voice-conformance/voice-conformance.sh ]; then
  step "voice conformance selftest (anti-vacuity)" bash testing/voice-conformance/voice-conformance.sh --selftest
  step "voice legs =ready (every declared leg LEG_STATUS=ready)" voice_legs_all_ready testing/voice-conformance/voice-conformance.sh ""
else
  absent_step "voice conformance selftest" "testing/voice-conformance/voice-conformance.sh — voice conformance rig not built yet"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "NO-DEFERRAL — nothing deferred; voice skeleton markers CLEARED (strict-done)"
step "no-deferral --selftest"    cargo xtask gate no-deferral-strict-done --selftest
step "no-deferral --strict-done" cargo xtask gate no-deferral-strict-done
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CONFIG-NOUN — four-noun parse residual holds at its locked-legitimate floor"
step "plane-config-noun-gate --selftest" bash scripts/plane-config-noun-gate.sh --selftest
# ZERO is deliberately NOT the done condition here — same treatment as the plane-noun/plane-grep
# billing-vocab meters the oracle excludes. Per the kickoff/LOCKED invariant: `pools`/`providers` STAY
# core-owned (CORE_OWNED_CONCRETE_SECTIONS, never evicted), and the `tools`/`agents`/`streams`
# DeployCfg fields are Option A's `deny_unknown_fields` floor (Option B is serde-blocked). So the
# residual is a LEGITIMATE floor, not debt; the DoD is "core's generic named-map MACHINERY names no
# plane noun" (Stage A, done), not "zero noun field refs".
#
# What IS asserted, therefore, is the floor: the armed gate must produce a residual (a run that could
# not print one is an error, not a pass), and that residual must not RISE above the number declared
# here. The gate's own exit status is 1 while the residual is above zero — by design — so it can never
# be the verdict on its own; it is captured and reported so a crash is distinguishable from the
# expected refusal, and a run that printed no countable verdict line is RED whatever it exited.
#
# THE FLOOR, RE-MEASURED ON THIS TREE (2026-09-21): 17 distinct core parse-target lines (pools 5 ·
# tools 3 · agents 2 · streams 7 -- `GREP_GATE_REPORT_ONLY=0 bash scripts/plane-config-noun-gate.sh
# --check`, confirmed stable over three consecutive runs). This constant previously said 16, copied
# from a note that itself admitted it could not re-measure: scripts/plane-config-noun-gate.sh's
# CORE_ROOT used to read "crates/busbar-core/src", which was deleted when busbar-core was absorbed
# into busbar-kernel, so the armed gate printed no residual line at all and the
# 16 was carried forward unverified rather than measured. scripts/plane-config-noun-gate.sh has since
# been repointed at CORE_ROOTS="crates/busbar-kernel/src" (its own
# CORE_ROOTS section), so the gate runs again and the true residual is 17, not 16 -- 16 was the wrong
# number, not the comment that used to claim 19. Lower this number the moment a section is evicted;
# a fall is reported as a fall and tells you what to lower it to.
CONFIG_NOUN_FLOOR=17
config_noun_residual() {
  local out rc line count
  out="$(GREP_GATE_REPORT_ONLY=0 bash scripts/plane-config-noun-gate.sh --check 2>&1)"; rc=$?
  line="$(printf '%s\n' "$out" | grep -E "distinct core parse-target lines" | tail -1)"
  count="$(printf '%s\n' "$line" | sed -e 's/.*distinct core parse-target lines): *//' -e 's/[^0-9].*$//')"
  if [ -z "$count" ]; then
    printf '%s\n' "$out"
    printf 'the armed gate printed NO residual line (exit %s): it errored, or its verdict wording moved.\n' "$rc"
    printf 'Nothing was compared to the floor, so this is RED rather than an unavailable count.\n'
    return 1
  fi
  if [ "$rc" -gt 1 ]; then
    printf '%s\n' "$out"
    printf 'the armed gate exited %s (usage/error, not its residual verdict) — residual %s not trusted.\n' "$rc" "$count"
    return 1
  fi
  if [ "$count" -gt "$CONFIG_NOUN_FLOOR" ]; then
    printf '%s\n' "$out"
    printf 'residual ROSE: %s core parse-target line(s), above the declared floor of %s (gate exit %s).\n' \
      "$count" "$CONFIG_NOUN_FLOOR" "$rc"
    return 1
  fi
  if [ "$count" -lt "$CONFIG_NOUN_FLOOR" ]; then
    printf 'residual FELL to %s (declared floor %s, gate exit %s) — lower CONFIG_NOUN_FLOOR to %s.\n' \
      "$count" "$CONFIG_NOUN_FLOOR" "$rc" "$count"
    return 0
  fi
  printf 'residual %s, exactly the declared floor (gate exit %s).\n' "$count" "$rc"
}
step "four-noun residual is at or below its declared floor ($CONFIG_NOUN_FLOOR)" config_noun_residual
printf '  \033[36m[info]\033[0m '
GREP_GATE_REPORT_ONLY=0 bash scripts/plane-config-noun-gate.sh --check 2>&1 | grep -E "distinct core parse-target lines" | tail -1 || echo "config-noun count unavailable"
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "EQUALITY — capability-equality ledger has 0 missing cells, on the legacy path AND over the loop"
step "capability-equality-summary --selftest" python3 scripts/capability-equality-summary.py --selftest
# The summary prints the missing count but exits 0 while the pin is honest; DONE additionally requires
# ZERO missing, so assert it explicitly here.
step "0 missing cells (LLM==MCP==A2A)" python3 -c '
import json, sys
d = json.load(open("qa/capability-equality.json"))
m = [c["capability"] + "/" + c["plane"] for c in d["cells"] if c["state"] == "missing"]
print((str(len(m)) + " missing cell(s): " + ", ".join(m)) if m else "0 missing cells")
sys.exit(1 if m else 0)
'
# THE ROOT COLUMN. Every plane also runs through the composition root, so the ledger carries a second
# verdict per cell over its plane's `root-*` leg. Two things are asserted here and neither is the
# other: that the column HOLDS (the cargo gate, run with every leg's feature on — the three `root-*`
# features and the `plane-mcp` / `plane-a2a` features that link the two planes the kernel-loop rider
# serves), and that every cell it calls `proven`
# actually RUNS and passes (the summary's own runner, which refuses a run that executed a different
# set). The remaining "none" cells are the switch-over queue and are PRINTED, not fatal — the same
# honest-ledger posture the missing set has.
step "capability_equality gate, five legs on" \
  cargo test -p busbar --features root-admin,plane-mcp,plane-a2a,root-voice,root-llm --quiet --test capability_equality
step "every root-leg proof cell RUNS and passes" python3 scripts/capability-equality-summary.py --root-legs
printf '  \033[36m[info]\033[0m '
python3 scripts/capability-equality-summary.py 2>/dev/null | grep -E "^ROOT-EQUALITY:" || echo "root-equality count unavailable"
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "PARITY — the shadow oracle: this build vs the published 1.5.5 binary (0 divergences)"
# The user-observable contract: every cell recorded from the released 1.5.5 artifact (by digest)
# is reproduced by the candidate byte for byte. The golden is the COMMITTED 1.5.5 recording, copied
# in and checked whole on every run and never re-recorded here (TODO item 41); the candidate is
# recorded fresh for BOTH legs the release claims — the default all-planes build and the LLM-only
# build (TODO item 38). A cell the golden could not produce is a NAMED gap, never a pass.
#
# THE SAME BLESS-ENV ASSERTION THE BYTE-IDENTITY GROUP MAKES, and this group needs it more. It used
# to say "SHADOW_ORACLE_GOLDEN may point at an existing recording" and was exempt from the check
# entirely — so the one variable that can make this group diff the candidate against ITSELF was the
# one variable nobody asserted. `SHADOW_ORACLE_GOLDEN=$ORACLE_DIR/recordings/candidate` produces a
# flawless parity report (every cell present, zero divergences) about nothing at all, and unlike a
# regenerated golden it leaves no artifact for a reviewer to notice afterwards.
if ! assert_bless_env_empty >/tmp/done-parity-env.$$ 2>&1; then
  printf '  \033[31m[RED]\033[0m  bless/repoint env is NOT empty — refusing PARITY (the golden could be the candidate itself)\n'
  sed 's/^/          /' /tmp/done-parity-env.$$
  rm -f /tmp/done-parity-env.$$
  CUR_RED=1; CUR_FIRST_NOTE="bless/repoint env not empty (parity)"
elif [ -x bin/oracle ]; then
  rm -f /tmp/done-parity-env.$$
  printf '  \033[32m[ok]\033[0m   bless/repoint env is empty — the golden is the pinned 1.5.5 recording, not an operator-chosen path\n'
  step "replay-selftest (the differ can see a diff)" ./bin/oracle replay-selftest
  # cells.json IS the owed set — the recorder and the replayer both iterate it, and every count in
  # the parity verdict below is a count over it. A hand edit, or a generator change nobody ran
  # --write for, would make this whole group measure a cell set that was never reviewed.
  step "enumerate-cells --check (cells.json is what the generator derives)" ./bin/oracle cells --check
  # THE PUBLISHED BINARY, fetched by pinned digest (idempotent: a verified cache is a no-op).
  step "fetch-golden (the published $PARITY_BASELINE_VERSION binary, by pinned digest)" ./bin/oracle fetch-golden
  ORACLE_DIR="target/oracle"
  GOLDEN="$ORACLE_DIR/recordings/golden"
  # THE REFERENCE: the committed recording, copied in fresh and checked whole — never re-recorded on
  # this machine (TODO item 41; see parity_install_golden above). A golden that is not whole is RED
  # and nothing is compared against it.
  PARITY_GOLDEN_OK=0
  if parity_install_golden "$PARITY_COMMITTED_GOLDEN" "$GOLDEN" >/tmp/done-parity-golden.$$ 2>&1; then
    printf '  \033[32m[ok]\033[0m   the golden is the committed %s recording, copied in and WHOLE (never re-recorded here)\n' "$PARITY_BASELINE_VERSION"
    sed 's/^/          /' /tmp/done-parity-golden.$$
    PARITY_GOLDEN_OK=1
  else
    printf '  \033[31m[RED]\033[0m  the committed %s golden could not be installed WHOLE — nothing is compared against it\n' "$PARITY_BASELINE_VERSION"
    sed 's/^/          /' /tmp/done-parity-golden.$$
    CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="committed golden not whole (parity)"
  fi
  rm -f /tmp/done-parity-golden.$$
  step "the golden is the published $PARITY_BASELINE_VERSION binary, by committed digest" \
    assert_golden_is_pinned "$GOLDEN" testing/shadow-oracle/golden-digests.tsv "$PARITY_BASELINE_VERSION"
  step "every in-scope cell has a golden or a named reason; owed-baseline IS the golden" \
    assert_golden_bookkeeping "$GOLDEN" testing/shadow-oracle/owed-baseline.txt testing/shadow-oracle/accepted-gaps.json testing/shadow-oracle/cells.json
  # THE SUBJECT, BOTH LEGS (TODO item 38). Each is built, taken from the build's own artefact path,
  # digested, recorded, checked to name that digest, and replayed strictly under its own name.
  PARITY_LEG_SHAS=""
  [ "$PARITY_GOLDEN_OK" -eq 1 ] || absent_step "the parity recordings of both legs" \
    "a whole committed golden — a reference that is not whole owes fewer cells, and owing fewer is how this group goes quietly green"
  for PARITY_LEG in $PARITY_LEGS; do
    [ "$PARITY_GOLDEN_OK" -eq 1 ] || break
    CAND="$ORACLE_DIR/recordings/candidate-$PARITY_LEG"
    REPORT="$ORACLE_DIR/reports/latest-$PARITY_LEG"
    rm -rf "$CAND"
    PARITY_BIN=""; PARITY_SHA=""; PARITY_SUBJECT_OK=0
    if PARITY_BIN="$(parity_build_and_resolve "$PARITY_LEG" 2>/tmp/done-parity-build.$$)"; then
      printf '  \033[32m[ok]\033[0m   [%s] cargo build -p busbar --release --locked %s\n' "$PARITY_LEG" "$(parity_leg_args "$PARITY_LEG" "$PARITY_MANIFEST" 2>/dev/null | tr '\n' ' ')"
      printf '          artefact: %s\n' "$PARITY_BIN"
    else
      printf '  \033[31m[RED]\033[0m  [%s] the release build of this leg failed\n' "$PARITY_LEG"
      sed 's/^/          /' /tmp/done-parity-build.$$ | tail -4
      CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="release build failed (parity, $PARITY_LEG)"
      PARITY_BIN=""
    fi
    rm -f /tmp/done-parity-build.$$
    if [ -n "$PARITY_BIN" ]; then
      if assert_candidate_bin_sane "$PARITY_BIN" >/tmp/done-parity-bin.$$ 2>&1; then
        PARITY_SHA="$(sha256_of "$PARITY_BIN" 2>/dev/null)" || PARITY_SHA=""
        if [ -n "$PARITY_SHA" ]; then
          printf '  \033[32m[ok]\033[0m   [%s] the candidate is a real, unlinked artefact of this build\n' "$PARITY_LEG"
          printf '          candidate sha256 %s\n' "$PARITY_SHA"
          PARITY_SUBJECT_OK=1
        else
          printf '  \033[31m[RED]\033[0m  [%s] the candidate could not be digested — its identity cannot be carried into the report\n' "$PARITY_LEG"
          CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="candidate not digestible (parity, $PARITY_LEG)"
        fi
      else
        printf '  \033[31m[RED]\033[0m  [%s] the candidate binary is not an artefact this run can prove it built\n' "$PARITY_LEG"
        sed 's/^/          /' /tmp/done-parity-bin.$$
        CUR_RED=1; [ -z "$CUR_FIRST_NOTE" ] && CUR_FIRST_NOTE="candidate binary refused (parity, $PARITY_LEG)"
      fi
      rm -f /tmp/done-parity-bin.$$
    fi
    PARITY_LEG_SHAS="$PARITY_LEG_SHAS $PARITY_LEG=$PARITY_SHA"
    if [ "$PARITY_SUBJECT_OK" -eq 1 ]; then
      step "[$PARITY_LEG] record the candidate (the artefact cargo named)" ./bin/oracle record --bin "$PARITY_BIN" --plane all --out "$CAND"
      step "[$PARITY_LEG] the recording names the binary this run built" \
        assert_recorded_subject "$CAND" "$PARITY_SHA" "the $PARITY_LEG candidate recording"
      # `--strict` IS WHAT MAKES THE EXIT CODE THE VERDICT. Without it the differ prints its rows and
      # exits 0 whatever they say — including when the selection matched nothing.
      #
      # `--allow-harness-skew` IS PASSED HERE, BY NAME, for the reason ci.yml's shadow-oracle job gives
      # beside its own: the golden is the COMMITTED 1.5.5 recording, taken with the Python harness, and
      # the candidate was just recorded with the Rust engine, so the differ's same-revision guard would
      # refuse the pair. This run no longer re-records its reference (TODO item 41), which is what used
      # to keep the revisions equal. DELETE this flag with the golden re-take (TODO item 50).
      step "[$PARITY_LEG] replay: candidate vs golden (strict)" \
        ./bin/oracle replay --golden "$GOLDEN" --candidate "$CAND" --out "$REPORT" --allow-harness-skew --strict
      # ...and the same two facts re-derived from the report the differ wrote, so the claim does not
      # rest on one flag in one pinned engine. A green is a statement about the OWED cells only.
      step "[$PARITY_LEG] the report's own numbers: cells were compared, and none diverged" \
        assert_parity_verdict "$REPORT"
    else
      absent_step "[$PARITY_LEG] the parity recording and its verdict" \
        "a candidate binary this run can prove it built — nothing was recorded, so nothing is proven; the release build above is where to start"
    fi
  done
  PARITY_SHA_DEFAULT=""; PARITY_SHA_LLM=""
  for PARITY_LEG in $PARITY_LEG_SHAS; do
    case "$PARITY_LEG" in default=*) PARITY_SHA_DEFAULT="${PARITY_LEG#default=}" ;; llm-only=*) PARITY_SHA_LLM="${PARITY_LEG#llm-only=}" ;; esac
  done
  step "the default and llm-only legs are two different binaries" \
    assert_legs_distinct "$PARITY_SHA_DEFAULT" "$PARITY_SHA_LLM"
else
  absent_step "shadow oracle" "bin/oracle"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "DESIGN — every ARCHITECTURE.md Appendix B binding is mapped to a check that exists"
# The design bindings ledger (qa/design-bindings.json) maps each parity binding to the tests, oracle
# cells, lints and gates that prove it. Plain --check reports gaps; --strict owes EVERY binding to the
# verdict so an unmapped binding is red. DONE means the design is fully bound, not partly.
step "design-bindings --selftest"  cargo xtask gate design-bindings --selftest
step "design-bindings --strict"    cargo xtask gate design-bindings --strict
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "AUDIT-LEDGER — every production path is covered by a scope, nothing open at HIGH/MEDIUM"
# qa/audit-ledger.json carries one scope per production path, its tree hash at the audited commit and
# the round that produced the result. --check is red two ways: a tracked production file that no
# scope covers (coverage cannot silently regress when a crate is added), and a scope with findings
# recorded and no fix commit stamped. A result whose tree hash has moved reads `stale` in
# docs/design/AUDIT-STATUS.md rather than green — an audit describes one tree, not the code forever.
if [ -f qa/audit-ledger.json ]; then
  # The gate's own RED proof runs first, as everywhere else. It judges the five rules about the
  # REGISTER (is the instrument believable); `--check` below judges those five plus the two about
  # the AUDIT (is coverage complete, is anything still open at HIGH/MEDIUM) — which are the ones
  # that are red until the audit finishes, and this DONE claim is where that red belongs.
  # The `audit-ledger` GATE was deleted with the old register; what survives, and what
  # judges a restored register, is `cargo xtask ledger`. Its rules' own RED proofs are its unit
  # tests, declared by count so a filter that drifts off them is RED rather than vacuously green.
  step "audit ledger rules (xtask audit + audit_cmd tests)" filtered_cargo_test 20 cargo test -p xtask --lib audit
  step "audit-ledger --check"  cargo xtask ledger --check
else
  absent_step "audit ledger" "qa/audit-ledger.json"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "CHANGELOG — every accepted register entry is named"
# testing/shadow-oracle/accepted-differences.json's own differ refuses an entry that accepts
# status/effects.usage without kind=breaking and a `changelog` field; this gate closes the other
# half -- that the named line was actually WRITTEN, verbatim, in CHANGELOG.md, not just declared --
# and it owes that of improvements too, which the owner rule accepts "named in the CHANGELOG".
# The gate is `cargo xtask gate changelog-register` since the conversion; the guard follows it
# rather than the file it used to live in. Note what the guard is FOR: absent_step is RED, so a
# gate that moved and took its call site with it would have blocked the DONE claim rather than
# quietly dropping a check -- which is the behaviour to keep, not to route around.
if cargo xtask gate --list >/dev/null 2>&1; then
  step "changelog-register --selftest" cargo xtask gate changelog-register --selftest
  step "changelog-register"            cargo xtask gate changelog-register
else
  absent_step "changelog register gate" "cargo xtask gate changelog-register"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "INVENTORY-COVERAGE — every docs/design/inventory/*.md row id is bound to an oracle cell"
# Appendix B says every inventory row is a parity binding AND an oracle cell; this is the check that
# was missing. qa/inventory-gaps.json names every row id with no citing cell yet, so a gap is a
# visible, owned line item rather than a silent hole. DONE means no id has no cell and no name.
# The bash wrapper and its Python were deleted at c8272b166; this reads the Rust gate that replaced
# them, which is registered, run by ci.yml on every push, and cited by design binding PB-0. The
# guard stays a guard -- it now asks whether the GATE is registered, not whether a file is on disk,
# because that is what "the check can run" means for a gate that lives in a crate.
if cargo xtask gate --list 2>/dev/null | grep -q '\binventory-coverage\b'; then
  step "inventory-coverage --selftest" cargo xtask gate inventory-coverage --selftest
  step "inventory-coverage --check"    cargo xtask gate inventory-coverage
else
  absent_step "inventory coverage gate" "cargo xtask gate inventory-coverage"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "KERNEL — the Teller loop battery, the capability fixtures and attempt identity are green"
# The kernel crate's integration tests are the loop battery (step order, refusal stops at its step,
# every reason posts, the settlement table, the two-sided canary, kill points). The caps fixtures
# prove the tokens cannot be forged.
#
# THE CAPS STEP NAMES `busbar-contract`, NOT `busbar-caps`. busbar-caps was folded
# into busbar-contract as `busbar_contract::caps`, and the crate and its
# workspace member were deleted. `cargo test -p busbar-caps` does not run a reduced set against the survivor --
# cargo cannot resolve the package at all, so the step errored and the whole KERNEL group was red on
# the harness rather than on the tree. The fixtures came with the fold: they are the ~75 tests under
# `caps::tests::*` (crates/busbar-contract/src/caps/tests/{mod,the_posting_arithmetic,
# what_the_record_reads,what_the_usage_report_says}.rs) plus the lint-rule table the construction
# gate's `hold-escapes` rule reads out of caps/fixtures/lint_rules.rs. The selector is the WHOLE
# crate, exactly as the busbar-caps line was a whole-crate run -- a superset of what it used to
# cover, and a whole-crate run is the one shape that cannot go vacuously green on a moved filter. attempt_identity proves the one attempt
# seam produces the bytes and breaker mutations the two legacy twins produced.
#
# THE FILTER MATCHES 2 TESTS, BOTH LEGITIMATE, NOT A LOOSENED FILTER. `attempt_identity` selects by
# substring on the fully-qualified test name, so it sweeps the whole `attempt_identity_tests` module
# (`crates/busbar-llm/src/engine/tests/attempt_identity_tests.rs`), which today holds:
#   * `walk_vs_pipeline_attempt_identity` -- the identity harness itself (legacy twin vs the unified
#     attempt seam, table-driven over 200+ cases).
#   * `eventstream_normalization_blanks_the_reading_and_nothing_else` -- added
#     directly beside the harness, to prove the `normalize()` helper the harness diffs THROUGH
#     collapses only the non-identity-bearing framing bytes (measured latencyMs, CRC/length bytes)
#     and NOT the frame's real content -- the module's own doc says a broken normalizer "could pass
#     by erasing the body, which would make the identity rig above green over nothing." That makes
#     it a deliberate anti-vacuity companion to the harness, not scope the filter picked up by
#     accident, so the expected count is 2, not the module's previous 1.
if [ -d crates/busbar-kernel ]; then
  step "busbar-kernel battery"           cargo test -p busbar-kernel --quiet
  step "caps fixtures (busbar-contract)" cargo test -p busbar-contract --quiet
  step "attempt identity (busbar-llm)"   filtered_cargo_test 2 cargo test -p busbar-llm --quiet attempt_identity
else
  absent_step "kernel battery" "crates/busbar-kernel"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "ISOMORPHISM — plane_isomorphism gate present and green"
if [ -f crates/busbar/tests/plane_isomorphism.rs ]; then
  step "plane_isomorphism test (incl. its selftests)" cargo test -p busbar --quiet --test plane_isomorphism
else
  absent_step "plane_isomorphism test" "crates/busbar/tests/plane_isomorphism.rs"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "TELLER-STEPS — H2: one conformance cell per Teller step per plane, and one root-leg cell beside it"
if [ -f qa/teller-steps.json ]; then
  step "teller-steps self-test"  cargo xtask gate teller-steps --selftest
  step "teller-steps matrix"     cargo xtask gate teller-steps
  # The ROOT column beside the rig column: every (plane x step) cell also names the root::units_*
  # cell that drives that step through run_unit, or a named gap. The gate verifies the column holds
  # (a proven cell's fn exists in its own leg's file; a leg proving nothing is red); this RUNS every
  # named cell with all five legs on, so "proven" means watched rather than present on disk.
  step "every root-leg step cell RUNS and passes" cargo xtask teller-steps --root-legs
  # And the same treatment for the RIG column the matrix's `cell` values name. The gate above proves
  # every id still resolves to the scenario, subject script, voice leg or suite that owns it; this
  # RUNS the rigs behind them.
  #
  # THIS ARM IS DRIVEN FROM HERE, NOT FROM THE GATE RUNNER. `cargo xtask gate segregation` forbids
  # xtask from running the oracle's own code — a runner that executes its subject is a runner whose
  # verdict moves when the subject does — so the invocation lives with its caller. Its two refusals
  # come with it: a missing rig ledger and a missing release binary are REFUSALS, not skips. Nothing
  # ran, so nothing is proven.
  #
  # testing/shadow-oracle/rigs-ledger.sh WAS absent from this tree, and the reason this group used to
  # print for that was wrong in both halves. It said the work had been "ported to library leaves
  # only, not re-exposed as a CLI arm" in the pinned engine, citing
  # crates/busbar-release-oracle/PORT-REMAINING.md. That document does not say that. What it says,
  # verbatim, is one line (busbar-release/crates/busbar-release-oracle/PORT-REMAINING.md:67), filed
  # under the heading at :57, "STILL DEFERRED (recorder internals the harness itself provides; we
  # DRIVE them, never reimplement)":
  #
  #     - `rigs-ledger.sh` / `fixture-gate-selftest.sh` — separate plane-rigs gate, not the LLM
  #       money proof.
  #
  # So it was never ported: `grep -rln rigs crates/busbar-release-oracle/src/` returns nothing, and
  # that crate has no `recorder::*` leaves at all, for rigs or anything else. It was ruled OUT of
  # that port's scope, by name, as not being the money proof. The old citation both misquoted the
  # source and understated the work — re-exposing an already-ported CLI arm is small, and this was
  # not that.
  #
  # AND THE RULING IS RIGHT, WHICH MAKES "WAIT FOR UPSTREAM" THE WRONG ANSWER. A plane-rigs gate is
  # not the LLM money oracle's job, so no CLI surface was ever going to land in busbar-release for
  # this caller to drive. The gate belongs HERE, beside the other rows that read this tree — and it
  # was here: testing/shadow-oracle/rigs-ledger.sh, deleted by c73ae4f66 ("the oracle tool leaves
  # this tree"), a sweep that moved the JUDGE out and took this bridge with it even though the
  # bridge drives busbar's OWN rigs (scripts/mcp-conformance.sh, scripts/a2a-subject/boot.sh,
  # testing/voice-conformance/voice-conformance.sh) and never touches the judge. The one upstream
  # hook it needed — voice-conformance.sh's additive VOICE_RESULT_LOG — survived the sweep intact,
  # which is what made restoring it a restore rather than a rewrite. It is restored from fa15cd661.
  #
  # THIS ARM IS STILL DRIVEN FROM HERE, NOT FROM THE GATE RUNNER, and that is not this file's
  # opinion: xtask/src/gates/segregation.rs names this exact path and this exact caller as the rule
  # — "`teller-steps` may ask `rigs-baseline.json` what ids exist, and may NOT run `rigs-ledger.sh`
  # to find out … that arm stayed in `scripts/verify-1.6.0-done.sh`, where a caller driving the
  # oracle is a caller, rather than moving into the gate runner, where it would be the runner
  # importing its subject." A `cargo xtask teller-steps --rig-legs` would break segregation; the
  # repoint is to the restored script, not to a new gate flag.
  #
  #
  # WHAT THIS LEDGER COVERS, WRITTEN DOWN SO THE STEP LABEL CANNOT BE READ AS MORE THAN IT IS. The
  # rig column fills 50 plane x step slots, 2 of which are declared gaps, leaving 48 named cells.
  # This ledger folds FOUR namespaces -- mcp.rig, a2a.battery, a2a.tck, voice.rig -- which is 21 of
  # them. Another 23 (teller|*, llm|*, concurrency|*, admin.ops|*) are shadow-oracle corpus cells
  # and RUN in the PARITY group against the published 1.5.5 golden. That leaves FOUR named cells
  # with a resolvable owner and no arm in this file that runs them:
  #   mcp.battery|ADV.MALFORMED-JSON, mcp.battery|SEAM.UPSTREAM-FAILURE-IS-TOOL-ERROR
  #     -> testing/mcp-conformance/src/suites/{server-adversarial,seam}.mjs
  #   a2a.supplement|AUTH-SERVER-002, a2a.supplement|AUTH-SCOPE-001
  #     -> testing/a2a-supplement/run-supplement.sh
  # Both runners exist in this tree; neither is wired to a done-oracle arm. Named here as a gap
  # someone can close rather than left as the difference between what the label says and what ran.
  # The self-test runs FIRST (the house rule): a ledger whose own vacuity guards have stopped firing
  # is worse than none, and this one proves six of them — a flipped baseline row, a red run, a zero-
  # row run, a leg that enumerated nothing, and --rebaseline refusing on red / writing on green.
  # The refusals stay refusals: a missing script or a missing release binary is a REFUSAL, not a
  # skip. Nothing ran, so nothing is proven.
  if [ ! -x testing/shadow-oracle/rigs-ledger.sh ]; then
    absent_step "the rig suites the matrix cites RUN and pass" \
      "testing/shadow-oracle/rigs-ledger.sh — the plane-rigs bridge that folds the MCP / A2A / voice rigs into one ledger. Restore it (git show fa15cd661:testing/shadow-oracle/rigs-ledger.sh); it is NOT coming from busbar-release, which ruled it out of the oracle port by name (PORT-REMAINING.md:67)."
  elif [ -L target/release/busbar ]; then
    # THE SAME WRONG-SUBJECT HAZARD THE PARITY GROUP NOW REFUSES, on the one path this arm still
    # takes literally. `-x` follows a symlink, so the guard below passes on a link into another
    # checkout's target dir and the rigs go on to judge THAT binary while this file's banner says
    # this tree was measured. A link here has been left behind by a neighbouring build on this very
    # checkout, so this is a refusal that has already had to fire once.
    step "rigs-ledger --selftest (the ledger's own vacuity guards still fire)" \
      bash testing/shadow-oracle/rigs-ledger.sh --selftest
    absent_step "the rig suites the matrix cites RUN and pass" \
      "an unlinked target/release/busbar — the path is a SYMLINK to $(readlink target/release/busbar), so the rigs would judge whatever tree that points at and this file would report the answer as this one's. Remove the link and build here: cargo build --release -p busbar"
  elif [ ! -x target/release/busbar ]; then
    step "rigs-ledger --selftest (the ledger's own vacuity guards still fire)" \
      bash testing/shadow-oracle/rigs-ledger.sh --selftest
    absent_step "the rig suites the matrix cites RUN and pass" \
      "target/release/busbar — the MCP and A2A legs are armed from it (MCP_SUBJECT_BUSBAR_BIN / A2A_SUBJECT_BUSBAR_BIN), so without it the rigs cannot run at all. Build it first: cargo build --release -p busbar"
  else
    step "rigs-ledger --selftest (the ledger's own vacuity guards still fire)" \
      bash testing/shadow-oracle/rigs-ledger.sh --selftest
    step "the rig suites the matrix cites RUN and pass (mcp.rig / a2a.battery / a2a.tck / voice.rig)" \
      bash testing/shadow-oracle/rigs-ledger.sh --bin target/release/busbar --check
  fi
  printf '  \033[36m[info]\033[0m '
  cargo xtask teller-steps 2>/dev/null | grep -E "^ROOT-STEPS:" || echo "root-steps count unavailable"
else
  absent_step "teller-steps" "qa/teller-steps.json"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "PUBLIC-HYGIENE — nothing a customer can read describes how the software was built (0 hits)"
# scripts/public-hygiene-lint.py: no shipped file (source, scripts/, docs/ outside design/, generated
# artifacts) may carry an internal tracker/audit-round id, a private-doc pointer, how-it-was-built
# process narration, delivery-plan vocabulary, editor-directed prose, authoring meta-commentary, a
# named individual, a developer home directory, or a bare commit-hash citation. DONE means 0 hits,
# not "0 hits we noticed."
if [ -f scripts/public-hygiene-lint.py ]; then
  step "public-hygiene-lint --selftest" python3 scripts/public-hygiene-lint.py --selftest
  step "public-hygiene-lint --check"    python3 scripts/public-hygiene-lint.py --root . --quiet
else
  absent_step "public hygiene gate" "scripts/public-hygiene-lint.py"
fi
end_group

# ─────────────────────────────────────────────────────────────────────────────────────────────────
begin_group "STORE-QA — the durable-store QA cycle's service pins hold, and its fixtures still work"
# docs/design/store-qa-cycle.md is the standing loop that keeps busbar's four durable stores
# (sqlite, postgres, mysql, valkey) proven run after run. Its foundation is that the backend
# containers are the SAME BYTES everywhere they are stood up — and they were not: four workflows
# agreed on a digest while scripts/release-check.sh, the script the qa gate runs, used floating
# tags. testing/fleet-fixtures/service-images.tsv is the one pinned list; the lint is what keeps
# every workflow reading it, since Actions cannot read a file into a `services:` block.
#
# This group is in the DONE readout because the cycle is a loop, not a task: a pin that drifts, or a
# fixture whose port band creeps into the shadow oracle's, breaks a store proof quietly and much
# later. Both self-tests run FIRST — a lint whose own rules have stopped firing is worse than none.
if cargo xtask gate --list 2>/dev/null | grep -q '\bservice-images\b'; then
  step "service-images-check --selftest"      cargo xtask gate service-images --selftest
  step "service-images-check (every workflow image is the pinned digest)" cargo xtask gate service-images
else
  absent_step "service image pin gate" "cargo xtask gate service-images"
fi
if [ -f testing/fleet-fixtures/store-services.sh ]; then
  # No docker needed: the fixture self-test asserts properties of the pinned table and of the
  # script's own rules — the local port band stays disjoint from the oracle's 487xx/488xx band, a
  # namespace token cannot reach DDL unvalidated, a valkey namespace never lands on the index `url`
  # hands out, `down` is safe when nothing is up.
  step "store-services fixtures --selftest"   bash testing/fleet-fixtures/store-services.sh --selftest
else
  absent_step "local store fixtures" "testing/fleet-fixtures/store-services.sh"
fi
end_group

# ── THE ONE VERDICT ─────────────────────────────────────────────────────────────────────────────
hdr "1.6.0 DONE-ORACLE READOUT"
final_verdict
exit $?
