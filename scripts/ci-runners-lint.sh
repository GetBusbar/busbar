#!/usr/bin/env bash
# `bash -n` and `shellcheck -x` over every script that keeps the runner fleet alive.
#
#   ./scripts/ci-runners-lint.sh
#   ./scripts/ci-runners-lint.sh --selftest    # prove the gate is RED-able before its verdict is trusted
#
# WHY THIS IS A SCRIPT AND NOT A LINE IN A RUNBOOK. These scripts are the thing that brings CI back
# when CI is down, so they are the one place where "it has a syntax error" is discovered at exactly
# the moment nobody can afford to discover it. `shellcheck -x` follows the `source=` directive into
# ci-runners-lib.sh, so a helper renamed in the library is caught here rather than at 03:00 by an
# unset variable in a top-up loop.
#
# THE SCAN SET IS DERIVED, NOT A HAND-LIST. It WAS a hardcoded list of nine filenames, so the gate's
# own subject could grow behind its back: a new `scripts/ci-runners-<x>.sh` added to the fleet and
# not added to the list was linted by NOTHING, and the gate stayed green while an unlinted script
# with a syntax error shipped — the exact "it has a syntax error" discovered at 03:00 that this file
# exists to prevent. So the set is now globbed from disk (`ci-runners-*.sh` plus the `ci-remote-lib.sh`
# it sources), floored so an empty glob is a refusal rather than a clean scan, and its coverage is
# proven by `--selftest`. A new fleet script cannot be added without this gate seeing it.
#
# EVERY SUPPRESSION IN THESE FILES IS INLINE AND CARRIES ITS REASON. There is no config file and no
# blanket exclude list, because a blanket exclude is how a real finding gets to hide behind a
# deliberate one. The two that recur: SC2086 on `--instance-ids $LIST` (AWS wants separate argv
# entries, so the word-splitting is the point) and SC2016 on `'$Latest'` (EC2's literal
# launch-template version alias) and on JMESPath backticks.
#
# scripts/ci-runner-bootstrap.sh is deliberately NOT scanned. It is a user-data TEMPLATE, not a
# script that runs here: it carries `__PLACEHOLDER__` tokens that ci-runners-up.sh substitutes, its
# "unused" variables are consumed by the here-docs it writes out on the box, and its one SC2086 is
# an intentional split of SCCACHE_ENV. It is also gzipped into a 16384-byte user-data budget, so
# every suppression comment added to it is bytes spent against the cap that broke the fleet once
# already. Lint it by hand when it changes; do not add it here. It is EXCLUDED BY THE GLOB, not by a
# list: its name is `ci-runner-bootstrap.sh` (singular `ci-runner-`), so `ci-runners-*.sh` never
# matches it, and `--selftest` proves that exclusion holds.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

note() { printf '  %s\n' "$1"; }

# ── THE SCAN SET, DERIVED FROM DISK ───────────────────────────────────────────────────────────────
# Every `ci-runners-*.sh` in the scripts dir (which includes this linter and the selftest harness),
# plus the `ci-remote-lib.sh` those scripts source. `ci-runner-bootstrap.sh` is `ci-runner-` not
# `ci-runners-`, so the glob excludes it with no special case. One path per line.
discover_fleet_scripts() {
  local dir="$1" f
  for f in "$dir"/ci-runners-*.sh; do
    [ -e "$f" ] && printf '%s\n' "$f"
  done
  [ -e "$dir/ci-remote-lib.sh" ] && printf '%s\n' "$dir/ci-remote-lib.sh"
}

# ── THE LINT ITSELF (one copy; the self-test drives THIS function, never a duplicate) ─────────────
# `bash -n` (parse) then `shellcheck -x` (follow `source=`) over each file. Returns non-zero the
# moment any file fails either check — a lint that could not fail its own broken input is not a lint.
# The shellcheck pass runs when present and is reported as SKIPPED when not, so the self-test can
# prove the parse arm's RED/GREEN on a machine without it; the real run below still HARD-REQUIRES it.
lint_files() {
  local rc=0 f
  for f in "$@"; do
    printf '%-34s ' "$(basename "$f")"
    if bash -n "$f" 2>/dev/null; then printf 'bash -n: OK   '; else printf 'bash -n: FAIL '; rc=1; fi
    if type -p shellcheck >/dev/null 2>&1; then
      if shellcheck -x "$f"; then
        echo 'shellcheck: CLEAN'
      else
        echo 'shellcheck: FINDINGS (above)'
        rc=1
      fi
    else
      echo 'shellcheck: SKIPPED (not installed)'
    fi
  done
  return "$rc"
}

# ── SELF-TEST — the gate cannot be lied to ────────────────────────────────────────────────────────
# COVERAGE proves the judge-nothing gap is closed (a new fleet script IS discovered, the template is
# NOT); RED proves a broken script fails the lint; GREEN proves a clean one passes. RED/GREEN drive
# the bash -n arm, so they hold with or without shellcheck installed.
run_selftest() {
  printf '\n== ci-runners-lint SELF-TEST (the gate cannot be lied to) ==\n'
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0

  # COVERAGE — a new ci-runners-*.sh is discovered without editing this gate; the bootstrap TEMPLATE
  # and an unrelated ci-remote-*.sh helper are not swept in by the glob.
  : > "$tmp/ci-runners-newthing.sh"
  : > "$tmp/ci-remote-lib.sh"
  : > "$tmp/ci-runner-bootstrap.sh"
  local disc; disc="$(discover_fleet_scripts "$tmp")"
  if grep -q '/ci-runners-newthing\.sh$' <<<"$disc"; then
    note "COVERAGE: a new ci-runners-*.sh is discovered with no edit to this gate"
  else
    fail=1; note "COVERAGE FAILED: a new ci-runners-*.sh was NOT discovered"
  fi
  if grep -q '/ci-remote-lib\.sh$' <<<"$disc"; then
    note "COVERAGE: the sourced ci-remote-lib.sh is discovered"
  else
    fail=1; note "COVERAGE FAILED: ci-remote-lib.sh was NOT discovered"
  fi
  if grep -q 'ci-runner-bootstrap\.sh' <<<"$disc"; then
    fail=1; note "COVERAGE FAILED: the bootstrap TEMPLATE was swept in (the glob must exclude it)"
  else
    note "COVERAGE: the bootstrap template stays excluded (ci-runner- != ci-runners-)"
  fi

  # RED — a syntactically broken script fails the lint. A lone `fi` is a parse error under `bash -n`.
  printf 'fi\n' > "$tmp/ci-runners-broken.sh"
  if lint_files "$tmp/ci-runners-broken.sh" >/dev/null 2>&1; then
    fail=1; note "RED FAILED: a syntactically broken script PASSED the lint"
  else
    note "RED: a syntactically broken script fails the lint"
  fi

  # GREEN — a clean script passes.
  printf '%s\n' '#!/usr/bin/env bash' 'echo ok' > "$tmp/ci-runners-clean.sh"
  if lint_files "$tmp/ci-runners-clean.sh" >/dev/null 2>&1; then
    note "GREEN: a clean script passes the lint"
  else
    fail=1; note "GREEN FAILED: a clean script was rejected"
  fi

  # FLOOR — an empty directory yields no scripts, which the main path must refuse rather than read as
  # a clean scan. (The main floor is enforced below; here we prove the discovery is genuinely empty.)
  mkdir -p "$tmp/empty"
  if [ -z "$(discover_fleet_scripts "$tmp/empty")" ]; then
    note "FLOOR: an empty scripts dir discovers nothing (the vacuous input the floor refuses)"
  else
    fail=1; note "FLOOR FAILED: an empty scripts dir discovered something"
  fi

  printf '\n== result ==\n'
  if [ "$fail" -ne 0 ]; then
    note "ci-runners-lint SELF-TEST FAILED — the gate would let a broken or unseen fleet script through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

type -p shellcheck >/dev/null 2>&1 || {
  echo "shellcheck is not installed: brew install shellcheck" >&2
  exit 2
}

# THE SCAN SET IS DISCOVERED AND FLOORED BEFORE THE LOOP. A glob that matched nothing — this file run
# from the wrong directory, the fleet scripts relocated, a `set -u` literal-glob handed to the loop —
# would lint zero files and exit 0, a clean bill of health for a scan that never happened. The fleet
# has never had fewer than a handful of these scripts, so fewer than three is a broken discovery, not
# a shrunken fleet.
files=()
while IFS= read -r f; do files+=("$f"); done < <(discover_fleet_scripts "$HERE")
if [ "${#files[@]}" -lt 3 ]; then
  echo "FAIL: discovered only ${#files[@]} fleet script(s) under $HERE — the scan set is broken," >&2
  echo "      not the fleet shrunk. A count this low is a scan that did not happen, refused." >&2
  exit 1
fi

rc=0
lint_files "${files[@]}" || rc=1
exit "$rc"
