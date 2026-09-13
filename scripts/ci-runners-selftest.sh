#!/usr/bin/env bash
# Behavioural selftest for the fleet's REGISTRATION PATH. Runs on a laptop with no AWS credentials,
# no gh auth and no fleet: every case is either a property of the source or a call into
# register_agents with `gh` and `aws` stubbed on PATH.
#
#   ./scripts/ci-runners-selftest.sh
#
# WHY THIS EXISTS. On 2026-09-10 a spot interruption wave replaced seven runner boxes; forty
# minutes later the org had 8 runner agents online of 40. Every box had finished its bootstrap and
# unpacked all four runner trees. Nothing was wrong with the AMI, the user-data, the labels or the
# egress: ci-runners-reconcile.sh registered by shelling out to `"$HERE/ci-runners-register.sh"`
# with `>/dev/null 2>&1 || true`, the reconcile was being run from a copied scripts directory that
# did not contain that file, and so every pass reported the boxes as still bootstrapping. The
# failure was invisible because it was DISCARDED, and the fleet stayed half-size until a human
# read a log line that said the fleet was fine.
#
# Cases A and B are that bug: they fail on the code as it was and pass on the code as it is.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

pass=0; fail=0
ok()   { printf '  ok   %s\n' "$1"; pass=$(( pass + 1 )); }
bad()  { printf '  FAIL %s\n' "$1"; fail=$(( fail + 1 )); }
case_() { printf '%s\n' "$1"; }

# ── A. A scripts directory without ci-runners-register.sh still registers ───────────────────────
# THE ORIGINAL DEFECT, as a property of a directory rather than of a line of code: copy in exactly
# what the reconcile sources and nothing else, and the registration entry point must still be
# there. Sourcing is fatal when the library is missing, which is the whole point of moving the mint
# and the dispatch into it — a partial copy now cannot run at all, where before it ran and lied.
case_ "A. registration survives a scripts/ copy that lacks ci-runners-register.sh"
A_DIR="$(mktemp -d)"
cp "$HERE/ci-runners-lib.sh" "$A_DIR/"
# shellcheck disable=SC1091  # the fixture's copy is made at run time; the real one is linted above
if ( set -uo pipefail; . "$A_DIR/ci-runners-lib.sh"; declare -f register_agents >/dev/null ) 2>/dev/null; then
  ok "register_agents is reachable from the library alone"
else
  bad "register_agents is NOT reachable without ci-runners-register.sh"
fi
if [ -e "$A_DIR/ci-runners-register.sh" ]; then bad "the fixture accidentally contains the sibling script"; fi
rm -rf "$A_DIR"

# ── B. The reconcile keeps the registration's exit status ───────────────────────────────────────
case_ "B. ci-runners-reconcile.sh does not discard the registration's outcome"
# COMMENTS ARE STRIPPED FIRST. The reconcile quotes the old line in the comment that explains why
# it is gone, and a naive grep reads that history as the bug still being present.
code() { sed -e 's/[[:space:]]*#.*$//' "$1"; }
if code "$HERE/ci-runners-reconcile.sh" | grep -q 'ci-runners-register\.sh"'; then
  bad "the reconcile still execs a sibling script to register"
else
  ok "the reconcile does not exec a sibling script to register"
fi
# shellcheck disable=SC2016  # `$REACHABLE` is the literal text being searched for, not an expansion
if code "$HERE/ci-runners-reconcile.sh" | grep -q 'register_agents \$REACHABLE'; then
  ok "the reconcile calls register_agents"
else
  bad "the reconcile does not call register_agents"
fi
if grep -q 'REGISTRATION STEP FAILED' "$HERE/ci-runners-reconcile.sh"; then
  ok "a failed registration is reported as itself, not as 'bootstrap is not finished'"
else
  bad "a failed registration is still indistinguishable from a bootstrapping box"
fi

# ── C. A failed token mint is a non-zero return, not a silent pass ──────────────────────────────
# `gh` stubbed to print nothing is the org API limit being exhausted, which is the OTHER way this
# step fails on a real morning.
case_ "C. an empty registration token fails loudly"
C_BIN="$(mktemp -d)"
printf '#!/bin/sh\nexit 0\n' > "$C_BIN/gh";  chmod +x "$C_BIN/gh"
printf '#!/bin/sh\nexit 0\n' > "$C_BIN/aws"; chmod +x "$C_BIN/aws"
out="$( PATH="$C_BIN:$PATH" CI_RUNNER_DRY_RUN=0 bash -c ". '$HERE/ci-runners-lib.sh'; register_agents i-0selftest" 2>&1 )"
rc=$?
if [ "$rc" != 0 ]; then ok "register_agents returned non-zero"; else bad "register_agents returned 0 on an empty token"; fi
if printf '%s' "$out" | grep -q 'REGISTRATION FAILED'; then ok "it says REGISTRATION FAILED"; else bad "no REGISTRATION FAILED in: $out"; fi
rm -rf "$C_BIN"

# ── D. Nothing token-shaped is ever printed ─────────────────────────────────────────────────────
# The dry-run path names the API call and the boxes and never the credential; the live path prints
# only that a token was minted. A token in a log is a token in every scrollback and every paste.
case_ "D. the registration never prints the token"
D_BIN="$(mktemp -d)"
printf '#!/bin/sh\necho SELFTESTTOKENVALUE\n' > "$D_BIN/gh";  chmod +x "$D_BIN/gh"
printf '#!/bin/sh\necho cmd-0selftest\n'      > "$D_BIN/aws"; chmod +x "$D_BIN/aws"
out="$( PATH="$D_BIN:$PATH" CI_RUNNER_DRY_RUN=1 bash -c ". '$HERE/ci-runners-lib.sh'; register_agents i-0selftest" 2>&1 )"
if printf '%s' "$out" | grep -q SELFTESTTOKENVALUE; then bad "the token appeared in the output"; else ok "no token in the dry-run output"; fi
if printf '%s' "$out" | grep -q 'i-0selftest'; then ok "the dry run names the boxes it would register"; else bad "the dry run does not name the boxes"; fi
rm -rf "$D_BIN"

printf '\nci-runners-selftest: %s passed, %s failed\n' "$pass" "$fail"
[ "$fail" = 0 ]
