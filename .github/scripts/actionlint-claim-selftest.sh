#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Selftest for .github/actionlint.yaml (item 458 of the 1.6.0 audit; follow-up per architect note).
#
# 458: the file's header comment claimed "actionlint says so before it is pushed" as an
#      unconditional guarantee. Measured (at the time of the original fix): no workflow under
#      .github/workflows/ invoked actionlint; the only caller was scripts/land.sh, gated behind
#      `command -v actionlint`, falling back to a bare YAML parse (which cannot catch a bad runner
#      label) when the binary isn't installed.
#
# Follow-up: the first version of this script hard-failed whenever ANY workflow merely CONTAINED
# the word "actionlint" (a comment, a step `name:`, an `echo`) — which blocks W0.12 from ever wiring
# a real CI invocation, since adding the word anywhere would trip it. Narrowed to detect a REAL
# invocation: a line that is not a comment, not a bare step `name:`, and does not mention
# `actionlint` only inside an `echo`/`printf` string — i.e. a `run:` line that actually executes the
# `actionlint` binary as a command.
#
# The claim in .github/actionlint.yaml must track that measurement via one of two exact markers:
#   - "ACTIONLINT CI ENFORCEMENT: NOT WIRED"  — while no real invocation exists anywhere in
#     .github/workflows/
#   - "ACTIONLINT CI ENFORCEMENT: WIRED"      — once a real invocation exists; whoever adds the
#     workflow step (W0.12) must flip the marker in the same change, or this selftest goes red for
#     staleness instead of for the original overclaim.
#
# Run: .github/scripts/actionlint-claim-selftest.sh   (exit 0 = the marker matches measured
# reality; non-zero = it doesn't, with the failing assertion on stderr)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
cfg="$repo/.github/actionlint.yaml"
fail=0

check() {
  local desc="$1"; shift
  if ! "$@"; then
    echo "RED — $desc" >&2
    fail=1
  fi
}

marker_not_wired='ACTIONLINT CI ENFORCEMENT: NOT WIRED'
marker_wired='ACTIONLINT CI ENFORCEMENT: WIRED'

# Measure: does any workflow contain a REAL actionlint invocation?
#   - skip comment-only lines (first non-space char is '#')
#   - skip a bare step `name:` line mentioning the word (names describe, they don't execute)
#   - skip a line where the mention is only inside an echo/printf string (fake invocation)
# Anything else containing the word "actionlint" as a token is treated as a real invocation line.
real_invocation=""
if compgen -G "$repo/.github/workflows/*.yml" > /dev/null; then
  for f in "$repo"/.github/workflows/*.yml; do
    while IFS= read -r line; do
      trimmed="$(printf '%s' "$line" | sed -E 's/^[[:space:]]+//')"
      [ -z "$trimmed" ] && continue
      case "$trimmed" in
        '#'*) continue ;;
      esac
      # strip a leading YAML list-item marker ("- ") before checking for a bare step `name:` line —
      # a step's *name* describing actionlint does not execute it.
      unlisted="$(printf '%s' "$trimmed" | sed -E 's/^-[[:space:]]*//')"
      case "$unlisted" in
        name:*) continue ;;
      esac
      case "$trimmed" in
        *actionlint*) : ;;
        *) continue ;;
      esac
      case "$trimmed" in
        *echo*actionlint*|*printf*actionlint*) continue ;;
        *actionlint*echo*|*actionlint*printf*) continue ;;
      esac
      real_invocation="$f: $trimmed"
      break
    done < "$f"
    [ -n "$real_invocation" ] && break
  done
fi

if [ -n "$real_invocation" ]; then
  # RED arm: a real invocation now exists, but the claim is stale (still says NOT WIRED, or never
  # says WIRED at all) — the file must be updated in the same change that wires the workflow step.
  check "actionlint.yaml must claim WIRED now that a real invocation exists ($real_invocation)" \
    grep -qF "$marker_wired" "$cfg"
  check "actionlint.yaml must drop the NOT-WIRED marker now that a real invocation exists" \
    bash -c "! grep -qF '$marker_not_wired' '$cfg'"
else
  # RED arm: no real invocation exists (including the case where the only workflow mentions of
  # "actionlint" are a comment or an echo — those are filtered out above, so they count as "none"),
  # but the file claims WIRED anyway, or has dropped the honest NOT-WIRED marker.
  check "actionlint.yaml must claim NOT WIRED while no real invocation exists" \
    grep -qF "$marker_not_wired" "$cfg"
  check "actionlint.yaml must not claim WIRED while no real invocation exists" \
    bash -c "! grep -qF '$marker_wired' '$cfg'"
fi

check "actionlint.yaml must name its one real (conditional) local caller" \
  grep -q 'scripts/land.sh' "$cfg"
check "actionlint.yaml must name the command -v gate that makes that caller conditional" \
  grep -q 'command -v actionlint' "$cfg"

exit $fail
