#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Selftest for .github/required-status-checks.md (items 454, 455 of the 1.6.0 audit).
#
# 454: the doc must name every workflow_run/push-gated release-blocking battery that can go red on
#      a qa promotion, in either the required table or the "Intentionally NOT required" section —
#      `Voice conformance verdict` (qa-conformance-voice.yml) and `cargo-fuzz (bounded, qa boundary)`
#      (qa-fuzz.yml) were missing from both.
# 455: the doc's cargo-deny required-context name must be reconciled against what actually reports
#      on main/dev/qa today (the pre-#78-rename `security.yml` job, with no ` + cargo-audit` suffix)
#      — not just against predev's renamed qa-security.yml.
#
# Adding a leg (and job) to the Voice verdict's `needs:` list makes the doc's hardcoded "8 legs" /
# "9-job battery" counts stale. The doc's leg
# list is now DERIVED from `verdict`'s `needs:` at selftest time instead of being a fixed number —
# every leg named there must appear in the doc's Voice row, and the doc must not spell a fixed leg
# count that can drift out from under it again.
#
# Run: .github/scripts/required-status-checks-selftest.sh   (exit 0 = doc is internally consistent
# with the workflow files it describes; non-zero = drift, with the failing assertion on stderr)
set -euo pipefail

repo="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
doc="$repo/.github/required-status-checks.md"
fail=0

check() {
  local desc="$1"; shift
  if ! "$@"; then
    echo "RED — $desc" >&2
    fail=1
  fi
}

# 454: Voice conformance verdict and cargo-fuzz must be named in the doc, and the names must match
# the real job `name:` in their workflows (not a stale or guessed string).
voice_job_name=$(grep -A2 '^  verdict:' "$repo/.github/workflows/qa-conformance-voice.yml" | grep 'name:' | head -1 | sed -E 's/^[[:space:]]*name:[[:space:]]*//')
fuzz_job_name=$(grep -A1 '^  cargo-fuzz:' "$repo/.github/workflows/qa-fuzz.yml" | grep 'name:' | head -1 | sed -E 's/^[[:space:]]*name:[[:space:]]*//')

check "doc must name Voice conformance verdict (job name: $voice_job_name)" \
  grep -qF "$voice_job_name" "$doc"
check "doc must name qa-conformance-voice.yml as the Voice verdict's workflow" \
  grep -q 'qa-conformance-voice.yml' "$doc"

# 454 follow-up: derive the Voice verdict's actual leg set from its own `needs:` list — the ground
# truth — instead of a number anyone could let drift. Every leg named there must be named in the
# doc's Voice row, and the doc must not spell a fixed leg/job count (which the last leg-add already
# made stale once).
voice_legs=$(awk '
  /^  verdict:/ { in_verdict=1 }
  in_verdict && /^  [a-z][a-zA-Z0-9_-]*:$/ && $0 !~ /^  verdict:/ { exit }
  in_verdict && /^    needs:/ { in_needs=1; next }
  in_verdict && in_needs && /^      - / { sub(/^      - /, ""); print; next }
  in_verdict && in_needs && /^    [a-z]/ { exit }
' "$repo/.github/workflows/qa-conformance-voice.yml")

if [ -z "$voice_legs" ]; then
  echo "RED — could not derive verdict's needs: list from qa-conformance-voice.yml; selftest's awk parse is broken, not the doc" >&2
  fail=1
else
  while IFS= read -r leg; do
    [ -z "$leg" ] && continue
    check "doc's Voice row must name leg '$leg' (verdict's own needs: list)" \
      grep -q "$leg" "$doc"
  done <<< "$voice_legs"
fi

check "doc must not spell a fixed Voice leg/job count (it drifts — state the set, not a number)" \
  bash -c "! grep -qE '[0-9]+[- ](Voice conformance leg|job Voice)' '$doc'"
check "doc must name cargo-fuzz (job name: $fuzz_job_name)" \
  grep -qF "$fuzz_job_name" "$doc"
check "doc must name qa-fuzz.yml as the fuzz gate's workflow" \
  grep -q 'qa-fuzz.yml' "$doc"

# 455: the doc's cargo-deny row must not claim a context name that never reports on qa/main without
# also saying so. The renamed (predev) job name carries " + cargo-audit"; the doc must flag that this
# differs from what main/dev/qa currently run.
predev_cargo_deny_name=$(grep -A1 '^  cargo-deny:' "$repo/.github/workflows/qa-security.yml" | grep 'name:' | head -1 | sed -E 's/^[[:space:]]*name:[[:space:]]*//')
check "doc must still name predev's current cargo-deny job (name: $predev_cargo_deny_name)" \
  grep -qF "$predev_cargo_deny_name" "$doc"
check "doc must flag the promotion-freshness gap on the cargo-deny row (no bare, uncaveated claim)" \
  grep -q 'pre-rename name instead until that promotion lands' "$doc"

exit $fail
