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
