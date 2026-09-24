#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Selftest for .github/actionlint.yaml (item 458 of the 1.6.0 audit).
#
# 458: the file's header comment claimed "actionlint says so before it is pushed" as an
#      unconditional guarantee. Measured: no workflow under .github/workflows/ invokes actionlint;
#      the only caller is scripts/land.sh, and even there it is conditional on
#      `command -v actionlint` (falls back to a bare YAML parse otherwise). The comment must not
#      claim CI enforcement it does not have, and must say where real enforcement would need to be
#      wired (a .github/workflows/ change, outside this file's directory).
#
# Run: .github/scripts/actionlint-claim-selftest.sh   (exit 0 = the comment's claim matches
# measured reality; non-zero = the file overclaims again, with the failing assertion on stderr)
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

# Measure reality: no workflow invokes actionlint.
if grep -rq 'actionlint' "$repo/.github/workflows/" 2>/dev/null; then
  echo "RED — a workflow now invokes actionlint; this selftest's 'not a CI gate' claim is stale and .github/actionlint.yaml's comment must be revised to match (and this script updated)." >&2
  fail=1
fi

# The file must no longer make the bare, unconditional "before it is pushed" claim without the
# caveat that it is land.sh-local and command -v-gated.
check "actionlint.yaml must not carry the bare unconditional claim without a caveat" \
  bash -c "! grep -q 'and actionlint says so before it is pushed\.\$' '$cfg'"
check "actionlint.yaml must state this is not a CI gate today" \
  grep -q 'NOT A CI GATE TODAY' "$cfg"
check "actionlint.yaml must name its one real (conditional) caller" \
  grep -q 'scripts/land.sh' "$cfg"
check "actionlint.yaml must name the command -v gate that makes the caller conditional" \
  grep -q 'command -v actionlint' "$cfg"

exit $fail
