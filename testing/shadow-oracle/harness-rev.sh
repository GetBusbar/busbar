#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Shared provenance helpers for the shadow oracle. A golden or candidate recording only proves
# anything about busbar if we also know two things about how it was made:
#
#   harness_rev    which revision of the FILES THAT DECIDE WHAT GETS RECORDED AND HOW IT IS
#                  COMPARED produced it: cells.json, normalize.py, capture*.py, oracle-config.sh,
#                  mock-upstream.py, build-request.py, record.sh, scripts/*.sh, fixtures/*.json.
#                  This is the SAME file list ci.yml hashes for its shadow-oracle cache key —
#                  computed here, in one place, so record.sh, diff-cells.py and ci.yml can never
#                  quietly drift onto different definitions of "the harness changed".
#   binary_sha256  which exact binary file produced it (sha256 of the file's bytes).
#
# Usable two ways:
#   source testing/shadow-oracle/harness-rev.sh    # then call harness_rev / binary_sha256 / host_triple
#   bash testing/shadow-oracle/harness-rev.sh       # prints "harness_rev <hash>" (ci.yml, humans)
set -uo pipefail
_hr_here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_hr_sha256_stdin() {  # read bytes on stdin, print the hex digest
  if command -v sha256sum >/dev/null 2>&1; then sha256sum | cut -d' ' -f1
  else shasum -a 256 | cut -d' ' -f1; fi
}

sha256_of() {  # sha256_of <file> -> hex digest
  if command -v sha256sum >/dev/null 2>&1; then sha256sum "$1" | cut -d' ' -f1
  else shasum -a 256 "$1" | cut -d' ' -f1; fi
}

binary_sha256() { sha256_of "$1"; }  # binary_sha256 <path-to-busbar-binary>

harness_rev() {  # sha256 over the exact file set ci.yml's shadow-oracle cache key hashes
  local d="$_hr_here"
  cat "$d/cells.json" "$d/normalize.py" "$d"/capture*.py "$d/oracle-config.sh" "$d/mock-upstream.py" \
      "$d/build-request.py" "$d/record.sh" "$d"/scripts/*.sh "$d"/fixtures/*.json 2>/dev/null | _hr_sha256_stdin
}

host_triple() {  # the running machine's target triple, as busbar release assets name it
  case "$(uname -sm)" in
    "Darwin arm64") echo aarch64-apple-darwin ;;
    "Darwin x86_64") echo x86_64-apple-darwin ;;
    "Linux aarch64"|"Linux arm64") echo aarch64-unknown-linux-gnu ;;
    "Linux x86_64") echo x86_64-unknown-linux-gnu ;;
    *) echo "unknown-$(uname -sm | tr ' ' '-')" ;;
  esac
}

# Run directly (not sourced): print the harness revision, e.g. for ci.yml's cache key or a human
# checking whether their tree still matches a cached golden.
if [ "${BASH_SOURCE[0]}" = "${0}" ]; then
  echo "harness_rev $(harness_rev)"
fi
