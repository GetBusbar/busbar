#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Shared provenance helpers for the shadow oracle. A golden or candidate recording only proves
# anything about busbar if we also know two things about how it was made:
#
#   harness_rev    which revision of the FILES THAT DECIDE WHAT GETS RECORDED AND HOW IT IS
#                  COMPARED produced it: cells.json, every *.py beside this file, oracle-config.sh,
#                  record.sh, everything under scripts/, fixtures/*.json, and the two digest pins
#                  (golden-digests.tsv, plugin-digests.tsv) — names as well as bytes.
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
  local d="$_hr_here" f
  # WHOLE DIRECTORIES, NOT A HAND-KEPT LIST OF NAMES. The old globs named `normalize.py`,
  # `capture*.py`, `build-request.py` and `scripts/*.sh` one by one, so apply-mutation.py (which
  # rewrites the config a mutation cell is recorded against) and scripts/apply-deferred-decisions.py
  # (which supplies the decisions a migrated corpus config is validated with) could change without
  # moving the rev — CI would then restore a golden recorded under different config-shaping code and
  # diff-cells' skew guard would see nothing to complain about. `*.py` and `scripts/*` close that by
  # construction: a new helper is covered the day it lands, not the day someone remembers.
  #
  # The two digest pins are in the set for the same reason: a re-pinned golden binary or plugin is a
  # different harness even though no code changed.
  #
  # NAMES ARE HASHED ALONGSIDE THE BYTES. Concatenated contents alone cannot see a file being added
  # or removed (an empty new fixture, a deleted script) — and both change what gets recorded.
  # LC_ALL=C fixes the glob order, or the same tree hashes differently under a different locale.
  (
    LC_ALL=C
    for f in "$d/cells.json" "$d"/*.py "$d/oracle-config.sh" "$d/record.sh" "$d"/scripts/* \
             "$d"/fixtures/*.json "$d/golden-digests.tsv" "$d/plugin-digests.tsv"; do
      [ -f "$f" ] || continue
      printf '%s\n' "${f#"$d"/}"
      cat "$f"
    done
  ) | _hr_sha256_stdin
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
