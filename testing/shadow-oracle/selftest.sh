#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The shadow oracle's SELFTEST: prove the harness's own config is accepted by every binary the oracle
# will drive — the dev build AND the published reference (1.5.5 for the LLM golden). A recorder that
# only validates on one binary would silently record nothing on the other ("zero rows is red").
#
#   testing/shadow-oracle/selftest.sh <busbar-binary>...
#   e.g. selftest.sh target/debug/busbar ~/.cache/busbar-oracle/1.5.5/busbar
#
# Exit non-zero if ANY binary rejects the oracle config. Runs under bash on purpose (see the
# ORACLE_DIALECTS array note in oracle-config.sh).
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
# shellcheck source=oracle-config.sh
source "${here}/oracle-config.sh"

[ $# -ge 1 ] || { echo "usage: $0 <busbar-binary>..." >&2; exit 2; }
command -v jq >/dev/null 2>&1 || echo "note: jq missing — key minting (not exercised here) needs it" >&2

fails=0
for bin in "$@"; do
  if [ ! -x "$bin" ]; then echo "FAIL  not executable: $bin"; fails=$((fails+1)); continue; fi
  WORK="$(mktemp -d "${TMPDIR:-/tmp}/shadow-oracle-selftest.XXXXXX")"
  export BUSBAR_BIN="$bin" WORK
  ver="$("$bin" --version 2>/dev/null | head -1 || echo "$bin")"
  if ! oracle_write_config "$WORK" 48801 48802 48771; then
    echo "FAIL  write-config: ${ver}"; fails=$((fails+1)); continue
  fi
  if oracle_env "$BUSBAR_BIN" --validate >"${WORK}/validate.log" 2>&1; then
    echo "PASS  validate: ${ver}"
  else
    echo "FAIL  validate: ${ver}"; sed 's/^/        /' "${WORK}/validate.log" | tail -8; fails=$((fails+1))
  fi
done
[ "$fails" -eq 0 ]
