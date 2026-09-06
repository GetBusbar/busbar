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
#
# `--validate` IS NOT THE WHOLE QUESTION, and on its own it answers a smaller one than the name of
# this file suggests. It proves the config parses and every referenced module resolves. It does not
# prove this binary can be BOOTED by the recorder, that keys can be minted against it, that a cell
# drives through to the mock, or that a ledger row and a normalized cell come out the other end —
# and every one of those is a way for record.sh to produce an empty recording. An empty recording is
# not silent, but it is only caught downstream, by the replay's zero-rows guard, at which point the
# reported fact is "the candidate diverges everywhere" rather than "the recorder could not drive
# this binary". So each binary also records ONE cheap cell end to end and the result is asserted:
# at least one PASS row in the ledger, and a non-empty cells/ directory. One cell, because this is a
# smoke test of the RECORDER and not a recording; the real ones are made by record.sh directly.
#
# It cannot touch the golden. Every smoke recording goes to its own directory under the repo's
# target/ (never $TMPDIR, so nothing outlives the tree), on ports offset away from the recorder's
# defaults, and the EXIT trap below removes them whichever way this script leaves.
set -uo pipefail
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "${here}/../.." && pwd)"
# shellcheck source=oracle-config.sh
source "${here}/oracle-config.sh"

[ $# -ge 1 ] || { echo "usage: $0 <busbar-binary>..." >&2; exit 2; }
command -v jq >/dev/null 2>&1 || echo "note: jq missing — key minting (not exercised here) needs it" >&2

# The cheapest cell in the LLM plane that still exercises the whole path: one non-streaming chat
# completion, same dialect in and out, expected to succeed. A streaming or error cell would prove
# the same thing about the recorder and take longer to do it.
SMOKE_CELL='^llm\|anthropic\|anthropic\|request\|ok$'

# Work dirs are collected as they are made, so the trap removes exactly what this run created and an
# early `exit` (a binary that is not executable, an interrupt) cleans up the same as a full run.
WORKDIRS=()
_clean_selftest() { [ "${#WORKDIRS[@]}" -eq 0 ] || rm -rf "${WORKDIRS[@]}"; }
trap _clean_selftest EXIT

SMOKE_ROOT="${repo}/target/oracle/selftest"
mkdir -p "$SMOKE_ROOT"

fails=0
n=0
for bin in "$@"; do
  n=$((n + 1))
  if [ ! -x "$bin" ]; then echo "FAIL  not executable: $bin"; fails=$((fails+1)); continue; fi
  WORK="$(mktemp -d "${SMOKE_ROOT}/work.XXXXXX")"
  WORKDIRS+=("$WORK")
  export BUSBAR_BIN="$bin" WORK
  ver="$("$bin" --version 2>/dev/null | head -1 || echo "$bin")"
  if ! oracle_write_config "$WORK" 48801 48802 48771; then
    echo "FAIL  write-config: ${ver}"; fails=$((fails+1)); continue
  fi
  if oracle_env "$BUSBAR_BIN" --validate >"${WORK}/validate.log" 2>&1; then
    echo "PASS  validate: ${ver}"
  else
    echo "FAIL  validate: ${ver}"; sed 's/^/        /' "${WORK}/validate.log" | tail -8; fails=$((fails+1))
    continue
  fi

  # ONE CELL, END TO END. Ports are offset per binary so two binaries in one invocation cannot
  # collide, and all three are far from the recorder's defaults (48811/48812/48781) so a smoke run
  # cannot disturb a real recording that happens to be in flight.
  rec="$(mktemp -d "${SMOKE_ROOT}/rec.XXXXXX")"
  WORKDIRS+=("$rec")
  ORACLE_LISTEN_PORT=$((48851 + n * 3)) ORACLE_ADMIN_PORT=$((48852 + n * 3)) ORACLE_MOCK_PORT=$((48853 + n * 3)) \
    bash "${here}/record.sh" --bin "$bin" --plane llm --filter "$SMOKE_CELL" --out "$rec" \
    >"${rec}/record.log" 2>&1
  passes="$(awk -F'\t' '$2=="PASS"{n++} END{print n+0}' "${rec}/ledger.tsv" 2>/dev/null || echo 0)"
  cells="$(ls "${rec}/cells" 2>/dev/null | wc -l | tr -d ' ')"
  if [ "$passes" -ge 1 ] && [ "$cells" -ge 1 ]; then
    echo "PASS  record one cell: ${ver} (${passes} PASS row(s), ${cells} cell file(s))"
  else
    echo "FAIL  record one cell: ${ver} — ${passes} PASS row(s), ${cells} cell file(s); the recorder cannot drive this binary, so a real recording would come out empty"
    sed 's/^/        /' "${rec}/record.log" 2>/dev/null | tail -12
    fails=$((fails+1))
  fi
done
[ "$fails" -eq 0 ]
