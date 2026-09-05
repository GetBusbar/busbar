#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# changelog-register-check.sh -- THE CHANGELOG REGISTER GATE.
#
# Answers one narrow question: does every `kind: breaking` entry in
# testing/shadow-oracle/accepted-differences.json have its `changelog` field's exact line present,
# verbatim, in CHANGELOG.md? testing/shadow-oracle's own differ already refuses a register entry
# that accepts `status`/`effects.usage` without kind=breaking and a `changelog` field; this gate
# closes the other half of that contract -- that the named line was actually WRITTEN, not just
# declared -- so the CHANGELOG cannot drift silently out of sync with what the owner accepted.
#
#   --check      run the check against the real register + CHANGELOG.md; red on any missing line
#   --selftest   the gate proves itself first: a present line -> PASS; an absent line -> FAIL; a
#                missing `changelog` field -> FAIL; zero breaking entries -> PASS/vacuous-ok
#
# bash 3.2 + python3 (stdlib), the same bare-runner posture as the sibling gates
# (scripts/design-bindings.sh).
set -uo pipefail
cd "$(dirname "$0")/.."

PY=python3
CHECK="scripts/changelog-register-check.py"

usage() { sed -n '5,18p' "$0"; }

MODE=""
for arg in "$@"; do
  case "$arg" in
    --check) MODE=check ;;
    --selftest) MODE=selftest ;;
    -h|--help) usage; exit 0 ;;
    *) echo "usage: $0 --check | --selftest" >&2; exit 2 ;;
  esac
done

case "$MODE" in
  check) "$PY" "$CHECK" ;;
  selftest) "$PY" "$CHECK" --selftest ;;
  *) usage; exit 2 ;;
esac
