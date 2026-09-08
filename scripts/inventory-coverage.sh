#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# inventory-coverage.sh -- thin wrapper around scripts/inventory-coverage.py so this gate can be
# invoked the same way as its sibling scripts/*-gate.sh scripts (a bash entry point, run from any
# working directory). All the real logic (parsing the inventory tables, matching them against
# testing/shadow-oracle/cells.json and the golden ledger, and rewriting the coverage table in
# docs/design/1.5.5-BEHAVIOUR.md) lives in the Python script; this file just finds python3 and
# forwards the one flag it was given.
#
# Usage: inventory-coverage.sh --write | --check | --selftest
set -uo pipefail
cd "$(dirname "$0")/.."

PY=python3
DERIVE="scripts/inventory-coverage.py"

case "${1:-}" in
  --write|--check|--selftest) "$PY" "$DERIVE" "$1" ;;
  *) echo "usage: $0 --write | --check | --selftest" >&2; exit 2 ;;
esac
