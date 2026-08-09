#!/usr/bin/env bash
# Run the battery against the CONTROL (the pinned reference implementation).
#
# WHAT THIS JOB PROVES: that the HARNESS still works. It does not test any
# product. If a test here goes red, the test is wrong, or the control changed,
# or our reading of the spec was wrong. Any of those you want to know the same
# day, not while chasing a phantom defect in a subject.
#
# Usage: scripts/run-control.sh [tier]     tier defaults to push,pr
set -euo pipefail
cd "$(dirname "$0")/.."

TIER="${1:-push,pr}"
VENV="${MCP_CONTROL_VENV:-.venv-control}"
PY="$VENV/bin/python"

if [ ! -x "$PY" ]; then
  echo "control not installed. Run scripts/setup-control.sh first." >&2
  exit 2
fi

mkdir -p reports
exec node bin/mcp-battery.mjs run \
  --name "control-python-mcp-2.0.0" \
  --server-cmd "$PY $(pwd)/control/control_server.py" \
  --client-cmd "$PY $(pwd)/control/control_client.py" \
  --failing-tool always_fails \
  --tier "$TIER" \
  --expected-failures control/control-baseline.json \
  --out "reports/control-${TIER//,/-}.json"
