#!/usr/bin/env bash
# Install the pinned CONTROL implementation into a local virtualenv.
#
# The pin lives in control/requirements.txt and is EXACT. A control upgrade
# changes what "conformant" means for the whole battery, so it must be a
# deliberate, reviewed commit, never a floating range.
set -euo pipefail
cd "$(dirname "$0")/.."

VENV="${MCP_CONTROL_VENV:-.venv-control}"
PY="${PYTHON:-python3}"

if [ ! -d "$VENV" ]; then
  "$PY" -m venv "$VENV"
fi
"$VENV/bin/pip" install --quiet --upgrade pip
"$VENV/bin/pip" install --quiet -r control/requirements.txt

echo "control interpreter : $VENV/bin/python"
"$VENV/bin/python" - <<'PY'
import importlib.metadata as md
print("control package     : mcp", md.version("mcp"))
from mcp_types.version import MODERN_PROTOCOL_VERSIONS, KNOWN_PROTOCOL_VERSIONS
print("modern revisions    :", ", ".join(MODERN_PROTOCOL_VERSIONS))
print("all known revisions :", ", ".join(KNOWN_PROTOCOL_VERSIONS))
PY
