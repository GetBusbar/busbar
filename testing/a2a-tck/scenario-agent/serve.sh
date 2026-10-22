#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# Serve the TCK scenario agent (see scenario_agent.py) on one loopback port.
#
# THE PIN, and why it is this one. The scenario agent implements the TCK's published SUT behaviour
# contract on top of the A2A project's own Python SDK, so the SDK version decides every byte on the
# wire that is not a scenario decision. It is the SAME version this repository already pins as the
# a2a-python CONTROL in `testing/a2a-harness/scripts/install-control.sh`, and it is READ from that
# file rather than spelled here, so the tree holds ONE opinion about which a2a-python it talks
# about. There is no fallback: if that file is gone or no longer states its pin in the form read
# below, this refuses to serve rather than guess.
#
# usage: serve.sh <port> [--public-url URL]
set -euo pipefail
cd "$(dirname "$0")"

PORT="${1:?usage: serve.sh <port> [--public-url URL]}"; shift || true

harness_pin_file="../../a2a-harness/scripts/install-control.sh"
if [ ! -e "$harness_pin_file" ]; then
  echo "the a2a-sdk pin is read from testing/a2a-harness/scripts/install-control.sh, and that \
file is not there -- refusing to serve" >&2
  exit 2
fi
harness_text="$(cat "$harness_pin_file" 2>/dev/null)" || {
  echo "testing/a2a-harness/scripts/install-control.sh is there but is not readable as a file -- \
refusing to serve" >&2
  exit 2
}
# One sed pass that quits on the first match, so no pipe can fail under pipefail.
CONTROL_PY_VERSION="$(sed -n '/^CONTROL_PY_VERSION="/{s/^CONTROL_PY_VERSION="\([^"]*\)".*/\1/p;q;}' <<< "$harness_text")"
if [ -z "$CONTROL_PY_VERSION" ]; then
  echo "testing/a2a-harness/scripts/install-control.sh states no CONTROL_PY_VERSION=\"...\" line, \
so there is no a2a-sdk pin -- refusing to serve" >&2
  exit 2
fi

WORK="${A2A_SCENARIO_AGENT_WORK:-${TMPDIR:-/tmp}/a2a-scenario-agent}"
VENV="$WORK/venv-$CONTROL_PY_VERSION"
mkdir -p "$WORK" 2>/dev/null || {
  echo "could not create the scenario agent's work directory $WORK -- refusing to serve" >&2
  exit 2
}

# discard <dir> <what>: remove a half-made <what> so the next run builds it again instead of
# trusting it, and say whether it is gone (a refusal names both outcomes; it never assumes one).
discard () {
  if [ ! -e "$1" ]; then
    echo "nothing was left at $1"
    return 0
  fi
  rm -rf "$1" 2>/dev/null || true
  if [ -e "$1" ]; then
    echo "the half-made $2 at $1 could not be removed; remove it by hand"
  else
    echo "the half-made $2 at $1 was removed"
  fi
}

if [ ! -x "$VENV/bin/python" ]; then
  echo "installing a2a-sdk ${CONTROL_PY_VERSION} into $VENV" >&2
  python3 -m venv "$VENV" \
    && "$VENV/bin/pip" -q install --upgrade pip \
    && "$VENV/bin/pip" -q install "a2a-sdk[http-server]==${CONTROL_PY_VERSION}" uvicorn starlette \
    || {
      note="$(discard "$VENV" virtualenv)"
      echo "could not install a2a-sdk ${CONTROL_PY_VERSION} into $VENV; $note -- refusing to serve" >&2
      exit 2
    }
fi

# A pin that is not verified after install is a wish -- a cached venv from a different pin would
# otherwise be reused in silence and the number attributed to the wrong peer. A venv whose version
# cannot be read at all is refused the same way, with its own word for it.
got="$("$VENV/bin/python" -c 'import importlib.metadata as m; print(m.version("a2a-sdk"))' 2>/dev/null)" \
  || got="unreadable"
[ "$got" = "$CONTROL_PY_VERSION" ] || {
  echo "a2a-sdk in $VENV is $got, pin is $CONTROL_PY_VERSION -- refusing to serve" >&2
  exit 2
}

exec "$VENV/bin/python" scenario_agent.py --port "$PORT" "$@"
