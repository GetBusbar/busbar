#!/usr/bin/env bash
# Install the pinned A2A control implementations.
#
# The versions here are PINNED ON PURPOSE. The control defines what
# "conformant" means for this harness, so a silent upgrade would silently
# change the answer. Bump them deliberately, re-record the baselines, and read
# the diff.
set -euo pipefail

CONTROL_GO_VERSION="v2.4.0"       # github.com/a2aproject/a2a-go
CONTROL_PY_VERSION="1.1.2"        # PyPI a2a-sdk
CONTROL_PY_TAG="v1.1.2"           # github.com/a2aproject/a2a-python (samples)

BIN_DIR="${A2AHT_CONTROL_BIN:-$HOME/.a2aht/bin}"
SRC_DIR="${A2AHT_CONTROL_SRC:-$HOME/.a2aht/src}"
mkdir -p "$BIN_DIR" "$SRC_DIR"

what="${1:-all}"

install_go() {
  echo "installing control: a2a-go ${CONTROL_GO_VERSION}"
  GOBIN="$BIN_DIR" go install \
    "github.com/a2aproject/a2a-go/v2/cmd/a2a@${CONTROL_GO_VERSION}"
  "$BIN_DIR/a2a" --help >/dev/null
  echo "  installed: $BIN_DIR/a2a"
}

install_py() {
  echo "installing control: a2a-python ${CONTROL_PY_VERSION}"
  python3 -m venv "$SRC_DIR/venv"
  "$SRC_DIR/venv/bin/pip" install -q --upgrade pip
  "$SRC_DIR/venv/bin/pip" install -q \
    "a2a-sdk[http-server]==${CONTROL_PY_VERSION}" grpcio fastapi uvicorn
  if [ ! -d "$SRC_DIR/a2a-python" ]; then
    git clone -q --depth 1 --branch "${CONTROL_PY_TAG}" \
      https://github.com/a2aproject/a2a-python.git "$SRC_DIR/a2a-python"
  fi
  echo "  installed: $SRC_DIR/venv, samples at $SRC_DIR/a2a-python/samples"
}

case "$what" in
  go) install_go ;;
  python) install_py ;;
  all) install_go; install_py ;;
  *) echo "usage: $0 [go|python|all]" >&2; exit 2 ;;
esac

echo
echo "control versions pinned by this script:"
echo "  a2a-go      ${CONTROL_GO_VERSION}"
echo "  a2a-sdk     ${CONTROL_PY_VERSION}"
