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

# THE VIRTUALENVS' PYTHON. a2a-sdk 1.1.2 requires Python >= 3.10 and the pinned a2a-tck >= 3.11
# (its pyproject), so on a runner whose python3 is older (Amazon Linux 2023 ships 3.9) neither
# virtualenv can be built: pip answers "from versions: none", the scenario agent never comes up, and
# the A2A battery and TCK legs record no report at all. `venv_python` prints an interpreter that
# can build both: python3 when it is >= 3.11, else the first python3.1x on PATH that is, else a
# pinned CPython (python-build-standalone) under $A2AHT_PYTHON_DIR, its archive checked against the
# sha256 this file commits BEFORE it is unpacked. No pin for the platform, a failed download or a
# hash that is not the pin is a refusal, never a fall-back to the older python3.
PY_MIN="3.11"
PY_PIN_RELEASE="20261021"            # github.com/astral-sh/python-build-standalone
PY_PIN_VERSION="3.12.15"
py_pin_sha256() {  # $1 = the target triple python-build-standalone names
  case "$1" in
    aarch64-unknown-linux-gnu) echo "f53cca8fcd20805bddaa8bff1ef722a6918f8225d37561bd36ad901d13d580af" ;;
    x86_64-unknown-linux-gnu)  echo "5ff9f0602ce964a529ed1e8555d3abab6341926d724402ba9a15e9e877191124" ;;
    aarch64-apple-darwin)      echo "a18cc33862b53bd54a148c710def5375c1b47470cccedf817a19c2d211764584" ;;
    x86_64-apple-darwin)       echo "869e0b30959beccc616ce14907439f4d0b3170c5830a2362dade07f07b0ed3b8" ;;
    *) return 1 ;;
  esac
}
py_new_enough() {  # $1 = an interpreter
  "$1" -c "import sys; sys.exit(0 if sys.version_info >= tuple(int(n) for n in '$PY_MIN'.split('.')) else 1)" \
    >/dev/null 2>&1
}
venv_python() {
  local c arch triple want root dir tgz got
  for c in python3 python3.14 python3.13 python3.12 python3.11; do
    if command -v "$c" >/dev/null 2>&1 && py_new_enough "$c"; then command -v "$c"; return 0; fi
  done
  case "$(uname -m)" in x86_64|amd64) arch=x86_64 ;; aarch64|arm64) arch=aarch64 ;; *) arch="" ;; esac
  case "$(uname -s)" in Linux) triple="$arch-unknown-linux-gnu" ;; Darwin) triple="$arch-apple-darwin" ;; *) triple="" ;; esac
  want="$(py_pin_sha256 "$triple")" || {
    echo "no python3 >= $PY_MIN on PATH and no pinned CPython for $(uname -s)/$(uname -m) -- refusing" >&2
    return 2
  }
  root="${A2AHT_PYTHON_DIR:-$HOME/.a2aht/python}"
  dir="$root/cpython-$PY_PIN_VERSION+$PY_PIN_RELEASE-$triple"
  if [ ! -x "$dir/bin/python3" ]; then
    mkdir -p "$root"
    tgz="$dir.tar.gz"
    curl -fsSL --retry 3 -o "$tgz" \
      "https://github.com/astral-sh/python-build-standalone/releases/download/$PY_PIN_RELEASE/cpython-$PY_PIN_VERSION%2B$PY_PIN_RELEASE-$triple-install_only.tar.gz" \
      || { rm -f "$tgz"; echo "could not download CPython $PY_PIN_VERSION ($triple) -- refusing" >&2; return 2; }
    if command -v sha256sum >/dev/null 2>&1; then got="$(sha256sum "$tgz" | cut -d' ' -f1)"; else got="$(shasum -a 256 "$tgz" | cut -d' ' -f1)"; fi
    [ "$got" = "$want" ] || { rm -f "$tgz"; echo "CPython $PY_PIN_VERSION ($triple) sha256 $got is not the pinned $want -- refusing" >&2; return 2; }
    rm -rf "$dir.part" && mkdir -p "$dir.part" && tar -xzf "$tgz" -C "$dir.part" \
      && rm -rf "$dir" && mv "$dir.part/python" "$dir" \
      || { rm -rf "$dir.part" "$tgz"; echo "could not unpack CPython $PY_PIN_VERSION into $dir -- refusing" >&2; return 2; }
    rm -rf "$dir.part" "$tgz"
  fi
  py_new_enough "$dir/bin/python3" \
    || { echo "the pinned CPython at $dir does not run as Python >= $PY_MIN -- refusing" >&2; return 2; }
  printf '%s\n' "$dir/bin/python3"
}

install_go() {
  echo "installing control: a2a-go ${CONTROL_GO_VERSION}"
  GOBIN="$BIN_DIR" go install \
    "github.com/a2aproject/a2a-go/v2/cmd/a2a@${CONTROL_GO_VERSION}"
  "$BIN_DIR/a2a" --help >/dev/null
  echo "  installed: $BIN_DIR/a2a"
}

install_py() {
  echo "installing control: a2a-python ${CONTROL_PY_VERSION}"
  local py; py="$(venv_python)" || exit 2
  "$py" -m venv "$SRC_DIR/venv"
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
  venv-python) venv_python; exit $? ;;
  go) install_go ;;
  python) install_py ;;
  all) install_go; install_py ;;
  *) echo "usage: $0 [go|python|all|venv-python]" >&2; exit 2 ;;
esac

echo
echo "control versions pinned by this script:"
echo "  a2a-go      ${CONTROL_GO_VERSION}"
echo "  a2a-sdk     ${CONTROL_PY_VERSION}"
