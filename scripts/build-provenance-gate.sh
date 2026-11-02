#!/usr/bin/env bash
# Assert the optimization posture reported by the actual busbar artifact.
# Production Cargo builds also use this file as RUSTC_WRAPPER. Only the final dist/default
# executable gets a receipt, derived from its actual rustc argv immediately before exec.
# A profile table, the gate's environment, or a PGO marker cannot substitute for that receipt.
# This describes compiler inputs and source custody; it does not attest native build hardware.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
BUILD_RS="$ROOT/crates/busbar/build.rs"

source_commit() {
  env -u GIT_INDEX_FILE -u GIT_DIR -u GIT_WORK_TREE git -C "$ROOT" rev-parse --verify HEAD
}

# Parse both rustc spellings, preserving last-option-wins semantics and exact option names.
read_codegen_option() {
  case "$1" in
    lto) RUSTC_LTO=fat ;;
    lto=*) RUSTC_LTO="${1#lto=}" ;;
    codegen-units=*) RUSTC_CODEGEN_UNITS="${1#codegen-units=}" ;;
  esac
}
read_rustc_arguments() {
  RUSTC_LTO=unknown RUSTC_CODEGEN_UNITS=unknown RUSTC_CRATE='' RUSTC_BIN=false RUSTC_TEST=false
  while [ "$#" -gt 0 ]; do
    case "$1" in
      -C)
        shift
        [ "$#" -gt 0 ] || return 1
        read_codegen_option "$1" ;;
      -C*) read_codegen_option "${1#-C}" ;;
      --crate-name)
        shift
        [ "$#" -gt 0 ] || return 1
        RUSTC_CRATE="$1" ;;
      --crate-name=*) RUSTC_CRATE="${1#--crate-name=}" ;;
      --crate-type)
        shift
        [ "$#" -gt 0 ] || return 1
        [ "$1" != bin ] || RUSTC_BIN=true ;;
      --crate-type=bin) RUSTC_BIN=true ;;
      --test) RUSTC_TEST=true ;;
    esac
    shift
  done
  case "$RUSTC_LTO" in
    yes|true) RUSTC_LTO=fat ;;
    no|false) RUSTC_LTO=off ;;
  esac
}

rustc_wrapper() {
  local compiler="$1" manifest_dir status source clean
  shift
  # Cargo nests a workspace wrapper between this wrapper and rustc. A downstream wrapper could
  # change argv after our receipt, so refuse it rather than claiming its eventual compiler inputs.
  case "$compiler" in
    rustc|rustc.exe|*/rustc|*/rustc.exe|*\\rustc.exe) ;;
    *) echo "build-provenance-gate: expected rustc, found another wrapper: $compiler" >&2; return 1 ;;
  esac
  read_rustc_arguments "$@"
  # Build scripts, proc macros, dependencies and rustc probes receive the original argv/env.
  if [ "$RUSTC_CRATE" = busbar ] && [ "$RUSTC_BIN" = true ] && [ "$RUSTC_TEST" = false ] \
    && [ "${CARGO_PKG_NAME:-}" = busbar-default ]; then
    manifest_dir="$(cd "${CARGO_MANIFEST_DIR:?Cargo manifest directory missing}" && pwd -P)"
    if [ "$manifest_dir" = "$ROOT/dist/default" ]; then
      source="$(source_commit)" || source=unknown
      if [ "$source" = unknown ] || [ "${BUSBAR_PROVENANCE_SOURCE:-}" != "$source" ]; then
        echo 'build-provenance-gate: source changed since build preparation, or no source expectation was supplied' >&2
        return 1
      fi
      clean=unknown
      if status="$(env -u GIT_INDEX_FILE -u GIT_DIR -u GIT_WORK_TREE git -C "$ROOT" status --porcelain --untracked-files=normal)"; then
        clean=false
        [ -n "$status" ] || clean=true
      fi
      # build.rs supplies unverified defaults, overriding caller-forged env values. Only this
      # final compiler invocation replaces them, after Cargo has resolved profiles/config/env.
      export BUSBAR_BUILD_LTO="$RUSTC_LTO"
      export BUSBAR_BUILD_CODEGEN_UNITS="$RUSTC_CODEGEN_UNITS"
      export BUSBAR_BUILD_RECEIPT=rustc-argv
      export BUSBAR_BUILD_PACKAGE=busbar-default
      export BUSBAR_BUILD_MANIFEST=dist/default/Cargo.toml
      export BUSBAR_BUILD_SOURCE_COMMIT="$source"
      export BUSBAR_BUILD_SOURCE_CLEAN="$clean"
    fi
  fi
  case "$(uname -s)" in
    # Cargo supplied native Windows arguments already. Git Bash must not rewrite path-like
    # codegen/linker arguments between this receipt and the native rustc process.
    MINGW*|MSYS*|CYGWIN*) MSYS2_ARG_CONV_EXCL='*' exec "$compiler" "$@" ;;
    *) exec "$compiler" "$@" ;;
  esac
}

check_build_environment() {
  local config_dir config_file cargo_config_dir profile_env python_bin
  if [ "${CARGO_ENCODED_RUSTFLAGS+x}" = x ]; then
    echo 'build-provenance-gate: unset CARGO_ENCODED_RUSTFLAGS; it overrides production RUSTFLAGS even when empty' >&2
    return 1
  fi
  while IFS= read -r profile_env; do
    case "$profile_env" in
      CARGO_PROFILE_RELEASE_LTO)
        case "${!profile_env}" in fat|true) continue ;; esac ;;
      CARGO_PROFILE_RELEASE_CODEGEN_UNITS)
        [ "${!profile_env}" != 1 ] || continue ;;
      CARGO_PROFILE_RELEASE_OPT_LEVEL)
        [ "${!profile_env}" != 3 ] || continue ;;
      CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS)
        [ "${!profile_env}" != false ] || continue ;;
      *) continue ;;
    esac
    echo "build-provenance-gate: $profile_env conflicts with the required release posture" >&2
    return 1
  done < <(compgen -e)
  if [ -n "${RUSTC_WRAPPER:-}" ] || [ -n "${RUSTC_WORKSPACE_WRAPPER:-}" ] \
    || [ -n "${CARGO_BUILD_RUSTC_WRAPPER:-}" ] || [ -n "${CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER:-}" ]; then
    echo 'build-provenance-gate: an existing rustc wrapper must be explicitly integrated; refusing to replace it' >&2
    return 1
  fi
  if [ "${BUSBAR_PROVENANCE_WRAPPER+x}" = x ]; then
    echo 'build-provenance-gate: unset reserved BUSBAR_PROVENANCE_WRAPPER before building' >&2
    return 1
  fi
  # Cargo searches config from the invocation directory through its ancestors, then CARGO_HOME.
  # Refuse a configured wrapper too: setting RUSTC_WRAPPER must not silently disable it.
  python_bin=python3
  command -v python3 >/dev/null 2>&1 || python_bin=python
  config_dir="$PWD"
  cargo_config_dir="${CARGO_HOME:-$HOME/.cargo}"
  while :; do
    for config_file in "$config_dir/.cargo/config" "$config_dir/.cargo/config.toml" \
      "$cargo_config_dir/config" "$cargo_config_dir/config.toml"; do
      [ -f "$config_file" ] || continue
      "$python_bin" -I - "$config_file" <<'PYCONFIG' || return 1
import sys
try:
    import tomllib
    with open(sys.argv[1], "rb") as config:
        data = tomllib.load(config)
except (ImportError, OSError, ValueError):
    sys.exit("build-provenance-gate: cannot verify Cargo config " + sys.argv[1] + " (requires Python 3.11+ and valid TOML)")
build = data.get("build", {})
if any(build.get(key) for key in ("rustc-wrapper", "rustc-workspace-wrapper")):
    sys.exit("build-provenance-gate: wrapper configured in " + sys.argv[1] + "; refusing to replace it")
if data.get("include"):
    sys.exit("build-provenance-gate: included Cargo config needs explicit wrapper integration: " + sys.argv[1])
PYCONFIG
    done
    [ "$config_dir" != / ] || break
    config_dir="${config_dir%/*}"
    [ -n "$config_dir" ] || config_dir=/
  done
}

prepare_wrapper() {
  # Windows Cargo uses CreateProcess, which does not interpret a shell script's shebang.
  # A .cmd trampoline invokes the same gate in Git Bash, preserving the Cargo argument vector.
  case "$(uname -s)" in
    MINGW*|MSYS*|CYGWIN*)
      local python_bin=python3 wrapper_file="$ROOT/target/busbar-rustc-receipt.cmd"
      command -v python3 >/dev/null 2>&1 || python_bin=python
      mkdir -p "$ROOT/target"
      "$python_bin" -I - "$(cygpath -m "$wrapper_file")" \
        "$(cygpath -m "$(command -v bash)")" "$(cygpath -m "$ROOT/scripts/build-provenance-gate.sh")" <<'PYWRAPPER'
import os
import sys
from pathlib import Path

output, bash, gate = sys.argv[1:]
# Literal paths in batch files must escape percent expansion, even within quotes.
bash, gate = (value.replace("%", "%%") for value in (bash, gate))
temp = Path(output + ".tmp-" + str(os.getpid()))
temp.write_bytes(('@echo off\r\nsetlocal DisableDelayedExpansion\r\n"%s" "%s" %%*\r\n' % (bash, gate)).encode())
os.replace(temp, output)
PYWRAPPER
      cygpath -m "$wrapper_file" ;;
    *) printf '%s\n' "$ROOT/scripts/build-provenance-gate.sh" ;;
  esac
}

# This variable is set only on the Cargo command, never on the output-side gate invocation.
if [ "${BUSBAR_PROVENANCE_WRAPPER:-}" = 1 ]; then
  [ "$#" -ge 1 ] || { echo 'build-provenance-gate: wrapper needs rustc argv' >&2; exit 2; }
  rustc_wrapper "$@"
fi
if [ "${1:-}" = --check-build-env ]; then
  [ "$#" = 1 ] || exit 2
  check_build_environment
  exit $?
fi
if [ "${1:-}" = --prepare-wrapper ]; then
  [ "$#" = 1 ] || exit 2
  prepare_wrapper
  exit $?
fi

field() { printf '%s\n' "$1" | tr ' ' '\n' | awk -F= -v k="$2" '$1==k{print $2; exit}'; }

assert_pgo_provenance() {
  local src="$1"
  if [ ! -f "$src" ]; then
    echo "  FAIL: no build script at $src"; return 1
  fi
  if grep -Eq '(env::var|env!|option_env!|var_os)[^)]*[A-Z_]*PGO' "$src"; then
    echo "  FAIL: $src derives pgo from a builder-set environment variable"; return 1
  fi
  if ! grep -q 'profile-use' "$src"; then
    echo "  FAIL: $src never looks for -Cprofile-use"; return 1
  fi
}

# Internal fixture hook; the public CLI accepts an executable, never a caller-supplied line.
assert_line() {
  local line="$1" expect_profile="$2" expect_pgo="$3" expect_source="${4:-}" fail=0 key want got
  echo "  stamp: $line"
  for key in profile pgo; do
    case "$key" in profile) want="$expect_profile" ;; pgo) want="$expect_pgo" ;; esac
    got="$(field "$line" "$key")"
    if [ "$got" != "$want" ]; then echo "  FAIL: $key = '${got:-<absent>}' (expect $want)"; fail=1; fi
  done
  if [ "$expect_profile" = release ]; then
    for key in opt-level debug-assertions lto codegen-units receipt package manifest source-clean source-commit; do
      case "$key" in
        opt-level) want=3 ;;
        debug-assertions) want=false ;;
        lto) want=fat ;;
        codegen-units) want=1 ;;
        receipt) want=rustc-argv ;;
        package) want=busbar-default ;;
        manifest) want=dist/default/Cargo.toml ;;
        source-clean) want=true ;;
        source-commit) want="$expect_source" ;;
      esac
      got="$(field "$line" "$key")"
      if [ -z "$want" ] || [ "$got" != "$want" ]; then
        echo "  FAIL: $key = '${got:-<absent>}' (expect ${want:-<verified source commit>})"; fail=1
      fi
    done
    # Never resolve (profile-table) using a mutable checkout. It says nothing about the Cargo
    # profile environment/configuration that produced these bytes, or even their owning workspace.
    if ! [[ "$expect_source" =~ ^[0-9a-f]{40}$ ]]; then
      echo '  FAIL: expected source commit is not a full Git SHA'; fail=1
    fi
  fi
  return "$fail"
}

selftest() {
  local sha=1111111111111111111111111111111111111111 good bad fixture st_work output
  good="profile=release opt-level=3 lto=fat codegen-units=1 debug-assertions=false pgo=false receipt=rustc-argv package=busbar-default manifest=dist/default/Cargo.toml source-clean=true source-commit=$sha"
  assert_line "$good" release false "$sha" >/dev/null || { echo 'SELFTEST FAILED: control rejected'; return 1; }
  assert_line "${good/pgo=false/pgo=true}" release true "$sha" >/dev/null \
    || { echo 'SELFTEST FAILED: PGO control rejected'; return 1; }
  assert_line 'profile=debug pgo=false' debug false >/dev/null \
    || { echo 'SELFTEST FAILED: debug control rejected'; return 1; }
  for fixture in profile=debug opt-level=0 opt-level=2 opt-level=s debug-assertions=true pgo=true \
    lto=thin lto=off 'lto=(profile-table)' codegen-units=16 codegen-units=unknown \
    receipt=unverified package=busbar manifest=Cargo.toml source-clean=false source-clean=unknown \
    source-commit=2222222222222222222222222222222222222222; do
    # Replace exactly one accepted field; every other invariant remains the passing control.
    bad="$(printf '%s\n' "$good" | tr ' ' '\n' | awk -F= -v key="${fixture%%=*}" -v replacement="$fixture" '$1==key{$0=replacement}{print}' | tr '\n' ' ')"
    if assert_line "$bad" release false "$sha" >/dev/null; then
      echo "SELFTEST FAILED: accepted $fixture"; return 1
    fi
  done
  for fixture in profile opt-level debug-assertions pgo lto codegen-units receipt package manifest source-clean source-commit; do
    bad="$(printf '%s\n' "$good" | tr ' ' '\n' | awk -F= -v key="$fixture" '$1!=key{print}' | tr '\n' ' ')"
    if assert_line "$bad" release false "$sha" >/dev/null; then
      echo "SELFTEST FAILED: accepted missing $fixture"; return 1
    fi
  done
  # A fat root table cannot rescue a thin dist/default artifact: only final rustc argv counts.
  read_rustc_arguments --crate-name busbar --crate-type bin -C lto=fat -Ccodegen-units=1 -Clto=thin
  [ "$RUSTC_LTO" = thin ] && [ "$RUSTC_CODEGEN_UNITS" = 1 ] && [ "$RUSTC_CRATE" = busbar ] && [ "$RUSTC_BIN" = true ] \
    || { echo 'SELFTEST FAILED: final Cargo overrides not read'; return 1; }
  read_rustc_arguments --crate-name=busbar --crate-type=bin -Clto=thin -C lto -Ccodegen-units=16 -C codegen-units=1 -Clinker-plugin-lto=thin
  [ "$RUSTC_LTO" = fat ] && [ "$RUSTC_CODEGEN_UNITS" = 1 ] \
    || { echo 'SELFTEST FAILED: exact option names/last value not honored'; return 1; }
  read_rustc_arguments --crate-name proc_macro_fixture --crate-type proc-macro -C lto=off
  [ "$RUSTC_BIN" = false ] || { echo 'SELFTEST FAILED: proc macro treated as final binary'; return 1; }
  read_rustc_arguments --crate-name busbar --crate-type bin --test -C lto=fat
  [ "$RUSTC_TEST" = true ] || { echo 'SELFTEST FAILED: test executable treated as shipped binary'; return 1; }

  # Exercise the real wrapper dispatch against an argv/env recorder, never a Rust compiler.
  st_work="$(mktemp -d)"
  trap 'rm -rf "$st_work"' RETURN
  cat > "$st_work/rustc" <<'SPY'
#!/usr/bin/env bash
printf '%s\n' "lto=${BUSBAR_BUILD_LTO-unset}" "units=${BUSBAR_BUILD_CODEGEN_UNITS-unset}" \
  "receipt=${BUSBAR_BUILD_RECEIPT-unset}" "source=${BUSBAR_BUILD_SOURCE_COMMIT-unset}"
printf 'arg=%s\n' "$@"
SPY
  chmod +x "$st_work/rustc"
  output="$(CARGO_PKG_NAME=busbar-default CARGO_MANIFEST_DIR="$ROOT/dist/default" \
    BUSBAR_PROVENANCE_SOURCE="$(source_commit)" \
    BUSBAR_BUILD_RECEIPT=unverified BUSBAR_BUILD_LTO=unverified \
    rustc_wrapper "$st_work/rustc" --crate-name busbar --crate-type bin -Clto=fat -C codegen-units=1 -L 'path with spaces')"
  for fixture in lto=fat units=1 receipt=rustc-argv "source=$(source_commit)" 'arg=path with spaces'; do
    if ! printf '%s\n' "$output" | grep -qxF "$fixture"; then
      echo "SELFTEST FAILED: final compiler receipt/argv omitted $fixture"; return 1
    fi
  done
  if output="$(CARGO_PKG_NAME=busbar-default CARGO_MANIFEST_DIR="$ROOT/dist/default" \
    BUSBAR_PROVENANCE_SOURCE=not-the-current-source \
    rustc_wrapper "$st_work/rustc" --crate-name busbar --crate-type bin -Clto=fat -Ccodegen-units=1 2>&1)"; then
    echo 'SELFTEST FAILED: receipt accepted a changed/missing source expectation'; return 1
  fi
  output="$(CARGO_PKG_NAME=proc-macro-fixture BUSBAR_BUILD_RECEIPT=unverified BUSBAR_BUILD_LTO=off \
    rustc_wrapper "$st_work/rustc" --crate-name fixture --crate-type proc-macro -C lto=thin)"
  if ! printf '%s\n' "$output" | grep -qxF receipt=unverified \
    || ! printf '%s\n' "$output" | grep -qxF lto=off; then
    echo 'SELFTEST FAILED: non-final compiler environment changed'; return 1
  fi
  printf 'fn main() { let pgo = std::env::var("BUSBAR_PGO"); /* profile-use */ }\n' > "$st_work/env.rs"
  printf 'fn main() {}\n' > "$st_work/blind.rs"
  for fixture in "$st_work/env.rs" "$st_work/blind.rs" "$st_work/missing.rs"; do
    if assert_pgo_provenance "$fixture" >/dev/null; then
      echo "SELFTEST FAILED: accepted missing/unreliable PGO derivation in $fixture"; return 1
    fi
  done
  # Profile environment overrides and encoded flags must be refused before any compiler runs.
  (
    local exported
    while IFS= read -r exported; do
      case "$exported" in
        CARGO_PROFILE_*|CARGO_ENCODED_RUSTFLAGS|RUSTC_WRAPPER|RUSTC_WORKSPACE_WRAPPER|CARGO_BUILD_RUSTC_WRAPPER|CARGO_BUILD_RUSTC_WORKSPACE_WRAPPER|BUSBAR_PROVENANCE_WRAPPER)
          unset "$exported" ;;
      esac
    done < <(compgen -e)
    export CARGO_HOME="$st_work/cargo-home"
    mkdir -p "$CARGO_HOME" "$st_work/config-case/.cargo"
    cd "$st_work/config-case"
    check_build_environment || { echo 'SELFTEST FAILED: clean build environment rejected'; exit 1; }
    CARGO_PROFILE_RELEASE_LTO=fat CARGO_PROFILE_RELEASE_CODEGEN_UNITS=1 \
      CARGO_PROFILE_RELEASE_OPT_LEVEL=3 CARGO_PROFILE_RELEASE_DEBUG_ASSERTIONS=false \
      check_build_environment || { echo 'SELFTEST FAILED: matching release overrides rejected'; exit 1; }
    if CARGO_PROFILE_RELEASE_LTO=thin check_build_environment >/dev/null 2>&1; then
      echo 'SELFTEST FAILED: Cargo LTO env override accepted'; exit 1
    fi
    if CARGO_PROFILE_RELEASE_CODEGEN_UNITS=16 check_build_environment >/dev/null 2>&1; then
      echo 'SELFTEST FAILED: Cargo codegen env override accepted'; exit 1
    fi
    if CARGO_ENCODED_RUSTFLAGS='' check_build_environment >/dev/null 2>&1; then
      echo 'SELFTEST FAILED: empty encoded rustflags accepted'; exit 1
    fi
    if RUSTC_WRAPPER=owner-instrumentation check_build_environment >/dev/null 2>&1; then
      echo 'SELFTEST FAILED: existing owner wrapper replaced'; exit 1
    fi
    printf 'build."rustc-workspace-wrapper" = "owner-instrumentation"\n' > .cargo/config.toml
    if check_build_environment >/dev/null 2>&1; then
      echo 'SELFTEST FAILED: configured owner wrapper replaced'; exit 1
    fi
  ) || return 1
  assert_pgo_provenance "$BUILD_RS" || return 1
  if "$0" --line "$good" release false >/dev/null 2>&1; then
    echo 'SELFTEST FAILED: accepted --line'; return 1
  fi
  if "$0" "$BUILD_RS" release false >/dev/null 2>&1; then
    echo 'SELFTEST FAILED: accepted non-executable subject'; return 1
  fi
  echo '[selftest] PASS (fixtures only; no compiled artifact qualified)'
}

usage() {
  echo 'usage: build-provenance-gate.sh <binary> <release|debug> <true|false>' >&2
  echo '       build-provenance-gate.sh --selftest' >&2
}
if [ "${1:-}" = --selftest ]; then selftest; exit $?; fi
[ "$#" -eq 3 ] || { usage; exit 2; }
case "$2:$3" in release:true|release:false|debug:true|debug:false) ;; *) usage; exit 2 ;; esac
BIN="$1"
[ -x "$BIN" ] || { echo "build-provenance-gate: '$BIN' is not executable" >&2; exit 2; }
LINE="$("$BIN" --build-info)"
assert_pgo_provenance "$BUILD_RS" || exit 1
EXPECTED_SOURCE="$(source_commit)" || { echo 'build-provenance-gate: cannot identify expected source' >&2; exit 1; }
# This only establishes the expected checkout identity. The artifact must independently carry
# its own clean source receipt from the final compiler invocation; current files cannot supply it.
EXPECTED_STATUS="$(env -u GIT_INDEX_FILE -u GIT_DIR -u GIT_WORK_TREE git -C "$ROOT" status --porcelain --untracked-files=normal)" \
  || { echo 'build-provenance-gate: cannot establish expected checkout identity' >&2; exit 1; }
[ -z "$EXPECTED_STATUS" ] || { echo 'build-provenance-gate: expected checkout is dirty; no exact committed source to compare' >&2; exit 1; }
if assert_line "$LINE" "$2" "$3" "$EXPECTED_SOURCE"; then
  echo 'build-provenance-gate: PASS (compiler/source receipt; native hardware is not attested)'
else
  echo 'build-provenance-gate: FAIL: artifact does not prove the expected release posture/source' >&2
  exit 1
fi
