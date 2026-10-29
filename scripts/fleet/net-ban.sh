#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# THE SOCKET/TLS BAN every first-party plugin repo runs (.github/fleet/deps.toml [net-ban];
# BUSBAR-1.6.0.md line 3980, OWNER LAW 2026-09-27: "NO plugin opens its own socket, dials, binds, or
# does TLS"). A connection is a declared need the host's connector judges (the one destination
# guard) and dials; a plugin that dials for itself is a connection no guard ever judged. RED on:
#
#   crates    a banned crate in the plugin crate's NORMAL + BUILD closure (dev-dependencies are its
#             tests, not the shipped image);
#   features  a banned `crate/feature` turned on in that closure (`tokio/net`, ...);
#   imports   a banned symbol the BUILT cdylib imports (`socket`, `connect`, `getaddrinfo`, ...): the
#             post-link scan, which catches a dial no crate list names (std::net included).
#
# `carriers` (repo names) are exempt from the socket half of the import list; it is empty today.
#
# Usage: net-ban.sh <plugin-root> <plugin-crate> <cdylib> [<deps.toml>]
#          (deps.toml default: the .github/fleet/deps.toml of the busbar checkout this script sits in;
#           NET_BAN_REPO names the repo for `carriers`, default the plugin root's directory name)
#        net-ban.sh --selftest   every refusal fires on its planted defect (builds offline fixtures)
set -euo pipefail

here="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

policy() {  # policy <deps.toml> <crates|features|imports|carriers>: one entry per line
  python3 - "$1" "$2" <<'PY'
import sys, tomllib
with open(sys.argv[1], "rb") as f:
    d = tomllib.load(f)
nb = d.get("net-ban")
if not isinstance(nb, dict):
    sys.exit(f"net-ban: {sys.argv[1]} states no [net-ban] table")
v = nb.get(sys.argv[2], [])
if not isinstance(v, list):
    sys.exit(f"net-ban: [net-ban] {sys.argv[2]} is not a list")
for e in v:
    print(e)
PY
}

imports_of() {  # imports_of <cdylib>: every undefined (imported) symbol, unversioned, one per line
  case "$(uname -s)" in
    Darwin) nm -u "$1" | sed -e 's/^_//' ;;
    *) nm -D --undefined-only "$1" | awk '{print $NF}' | sed -e 's/@.*//' ;;
  esac
}

check() {  # check <plugin-root> <crate> <cdylib> <deps.toml>
  local root="$1" crate="$2" lib="$3" deps="$4" fail=0 repo
  repo="${NET_BAN_REPO:-$(basename "$(cd "$root" && pwd)")}"
  err() { echo "::error::net-ban: $*" >&2; fail=1; }
  [ -f "$deps" ] || { err "no policy at $deps"; return 1; }
  [ -f "$lib" ] || { err "no built cdylib at $lib"; return 1; }
  local banned_crates banned_features banned_imports carriers
  banned_crates="$(policy "$deps" crates)"
  banned_features="$(policy "$deps" features)"
  banned_imports="$(policy "$deps" imports)"
  carriers="$(policy "$deps" carriers)"

  # The shipped closure: normal + build edges, every target, each package with its features.
  local tree
  tree="$(cd "$root" && cargo tree --locked --offline -p "$crate" -e normal,build --target all \
    --prefix none --no-dedupe -f '{p}|{f}' 2>&1)" || { err "cargo tree failed for $crate: $tree"; return 1; }
  local line name feats b c f
  while IFS= read -r line; do
    [ -n "$line" ] || continue
    name="${line%% *}"
    feats="${line#*|}"
    while IFS= read -r b; do
      [ -n "$b" ] && [ "$name" = "$b" ] && err "$crate ships banned crate '$b' ($line)"
    done <<< "$banned_crates"
    while IFS= read -r b; do
      [ -n "$b" ] || continue
      c="${b%%/*}"; f="${b#*/}"
      if [ "$name" = "$c" ] && printf ',%s,' "$feats" | grep -qF ",$f,"; then
        err "$crate ships banned feature '$b' ($line)"
      fi
    done <<< "$banned_features"
  done < <(printf '%s\n' "$tree" | sort -u)

  # The built cdylib: what it imports.
  local imported sym
  imported="$(imports_of "$lib" | sort -u)"
  if printf '%s\n' "$carriers" | grep -qxF "$repo"; then
    echo "net-ban: $repo is a listed carrier: the socket half of the import scan is not applied"
  else
    while IFS= read -r sym; do
      [ -n "$sym" ] && printf '%s\n' "$imported" | grep -qxF "$sym" && err "$(basename "$lib") imports banned symbol '$sym' (a socket, a dial or TLS of its own)"
    done <<< "$banned_imports"
  fi
  [ "$fail" = 0 ] && echo "net-ban: ok — $crate ships no socket, dial or TLS of its own ($(basename "$lib"))"
  return "$fail"
}

selftest() {
  local tmp rc=0 ran=0
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  export CARGO_TARGET_DIR="$tmp/target"
  # The policy under test: busbar's own.
  local deps="$here/../../.github/fleet/deps.toml"
  mk() {  # mk <body of lib.rs> [extra Cargo.toml lines]: a fixture plugin, its cdylib built
    rm -rf "$tmp/p"; mkdir -p "$tmp/p/src"
    printf '[package]\nname = "fixture-plugin"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n[lib]\ncrate-type = ["cdylib"]\n[profile.release]\nlto = true\n%s\n' "${2:-}" > "$tmp/p/Cargo.toml"
    printf '%s\n' "$1" > "$tmp/p/src/lib.rs"
    (cd "$tmp/p" && cargo generate-lockfile --offline -q && cargo build --release --offline -q) >&2
  }
  lib() { ls "$tmp/target/release/"libfixture_plugin.{so,dylib} 2>/dev/null | head -1; }
  expect() {  # expect <label> <ok|red> [needle]
    ran=$((ran + 1))
    local out st=0
    out="$(NET_BAN_REPO=fixture check "$tmp/p" fixture-plugin "$(lib)" "$deps" 2>&1)" || st=$?
    if [ "$2" = ok ] && [ "$st" = 0 ]; then echo "  [ok]     $1"
    elif [ "$2" = red ] && [ "$st" != 0 ] && printf '%s' "$out" | grep -qF "$3"; then echo "  [ok]     $1"
    else echo "  [FAILED] $1 (exit $st): $out"; rc=1; fi
  }
  local clean='#[no_mangle] pub extern "C" fn busbar_fixture(a: u32, b: u32) -> u32 { a.wrapping_add(b) }'
  local dials='#[no_mangle] pub extern "C" fn busbar_fixture() -> u32 { std::net::TcpStream::connect("10.0.0.1:443").map_or(0, |_| 1) }'
  # Crates named like a banned one, as local path crates: what a plugin's closure would hold.
  for n in socket2 tokio; do
    mkdir -p "$tmp/$n/src"; : > "$tmp/$n/src/lib.rs"
    printf '[package]\nname = "%s"\nversion = "0.1.0"\nedition = "2021"\n[workspace]\n[features]\nnet = []\nrt = []\n' "$n" > "$tmp/$n/Cargo.toml"
  done
  echo "net-ban selftest"
  mk "$clean"; expect "a plugin that dials nothing passes (control)" ok
  mk "$dials"; expect "a plugin that calls std::net::TcpStream::connect itself is refused" red "imports banned symbol 'connect'"
  mk "$clean" "[dependencies]
socket2 = { path = \"../socket2\" }"; expect "a banned crate in the shipped closure is refused" red "banned crate 'socket2'"
  mk "$clean" "[build-dependencies]
socket2 = { path = \"../socket2\" }"; expect "a banned crate as a build dependency is refused" red "banned crate 'socket2'"
  mk "$clean" "[dev-dependencies]
socket2 = { path = \"../socket2\" }"; expect "a banned crate as a dev-dependency (its tests) passes" ok
  mk "$clean" "[dependencies]
tokio = { path = \"../tokio\", features = [\"net\"] }"; expect "a banned feature (tokio/net) is refused" red "banned feature 'tokio/net'"
  mk "$clean" "[dependencies]
tokio = { path = \"../tokio\", features = [\"rt\"] }"; expect "an allowed feature of the same crate passes" ok
  [ "$ran" = 7 ] || { echo "net-ban selftest: only $ran of 7 cases ran"; return 1; }
  [ "$rc" = 0 ] && echo "net-ban selftest: every refusal fires on its planted defect" || echo "net-ban selftest: FAILED"
  return "$rc"
}

case "${1:-}" in
  --selftest) selftest ;;
  -*|"") echo "usage: net-ban.sh <plugin-root> <plugin-crate> <cdylib> [<deps.toml>] | --selftest" >&2; exit 2 ;;
  *) check "$1" "${2:?plugin crate}" "${3:?cdylib}" "${4:-$here/../../.github/fleet/deps.toml}" ;;
esac
