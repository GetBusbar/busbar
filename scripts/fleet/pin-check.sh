#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# THE PIN CHECK every first-party plugin repo runs (plugin-ci.yml's `pin` job, and `busbar-release plugin
# check` reads the same rules). A plugin repo names the busbar it builds against in FOUR places, and
# they must agree, or what CI proves is not what the release builds:
#
#   .busbar-ref          "<40-hex sha> <version>", the record the release and the repin read;
#   every Cargo.toml     each `busbar-* = { git = "https://github.com/GetBusbar/busbar", rev = ... }`;
#   Cargo.lock           the resolved `git+https://github.com/GetBusbar/busbar?rev=<sha>#<sha>`;
#   .github/workflows    each `uses: GetBusbar/busbar/.github/workflows/<file>@<ref>` (the reusable
#                        workflows are taken at the pin, so the CI logic and the contract move together).
#
# A C plugin (PIN_CHECK_LANG=c; plugin-ci.yml's `plugin_lang: c`, BUSBAR-1.6.0.md decision #84)
# builds from busbar_plugin.h alone: it names busbar in .busbar-ref and its workflows only, and a
# Cargo.toml or Cargo.lock in it is refused (no Rust, no busbar crate).
#
# THE TRANSPORT FRAMERS a networked plugin's conformance host takes as dev-dependencies (rendered by
# the fleet template, ARCHITECT Q-P4-9: GetBusbar/busbar-transport-*, each its own repo) are pinned
# too: each such source in the lock must be the one busbar's own Cargo.lock at the pin records for that
# crate (PIN_CHECK_BUSBAR_LOCK, default: the Cargo.lock of the busbar checkout this script sits in).
#
# Two more refusals: a manifest that names a path OUTSIDE the repo (a sibling-checkout dependency
# builds whatever happens to sit beside the checkout, not the pin), and a retired busbar crate
# (a plugin's busbar closure is busbar-contract, plus busbar-plugin-loader for its tests).
#
# Usage: [PIN_CHECK_LANG=c] pin-check.sh [<plugin-root>]      (default: .)
#        pin-check.sh --selftest           every refusal fires on its planted defect, offline
set -euo pipefail

SRC='https://github.com/GetBusbar/busbar'
# The transport framer repos (their sources in a lock).
FRAMER_SRC='https://github.com/GetBusbar/busbar-transport-'

lock_sources() {  # lock_sources <Cargo.lock>: "<name> <source>" per package with a source
  awk '/^\[\[package\]\]/{n=""} /^name = /{gsub(/"/,"",$3); n=$3} /^source = /{gsub(/"/,"",$3); if (n!="") print n, $3}' "$1"
}

check() {
  local root="$1" fail=0
  err() { echo "::error::pin-check: $*" >&2; fail=1; }
  workflows() {  # every busbar reusable workflow a workflow takes is taken at the pin
    if [ -d "$1/.github/workflows" ]; then
      local refs r
      refs="$(grep -rhoE 'GetBusbar/busbar/\.github/workflows/[A-Za-z0-9_.-]+@[^[:space:]]+' "$1/.github/workflows" | sed 's/.*@//' | sort -u || true)"
      for r in $refs; do
        [ "$r" = "$2" ] || err "a workflow takes a busbar reusable workflow at '$r', not the pin $2"
      done
    fi
  }
  [ -f "$root/.busbar-ref" ] || { err ".busbar-ref is missing"; return 1; }
  local pin ver
  pin="$(awk '{print $1; exit}' "$root/.busbar-ref")"
  ver="$(awk '{print $2; exit}' "$root/.busbar-ref")"
  [[ "$pin" =~ ^[0-9a-f]{40}$ ]] || err ".busbar-ref field 1 is not a full 40-hex sha: '$pin'"
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || err ".busbar-ref field 2 is not a version: '$ver'"

  local manifests=() m
  while IFS= read -r m; do manifests+=("$m"); done < <(cd "$root" && find . -name Cargo.toml -not -path '*/target/*' -not -path './.git/*' | sort)
  if [ "${PIN_CHECK_LANG:-rust}" = c ]; then
    [ "${#manifests[@]}" = 0 ] || err "a C plugin carries Cargo.toml (${manifests[*]}): it builds from busbar_plugin.h alone"
    [ ! -f "$root/Cargo.lock" ] || err "a C plugin carries Cargo.lock: it builds from busbar_plugin.h alone"
    workflows "$root" "$pin"
    [ "$fail" = 0 ] && echo "pin-check: ok — busbar ${pin} ${ver} (C: .busbar-ref, workflows)"
    return "$fail"
  fi
  [ "${#manifests[@]}" -gt 0 ] || err "no Cargo.toml under $root"

  local revs="" line r
  for m in "${manifests[@]}"; do
    while IFS= read -r line; do
      r="$(printf '%s' "$line" | grep -oE 'rev *= *"[0-9a-f]+"' | grep -oE '[0-9a-f]{7,}' || true)"
      if [ -z "$r" ]; then
        err "$m names the busbar git source without a rev (a branch or tag moves under the pin): $line"
      else
        revs="$revs $r"
      fi
    done < <(grep -E "git *= *\"${SRC}(\.git)?\"" "$root/$m" || true)
    # A path dependency must stay inside the repo.
    while IFS= read -r line; do
      local p dir abs
      p="$(printf '%s' "$line" | sed -E 's/.*path *= *"([^"]+)".*/\1/')"
      dir="$(dirname "$root/$m")"
      abs="$(cd "$dir" 2>/dev/null && cd "$(dirname "$p")" 2>/dev/null && pwd)/$(basename "$p")" || abs=""
      case "$abs" in
        "$(cd "$root" && pwd)"/*) ;;
        *) err "$m names a path dependency outside the repo (a sibling checkout builds whatever sits beside it, not the pin): $line" ;;
      esac
    done < <(grep -E '^[^#]*path *= *"' "$root/$m" | grep -vE '^\s*(path|name) *= *"[^"]*"\s*$' || true)
    if grep -nE '^[[:space:]]*busbar-(api|plugin-sdk|plugin-testkit|plugin-sign)[[:space:]]*=' "$root/$m" >&2; then
      err "$m names a retired busbar crate (a plugin's busbar closure is busbar-contract, plus busbar-plugin-loader for tests)"
    fi
  done
  revs="$(printf '%s\n' $revs | sort -u | grep . || true)"
  if [ -z "$revs" ]; then
    err "no manifest names the busbar git source at a rev"
  elif [ "$revs" != "$pin" ]; then
    err "busbar revs in the manifests ($(echo "$revs" | tr '\n' ' ')) != .busbar-ref ($pin)"
  fi

  if [ -f "$root/Cargo.lock" ]; then
    # busbar's own source exactly (`<SRC>?`): another GetBusbar repo (a transport framer a networked
    # plugin's conformance host takes as a dev-dependency) is its own source at its own rev.
    if grep -E "^source = \"git\+${SRC}\?" "$root/Cargo.lock" | grep -vqF "?rev=${pin}#${pin}\""; then
      err "Cargo.lock resolves a busbar source other than rev=${pin}"
    fi
    # Each transport framer at the source busbar's own lock at the pin records for it.
    local framers name src want block
    framers="$(lock_sources "$root/Cargo.lock" | grep -F " git+${FRAMER_SRC}" || true)"
    if [ -n "$framers" ]; then
      block="${PIN_CHECK_BUSBAR_LOCK:-$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)/Cargo.lock}"
      if [ ! -f "$block" ]; then
        err "Cargo.lock resolves a transport framer, and busbar's Cargo.lock at the pin is not at $block to hold it to"
      else
        while read -r name src; do
          want="$(lock_sources "$block" | awk -v n="$name" '$1==n{print $2}' | sort -u)"
          if [ -z "$want" ]; then
            err "Cargo.lock resolves $name from $src, and busbar at the pin links no $name"
          elif [ "$src" != "$want" ]; then
            err "Cargo.lock resolves $name at ${src##*#}, not the rev busbar's lock at the pin records (${want##*#})"
          fi
        done <<< "$framers"
      fi
    fi
  else
    err "Cargo.lock is missing (a release builds --locked)"
  fi

  workflows "$root" "$pin"

  [ "$fail" = 0 ] && echo "pin-check: ok — busbar ${pin} ${ver} (${#manifests[@]} manifest(s), Cargo.lock, workflows)"
  return "$fail"
}

selftest() {
  local tmp rc=0 ran=0 pin=0123456789abcdef0123456789abcdef01234567 other=89abcdef0123456789abcdef0123456789abcdef
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  mk() {  # a clean fixture repo
    rm -rf "$tmp/r"; mkdir -p "$tmp/r/logic" "$tmp/r/adapter" "$tmp/r/.github/workflows"
    printf '%s 1.6.0\n' "$pin" > "$tmp/r/.busbar-ref"
    printf '[workspace]\nmembers = ["logic", "adapter"]\n' > "$tmp/r/Cargo.toml"
    printf '[package]\nname = "l"\n[dependencies]\nbusbar-contract = { git = "%s", rev = "%s" }\n' "$SRC" "$pin" > "$tmp/r/logic/Cargo.toml"
    printf '[package]\nname = "a"\n[dependencies]\nl = { path = "../logic" }\n[dev-dependencies]\nbusbar-plugin-loader = { git = "%s", rev = "%s" }\n' "$SRC" "$pin" > "$tmp/r/adapter/Cargo.toml"
    printf '[[package]]\nname = "busbar-contract"\nsource = "git+%s?rev=%s#%s"\n' "$SRC" "$pin" "$pin" > "$tmp/r/Cargo.lock"
    printf 'jobs:\n  ci:\n    uses: GetBusbar/busbar/.github/workflows/plugin-ci.yml@%s\n' "$pin" > "$tmp/r/.github/workflows/ci.yml"
  }
  mkc() {  # a clean C fixture repo: sources, .busbar-ref, the CI caller; no Cargo
    rm -rf "$tmp/r"; mkdir -p "$tmp/r/secret-c" "$tmp/r/.github/workflows"
    printf '%s 1.6.0\n' "$pin" > "$tmp/r/.busbar-ref"
    printf '#include "busbar_plugin.h"\n' > "$tmp/r/secret-c/door.c"
    printf 'jobs:\n  ci:\n    uses: GetBusbar/busbar/.github/workflows/plugin-ci.yml@%s\n' "$pin" > "$tmp/r/.github/workflows/ci.yml"
  }
  expect() {  # expect <label> <ok|red> [needle]   (PIN_CHECK_LANG as the caller sets it)
    ran=$((ran + 1))
    local out st=0
    out="$(check "$tmp/r" 2>&1)" || st=$?
    if [ "$2" = ok ] && [ "$st" = 0 ]; then echo "  [ok]     $1"
    elif [ "$2" = red ] && [ "$st" != 0 ] && printf '%s' "$out" | grep -qF "$3"; then echo "  [ok]     $1"
    else echo "  [FAILED] $1 (exit $st): $out"; rc=1; fi
  }
  echo "pin-check selftest"
  mk; expect "a clean repo passes (control)" ok
  mk; printf '%s 1.6.0\n' "${pin:0:9}" > "$tmp/r/.busbar-ref"; expect "a short sha in .busbar-ref is refused" red "not a full 40-hex sha"
  mk; sed -i.bak "s/$pin/$other/" "$tmp/r/logic/Cargo.toml"; expect "a manifest rev that disagrees with .busbar-ref is refused" red "!= .busbar-ref"
  mk; sed -i.bak "s#, rev = \"$pin\"#, branch = \"predev\"#" "$tmp/r/logic/Cargo.toml"; expect "a busbar git dependency on a branch is refused" red "without a rev"
  mk; printf 'x = { path = "../../busbar/crates/x" }\n' >> "$tmp/r/adapter/Cargo.toml"; expect "a sibling-checkout path dependency is refused" red "outside the repo"
  mk; printf 'busbar-plugin-sdk = { git = "%s", rev = "%s" }\n' "$SRC" "$pin" >> "$tmp/r/adapter/Cargo.toml"; expect "a retired busbar crate is refused" red "retired busbar crate"
  mk; sed -i.bak "s/rev=$pin#/rev=$other#/" "$tmp/r/Cargo.lock"; expect "a lock resolving another busbar rev is refused" red "Cargo.lock resolves"
  # busbar's own lock at the pin, as the framer check reads it.
  printf '[[package]]\nname = "busbar-transport-http"\nsource = "git+%s-transport-http?rev=%s#%s"\n' "$SRC" "$other" "$other" > "$tmp/busbar.lock"
  mk; printf '[[package]]\nname = "busbar-transport-http"\nsource = "git+%s-transport-http?rev=%s#%s"\n' "$SRC" "$other" "$other" >> "$tmp/r/Cargo.lock"; PIN_CHECK_BUSBAR_LOCK="$tmp/busbar.lock" expect "a transport framer at the rev busbar's lock records passes (not busbar's own source)" ok
  mk; printf '[[package]]\nname = "busbar-transport-http"\nsource = "git+%s-transport-http?rev=%s#%s"\n' "$SRC" "$pin" "$pin" >> "$tmp/r/Cargo.lock"; PIN_CHECK_BUSBAR_LOCK="$tmp/busbar.lock" expect "a transport framer at another rev than busbar's lock records is refused" red "not the rev busbar's lock at the pin records"
  mk; printf '[[package]]\nname = "busbar-transport-grpc"\nsource = "git+%s-transport-grpc?rev=%s#%s"\n' "$SRC" "$other" "$other" >> "$tmp/r/Cargo.lock"; PIN_CHECK_BUSBAR_LOCK="$tmp/busbar.lock" expect "a transport framer busbar does not link is refused" red "links no busbar-transport-grpc"
  mk; sed -i.bak "s/@$pin/@dev/" "$tmp/r/.github/workflows/ci.yml"; expect "a reusable workflow taken at a branch, not the pin, is refused" red "not the pin"
  mkc; PIN_CHECK_LANG=c expect "a C plugin with no Cargo passes (control)" ok
  mkc; printf '[workspace]\n' > "$tmp/r/Cargo.toml"; PIN_CHECK_LANG=c expect "a C plugin carrying a Cargo.toml is refused" red "carries Cargo.toml"
  mkc; sed -i.bak "s/@$pin/@$other/" "$tmp/r/.github/workflows/ci.yml"; PIN_CHECK_LANG=c expect "a C plugin's workflow off the pin is refused" red "not the pin"
  mkc; expect "a C plugin checked as Rust is refused (no Cargo.toml)" red "no Cargo.toml"
  [ "$ran" = 15 ] || { echo "pin-check selftest: only $ran of 15 cases ran"; return 1; }
  [ "$rc" = 0 ] && echo "pin-check selftest: every refusal fires on its planted defect" || echo "pin-check selftest: FAILED"
  return "$rc"
}

case "${1:-}" in
  --selftest) selftest ;;
  -*) echo "usage: pin-check.sh [<plugin-root>] | --selftest" >&2; exit 2 ;;
  *) check "${1:-.}" ;;
esac
