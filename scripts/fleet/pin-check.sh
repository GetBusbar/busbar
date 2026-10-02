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
# Two more refusals: a manifest that names a path OUTSIDE the repo (a sibling-checkout dependency
# builds whatever happens to sit beside the checkout, not the pin), and a retired busbar crate
# (a plugin's busbar closure is busbar-contract, plus busbar-plugin-loader for its tests).
#
# Usage: pin-check.sh [<plugin-root>]      (default: .)
#        pin-check.sh --selftest           every refusal fires on its planted defect, offline
set -euo pipefail

SRC='https://github.com/GetBusbar/busbar'

check() {
  local root="$1" fail=0
  err() { echo "::error::pin-check: $*" >&2; fail=1; }
  [ -f "$root/.busbar-ref" ] || { err ".busbar-ref is missing"; return 1; }
  local pin ver
  pin="$(awk '{print $1; exit}' "$root/.busbar-ref")"
  ver="$(awk '{print $2; exit}' "$root/.busbar-ref")"
  [[ "$pin" =~ ^[0-9a-f]{40}$ ]] || err ".busbar-ref field 1 is not a full 40-hex sha: '$pin'"
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || err ".busbar-ref field 2 is not a version: '$ver'"

  local manifests=() m
  while IFS= read -r m; do manifests+=("$m"); done < <(cd "$root" && find . -name Cargo.toml -not -path '*/target/*' -not -path './.git/*' | sort)
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
    if grep -E "^source = \"git\+${SRC}" "$root/Cargo.lock" | grep -vqF "?rev=${pin}#${pin}\""; then
      err "Cargo.lock resolves a busbar source other than rev=${pin}"
    fi
  else
    err "Cargo.lock is missing (a release builds --locked)"
  fi

  if [ -d "$root/.github/workflows" ]; then
    local refs
    refs="$(grep -rhoE 'GetBusbar/busbar/\.github/workflows/[A-Za-z0-9_.-]+@[^[:space:]]+' "$root/.github/workflows" | sed 's/.*@//' | sort -u || true)"
    for r in $refs; do
      [ "$r" = "$pin" ] || err "a workflow takes a busbar reusable workflow at '$r', not the pin $pin"
    done
  fi

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
  expect() {  # expect <label> <ok|red> [needle]
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
  mk; sed -i.bak "s/@$pin/@dev/" "$tmp/r/.github/workflows/ci.yml"; expect "a reusable workflow taken at a branch, not the pin, is refused" red "not the pin"
  [ "$ran" = 8 ] || { echo "pin-check selftest: only $ran of 8 cases ran"; return 1; }
  [ "$rc" = 0 ] && echo "pin-check selftest: every refusal fires on its planted defect" || echo "pin-check selftest: FAILED"
  return "$rc"
}

case "${1:-}" in
  --selftest) selftest ;;
  -*) echo "usage: pin-check.sh [<plugin-root>] | --selftest" >&2; exit 2 ;;
  *) check "${1:-.}" ;;
esac
