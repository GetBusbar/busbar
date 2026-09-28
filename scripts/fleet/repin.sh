#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# Move a plugin repo's busbar pin to <sha> (busbar version <version>) in ONE step, so the places that
# name it can never disagree (scripts/fleet/pin-check.sh is the check this keeps green):
#
#   .busbar-ref          "<sha> <version>";
#   every Cargo.toml     each `busbar-* = { git = "https://github.com/GetBusbar/busbar", rev = ... }`,
#                        which is what cargo actually BUILDS against;
#   Cargo.lock           the resolved busbar git source, so `--locked` builds keep working;
#   .github/workflows    each `uses: GetBusbar/busbar/.github/workflows/<file>@<sha>`: the thin
#                        callers take the reusable CI/release logic at the same busbar commit the
#                        contract comes from.
#
# One implementation for the whole fleet: plugin-repin.yml runs it in the plugin repo, and
# `cargo xtask fleet sync` produces the same four edits from plugins.yaml.
#
# Usage: repin.sh <40-hex sha> <version>     (run from the plugin repo root; needs cargo + network)
#        repin.sh --decide <sha|""> <version|"">
#        repin.sh --selftest                  (offline: the decision table and the refusals)
#
# --decide answers "did upstream move?" against `.busbar-ref` BY COMMIT, and prints `cut` or `skip`
# on stdout (the reason on stderr):
#   skip  no incoming commit (nothing to compare), or the incoming commit IS the recorded pin;
#   skip  the incoming version is OLDER than the recorded one (a pin never moves backwards);
#   cut   any other incoming commit: a newer version, or the same version string at a different
#         commit (a pin taken before the release was tagged is not the release).
set -euo pipefail

SRC='https://github.com/GetBusbar/busbar'

decide() {
  local in_sha="${1-}" in_ver="${2-}" rec_sha="" rec_ver=""
  in_ver="${in_ver#v}"
  if [ -f .busbar-ref ]; then
    rec_sha="$(awk '{print $1; exit}' .busbar-ref)"
    rec_ver="$(awk '{print $2; exit}' .busbar-ref)"
  fi
  if [ -n "$in_sha" ] && ! [[ "$in_sha" =~ ^[0-9a-f]{40}$ ]]; then
    echo "::error::decide: incoming sha '$in_sha' is not a full 40-hex busbar sha" >&2; return 1
  fi
  say() { echo "::notice::$2" >&2; echo "$1"; }
  if [ -z "$in_sha" ]; then
    say skip "no incoming busbar commit (recorded=${rec_sha:-none}) -> nothing to compare"
  elif [ "$in_sha" = "$rec_sha" ]; then
    say skip "incoming busbar ${in_sha} IS the recorded pin -> nothing to do"
  elif [ -n "$in_ver" ] && [ -n "$rec_ver" ] && [ "$in_ver" != "$rec_ver" ] \
       && [ "$(printf '%s\n%s\n' "$rec_ver" "$in_ver" | sort -V | tail -1)" = "$rec_ver" ]; then
    say skip "incoming busbar ${in_ver} is older than the recorded ${rec_ver} -> a pin never moves backwards"
  else
    say cut "upstream moved: busbar ${in_ver:-?} at ${in_sha}, recorded pin ${rec_ver:-none} at ${rec_sha:-none} -> cut"
  fi
}

repin() {
  local sha="${1:-}" ver="${2:-}"
  [ -n "$sha" ] && [ -n "$ver" ] || { echo "usage: repin.sh <sha> <version>" >&2; return 2; }
  ver="${ver#v}"
  [[ "$sha" =~ ^[0-9a-f]{40}$ ]] || { echo "::error::repin: '$sha' is not a full 40-hex busbar sha" >&2; return 1; }
  [[ "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+([-+][0-9A-Za-z.-]+)?$ ]] || { echo "::error::repin: '$ver' is not a version" >&2; return 1; }
  [ -f Cargo.lock ] || { echo "::error::repin: run from the repo root (no Cargo.lock here)" >&2; return 1; }

  local manifests=() m
  while IFS= read -r m; do manifests+=("$m"); done < <(git ls-files '*Cargo.toml' | xargs grep -l "git = \"${SRC}\"" || true)
  [ "${#manifests[@]}" -gt 0 ] || { echo "::error::repin: no manifest names the busbar git source" >&2; return 1; }
  for m in "${manifests[@]}"; do
    sed -i.repin-bak -E "s#(git = \"${SRC}\", rev = \")[0-9a-f]+\"#\\1${sha}\"#g" "$m"
    rm -f "$m.repin-bak"
  done
  printf '%s %s\n' "$sha" "$ver" > .busbar-ref
  local wf
  for wf in .github/workflows/*.yml; do
    [ -f "$wf" ] || continue
    sed -i.repin-bak -E "s#(GetBusbar/busbar/\.github/workflows/[A-Za-z0-9_.-]+@)[0-9a-f]{40}#\\1${sha}#g" "$wf"
    rm -f "$wf.repin-bak"
  done

  # Re-resolve ONLY what moved (the busbar git source); every other locked package stays as locked.
  cargo metadata --format-version 1 >/dev/null
  cargo metadata --format-version 1 --locked >/dev/null
  bash "$(dirname "$0")/pin-check.sh" .
  echo "busbar pin -> ${sha} ${ver} (${#manifests[@]} manifest(s), .busbar-ref, Cargo.lock, workflows)"
}

selftest() {
  local tmp rc=0 ran=0 a=1111111111111111111111111111111111111111 b=2222222222222222222222222222222222222222
  tmp="$(mktemp -d)"
  expect() {  # expect <label> <want> <sha> <ver>
    ran=$((ran + 1))
    local got; got="$(cd "$tmp" && decide "$3" "$4" 2>/dev/null || echo error)"
    if [ "$got" = "$2" ]; then echo "  [ok]     $1"; else echo "  [FAILED] $1 (want $2, got $got)"; rc=1; fi
  }
  echo "repin selftest (the cut/skip decision is by commit)"
  printf '%s 1.6.0\n' "$a" > "$tmp/.busbar-ref"
  expect "the recorded commit skips" skip "$a" 1.6.0
  expect "the same version at a DIFFERENT commit cuts" cut "$b" 1.6.0
  expect "a leading v does not hide a moved commit" cut "$b" v1.6.0
  expect "a newer version at another commit cuts" cut "$b" 1.7.0
  expect "an older version never moves the pin backwards" skip "$b" 1.5.5
  expect "no incoming commit skips" skip "" 1.7.0
  expect "a short incoming sha is an error, not a decision" error "${b:0:9}" 1.7.0
  rm -f "$tmp/.busbar-ref"
  expect "no recorded pin cuts on any incoming commit" cut "$b" 1.6.0
  ran=$((ran + 1))
  if out="$(cd "$tmp" && repin "${b:0:9}" 1.6.0 2>&1)"; then echo "  [FAILED] a short sha was accepted"; rc=1
  elif printf '%s' "$out" | grep -q "not a full 40-hex"; then echo "  [ok]     repin refuses a short sha before touching a file"
  else echo "  [FAILED] short sha refused for the wrong reason: $out"; rc=1; fi
  ran=$((ran + 1))
  if out="$(cd "$tmp" && repin "$b" "" 2>&1)"; then echo "  [FAILED] an empty version was accepted"; rc=1
  elif printf '%s' "$out" | grep -q "usage: repin.sh"; then echo "  [ok]     repin refuses an empty version"
  else echo "  [FAILED] empty version refused for the wrong reason: $out"; rc=1; fi
  rm -rf "$tmp"
  [ "$ran" = 10 ] || { echo "repin selftest: only $ran of 10 cases ran"; return 1; }
  [ "$rc" = 0 ] && echo "repin selftest: passed" || echo "repin selftest: FAILED"
  return "$rc"
}

case "${1:-}" in
  --decide) decide "${2-}" "${3-}" ;;
  --selftest) selftest ;;
  *) repin "${1:-}" "${2:-}" ;;
esac
