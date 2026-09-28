#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# The next release tag of a plugin repo (each plugin versions on its OWN semver line, independent of
# busbar's): INPUT_VERSION when given (with or without a leading v), else a patch bump of the highest
# v* tag, else INITIAL_VERSION (default 1.0.0) for a repo that has never released. Prints `vX.Y.Z`.
# One implementation for the fleet; plugin-repin.yml and plugin-release.yml take it from busbar.
#
# Usage: next-version.sh              (run inside the plugin repo)
#        next-version.sh --selftest   (offline, in a scratch repo)
set -euo pipefail

next() {
  local input="${INPUT_VERSION:-}" initial="${INITIAL_VERSION:-1.0.0}" latest base major rest minor patch
  if [ -n "$input" ]; then printf 'v%s\n' "${input#v}"; return 0; fi
  latest="$(git tag --list 'v*' | sort -V | tail -1 || true)"
  if [ -z "${latest:-}" ]; then printf 'v%s\n' "${initial#v}"; return 0; fi
  base="${latest#v}"
  major="${base%%.*}"; rest="${base#*.}"
  minor="${rest%%.*}"; patch="${rest#*.}"
  patch="${patch%%[-+]*}"
  case "$major" in ''|*[!0-9]*) major=0 ;; esac
  case "$minor" in ''|*[!0-9]*) minor=0 ;; esac
  case "$patch" in ''|*[!0-9]*) patch=0 ;; esac
  printf 'v%s.%s.%s\n' "$major" "$minor" "$((patch + 1))"
}

selftest() {
  local work rc=0 ran=0
  work="$(mktemp -d)"
  git -C "$work" init -q
  git -C "$work" -c core.hooksPath=/dev/null -c user.email=t@t -c user.name=t commit -q --allow-empty -m seed
  eq() { ran=$((ran + 1)); if [ "$1" = "$2" ]; then echo "  [ok]     $3"; else echo "  [FAILED] $3 (want $2, got $1)"; rc=1; fi; }
  echo "next-version selftest"
  eq "$(cd "$work" && INITIAL_VERSION=1.0.0 next)" v1.0.0 "no tag: the initial version"
  eq "$(cd "$work" && INITIAL_VERSION=2.3.0 next)" v2.3.0 "no tag: a custom initial version"
  git -C "$work" tag v1.0.0; git -C "$work" tag v1.0.9; git -C "$work" tag v1.2.9
  eq "$(cd "$work" && next)" v1.2.10 "a patch bump of the highest tag, compared as versions"
  git -C "$work" tag v1.2.11-rc1
  eq "$(cd "$work" && next)" v1.2.12 "a pre-release suffix is dropped before the bump"
  eq "$(cd "$work" && INPUT_VERSION=3.4.5 next)" v3.4.5 "an explicit version"
  eq "$(cd "$work" && INPUT_VERSION=v3.4.5 next)" v3.4.5 "an explicit version with a leading v"
  rm -rf "$work"
  [ "$ran" = 6 ] || { echo "next-version selftest: only $ran of 6 cases ran"; return 1; }
  [ "$rc" = 0 ] && echo "next-version selftest: passed" || echo "next-version selftest: FAILED"
  return "$rc"
}

case "${1:-}" in
  --selftest) selftest ;;
  "") next ;;
  *) echo "usage: next-version.sh [--selftest]" >&2; exit 2 ;;
esac
