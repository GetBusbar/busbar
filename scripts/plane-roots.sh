#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-roots.sh — THE ONE ANSWER TO "WHERE DOES A PLANE LIVE?", for the lints that need it.
#
# WHY THIS FILE EXISTS. 1.6.0's owner ruling R-E makes the MCP and A2A planes PLUGIN CRATES: a crate
# depending on `busbar-api` alone, which `busbar-core` depends on, exactly as it depends on
# `busbar-auth-admin-tokens` today. So `crates/busbar-core/src/{mcp,a2a}` is a FACT ABOUT TODAY'S
# TREE and not a permanent address — and four separate lints had it spelled as a constant, in a
# position where being wrong is SILENT:
#
#   * structure-lint.sh       — 6 signed choke-point/decision-input rows plus 22 census and axis
#                               scopes. Loud when the row's subject vanishes; silently NARROWER when
#                               only the SCOPE moves out from under it.
#   * blocking-ffi-lint.sh    — the planes are 71 of 238 scanned files and the scan floor is 100, so
#     settings-leak-lint.sh     dropping them leaves the floor comfortably cleared and the lint
#     response-header-lint.sh   reporting `ok` over a tree it no longer reads. The floor catches a
#                               root that MOVED. Nothing caught a root that SPLIT.
#
# Four copies of the same guess is four things to remember on the day the planes move, which is the
# definition of a gate that rots. There is one search rule and it lives here.
#
# THE RULE, and it is deliberately mechanical: a plane's root is THE ONE DIRECTORY NAMED AFTER IT
# anywhere under `crates/`. Three answers, one of which is a pass:
#
#   exactly one   — that is the home, wherever the tree put it. Moving the plane needs no edit here.
#   none          — FAILURE. Not "skip the plane": a plane nothing can locate is a plane every rule
#                   below is scanning zero files of, and zero is the passing answer to every ban.
#   more than one — FAILURE, and it is a FINDING rather than a nuisance: two directories claiming to
#                   be one plane is a half-finished move or a duplicated plane, and no caller can
#                   say which pair it just compared.
#
# CONTRACT. `plane_roots_resolve <plane> …` sets, for each plane, `PLANE_ROOT_<plane>`; on any
# failure it appends one line per problem to `PLANE_ROOTS_ERR` and returns 1. It NEVER exits and
# NEVER prints: the caller owns its own reporting style (structure-lint folds the lines into its
# running `fail`; the scan-floor lints print them and exit 1). Nothing here relaxes a rule — it
# turns WHERE each rule looks from a constant into a fact about the tree.

PLANE_ROOTS_ERR=""

plane_roots_resolve() {   # $1.. = plane keys. Sets PLANE_ROOT_<key> per plane; returns 1 on any failure.
  local plane hits n rc=0
  PLANE_ROOTS_ERR=""
  for plane in "$@"; do
    hits=$(find crates -type d -name "$plane" -not -path '*/target/*' 2>/dev/null | sort -u)
    n=$(printf '%s\n' "$hits" | grep -c . || true)
    if [ "$n" -eq 1 ]; then
      eval "PLANE_ROOT_${plane}=\$hits"
      continue
    fi
    rc=1
    eval "PLANE_ROOT_${plane}=PLANE-ROOT-UNRESOLVED/${plane}"
    if [ "$n" -eq 0 ]; then
      PLANE_ROOTS_ERR="${PLANE_ROOTS_ERR}PLANE-ROOT-MISSING: no directory named \`${plane}\` under crates/. Every rule
  that names this plane is now scanning NOTHING, and zero is the passing answer to a ban. If the
  plane legitimately moved somewhere this rule cannot see it, fix the search in
  scripts/plane-roots.sh — do not delete the rows or lower a scan floor.
"
    else
      PLANE_ROOTS_ERR="${PLANE_ROOTS_ERR}PLANE-ROOT-AMBIGUOUS: \`${plane}\` resolves to ${n} directories:
$(printf '%s\n' "$hits" | sed 's/^/    /')
  Two homes for one plane is a half-finished move or a duplicated plane; either way no caller can
  say which pair of trees it just compared. Resolve the tree.
"
    fi
  done
  return "$rc"
}
