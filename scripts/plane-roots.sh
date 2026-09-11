#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-roots.sh — THE ONE ANSWER TO "WHERE DOES A PLANE LIVE?", for the lints that need it.
#
# NO SHELL LINT SOURCES THIS FILE ANY MORE. All four callers below are `cargo xtask gate <name>`
# now, and the live implementation of the rule this file states is `xtask/src/planes.rs`, which is
# the one both the disk resolver and the overlay-aware one in `structure_lint::roots` go through.
# The file is kept until the end of the batch-1 conversion rather than deleted mid-flight, and this
# note is here so nobody reads its four-caller argument below as a description of today.
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
#     settings-leak gate       dropping them leaves the floor comfortably cleared and the lint
#     response-header gate     reporting `ok` over a tree it no longer reads. The floor catches a
#                               root that MOVED. Nothing caught a root that SPLIT.
#
# Four copies of the same guess is four things to remember on the day the planes move, which is the
# definition of a gate that rots. There is one search rule and it lives here.
#
# THE RULE, and it is deliberately mechanical: a plane's root is THE DIRECTORY THAT OWNS IT, found
# by NAME and then narrowed by OWNERSHIP. A name match alone is not an ownership claim — the wire-
# codec split (1.6.0 step 4) gives a plane a SECOND directory under its own name (`busbar-a2a-codec/
# src/a2a/` beside `busbar-a2a/src/a2a/`), and that second directory holds bytes-on-the-wire, not the
# plane's own declaration. A candidate must CARRY the plane's grammar to count: the file that
# declares `pub const PLANE_DECL: … PlaneDecl = …` directly inside it (`a2a/mod.rs`, `mcp/mod.rs` —
# the composition root's one stable handle onto the plane, per `crates/busbar-a2a/src/lib.rs` and
# `crates/busbar-mcp/src/mcp/mod.rs`). The codec crate only ever REFERENCES `PLANE_DECL.key`; it
# never declares one, so it is not a candidate. Three answers, one of which is a pass:
#
#   exactly one   — that is the home, wherever the tree put it. Moving the plane needs no edit here.
#   none          — FAILURE. Not "skip the plane": a plane nothing can locate is a plane every rule
#                   below is scanning zero files of, and zero is the passing answer to every ban.
#   more than one — FAILURE, and it is a FINDING rather than a nuisance: two directories BOTH
#                   declaring the same plane's `PLANE_DECL` is a half-finished move or a duplicated
#                   plane, and no caller can say which pair it just compared. Picking whichever sorts
#                   first would freeze one home's shapes and quietly un-freeze the other's — a
#                   coverage hole that reads green — so ambiguity is narrowed by ownership, never
#                   resolved by preference order.
#
# CONTRACT. `plane_roots_resolve <plane> …` sets, for each plane, `PLANE_ROOT_<plane>`; on any
# failure it appends one line per problem to `PLANE_ROOTS_ERR` and returns 1. It NEVER exits and
# NEVER prints: the caller owns its own reporting style (structure-lint folds the lines into its
# running `fail`; the scan-floor lints print them and exit 1). Nothing here relaxes a rule — it
# turns WHERE each rule looks from a constant into a fact about the tree.
#
# DRIVABLE OVER A THROWAWAY TREE, the same way `config-schema.py`'s sibling resolver is: set
# `PLANE_ROOTS_SEARCH_ROOT` to point the `find` below at a fixture tree instead of `crates/`, and
# `PLANE_ROOTS_GRAMMAR` to name the fixture's stand-in declaration string instead of the real one.
# `plane_roots_selftest` (below) is what exercises this — the resolver was previously reachable only
# as an import-time side effect of the four lints that source this file, so nothing drove either
# refusal on purpose.

PLANE_ROOTS_ERR=""

plane_roots_resolve() {   # $1.. = plane keys. Sets PLANE_ROOT_<key> per plane; returns 1 on any failure.
  local plane root grammar hits d owned n rc=0
  PLANE_ROOTS_ERR=""
  # ── ZERO PLANES IS NOT ZERO PROBLEMS ─────────────────────────────────────────────────────────────
  # Everything below refuses a plane that resolves to no home or two homes, on the stated ground that
  # zero is the passing answer to every ban the callers apply. That reasoning indicts the loop's own
  # arity first: `for plane in "$@"` over an empty list runs zero times, leaves `rc` at 0 and
  # PLANE_ROOTS_ERR empty, and hands the caller a silent success in which nothing was located and
  # therefore nothing will be scanned. The four callers pass literal keys today, so this is the hole
  # that has not opened yet rather than one that has — which is the only kind worth closing in a file
  # four lints delegate their scan addresses to.
  if [ "$#" -eq 0 ]; then
    PLANE_ROOTS_ERR="PLANE-ROOTS-EMPTY: plane_roots_resolve was called with NO plane keys. Zero planes
  resolved is zero planes located and zero files scanned, and zero is the passing answer to every rule
  that asks this file where to look. Fix the caller's plane list (scripts/plane-keys.sh) rather than
  resolving an empty set.
"
    return 1
  fi
  root="${PLANE_ROOTS_SEARCH_ROOT:-crates}"
  grammar="${PLANE_ROOTS_GRAMMAR:-pub const PLANE_DECL:}"
  for plane in "$@"; do
    hits=$(find "$root" -type d -name "$plane" -not -path '*/target/*' 2>/dev/null | sort -u)
    # A NAME MATCH IS NOT AN OWNERSHIP CLAIM (see the file header). A candidate must directly hold a
    # file that DECLARES the plane's grammar — not merely reference it three directories over — so
    # the codec split's same-named sibling is narrowed out before ambiguity is even considered.
    owned=""
    while IFS= read -r d; do
      [ -z "$d" ] && continue
      # THE ANSWER IS THE MATCHED FILE, NOT find's EXIT STATUS. `-exec … +` runs the command once
      # per batch of matched files, and a directory holding NO `.rs` file produces no batch at all:
      # `grep` never runs, find has nothing to complain about, and find exits 0. Read as a status,
      # that 0 says "this directory declares the plane's grammar" about a directory with no Rust in
      # it — a plane root resolved to somewhere that cannot possibly own the plane, which then
      # becomes the scan root every rule that names the plane uses. So the ownership claim is the
      # grep's OUTPUT (the file that carries the declaration), and an empty output owns nothing.
      if [ -n "$(find "$d" -maxdepth 1 -name '*.rs' -exec grep -l -- "$grammar" {} + 2>/dev/null)" ]; then
        owned="${owned}${d}
"
      fi
    done <<<"$hits"
    owned=$(printf '%s' "$owned" | sed '/^$/d' | sort -u)
    n=$(printf '%s\n' "$owned" | grep -c . || true)
    if [ "$n" -eq 1 ]; then
      eval "PLANE_ROOT_${plane}=\$owned"
      continue
    fi
    rc=1
    eval "PLANE_ROOT_${plane}=PLANE-ROOT-UNRESOLVED/${plane}"
    if [ "$n" -eq 0 ]; then
      PLANE_ROOTS_ERR="${PLANE_ROOTS_ERR}PLANE-ROOT-MISSING: no directory named \`${plane}\` under ${root}/ carries its
  \`${grammar}\` declaration. Every rule that names this plane is now scanning NOTHING, and zero is
  the passing answer to a ban. If the plane legitimately moved somewhere this rule cannot see it,
  fix the search in scripts/plane-roots.sh — do not delete the rows or lower a scan floor.
"
    else
      PLANE_ROOTS_ERR="${PLANE_ROOTS_ERR}PLANE-ROOT-AMBIGUOUS: \`${plane}\` resolves to ${n} directories that each declare its
  grammar:
$(printf '%s\n' "$owned" | sed 's/^/    /')
  Two homes for one plane's declaration is a half-finished move or a duplicated plane; either way no
  caller can say which pair of trees it just compared. Resolve the tree.
"
    fi
  done
  return "$rc"
}

# ── SELF-TEST. Drives `plane_roots_resolve` over three throwaway trees so the two refusals above are
# proven rather than assumed, plus one case over the REAL tree so the codec split itself is pinned as
# a regression test. Prints via `note` (defined by every caller before it sources this file) and
# returns the fixture failure count; the caller folds that into its own run/pass/fail counters.
plane_roots_selftest() {
  local tmp rc out fails=0 cases=0
  tmp="$(mktemp -d)"

  # Case 1: the wire-codec split — a same-named sibling that carries NO declaration is not a second
  # home, so the one directory that DOES declare the plane resolves, and the gate keeps covering it.
  mkdir -p "$tmp/split/plane-x/src/x" "$tmp/split/plane-x-codec/src/x"
  printf 'pub const PLANE_DECL: Foo = Foo;\n' >"$tmp/split/plane-x/src/x/mod.rs"
  printf 'pub fn canonical() {}\n' >"$tmp/split/plane-x-codec/src/x/canonical.rs"
  cases=$((cases + 1))
  rc=0
  out=$(PLANE_ROOTS_SEARCH_ROOT="$tmp/split" plane_roots_resolve x 2>/dev/null && printf '%s' "$PLANE_ROOT_x") || rc=$?
  if [ "$rc" -ne 0 ] || [ "$out" != "$tmp/split/plane-x/src/x" ]; then
    note "SELFTEST FAIL [plane-roots: codec-split-not-a-second-home] resolved to '${out:-<unset>}' (rc=${rc}), expected $tmp/split/plane-x/src/x with rc=0"
    fails=$((fails + 1))
  fi

  # Case 2: TWO real homes — both declare the plane. This MUST be refused, and the refusal must name
  # both, so whoever reads it can see which two directories are claiming one plane.
  mkdir -p "$tmp/two/plane-y/src/y" "$tmp/two/plane-y-fork/src/y"
  printf 'pub const PLANE_DECL: Foo = Foo;\n' >"$tmp/two/plane-y/src/y/mod.rs"
  printf 'pub const PLANE_DECL: Foo = Foo;\n' >"$tmp/two/plane-y-fork/src/y/mod.rs"
  cases=$((cases + 1))
  rc=0
  PLANE_ROOTS_SEARCH_ROOT="$tmp/two" plane_roots_resolve y >/dev/null 2>&1 && rc=1
  if [ "$rc" -ne 0 ]; then
    note "SELFTEST FAIL [plane-roots: two-declaring-homes-refused] two real declarations resolved instead of being refused"
    fails=$((fails + 1))
  elif ! printf '%s' "$PLANE_ROOTS_ERR" | grep -q "plane-y/src/y" || ! printf '%s' "$PLANE_ROOTS_ERR" | grep -q "plane-y-fork/src/y"; then
    note "SELFTEST FAIL [plane-roots: two-declaring-homes-named] refusal did not name both claiming directories: $PLANE_ROOTS_ERR"
    fails=$((fails + 1))
  fi

  # Case 3: NO home — the grammar left the tracked set entirely (a same-named directory exists but
  # declares nothing). A skip here would un-freeze a whole plane, so this is a hard error, not a skip.
  mkdir -p "$tmp/none/plane-z/src/z"
  printf 'pub fn unrelated() {}\n' >"$tmp/none/plane-z/src/z/canonical.rs"
  cases=$((cases + 1))
  rc=0
  PLANE_ROOTS_SEARCH_ROOT="$tmp/none" plane_roots_resolve z >/dev/null 2>&1 && rc=1
  if [ "$rc" -ne 0 ]; then
    note "SELFTEST FAIL [plane-roots: no-declaring-home-is-an-error] no declaration resolved instead of being refused"
    fails=$((fails + 1))
  fi

  # Case 3b: a same-named directory holding NO `.rs` FILE AT ALL. `find … -exec grep {} +` runs its
  # command once per batch of matched files, so with nothing to match it never runs grep and find
  # exits 0 — and the old ownership test read that 0 as "this directory declares the plane". The
  # plane then resolved to a directory with no Rust in it, which became the scan root for every rule
  # that names the plane: zero files scanned, and zero is the passing answer to a ban. Distinct from
  # case 3 (a directory that HAS Rust but declares nothing), which took the other branch and was
  # already refused.
  mkdir -p "$tmp/norust/plane-w/src/w/docs"
  printf 'not rust\n' >"$tmp/norust/plane-w/src/w/docs/NOTES.md"
  cases=$((cases + 1))
  rc=0
  PLANE_ROOTS_SEARCH_ROOT="$tmp/norust" plane_roots_resolve w >/dev/null 2>&1 && rc=1
  if [ "$rc" -ne 0 ]; then
    note "SELFTEST FAIL [plane-roots: a-directory-with-no-rust-owns-nothing] a directory holding no .rs file resolved as the plane's declaring home"
    fails=$((fails + 1))
  fi

  # Case 3c: NO PLANES AT ALL. Cases 1–3b drive the loop with a key and judge what it finds; this
  # drives the loop with nothing and judges the arity. An empty plane list used to return 0 with an
  # empty error string — a caller whose list came back empty was told every plane resolved.
  cases=$((cases + 1))
  rc=0
  plane_roots_resolve >/dev/null 2>&1 && rc=1
  if [ "$rc" -ne 0 ]; then
    note "SELFTEST FAIL [plane-roots: no-planes-is-an-error] an empty plane list resolved successfully"
    fails=$((fails + 1))
  elif ! printf '%s' "$PLANE_ROOTS_ERR" | grep -q "PLANE-ROOTS-EMPTY"; then
    note "SELFTEST FAIL [plane-roots: no-planes-is-named] the empty-list refusal did not name itself: $PLANE_ROOTS_ERR"
    fails=$((fails + 1))
  fi

  rm -rf "$tmp"

  # Case 4: COVERAGE — the real tree's `a2a` must resolve to the plane crate, not the codec crate,
  # proving the codec split above is not a fixture-only story. Callers of this self-test have already
  # `cd`ed to the repo root (structure-lint.sh does so before sourcing this file), so `crates/` here
  # is the real tree, not a fixture.
  cases=$((cases + 1))
  rc=0
  out=$(unset PLANE_ROOTS_SEARCH_ROOT; plane_roots_resolve a2a 2>/dev/null && printf '%s' "$PLANE_ROOT_a2a") || rc=$?
  case "$out" in
    */busbar-a2a/src/a2a) : ;;
    *)
      note "SELFTEST FAIL [plane-roots: real-a2a-resolves-to-the-owner] resolved to '${out:-<unset>}' (rc=${rc}), expected .../busbar-a2a/src/a2a"
      fails=$((fails + 1))
      ;;
  esac

  PLANE_ROOTS_SELFTEST_RAN=$cases
  PLANE_ROOTS_SELFTEST_FAIL=$fails
  # Always returns 0: callers read PLANE_ROOTS_SELFTEST_FAIL rather than the exit status, the same
  # convention structure-lint.sh's own selftest_* helpers use, so a fixture failure here reports and
  # continues instead of tripping this file's (or the sourcing caller's) `set -e`.
  return 0
}
