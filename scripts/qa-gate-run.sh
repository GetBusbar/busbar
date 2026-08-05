#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# qa-gate-run.sh - the qa-gate's ACTUAL LOGIC, versioned with the code it gates.
#
# WHY THIS FILE EXISTS (the dormancy bug it fixes)
# ------------------------------------------------
# `workflow_run` ALWAYS loads the workflow file from the DEFAULT branch. Whatever
# `.github/workflows/qa-gate.yml` looks like on `main` is what auto-fires, no matter what is on
# `qa`. Measured on qa c736177: the auto-fired gate ran ONE job while the whole segmentation
# umbrella sat unused on the `qa` branch. A gate improvement therefore cannot gate the release that
# ships it, and it fails SILENTLY - the run is green, it just did less than you think.
#
# The fix: qa-gate.yml on `main` is a thin, stable DISPATCHER. It checks out the triggering SHA and
# invokes THIS script FROM THAT CHECKOUT. Gate logic then rides the commit it gates: change this
# file on `qa` and the very next auto-fired gate runs the new logic, with no `main` edit and no
# dormancy window. `main` holds ~20 rarely-changing lines of YAML.
#
# WHAT CANNOT MOVE HERE (honest list). These are read by GitHub BEFORE any checkout exists, or are
# structural to the run graph, so they must stay in YAML on the default branch:
#   `on:` triggers, `concurrency`, `permissions`, secrets/env wiring, `runs-on`, `timeout-minutes`,
#   the `needs`/`if` job graph, and the `strategy.matrix` EXPRESSION (its CONTENTS come from here,
#   via the `matrix` subcommand writing a job output).
#
# SUBCOMMANDS
#   matrix                emit the live-mock fan-out matrix as JSON, derived from
#                         `qa-segments.sh --list` (qa/segments.toml is the source of truth). Writes
#                         `matrix=<json>` to $GITHUB_OUTPUT when set. NEVER emits an empty matrix.
#   fast                  the fast tier: segmentation self-test + every fast segment + an explicit
#                         PASS/SKIP report for the reserved live-mock slots (which are deliberately
#                         NOT given a runner of their own - see `matrix`).
#   build [OUT]           build ONCE everything the live-mock legs need from THIS workspace, prune,
#                         and tar to OUT (default: /tmp/busbar-target.tzst).
#   hydrate [IN]          restore that tarball over a fresh checkout and normalise mtimes so cargo
#                         sees the tree as FRESH; then assert freshness and warn loudly if not.
#   siblings              registry-driven sibling checkouts (plugins.yaml + busbar-admin).
#   segment ID            run exactly one segment by id (delegates to qa-segments.sh).
#   loader                the loader-mechanism tests against the real sibling-built sqlite plugin.
#
# Every subcommand is runnable locally, which is the other half of the point: the gate is no longer
# a thing that only exists inside GitHub's YAML.

set -euo pipefail
cd "$(dirname "$0")/.."

TARBALL_DEFAULT="/tmp/busbar-target.tzst"

log()  { printf '\n\033[1m== %s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
die()  { printf '\033[31mqa-gate-run: %s\033[0m\n' "$*" >&2; exit 1; }

# Emit a value to $GITHUB_OUTPUT when running under Actions; a no-op locally.
gh_output() {
  [ -n "${GITHUB_OUTPUT:-}" ] || return 0
  printf '%s=%s\n' "$1" "$2" >>"$GITHUB_OUTPUT"
}

# ── matrix: qa/segments.toml -> strategy.matrix contents ─────────────────────────────────────────
#
# REGISTRY-DRIVEN, NO HAND-WRITTEN LEGS. `qa-segments.sh --list` already emits the manifest as TSV
# expressly so CI can build its matrix; this turns that feed into JSON. The partition can be
# reshaped in qa/segments.toml (split `plugins` into one segment per plugin repo, arm a reserved
# slot, add a segment) with ZERO workflow edits - the workflow only ever names
# `needs.<job>.outputs.matrix`.
#
# Selection: status == active AND tier == live-mock.
#   - `fast` segments are the fast job's business, not a runner each.
#   - `reserved` segments return SKIP in about a second; giving each one a fresh runner would burn
#     a scarce concurrency slot to print one line. The account-wide concurrent-job cap is the real
#     ceiling on this whole design (see qa-gate.yml's fan-out note), so legs are spent only on work.
#     The `fast` subcommand reports the reserved live-mock slots instead, so nothing goes unreported.
#
# Forward compatible on purpose: the first four TSV columns are named (id/status/tier/run) and any
# further columns a future manifest grows are carried through as col5, col6, ... rather than
# crashing the parser, so adding a manifest field never requires touching this script first.
cmd_matrix() {
  local feed json
  feed="$(./scripts/qa-segments.sh --list)" || die "qa-segments.sh --list failed"
  [ -n "$feed" ] || die "qa-segments.sh --list returned an EMPTY feed - refusing to build a matrix"

  json="$(printf '%s\n' "$feed" | python3 -c '
import json, sys
NAMED = ["id", "status", "tier", "run"]
legs = []
for line in sys.stdin.read().splitlines():
    if not line.strip():
        continue
    cols = line.split("\t")
    seg = {}
    for i, col in enumerate(cols):
        seg[NAMED[i] if i < len(NAMED) else "col%d" % (i + 1)] = col
    if seg.get("status") == "active" and seg.get("tier") == "live-mock":
        legs.append({"id": seg["id"], "tier": seg["tier"]})
print(json.dumps({"segment": legs}, separators=(",", ":")))
')" || die "failed to convert the manifest feed to JSON"

  # A zero-leg matrix is the silent-dormancy failure mode all over again: GitHub would happily skip
  # the whole live-mock tier and report the umbrella green. Fail the run instead.
  if printf '%s' "$json" | grep -q '"segment":\[\]'; then
    die "no active live-mock segments in qa/segments.toml - the live-mock tier would silently not run"
  fi

  printf '%s\n' "$json"
  gh_output matrix "$json"
}

# ── fast: the fast tier, plus the reserved live-mock report ──────────────────────────────────────
cmd_fast() {
  log "segmentation self-test (the umbrella proves its own shape before it runs anything)"
  ./scripts/qa-segments.sh --selftest

  log "fast-tier segments (+ longest-first timing summary)"
  ./scripts/qa-segments.sh --run --tier fast

  # Reserved live-mock slots get no runner of their own (see cmd_matrix); report them here so every
  # manifest entry is still accounted for on every run.
  log "reserved live-mock slots (defined-but-inert; PASS/SKIP)"
  local id status tier
  while IFS=$'\t' read -r id status tier _; do
    [ -n "$id" ] || continue
    [ "$status" = "reserved" ] && [ "$tier" = "live-mock" ] || continue
    ./scripts/qa-segments.sh --segment "$id"
  done <<<"$(./scripts/qa-segments.sh --list)"
}

# ── build: compile ONCE for the whole fan-out ────────────────────────────────────────────────────
#
# THE FAN-OUT'S CENTRAL PROBLEM. Per-job fixed cost is paid N TIMES. This workspace builds with
# `lto = "fat"` + `codegen-units = 1` (Cargo.toml [profile.release]) - a deliberately brutal,
# largely un-parallelisable, un-sccache-able link. Ten legs each paying it would make wall clock
# WORSE than the sequential gate while looking like progress. So it is paid exactly once, here.
#
# IT MUST REPLAY THE CONSUMERS' EXACT COMMAND LINES, one per line below. This is the second trap in
# this file and it was also measured, not assumed. Cargo unifies features across the SELECTED
# package set, so `-p a -p b -p c -p d` and `-p a -p b` resolve different feature sets for shared
# dependencies, get different metadata hashes, and share nothing. A first attempt here built all
# four packages in ONE invocation; the downstream freshness check (which replayed only the two
# release-check.sh actually runs) then recompiled 124 units off a perfectly good artifact. Prebuild
# the exact invocations, and every one of them is a no-op downstream.
#
# The consumers, and why each is here:
#   -p busbar -p busbar-plugin-pack                 release-check.sh's Phase 0, verbatim. It
#                                                   hard-asserts both binaries exist.
#   -p busbar-hook-test-plugin                      in-tree dev-fixture cdylibs plugin-loader's
#   -p busbar-secret-example-plugin                 tests dlopen. Neither is a Cargo dependency of
#                                                   busbar-plugin-loader (they are only ever loaded
#                                                   at runtime via dlopen from inside a test), so no
#                                                   scoped loader test builds them on its own; both
#                                                   crates hard-panic under CI if they are missing.
#   test -p busbar-plugin-loader --no-run           the loader job's test binaries, linked here so
#                                                   that job only has to RUN them.
# If a leg ever grows a new cargo invocation against this workspace, add it here too, or that leg
# quietly pays a full build and the hydrate assertion will say so.
#
# What it does NOT build is the plugin SIBLING workspaces: each sibling is a separate workspace with
# its own target dir, its work is genuinely per-leg, and that is exactly the work we WANT fanned out.
cmd_build() {
  local out="${1:-$TARBALL_DEFAULT}"

  log "build once (1/3): busbar + busbar-plugin-pack (release-check.sh Phase 0's exact line)"
  cargo build --release -p busbar -p busbar-plugin-pack

  log "build once (2/3): the in-tree dlopen fixture cdylibs (the loader job's exact line)"
  cargo build --release -p busbar-hook-test-plugin -p busbar-secret-example-plugin

  log "build once (3/3): link the plugin-loader test binaries"
  DEV_GATE=1 cargo test --release -p busbar-plugin-loader --no-run

  [ -x target/release/busbar ] || die "target/release/busbar missing after build"
  [ -x target/release/busbar-plugin-pack ] || die "target/release/busbar-plugin-pack missing after build"

  # Prune what no leg can use. `.fingerprint`, `deps` and `build` all STAY: they are precisely what
  # makes a downstream `cargo build --release` a freshness check instead of a rebuild.
  log "prune"
  rm -rf target/debug target/package target/doc target/release/incremental
  du -sh target 2>/dev/null || true

  # zstd, not gzip: the payload is mostly rlibs and this runs on the critical path twice (once up,
  # once down per leg), so decompression speed matters more than the last few percent of ratio.
  # No GNU-only flags here (no --sort): this must also run under BSD tar for a local repro.
  log "pack -> ${out}"
  tar --zstd -cf "$out" target
  ls -lh "$out"
  gh_output tarball "$out"
}

# ── hydrate: restore that build into a fresh checkout WITHOUT tripping cargo's rebuild heuristic ──
#
# THE MTIME TRAP, and why a naive artifact restore silently does nothing. Cargo decides a unit is
# fresh by comparing the mtime of its `.fingerprint` reference file against the mtimes of the source
# files in its dep-info. `actions/checkout` writes every source file at CHECKOUT time, which is
# strictly LATER than the artifacts built in the earlier `build` job. Restore the tarball naively
# and the workspace members all look dirty: cargo rebuilds the fat-LTO crates in all N legs, the
# artifact becomes pure overhead, and NOTHING WARNS YOU - the run is still green, just slow.
#
# The obvious fix is to `touch` the restored target/ so the artifacts are newer than the sources.
# THAT DOES NOT WORK, and it was measured rather than assumed. On this workspace, against
# `cargo build --release -p busbar-plugin-abi` with every source file freshly re-stamped:
#     naive restore, no normalisation  ->  2 units recompiled
#     touch the restored target/       -> 18 units recompiled   (strictly WORSE)
#     age the SOURCES instead          ->  0 units recompiled   (and stable on a second run)
# Uniformly re-stamping target/ destroys the relative ordering BETWEEN artifacts, which cargo also
# reads: a dependency whose output now looks newer than its dependent's output forces the dependent
# to rebuild, so the "fix" cascades a rebuild through the graph.
#
# So this ages the SOURCES instead, leaving target/'s internal ordering exactly as the build job
# produced it. Every tracked file outside target/ is stamped to a fixed instant in the past, which
# makes it unconditionally older than every artifact, whatever order the checkout wrote it in.
# It is deliberately followed by a real freshness ASSERTION, because a regression here is invisible
# by construction. If cargo compiles anything, we say so, loudly.
#
# WHY AN ARTIFACT AND NOT JUST Swatinem/rust-cache. Both were on the table and rust-cache is kept in
# the build job (it makes the ONE build faster across runs). It cannot do this job, though:
# rust-cache deliberately drops workspace-member artifacts from what it saves, on the reasoning that
# local crates get rebuilt anyway. That is the exact opposite of what the fan-out needs - the
# workspace members ARE the expensive part here, since `busbar` is where fat LTO is paid. A cache
# restore would leave every leg re-linking. The artifact carries the whole target dir, members
# included, which is the only variant that actually removes the N-times cost.
#
# The price is the upload/download on the critical path, and it is smaller than it sounds: measured
# on this workspace, the pruned target/ is 765 MB and packs to a 246 MB zstd tarball. That is tens
# of seconds each way (and the download happens in parallel across legs), bought against a full
# fat-LTO relink per leg. If that ratio ever inverts, the prune list above is the lever.
#
# MEASURED, end to end, on an already-warm dependency cache: build-once 157s, and a hydrate into a
# tree whose every source file had just been re-stamped to `now` took 1s and the freshness
# assertion below reported no rebuild. The loader job's two invocations were likewise no-ops.
cmd_hydrate() {
  local in="${1:-$TARBALL_DEFAULT}"
  [ -f "$in" ] || die "no build tarball at ${in} - the build job's artifact did not arrive"

  log "hydrate target/ from ${in}"
  tar --zstd -xf "$in"
  [ -x target/release/busbar ] || die "hydrated tree has no target/release/busbar"

  # Age every source file so it is unconditionally older than every restored artifact. target/ and
  # .git/ are pruned: target/'s mtimes are precisely what must NOT be disturbed (see above), and
  # git's own object store has no business being re-stamped.
  log "age sources below the artifact timestamps (cargo freshness is mtime-based)"
  find . -path ./target -prune -o -path ./.git -prune -o -type f -print0 | xargs -0 touch -t 202001010000

  # ASSERT the hydration actually worked. A warning, not a hard failure: a cache miss should cost
  # wall clock, never turn a real gate red. But it must be impossible to miss.
  #
  # This replays release-check.sh's Phase 0 line VERBATIM, which is the point: it is the invocation
  # every live-mock leg is about to make, and (see cmd_build) an invocation that differs even in its
  # package SELECTION resolves different features and shares nothing. Asserting on the real line is
  # the only assertion worth making.
  log "freshness assertion: this build MUST be a no-op"
  local out
  out="$(cargo build --release -p busbar -p busbar-plugin-pack 2>&1)" || die "post-hydrate build failed"
  printf '%s\n' "$out" | tail -20
  if printf '%s\n' "$out" | grep -q '^ *Compiling'; then
    local n
    n="$(printf '%s\n' "$out" | grep -c '^ *Compiling')"
    echo "::warning title=qa-gate hydration miss::the restored target/ was NOT accepted as fresh - cargo recompiled ${n} unit(s). Every live-mock leg is now paying the fat-LTO build the build-once stage exists to avoid; wall clock will regress."
  else
    note "PASS  cargo accepted the hydrated target/ as fresh - no rebuild in this leg"
  fi
}

# ── siblings: registry-driven checkouts ──────────────────────────────────────────────────────────
#
# plugins.yaml (via plugin-registry-check.sh --list) is the single source of truth for which
# first-party plugin repos exist; this clones every one of them next to busbarAI/, exactly where
# release-check.sh expects its ../<dir> siblings. Adding a plugin is one plugins.yaml entry; no
# hand-written per-repo checkout steps to drift (the 1.5.0 ship found the hand-written list covering
# 6 of 8).
#
# Per-entry knobs live in the registry:
#   checkout_dir  clone destination when it differs from the repo name. No entry needs it today (the
#                 last user, the Valkey store, was renamed repo-and-directory in 1.5.3); the knob
#                 stays for the next repo rename.
#   checkout_ref  non-default branch to clone (headroom-hook pins `dev` - it carries the
#                 sibling-relative-path dependency fix this build actually needs; mirrors busbar's
#                 own main/dev split).
# A failed clone warns and continues; release-check.sh itself decides what is fatal
# (release_gate: required -> hard fail there).
#
# EVERY leg clones EVERY sibling, on purpose. Cloning is shallow and cheap (seconds); BUILDING a
# sibling is the expensive part and release-check.sh only builds what its segment touches. Cloning
# the full set keeps this script agnostic to how qa/segments.toml partitions its segments, which is
# the whole design goal - the partition must be reshapeable without reworking the plumbing.
cmd_siblings() {
  log "sibling checkouts (registry-driven from plugins.yaml)"
  [ -n "${GH_TOKEN:-}${GITHUB_TOKEN:-}" ] || note "no GH_TOKEN set - public clones may still work, private ones will not"

  local registry repo dir ref
  registry="$(./scripts/plugin-registry-check.sh --list)"
  [ -n "$registry" ] || die "empty registry feed"

  # feed fields: repo dir alias kind service release_gate gate checkout_ref
  while IFS=$'\t' read -r repo dir _ _ _ _ _ ref; do
    [ -n "$repo" ] || continue
    # An explicit `if`, not `[ ... ] && args+=(...)`: under `set -e` that form is only safe because
    # it is not the last statement in the body, which is a fragile thing to rely on.
    local args=(--depth 1)
    if [ "$ref" != "-" ]; then args+=(--branch "$ref"); fi
    echo "::group::clone GetBusbar/${repo} -> ${dir} (ref: ${ref})"
    if [ -d "../${dir}" ]; then
      note "already present: ../${dir}"
    elif ! (cd .. && gh repo clone "GetBusbar/${repo}" "${dir}" -- "${args[@]}"); then
      echo "::warning::clone of GetBusbar/${repo} failed - release-check.sh will skip or fail its phase"
    fi
    echo "::endgroup::"
  done <<<"$registry"

  # busbar-admin (busbarctl) is NOT a plugin, so it is not in plugins.yaml - but release-check.sh
  # runs its integration.sh against the freshly-built busbar (the reverse of the plugin phases,
  # bidirectional testing). Explicit sibling, same warn-and-continue posture.
  echo "::group::clone GetBusbar/busbar-admin -> busbar-admin"
  if [ -d ../busbar-admin ]; then
    note "already present: ../busbar-admin"
  elif ! (cd .. && gh repo clone GetBusbar/busbar-admin busbar-admin -- --depth 1); then
    echo "::warning::clone of GetBusbar/busbar-admin failed - the busbarctl reverse-direction phase will skip"
  fi
  echo "::endgroup::"

  ls -la ..
}

# ── segment: run exactly one leg ─────────────────────────────────────────────────────────────────
cmd_segment() {
  local id="${1:-}"
  [ -n "$id" ] || die "usage: $0 segment <id>"
  log "segment ${id}"
  ./scripts/qa-segments.sh --segment "$id"
}

# ── loader: coverage that lives in NEITHER release-check.sh NOR the segment manifest ─────────────
#
# These two steps were inline in qa-gate.yml's old single job and are NOT part of release-check.sh,
# so collapsing that job into the segment fan-out would have silently dropped them. Coverage is the
# constraint here, wall clock only the objective, so they get their own job. It is cheap: it
# hydrates the same build-once artifact, so the only real work is the sibling sqlite cdylib and the
# scoped loader test.
cmd_loader() {
  log "build the sibling store-sqlite-plugin cdylib (the loader tests dlopen the REAL one)"
  if [ -d ../store-sqlite ]; then
    (cd ../store-sqlite && cargo build --release -p busbar-store-sqlite-plugin) || \
      echo "::warning::store-sqlite sibling cdylib build failed"
  else
    echo "::warning::no ../store-sqlite sibling checkout - loader tests will fall back"
  fi

  # Hydration should already have supplied these, but build them explicitly anyway: both crates
  # hard-panic via their own path-discovery helpers under CI if they are ever missing, so a future
  # regression fails loud rather than silently losing this coverage again.
  log "build the in-tree hook-test-plugin and secret-example-plugin cdylibs"
  cargo build --release -p busbar-hook-test-plugin -p busbar-secret-example-plugin

  log "loader-mechanism tests against the real sibling-built store-sqlite-plugin"
  DEV_GATE=1 cargo test --release -p busbar-plugin-loader
}

case "${1:-}" in
  matrix)   cmd_matrix ;;
  fast)     cmd_fast ;;
  build)    shift; cmd_build "$@" ;;
  hydrate)  shift; cmd_hydrate "$@" ;;
  siblings) cmd_siblings ;;
  segment)  shift; cmd_segment "$@" ;;
  loader)   cmd_loader ;;
  -h | --help) sed -n '4,45p' "$0" ;;
  *) echo "usage: $0 {matrix|fast|build [OUT]|hydrate [IN]|siblings|segment ID|loader}" >&2; exit 2 ;;
esac
