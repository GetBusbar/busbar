#!/usr/bin/env bash
#
# release-check.sh — the 1.5.0 "plugin release" REAL end-to-end gate.
#
# WHAT THIS TESTS
#   Everything the unit/integration test suite cannot: that the ACTUAL signed-shape plugin
#   tarballs a user downloads (built + packed this script's own Phase 0b, in the same shape each
#   plugin's own standalone-repo release workflow packs it — busbarAI's release.yml no longer
#   builds or uploads store/auth plugin tarballs itself; see the "Store/auth plugin releases moved
#   out" comment in .github/workflows/release.yml) load into a REAL busbar binary, that busbar
#   serves REAL HTTP traffic through each backend exactly the way docs/getting-started.md and
#   docs/configuration.md tell an operator to configure it, and that keys/usage genuinely
#   SURVIVE A PROCESS RESTART, driven against store-postgres's own real-Postgres test suite (the
#   registry-driven suite loop, Phase 2 — a required sibling checkout). It builds real artifacts,
#   mints a real virtual key over the real admin API, drives a real chat-completion request
#   through a real (if minimal) mock upstream, and asserts real response bodies and real usage
#   counters — not just exit codes. (SQLite's, Valkey's, and OIDC's own real-ABI +
#   real-persistence proofs now live in their own repos too — see Phase 1 and the registry-driven
#   suite loop in Phase 2 below.)
#
#   WHICH plugins get WHICH phase is not decided here: plugins.yaml (repo root) is the single
#   source of truth. Every `gate: suite` entry is covered by Phase 2's ONE uniform loop (service
#   container from the entry's `service` field + BUSBAR_TEST_* env + `cargo test --workspace
#   --release` in the sibling checkout); the genuinely-special phases — sqlite's full-binary
#   Phase 1 (`gate: binary`) and the hook --validate smokes in Phase 5 (`gate: smoke`) — stay
#   explicit, and scripts/plugin-registry-check.sh enforces that no registry entry lacks coverage.
#
# WHAT THIS DOES NOT TEST
#   - Store-sqlite's hermetic in-process dlopen path — that's a separate, parallel test, and now
#     lives entirely in store-sqlite's own repo (GetBusbar/store-sqlite, a same-repo 2-crate
#     workspace) — see Phase 1 below for how this script reaches it via a sibling checkout.
#   - The release-SIGNING pipeline (BUSBAR_SIGN_KEY) — out of scope by design. Every tarball
#     here is packed with `--allow-unsigned`, exactly like CI's fallback path when the signing
#     secret isn't provisioned (see the TODO(release-keys) seam in release.yml).
#   - OIDC's real-ABI plugin proof — auth-oidc now lives entirely in its own repo (GetBusbar/auth-oidc,
#     a same-repo 2-crate workspace bringing 100% of its own logic + adapter). That repo's own test
#     suite already stands up a real local JWKS server + a real minted JWT and drives the plugin
#     through the real ABI. This script sibling-checks-out that repo and runs its suite as a gate
#     (the Phase 2 suite loop below) rather than reinventing a second, lower-quality fake-IdP proof.
#   - hashicorp-vault's real-ABI plugin proof — busbar-hashicorp-vault / busbar-hashicorp-vault-plugin
#     no longer live in this workspace (extracted to GetBusbar/hashicorp-vault). The Phase 2 suite
#     loop below runs THAT repo's own test suite (a sibling checkout) against a real Vault dev-mode container,
#     rather than duplicating the proof in-tree.
#   - Valkey's real-ABI + real-persistence proof — store-valkey now lives entirely in its own repo
#     (GetBusbar/store-valkey, a same-repo 2-crate workspace bringing 100% of its own logic +
#     adapter). That repo's own tests/e2e.rs already dlopens the real cdylib against a real
#     valkey/valkey:8, writes through it, closes + reopens the plugin, and independently verifies via the
#     plain busbar-store-valkey lib crate — genuine, hermetic, real-Valkey coverage. This script
#     sibling-checks-out that repo and runs its suite as a gate (the Phase 2 suite loop below) rather than
#     reinventing a second, lower-quality proof in-tree.
#   - Postgres's full-busbar-binary + real-HTTP-traffic + process-restart-durability proof —
#     store-postgres was likewise extracted to its own repo (GetBusbar/store-postgres); Phase 2
#     below runs THAT repo's own real-dlopen-ABI + real-Postgres test suite (against the same real
#     postgres:16 container this script always spun up) as the gate instead, the same trade-off
#     already made for OIDC and Valkey above.
#
# WHEN TO RUN
#   Pre-release, NOT on every commit. This is release infrastructure, not part of the normal
#   `cargo test --workspace` gate. Budget up to ~2 hours (dominated by `cargo build --release`
#   for the busbar binary + every plugin cdylib, run multiple times).
#
# BRANCH MODEL (dev → qa → main)
#   - `dev`: push often; only the cheap per-push CI (ci.yml) runs there. Nothing here.
#   - `qa`: promoting dev→qa is what spends THIS gate — qa-gate.yml runs release-check.sh on every
#     qa push (the pre-release soak). A green qa is what earns promotion to main.
#   - `main`: tag-on-main.yml auto-tags crates/busbar/Cargo.toml's version when it lands on main,
#     which cuts the release (release.yml binaries/downstream cascade + docker.yml). Prep the bump
#     on dev with prepare-release.yml before promoting.
#
# PREREQUISITES
#   - A working Rust toolchain (`cargo build --release` must succeed for this workspace).
#   - Docker running locally (`docker ps` must succeed) — needed for every `service`-backed suite
#     phase (postgres/mysql/valkey/vault per plugins.yaml). If Docker is unavailable the gate fails
#     loudly up front, because "gate incomplete" must never look like "gate green".
#   - python3 (stdlib only) — used for a tiny local mock upstream server. No network access
#     beyond localhost and the Docker daemon is required.
#   - A sibling checkout `../store-postgres` (GetBusbar/store-postgres) next to this repo — REQUIRED
#     (not optional): Phase 2 runs that repo's own `cargo test --workspace` as the Postgres gate.
#   - Optionally, sibling checkouts for every other plugins.yaml entry (`../store-sqlite`,
#     `../store-mysql`, `../store-valkey`, `../hashicorp-vault`, `../auth-oidc`, `../headroom-hook`,
#     `../webrequest-hook`) next to this repo. Each of these plugins has been fully extracted — its
#     own repo now owns 100% of its logic + release-gate proof (see that repo's own CI). If a
#     sibling is present, its phase below runs the real proof against it; if absent, that phase is
#     skipped loudly and does not fail the gate (documented — matches the task's explicit
#     instruction not to fail the whole run over a missing sibling).
#
# USAGE
#   scripts/release-check.sh                # run every phase
#   scripts/release-check.sh --skip-docker   # skip service-backed suite phases (fast local
#                                             # iteration only; NEVER a green release gate)
#   scripts/release-check.sh --list-phases   # machine-readable phase ids (one per line), exit 0
#   scripts/release-check.sh --list-segments # machine-readable "<partition> <segment>" pairs
#   scripts/release-check.sh --check-coverage # assert every partition's segments EXACTLY tile the
#                                             # phase set (no hole, no overlap); exit 1 on either
#   scripts/release-check.sh --segment <id>  # run ONLY that segment's phases (see SEGMENTATION)
#
# SEGMENTATION (1.5.3 unit G, made real)
#   The gate is a set of independently-runnable PHASES. `--list-phases` emits their ids; the ids
#   mirror the script's own numbering (phase-0a2-…, phase-0c-…, phase-1-…, phase-2-suite-<repo>,
#   phase-5-smoke-<name>, …). The `phase-2-suite-*` ids are DERIVED FROM plugins.yaml, so adding a
#   `gate: suite` plugin adds its phase id with zero edits here.
#
#   A SEGMENT is a named set of phases; a PARTITION is a named set of segments that must tile the
#   phase set EXACTLY. Two partitions are defined below:
#     live    core-data-plane + plugins — the aggregate form, where one `plugins` leg carries every
#             plugin phase.
#     fanout  core-data-plane + plugin-<repo> for EVERY plugins.yaml entry — the per-plugin fan-out.
#             This is exactly what scripts/qa-segments.sh emits once its capability probe sees the
#             `plugin-*` token from --list-segments: it suppresses the aggregate `plugins` stand-in
#             and expands one leg per registry entry. Every entry gets a leg regardless of its
#             `gate` (suite/binary/smoke), so no registry entry can produce a matrix leg whose run
#             command exits 2.
#   `--check-coverage` validates BOTH. A phase in zero segments of a partition is a silent coverage
#   hole (segmentation quietly testing less); a phase in two is wasted wall clock. Both are hard
#   errors that name the phase and the partition.
#
#   Phase 0 (build busbar + busbar-plugin-pack) is deliberately NOT a partitionable phase: it is
#   FIXED SETUP that any segment containing a binary-driving phase must pay. It is therefore excluded
#   from the phase set, and SKIPPED ENTIRELY when the selected segment needs no busbar binary (every
#   `phase-2-suite-*` phase only runs `cargo test` in a sibling checkout). That skip is the whole
#   reason a per-plugin fan-out can be faster rather than N-times slower.
#
# FAILURE POLICY
#   Fail-fast: `set -euo pipefail` plus an ERR trap that names the failing command. Every
#   docker container and every temp file/dir this script creates is torn down on exit — success,
#   failure, or signal — via a single EXIT trap. Safe to re-run; never leaves stray containers.

# -E so the ERR trap below is INHERITED by shell functions. Without it the trap only fires at top
# level, and every failure inside run_saturation_soak / run_store_backend_e2e / run_validate_smoke
# (i.e. most of the gate) exits silently with no "RELEASE GATE FAILED during phase: X" banner and no
# timing summary — observed on a real failing run. The FAILURE POLICY note above already promises
# "an ERR trap that names the failing command"; -E is what makes that true.
set -eEuo pipefail
cd "$(dirname "$0")/.."
REPO_ROOT="$PWD"

SKIP_DOCKER=0
# SEGMENT (1.5.3, unit G qa-gate segmentation): names WHICH qa-gate segment this invocation runs.
# It now GENUINELY PARTITIONS THE PHASES — `--segment core-data-plane` runs only the core-data-plane
# phases, `--segment plugin-store-postgres` runs only that plugin's suite phase. An unknown segment
# is a loud error, never a silent full run.
SEGMENT=""
LIST_PHASES=0
LIST_SEGMENTS=0
CHECK_COVERAGE=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --skip-docker) SKIP_DOCKER=1 ;;
    --list-phases) LIST_PHASES=1 ;;
    --list-segments) LIST_SEGMENTS=1 ;;
    --check-coverage) CHECK_COVERAGE=1 ;;
    --segment) shift; SEGMENT="${1:-}" ;;
    --segment=*) SEGMENT="${1#--segment=}" ;;
    *) echo "unknown argument: $1" >&2; exit 2 ;;
  esac
  shift
done

# ══ PHASE REGISTRY ════════════════════════════════════════════════════════════════════════════════
# The single in-script source of truth for "what phases exist". Parallel arrays, not associative
# ones: this script targets bash 3.2 (the macOS system bash), same constraint as the BG_PIDS indexing
# below. Each phase carries whether it NEEDS the Phase 0 busbar/pack binaries — that flag is what
# lets a suite-only segment skip the single most expensive fixed cost in the whole gate.
PHASE_IDS=()
PHASE_NEEDS_BIN=()
PHASE_DESC=()
add_phase() { PHASE_IDS+=("$1"); PHASE_NEEDS_BIN+=("$2"); PHASE_DESC+=("$3"); }

# The `gate: suite` phases are derived from plugins.yaml (the registry is the single source of truth
# for "what plugins exist"), so a new suite plugin gets a phase id here with zero edits to this file.
# Read up front, not lazily: a parse/shape failure must fail loudly rather than yield an empty gate.
REGISTRY_LIST="$(./scripts/plugin-registry-check.sh --list)"
[ -n "$REGISTRY_LIST" ] || { echo "plugin-registry-check.sh --list returned an empty registry" >&2; exit 1; }

# EVERY registry entry maps to exactly one phase id, keyed off its `gate` column. This is what lets
# `--segment plugin-<repo>` work for ALL TEN registry plugins rather than only the seven `gate: suite`
# ones: scripts/qa-segments.sh expands its per-plugin fan-out straight from plugins.yaml, so a
# registry entry with no accepted segment here would emit a matrix leg whose run command exits 2.
#   suite  -> phase-2-suite-<repo>    (sibling repo's own cargo test; needs no busbar binary)
#   binary -> phase-1-<alias>-binary  (store-sqlite's full-binary/HTTP/restart-durability phase)
#   smoke  -> phase-5-smoke-<alias>   (the hook plugins' --validate dlopen smokes)
plugin_phase_id() {
  local want="$1" r a g
  while IFS=$'\t' read -r r _ a _ _ _ g _; do
    if [ "$r" = "$want" ]; then
      case "$g" in
        suite)  echo "phase-2-suite-${r}" ;;
        binary) echo "phase-1-${a}-binary" ;;
        smoke)  echo "phase-5-smoke-${a}" ;;
        *) echo "plugins.yaml entry '${r}' has unknown gate '${g}'" >&2; return 1 ;;
      esac
      return 0
    fi
  done <<<"$REGISTRY_LIST"
  return 1
}
all_plugin_repos() {
  local r
  while IFS=$'\t' read -r r _ _ _ _ _ _ _; do
    if [ -n "$r" ]; then echo "$r"; fi
  done <<<"$REGISTRY_LIST"
  return 0
}
list_plugin_phase_ids() {
  local r
  while read -r r; do
    if [ -n "$r" ]; then plugin_phase_id "$r"; fi
  done <<<"$(all_plugin_repos)"
  return 0
}
# phase-2-suite-<repo> -> the registry service that phase needs a container for ("none" if any).
suite_phase_service() {
  local want="${1#phase-2-suite-}" r s g
  while IFS=$'\t' read -r r _ _ _ s _ g _; do
    if [ "$g" = "suite" ] && [ "$r" = "$want" ]; then echo "$s"; return 0; fi
  done <<<"$REGISTRY_LIST"
  echo "none"
  return 0
}

add_phase phase-0a2-signing-key  yes "Phase 0a2: signing-key requirement (fail-closed then green)"
add_phase phase-0c-soak-reject   yes "Phase 0c: saturation soak — on_exhausted: reject"
add_phase phase-0c-soak-queue    yes "Phase 0c: saturation soak — on_exhausted: queue{max_ms}"
# One phase per registry entry, in registry order. `gate: suite` phases need no busbar binary (they
# only run cargo test in a sibling checkout); binary/smoke phases drive the real binary and do.
while read -r _pr; do
  [ -n "$_pr" ] || continue
  _pid="$(plugin_phase_id "$_pr")"
  case "$_pid" in
    phase-2-suite-*) add_phase "$_pid" no  "Phase 2: sibling-suite gate for ${_pr}" ;;
    *)               add_phase "$_pid" yes "plugin phase for ${_pr}" ;;
  esac
done <<<"$(all_plugin_repos)"
add_phase phase-admin-cli          yes "Phase: busbar-admin CLI driven against the fresh busbar"
add_phase phase-152-feature-gate   yes "Phase: 1.5.2 feature gate (plugins.fetch + token-exchange + admin authz)"

all_phase_ids() { printf '%s\n' ${PHASE_IDS[@]+"${PHASE_IDS[@]}"}; }

phase_needs_binary() {
  local i=0
  while [ "$i" -lt "${#PHASE_IDS[@]}" ]; do
    if [ "${PHASE_IDS[$i]}" = "$1" ]; then
      if [ "${PHASE_NEEDS_BIN[$i]}" = "yes" ]; then return 0; else return 1; fi
    fi
    i=$((i + 1))
  done
  return 1
}

# ══ SEGMENT / PARTITION TABLE ═════════════════════════════════════════════════════════════════════
# EXPLICIT assignment on purpose: a derived complement ("everything the other segment does not take")
# can never have a hole, which would make --check-coverage unfalsifiable theatre. These lists are
# hand-maintained, so forgetting to place a newly-added phase IS possible — and is exactly what
# --check-coverage catches.
PARTITIONS="live fanout"

partition_segments() {
  case "$1" in
    live) echo "core-data-plane"; echo "plugins" ;;
    fanout)
      # EXACTLY what scripts/qa-segments.sh emits when its per-plugin fan-out goes live: the
      # aggregate `plugins` stand-in is suppressed and replaced by one plugin-<repo> leg per
      # plugins.yaml entry, alongside the unchanged core-data-plane leg.
      echo "core-data-plane"
      local pr
      while read -r pr; do
        if [ -n "$pr" ]; then echo "plugin-${pr}"; fi
      done <<<"$(all_plugin_repos)"
      ;;
    *) return 1 ;;
  esac
  return 0
}

# Prints the phase ids belonging to a segment, one per line. Empty output = unknown segment.
segment_phases() {
  local seg="$1" want
  case "$seg" in
    # ── partition: live (mirrors qa/segments.toml's two active live-mock segments) ──
    core-data-plane)
      echo phase-0a2-signing-key
      echo phase-0c-soak-reject
      echo phase-0c-soak-queue
      echo phase-admin-cli
      echo phase-152-feature-gate
      ;;
    # The aggregate plugin stand-in: every plugin phase in one leg. qa-segments.sh SUPPRESSES this
    # segment once the per-plugin fan-out is live, so exactly one of {plugins, plugin-*} ever runs.
    plugins)
      list_plugin_phase_ids
      ;;
    # ── partition: fanout (core-data-plane + one segment per plugins.yaml entry) ──
    # Not a hand-written list: whatever plugin_phase_id() maps the entry to, that one phase is the
    # leg. So a registry entry can never lack a runnable segment, whatever its `gate`.
    plugin-*)
      want="${seg#plugin-}"
      plugin_phase_id "$want" 2>/dev/null || true
      ;;
  esac
  return 0
}

# ── --list-phases ─────────────────────────────────────────────────────────────────────────────────
if [ "$LIST_PHASES" = "1" ]; then
  all_phase_ids
  exit 0
fi

# ── --list-segments ───────────────────────────────────────────────────────────────────────────────
# CONTRACT (consumed by scripts/qa-segments.sh's capability probe): print, one per line, the segment
# tokens this script accepts, and exit 0. The literal token `plugin-*` is emitted to ADVERTISE that
# per-plugin segments are supported — qa-segments.sh probes for exactly that line
# (`--list-segments | grep -qx 'plugin-\*'`) and, until it appears, falls back to the aggregate
# `plugins` segment. It is a capability marker, NOT a runnable segment id; the concrete
# `plugin-<repo>` ids printed alongside it are the runnable ones.
# Bare tokens only (no partition prefix): the probe is an exact whole-line match.
if [ "$LIST_SEGMENTS" = "1" ]; then
  # Deduped: core-data-plane belongs to BOTH partitions, but this is a set of accepted tokens.
  {
    for _part in $PARTITIONS; do
      while read -r _seg; do
        if [ -n "$_seg" ]; then echo "$_seg"; fi
      done <<<"$(partition_segments "$_part")"
    done
    echo 'plugin-*'
  } | awk '!seen[$0]++'
  exit 0
fi

# ── --check-coverage ──────────────────────────────────────────────────────────────────────────────
# For EVERY partition: the union of its segments' phase sets must equal the full phase set exactly.
#   phase in ZERO segments -> COVERAGE HOLE. This is the failure that matters: segmentation quietly
#                             testing less than the unsegmented gate, while still reporting green.
#   phase in TWO segments   -> DUPLICATE. Not a correctness hole, but wasted wall clock, which is the
#                             entire point of segmenting, so it is also a hard error.
# Also fails if a segment claims a phase id that does not exist (a typo'd/renamed assignment).
if [ "$CHECK_COVERAGE" = "1" ]; then
  cov_rc=0
  for _part in $PARTITIONS; do
    echo "=== coverage check: partition '${_part}' ==="
    _assigned=""
    while read -r _seg; do
      [ -n "$_seg" ] || continue
      _sp="$(segment_phases "$_seg")"
      if [ -z "$_sp" ]; then
        echo "  ERROR [${_part}]: segment '${_seg}' resolves to NO phases (unknown or empty segment)" >&2
        cov_rc=1
        continue
      fi
      echo "  segment '${_seg}': $(echo "$_sp" | grep -c . || true) phase(s)"
      while read -r _p; do
        [ -n "$_p" ] || continue
        if ! all_phase_ids | grep -qx -- "$_p"; then
          echo "  ERROR [${_part}]: segment '${_seg}' claims UNKNOWN phase '${_p}'" >&2
          cov_rc=1
        fi
        _assigned="${_assigned}${_p}"$'\n'
      done <<<"$_sp"
    done <<<"$(partition_segments "$_part")"

    while read -r _p; do
      [ -n "$_p" ] || continue
      _n="$(printf '%s' "$_assigned" | grep -cx -- "$_p" || true)"
      if [ "$_n" -eq 0 ]; then
        echo "  ERROR [${_part}]: COVERAGE HOLE — phase '${_p}' is in ZERO segments." >&2
        echo "         Segmenting on this partition would SILENTLY TEST LESS than the full gate." >&2
        cov_rc=1
      elif [ "$_n" -gt 1 ]; then
        echo "  ERROR [${_part}]: DUPLICATE — phase '${_p}' is in ${_n} segments." >&2
        echo "         It would run ${_n} times, wasting the wall clock segmenting is meant to save." >&2
        cov_rc=1
      fi
    done <<<"$(all_phase_ids)"

    if [ "$cov_rc" = "0" ]; then
      echo "  [ok] partition '${_part}' tiles all $(all_phase_ids | grep -c . || true) phases exactly once"
    fi
  done
  if [ "$cov_rc" != "0" ]; then
    echo >&2
    echo "!!! SEGMENT COVERAGE CHECK FAILED — do not segment the gate on this assignment !!!" >&2
    exit 1
  fi
  echo "[ok] every partition tiles the full phase set exactly once"
  exit 0
fi

# ── --segment: resolve the selected phase set ─────────────────────────────────────────────────────
# SELECTED_PHASES empty means "every phase" (an unsegmented full-gate run).
SELECTED_PHASES=""
if [ -n "$SEGMENT" ]; then
  SELECTED_PHASES="$(segment_phases "$SEGMENT")"
  if [ -z "$SELECTED_PHASES" ]; then
    echo "unknown --segment '$SEGMENT'. Known segments (partition segment):" >&2
    for _part in $PARTITIONS; do
      while read -r _seg; do
        if [ -n "$_seg" ]; then echo "  ${_part} ${_seg}" >&2; fi
      done <<<"$(partition_segments "$_part")"
    done
    exit 2
  fi
  echo "════════════════════════════════════════════════════════════════════════════"
  echo "=== release-check: qa-gate segment '${SEGMENT}' — running ONLY its phases ==="
  echo "════════════════════════════════════════════════════════════════════════════"
  while read -r _p; do
    if [ -n "$_p" ]; then echo "  ${_p}"; fi
  done <<<"$SELECTED_PHASES"
fi

phase_selected() {
  # Explicit if/return rather than `[ ... ] && return 0`: that idiom yields a nonzero status for the
  # whole function when the test fails, which trips `set -e` at any call site not in a condition.
  if [ -z "$SELECTED_PHASES" ]; then return 0; fi
  if printf '%s\n' "$SELECTED_PHASES" | grep -qx -- "$1"; then return 0; fi
  return 1
}

# Does ANY selected phase need the Phase 0 busbar/pack build? If not, Phase 0 is skipped outright —
# the fixed-cost saving that makes a per-plugin fan-out worth doing.
any_selected_needs_binary() {
  local p
  while read -r p; do
    [ -n "$p" ] || continue
    if phase_needs_binary "$p"; then return 0; fi
  done <<<"$(if [ -z "$SELECTED_PHASES" ]; then all_phase_ids; else printf '%s\n' "$SELECTED_PHASES"; fi)"
  return 1
}

# Does ANY selected phase need a Docker service container? Drives the Docker preflight, so a
# service-less segment (e.g. plugin-auth-oidc) no longer hard-fails on a machine without Docker.
any_selected_needs_service() {
  local p
  while read -r p; do
    case "$p" in
      phase-2-suite-*)
        if [ "$(suite_phase_service "$p")" != "none" ]; then return 0; fi
        ;;
    esac
  done <<<"$(if [ -z "$SELECTED_PHASES" ]; then all_phase_ids; else printf '%s\n' "$SELECTED_PHASES"; fi)"
  return 1
}

# ── Fail-fast diagnostics ────────────────────────────────────────────────────────────────────────
SECONDS=0
PHASE="startup"
on_err() {
  local ec=$?
  echo
  echo "!!! RELEASE GATE FAILED during phase: ${PHASE} (exit ${ec}) !!!"
  echo "    Elapsed: ${SECONDS}s. This means: DO NOT TAG THIS RELEASE."
  # Timings so far are still the most useful thing a failed run can hand back.
  end_phase "FAILED" 2>/dev/null || true
  print_timing_summary 2>/dev/null || true
  exit "$ec"
}
trap on_err ERR

phase() {
  PHASE="$1"
  echo
  echo "════════════════════════════════════════════════════════════════════════════"
  echo "=== ${1} ==="
  echo "════════════════════════════════════════════════════════════════════════════"
}

ok()   { echo "  [ok] $*"; }
note() { echo "  [note] $*"; }

# ── Per-phase wall-clock accounting ───────────────────────────────────────────────────────────────
# The point of segmenting is to shrink max(segment_duration), and you cannot minimise what you do not
# measure. Every phase records its own wall clock; the run ends with a summary sorted longest-first,
# and the FIXED SETUP cost (Phase 0's cargo build — paid once per INVOCATION, so N times under a
# per-plugin fan-out) is reported SEPARATELY from per-phase test time, because those two numbers
# answer different questions: fixed setup decides whether fanning out helps at all, per-phase test
# time decides where the critical path is once you have fanned out.
PHASE_RUN_IDS=()
PHASE_RUN_SECS=()
PHASE_RUN_STATUS=()
CURRENT_PHASE_ID=""
CURRENT_PHASE_T0=0
SETUP_SECS=0

begin_phase() { CURRENT_PHASE_ID="$1"; CURRENT_PHASE_T0=$SECONDS; phase "$2"; }

end_phase() {
  [ -n "$CURRENT_PHASE_ID" ] || return 0
  local d=$((SECONDS - CURRENT_PHASE_T0))
  PHASE_RUN_IDS+=("$CURRENT_PHASE_ID")
  PHASE_RUN_SECS+=("$d")
  PHASE_RUN_STATUS+=("${1:-ran}")
  echo "  [time] ${CURRENT_PHASE_ID}: ${d}s (${1:-ran})"
  CURRENT_PHASE_ID=""
}

record_phase_skip() {
  PHASE_RUN_IDS+=("$1")
  PHASE_RUN_SECS+=(0)
  PHASE_RUN_STATUS+=("${2:-skipped}")
}

print_timing_summary() {
  local i=0 total=0
  echo
  echo "════════════════════════════════════════════════════════════════════════════"
  echo "=== TIMING SUMMARY${SEGMENT:+ (segment: ${SEGMENT})} ==="
  echo "════════════════════════════════════════════════════════════════════════════"
  echo "FIXED SETUP (per invocation, paid once per parallel job):"
  echo "  phase-0-build (cargo build --release -p busbar -p busbar-plugin-pack): ${SETUP_SECS}s"
  echo
  # Total is summed in THIS shell first: the print loop below feeds a pipeline (subshell), so any
  # accumulation done inside it would be discarded.
  while [ "$i" -lt "${#PHASE_RUN_IDS[@]}" ]; do
    total=$((total + PHASE_RUN_SECS[i]))
    i=$((i + 1))
  done
  echo "PER-PHASE TEST TIME (longest first):"
  i=0
  while [ "$i" -lt "${#PHASE_RUN_IDS[@]}" ]; do
    printf '%08d\t%s\t%s\n' "${PHASE_RUN_SECS[$i]}" "${PHASE_RUN_IDS[$i]}" "${PHASE_RUN_STATUS[$i]}"
    i=$((i + 1))
  done | sort -rn | while IFS=$'\t' read -r s p st; do
    printf '  %6ss  %-34s %s\n' "$((10#$s))" "$p" "$st"
  done
  echo
  echo "  phase test time total : ${total}s"
  echo "  fixed setup           : ${SETUP_SECS}s"
  echo "  wall clock (this job) : ${SECONDS}s"
}

# ── Cleanup registry: docker containers, background PIDs, temp dirs. Torn down on ANY exit. ───────
DOCKER_CONTAINERS=()
BG_PIDS=()
TMP_DIRS=()

cleanup() {
  local ec=$?
  echo
  echo "--- cleanup (exit code ${ec}) ---"
  for pid in "${BG_PIDS[@]:-}"; do
    [ -n "$pid" ] && kill "$pid" >/dev/null 2>&1 || true
  done
  for pid in "${BG_PIDS[@]:-}"; do
    [ -n "$pid" ] && wait "$pid" >/dev/null 2>&1 || true
  done
  for c in "${DOCKER_CONTAINERS[@]:-}"; do
    [ -n "$c" ] && docker rm -f "$c" >/dev/null 2>&1 || true
  done
  for d in "${TMP_DIRS[@]:-}"; do
    [ -n "$d" ] && rm -rf "$d" || true
  done
  echo "--- cleanup done ---"
}
trap cleanup EXIT

new_tmpdir() {
  local d
  d="$(mktemp -d "${TMPDIR:-/tmp}/busbar-release-check.XXXXXX")"
  TMP_DIRS+=("$d")
  echo "$d"
}

# ── Wait-for-HTTP helper: real polling, no fixed sleeps. Fails loudly on timeout. ──────────────────
wait_for_http() {
  local url="$1" timeout_s="${2:-30}" waited=0
  until curl -fsS -o /dev/null "$url" 2>/dev/null; do
    waited=$((waited + 1))
    if [ "$waited" -ge "$timeout_s" ]; then
      echo "  timed out waiting for ${url} after ${timeout_s}s" >&2
      return 1
    fi
    sleep 1
  done
}

# ── Millisecond wall clock (the soak phase asserts per-request latency against the failover budget). ─
now_ms() { python3 -c 'import time; print(int(time.time()*1000))'; }

# ── Platform-specific cdylib naming (host-native build; matches release.yml's per-target matrix
#    entries for the OS this script actually runs on). ─────────────────────────────────────────────
case "$(uname -s)" in
  Darwin) LIBEXT="dylib"; LIBPREFIX="lib" ;;
  Linux)  LIBEXT="so";    LIBPREFIX="lib" ;;
  *) echo "unsupported OS for local release-check: $(uname -s)" >&2; exit 1 ;;
esac
VER="$(grep -m1 '^version' crates/busbar/Cargo.toml | sed -E 's/version *= *"([^"]+)"/\1/')"
note "Host: $(uname -s) $(uname -m), busbar version ${VER}, libext=${LIBEXT}"

PLUGIN_DIST="$(new_tmpdir)"
MOCK_TEXT_MARKER_SEQ=0

# ── Tiny local mock upstream (Anthropic-protocol) — a real HTTP server, not a canned function ─────
# call. Responds to any POST with a well-formed Anthropic Messages response whose text body embeds
# a unique marker, so the assertions below can prove the SPECIFIC response that came back through
# busbar (not just "some 200"), and whose usage.{input,output}_tokens are nonzero so the admin API's
# key-usage counters have something real to accumulate + persist across a restart.
#
# Third arg (optional) is a per-response INJECTED LATENCY in seconds (default 0). The saturation-soak
# phase uses it so an in-flight request HOLDS its lane permit long enough to drive the pool past
# `max_concurrent` — a real, wall-clock-observable saturation window, not a mocked flag. Threaded so
# a slow in-flight request never head-of-line-blocks a concurrent one at the mock itself.
start_mock_upstream() {
  local port="$1" marker="$2" delay="${3:-0}"
  local script
  script="$(new_tmpdir)/mock_upstream.py"
  cat >"$script" <<PYEOF
import http.server, json, sys, time

MARKER = ${marker@Q}
DELAY = float("${delay}")

class Handler(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        length = int(self.headers.get("Content-Length", 0))
        self.rfile.read(length)
        if DELAY > 0:
            time.sleep(DELAY)
        body = json.dumps({
            "id": "msg_release_check",
            "type": "message",
            "role": "assistant",
            "model": "test-model",
            "content": [{"type": "text", "text": MARKER}],
            "stop_reason": "end_turn",
            "usage": {"input_tokens": 11, "output_tokens": 7},
        }).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, fmt, *args):
        pass

http.server.ThreadingHTTPServer(("127.0.0.1", ${port}), Handler).serve_forever()
PYEOF
  # stdout/stderr → /dev/null: a backgrounded serve_forever that inherits its caller's stdout pipe
  # wedges any `$(start_mock_upstream ...)` capture on EOF for the whole CI timeout (the 1.5.2 gate's
  # 2h31m hang — see scripts/release-script-lint.sh). Redirect at the launch site so the server can
  # never leak stdout no matter how a future caller reads its pid. `$!`/BG_PIDS still track the pid.
  python3 "$script" >/dev/null 2>&1 &
  local pid=$!
  BG_PIDS+=("$pid")
  wait_for_http "http://127.0.0.1:${port}/" 10 || true # server has no GET route; just give it a beat
  echo "$pid"
}

# ── Build the busbar binary + the packer (FIXED SETUP, shared by every binary-driving phase) ───────
# NOT a partitionable phase: it is the cost of standing the gate up, and every parallel job that runs
# any binary-driving phase pays it in full. Under a per-plugin fan-out that means N x this number, so
# it is measured and reported separately. A segment made only of `phase-2-suite-*` phases (which just
# run `cargo test` inside a sibling checkout) needs neither binary, so it skips this outright.
BUSBAR_BIN="${REPO_ROOT}/target/release/busbar"
PACK_BIN="${REPO_ROOT}/target/release/busbar-plugin-pack"
if any_selected_needs_binary; then
  phase "Phase 0: build busbar binary + busbar-plugin-pack (FIXED SETUP)"
  _setup_t0=$SECONDS
  cargo build --release -p busbar -p busbar-plugin-pack
  [ -x "$BUSBAR_BIN" ] || { echo "busbar binary not found at $BUSBAR_BIN" >&2; exit 1; }
  [ -x "$PACK_BIN" ] || { echo "busbar-plugin-pack not found at $PACK_BIN" >&2; exit 1; }
  SETUP_SECS=$((SECONDS - _setup_t0))
  ok "busbar binary: $BUSBAR_BIN"
  ok "busbar-plugin-pack: $PACK_BIN"
  echo "  [time] FIXED SETUP (phase-0 build): ${SETUP_SECS}s"
else
  phase "Phase 0: SKIPPED — no selected phase needs the busbar binary (suite-only segment)"
  note "segment '${SEGMENT}' runs only sibling-suite phases; the busbar/pack release build is not"
  note "built at all. This is the fixed-cost saving that makes a per-plugin fan-out worthwhile."
fi

# ── Nothing left to build here. Every first-party store/auth/secret plugin has been extracted to
#    its own repo (GetBusbar/store-sqlite, GetBusbar/store-postgres, GetBusbar/store-valkey,
#    GetBusbar/auth-oidc, GetBusbar/hashicorp-vault; each a same-repo 2-crate workspace, the pattern
#    auth-oidc's own extraction established) — busbarAI's release.yml itself no longer builds or
#    packs any of them; it only ships the busbar binary + the bundled hook plugins now (see the
#    "Store/auth plugin releases moved out" comment there). Phase 1 and the registry-driven
#    Phase 2 suite loop below each gate on their respective repo's own test suite via a sibling
#    checkout instead.
phase "Phase 0b: nothing in-tree to build (every store/auth/secret plugin is fully extracted)"
ok "no in-tree plugin tarballs to pack"

ls -l "$PLUGIN_DIST"


# ── Phase 0a2: signing-key requirement — the exact end-user flow, fail-closed then green ────────────
#
# 1.5.1+: busbar NO LONGER auto-generates a signing key. A config naming the built-in `keys` verifier
# in auth.chain therefore REQUIRES auth.signing_key at validate/boot; without it busbar fail-closes
# with "auth.signing_key is required" (exit non-zero) rather than booting a data plane that verifies
# no signed key. This phase proves BOTH directions against the real binary via `--validate`:
#   (1) keys verifier + a usable admin mint path but NO signing_key  → --validate FAILS with that error
#   (2) `busbar --generate-signing-key` + auth.signing_key set        → --validate SUCCEEDS
# This is the regression twin of the core config-validate test (test_keys_chain_without_signing_key_is_boot_error).
if ! phase_selected phase-0a2-signing-key; then
  record_phase_skip phase-0a2-signing-key "not-in-segment"
else
begin_phase phase-0a2-signing-key "Phase 0a2: signing-key requirement — keys verifier without signing_key fail-closes, with it validates"
sk_work="$(new_tmpdir)"
cat >"${sk_work}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:9"
EOF
# (1) NO signing_key — must fail-closed at --validate with the actionable error.
# executable-config-lint: allow — DELIBERATELY INVALID: this config omits auth.signing_key precisely
# so the assertion below can prove busbar fail-closes on it. It must never be "fixed".
# NOTE on the auth shape used by every generated config in this script: 1.5.3 retired the INLINE
# chain/admin_auth entry, so a provider is DEFINED once under `identity-providers:` and REFERENCED by
# bare name. The old `admin_auth: [- admin-tokens: { token: … }]` is now a detect_legacy_markers hit
# that refuses to boot — which would make this assertion pass for the WRONG reason: the config would
# be rejected for its own grammar rather than for the missing signing_key it is testing.
cat >"${sk_work}/config-nokey.yaml" <<EOF
listen: "127.0.0.1:0"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain:
    - keys
  admin_auth: [admin-tokens]
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
if BUSBAR_CONFIG="${sk_work}/config-nokey.yaml" BUSBAR_PROVIDERS="${sk_work}/providers.yaml" \
     MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=release-check-admin \
     "$BUSBAR_BIN" --validate >"${sk_work}/nokey.log" 2>&1; then
  echo "  keys verifier with NO signing_key unexpectedly VALIDATED — the fail-closed guard is gone" >&2
  cat "${sk_work}/nokey.log" >&2
  exit 1
fi
grep -q "auth.signing_key is required" "${sk_work}/nokey.log" || {
  echo "  --validate failed but WITHOUT the expected 'auth.signing_key is required' error:" >&2
  cat "${sk_work}/nokey.log" >&2
  exit 1
}
ok "keys verifier with no signing_key fail-closes at --validate with the expected error"
# (2) generate a key, reference it — must validate clean.
"$BUSBAR_BIN" --generate-signing-key >"${sk_work}/signing.key" 2>/dev/null
[ -s "${sk_work}/signing.key" ] || { echo "  --generate-signing-key produced no key" >&2; exit 1; }
cat >"${sk_work}/config-key.yaml" <<EOF
listen: "127.0.0.1:0"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain:
    - keys
  signing_key: { file: "${sk_work}/signing.key" }
  admin_auth: [admin-tokens]
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
BUSBAR_CONFIG="${sk_work}/config-key.yaml" BUSBAR_PROVIDERS="${sk_work}/providers.yaml" \
  MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=release-check-admin \
  "$BUSBAR_BIN" --validate
ok "keys verifier WITH a generated signing_key validates clean"
end_phase ran
fi

# ── Phase 0c: lane-saturation soak — the Bug-1 SLO, proven end-to-end against the real binary ──────
#
# This is an ENGINE-level soak, NOT a plugin phase: it is deliberately OUTSIDE the plugins.yaml
# registry-driven loop (Phase 2) and needs no sibling checkout, no Docker, and no store plugin — it
# boots the real busbar binary against an in-RAM store (`store:` omitted) with `auth.chain: []` so
# every data-plane route is open, and drives real HTTP concurrency past a lane's `max_concurrent`.
# scripts/plugin-registry-check.sh check 3 only looks for suite-loop / `../<dir>` coverage per
# registry entry, so this standalone phase (touching no plugin dir) does not perturb that gate.
#
# It proves, against the real binary, the guarantees the property test (Phase 4) asserts in-process:
#   • reject           → excess-of-capacity requests get 503 + `Retry-After >= 2` (the at-capacity
#                        floor; NEVER the deceptive 1/0), returned FAST — well inside the failover budget.
#   • queue{max_ms}    → excess requests wait <= max_ms then dispatch-or-503, and NEVER hang past
#                        max_ms + budget (the Bug-1 anti-park guarantee).
#   • /stats + /metrics DURING the saturation window reflect it: the saturated lane shows
#                        `at_capacity: true` / `available: 0` / `inflight >= 1`, and under queue the
#                        pool shows `busbar_pool_queued > 0`.
# It is bounded on purpose (small request counts, short holder latencies, a 5s failover budget) so it
# adds well under a minute to the ~2h gate — a few real requests, not a load test.
SOAK_LISTEN_PORT=19080
SOAK_MOCK_PORT=19079

# One authed-less chat POST to the pool. Prints "HTTP<code> RA=<retry-after|none> MS=<wall-ms>" and
# uses a unique temp header/body file per call so CONCURRENT invocations never clobber each other.
soak_chat() {
  local u out code ra t0 t1
  u="$(mktemp "${SOAK_WORK}/req.XXXXXX")"
  t0="$(now_ms)"
  out="$(curl -s -o "${u}.body" -D "${u}.hdr" -w '%{http_code}' \
    "http://127.0.0.1:${SOAK_LISTEN_PORT}/v1/chat/completions" \
    -H 'Content-Type: application/json' \
    -d '{"model":"satpool","messages":[{"role":"user","content":"hi"}]}' 2>/dev/null || true)"
  t1="$(now_ms)"
  code="$out"
  ra="$( (grep -i '^retry-after:' "${u}.hdr" || true) | tr -d '\r' | awk '{print $2}')"
  ra="${ra:-none}"
  rm -f "$u" "${u}.body" "${u}.hdr"
  echo "HTTP${code} RA=${ra} MS=$((t1 - t0))"
}

# Write the soak config for a one-member pool (max_concurrent=1) pointing at the latency-injecting
# mock, under the given on_exhausted policy. The caller launches busbar (so its pid lands in the
# parent's BG_PIDS for the EXIT cleanup trap, not a command-substitution subshell's copy).
soak_write_config() {
  local policy="$1"
  cat >"${SOAK_WORK}/providers.yaml" <<EOF
slow:
  protocol: anthropic
  base_url: "http://127.0.0.1:${SOAK_MOCK_PORT}"
EOF
  cat >"${SOAK_WORK}/config.yaml" <<EOF
listen: "127.0.0.1:${SOAK_LISTEN_PORT}"
auth:
  chain: []
# 1.5.3 retired the top-level \`metrics:\` block; it is now an \`export:\` instance backed by the
# \`prometheus\` module. The old shape is a detect_legacy_markers hit, so busbar REFUSES TO BOOT on it
# ("this looks like a busbar 1.x config"), which made both soak scenarios fail with nothing but a
# /healthz timeout. The soak needs /metrics for its busbar_pool_queued assertion, so this instance is
# load-bearing, not decoration.
export:
  metrics: { module: prometheus, settings: { buffer_seconds: 60 } }
providers:
  slow:
    api_key: { env: MOCK_KEY }
models:
  slow-model:
    provider: slow
    max_concurrent: 1
pools:
  satpool:
    members:
      - model: slow-model
    failover:
      timeout_secs: 5
    on_exhausted: ${policy}
EOF
}

# Poll /stats until the lane reports at_capacity (proves the permit is genuinely held). Echoes the
# saturating snapshot's lane object; fails loudly if saturation never appears.
soak_wait_saturated() {
  local snap ac
  for _ in $(seq 1 50); do
    snap="$(curl -fsS "http://127.0.0.1:${SOAK_LISTEN_PORT}/stats" 2>/dev/null || echo '{}')"
    ac="$(echo "$snap" | jq -r '.lanes[] | select(.model=="slow-model") | .at_capacity')"
    if [ "$ac" = "true" ]; then
      echo "$snap" | jq -c '.lanes[] | select(.model=="slow-model") | {at_capacity,available,inflight,availability,recovery_hint_ms}'
      return 0
    fi
    sleep 0.1
  done
  echo "  soak: lane never reported at_capacity in /stats" >&2
  cat "${SOAK_WORK}/busbar.log" >&2 || true
  return 1
}

run_saturation_soak() {
  local budget_ms=5000
  SOAK_WORK="$(new_tmpdir)"
  local marker="soak-$$-${RANDOM}"
  # Declared up front (not inside scenario A) so scenario B is genuinely independent of it: either
  # scenario can be selected on its own by --segment.
  local mock_pid pid lane i r code ra ms holder qholder q1 q2 qseen qval q f ho

  # ---- Scenario A: on_exhausted: reject ----
  if ! phase_selected phase-0c-soak-reject; then
    record_phase_skip phase-0c-soak-reject "not-in-segment"
  else
  begin_phase phase-0c-soak-reject "Phase 0c: saturation soak — on_exhausted: reject (real binary, real HTTP, max_concurrent=1)"
  echo "  starting latency-injecting mock upstream on 127.0.0.1:${SOAK_MOCK_PORT} (delay=2.0s)"
  # NB: call as a statement with stdout to /dev/null (never `$(...)`) — the mock's serve_forever holds
  # its inherited stdout open, so a command substitution would block forever. It records its own pid
  # in BG_PIDS; grab the just-appended one (portable index for bash 3.2).
  start_mock_upstream "$SOAK_MOCK_PORT" "$marker" 2.0 >/dev/null
  local mock_pid="${BG_PIDS[$((${#BG_PIDS[@]} - 1))]}"
  soak_write_config reject
  BUSBAR_CONFIG="${SOAK_WORK}/config.yaml" BUSBAR_PROVIDERS="${SOAK_WORK}/providers.yaml" \
    MOCK_KEY=unused RUST_LOG=warn "$BUSBAR_BIN" >"${SOAK_WORK}/busbar.log" 2>&1 &
  local pid=$!; BG_PIDS+=("$pid")
  wait_for_http "http://127.0.0.1:${SOAK_LISTEN_PORT}/healthz" 30
  ok "busbar up (pid ${pid}), pool 'satpool' member max_concurrent=1, budget=5s"

  # Holder: one request that occupies the single permit for the mock's 2s latency.
  soak_chat >"${SOAK_WORK}/holder.out" & local holder=$!
  local lane; lane="$(soak_wait_saturated)"
  ok "/stats DURING saturation: ${lane}"
  echo "$lane" | jq -e '.at_capacity==true and .available==0 and .inflight>=1' >/dev/null \
    || { echo "  soak: capacity signal wrong (expected at_capacity=true, available=0, inflight>=1)" >&2; exit 1; }
  ok "capacity signal asserted: at_capacity=true, available=0, inflight>=1"

  # Excess: while the permit is held, more requests than capacity must 503 + Retry-After>=2, FAST.
  local i r code ra ms
  for i in 1 2 3; do
    r="$(soak_chat)"; echo "    excess #${i} -> ${r}"
    code="${r#HTTP}"; code="${code%% *}"
    ra="$(echo "$r" | sed -E 's/.*RA=([^ ]+).*/\1/')"
    ms="$(echo "$r" | sed -E 's/.*MS=([0-9]+).*/\1/')"
    [ "$code" = "503" ] || { echo "  soak reject excess#${i}: expected 503, got ${code}" >&2; exit 1; }
    { [ "$ra" != "none" ] && [ "$ra" -ge 2 ] 2>/dev/null; } \
      || { echo "  soak reject excess#${i}: Retry-After='${ra}' not >= 2 (the at-capacity floor)" >&2; exit 1; }
    [ "$ms" -lt "$budget_ms" ] || { echo "  soak reject excess#${i}: wall ${ms}ms exceeded ${budget_ms}ms budget (unbounded block)" >&2; exit 1; }
  done
  ok "REJECT SLO proven: excess -> 503 + Retry-After>=2, every request under the 5s failover budget"

  wait "$holder"; local ho; ho="$(cat "${SOAK_WORK}/holder.out")"
  echo "  holder result: ${ho}"
  echo "$ho" | grep -q 'HTTP200' || { echo "  soak: holder request should have dispatched 200: ${ho}" >&2; exit 1; }
  ms="$(echo "$ho" | sed -E 's/.*MS=([0-9]+).*/\1/')"
  [ "$ms" -lt "$budget_ms" ] || { echo "  soak: holder wall ${ms}ms exceeded budget" >&2; exit 1; }
  ok "holder dispatched 200 within budget (${ms}ms) — the ELIGIBLE request was served, not starved"
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true
  end_phase ran
  fi

  # ---- Scenario B: on_exhausted: queue{max_ms} ----
  if ! phase_selected phase-0c-soak-queue; then
    record_phase_skip phase-0c-soak-queue "not-in-segment"
    return 0
  fi
  begin_phase phase-0c-soak-queue "Phase 0c: saturation soak — on_exhausted: queue{max_ms:2000} (bounded wait, no unbounded park)"
  echo "  starting latency-injecting mock upstream on 127.0.0.1:${SOAK_MOCK_PORT} (delay=3.0s > max_ms)"
  start_mock_upstream "$SOAK_MOCK_PORT" "$marker" 3.0 >/dev/null
  mock_pid="${BG_PIDS[$((${#BG_PIDS[@]} - 1))]}"
  soak_write_config '{ queue: { max_ms: 2000 } }'
  BUSBAR_CONFIG="${SOAK_WORK}/config.yaml" BUSBAR_PROVIDERS="${SOAK_WORK}/providers.yaml" \
    MOCK_KEY=unused RUST_LOG=warn "$BUSBAR_BIN" >"${SOAK_WORK}/busbar.log" 2>&1 &
  pid=$!; BG_PIDS+=("$pid")
  wait_for_http "http://127.0.0.1:${SOAK_LISTEN_PORT}/healthz" 30
  ok "busbar up (pid ${pid}), queue{max_ms:2000} policy, holder latency 3.0s"

  soak_chat >"${SOAK_WORK}/qholder.out" & local qholder=$!
  lane="$(soak_wait_saturated)"
  ok "/stats DURING saturation (queue): ${lane}"

  # Two queued excess requests: they must PARK (busbar_pool_queued>0), then bound out at ~max_ms.
  soak_chat >"${SOAK_WORK}/q1.out" & local q1=$!
  soak_chat >"${SOAK_WORK}/q2.out" & local q2=$!
  local qseen=0 qval=0 q
  for _ in $(seq 1 40); do
    q="$(curl -fsS "http://127.0.0.1:${SOAK_LISTEN_PORT}/metrics" 2>/dev/null | awk '/^busbar_pool_queued/{print $2; exit}')"
    q="${q:-0}"
    if awk "BEGIN{exit !(${q}>0)}"; then qseen=1; qval="$q"; break; fi
    sleep 0.1
  done
  [ "$qseen" = "1" ] || { echo "  soak queue: busbar_pool_queued never went >0 during the park window" >&2; exit 1; }
  ok "/metrics DURING park: busbar_pool_queued=${qval} (> 0) — the queue policy is genuinely parking"

  wait "$q1"; wait "$q2"
  local f
  for f in q1 q2; do
    r="$(cat "${SOAK_WORK}/${f}.out")"; echo "    queued ${f} -> ${r}"
    code="$(echo "$r" | sed -E 's/HTTP([0-9]+).*/\1/')"
    ms="$(echo "$r" | sed -E 's/.*MS=([0-9]+).*/\1/')"
    { [ "$code" = "200" ] || [ "$code" = "503" ]; } \
      || { echo "  soak queue ${f}: expected dispatch(200) or bounded reject(503), got ${code}" >&2; exit 1; }
    [ "$ms" -lt $((2000 + budget_ms)) ] || { echo "  soak queue ${f}: wall ${ms}ms hung past max_ms(2000)+budget(${budget_ms}) — UNBOUNDED PARK (Bug 1)" >&2; exit 1; }
  done
  ok "QUEUE SLO proven: excess parked <= max_ms then dispatched-or-503, NONE hung past max_ms+budget"

  wait "$qholder" 2>/dev/null || true
  kill "$pid" 2>/dev/null || true; wait "$pid" 2>/dev/null || true
  kill "$mock_pid" 2>/dev/null || true; wait "$mock_pid" 2>/dev/null || true
  ok "saturation soak complete: elapsed=${SECONDS}s"
  end_phase ran
}

# Only stand the soak up at all if at least one of its two scenarios is in the segment.
if phase_selected phase-0c-soak-reject || phase_selected phase-0c-soak-queue; then
  run_saturation_soak
else
  record_phase_skip phase-0c-soak-reject "not-in-segment"
  record_phase_skip phase-0c-soak-queue "not-in-segment"
fi

# ── Shared traffic-and-restart-survival driver, parameterized by store module/settings ─────────────
# 1. writes config.yaml + providers.yaml exactly matching docs/getting-started.md +
#    docs/configuration.md's documented shapes
# 2. boots the real busbar binary against them (plugins.enabled + plugins.dir pointed at the real
#    packed tarballs above)
# 3. mints a real virtual key over the real admin API (POST /keys)
# 4. drives a real chat-completion request through the real mock upstream and asserts the response
#    body byte-for-byte on the marker text
# 5. asserts GET /keys/{id}/usage shows real nonzero request/token counters
# 6. kills the process, restarts it against the SAME store, and asserts the key + its usage
#    counters SURVIVED — the actual durability proof
run_store_backend_e2e() {
  local backend_label="$1" store_module="$2" store_settings_yaml="$3"
  local listen_port="$4" admin_port="$5" mock_port="$6"

  local work
  work="$(new_tmpdir)"
  local marker="release-check-${backend_label}-$$-${RANDOM}"

  echo "  starting mock upstream on 127.0.0.1:${mock_port} (marker=${marker})"
  start_mock_upstream "$mock_port" "$marker" >/dev/null

  cat >"${work}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "http://127.0.0.1:${mock_port}"
EOF

  # 1.5.1: the built-in `keys` verifier requires an explicit signing key — busbar no longer
  # auto-generates one. Mint a real ed25519 secret via the shipping command (secret -> stdout,
  # guidance -> stderr) into a file and reference it as a secret {file:} ref, exactly as an operator would.
  "$BUSBAR_BIN" --generate-signing-key >"${work}/signing.key" 2>/dev/null
  [ -s "${work}/signing.key" ] || { echo "  --generate-signing-key produced no key" >&2; exit 1; }

  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:${listen_port}"
admin_listen: "127.0.0.1:${admin_port}"
identity-providers:
  admin-tokens:
    module: admin-tokens
    token: { env: BUSBAR_ADMIN_TOKEN }
auth:
  chain:
    - keys
  signing_key: { file: "${work}/signing.key" }
  admin_auth: [admin-tokens]
plugins:
  enabled: true
  dir: "${PLUGIN_DIST}"
  trust:
    allow_unsigned: true
store:
  module: ${store_module}
  settings: ${store_settings_yaml}
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF

  # --validate first: the same fail-closed preflight boot performs, with zero side effects.
  echo "  --validate against this exact config..."
  BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
    MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=release-check-admin \
    "$BUSBAR_BIN" --validate
  ok "--validate clean for ${backend_label}"

  boot_busbar() {
    BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" \
      MOCK_KEY=unused BUSBAR_ADMIN_TOKEN=release-check-admin \
      RUST_LOG=warn \
      "$BUSBAR_BIN" >"${work}/busbar.log" 2>&1 &
    local pid=$!
    BG_PIDS+=("$pid")
    echo "$pid"
  }

  echo "  booting busbar (${backend_label})..."
  local pid; pid="$(boot_busbar)"
  wait_for_http "http://127.0.0.1:${listen_port}/healthz" 30
  ok "busbar up (pid ${pid}), /healthz green"

  echo "  minting a virtual key over the real admin API..."
  local mint_resp token key_id
  mint_resp="$(curl -fsS -X POST "http://127.0.0.1:${admin_port}/api/v1/admin/keys" \
    -H "Authorization: Bearer release-check-admin" -H "Content-Type: application/json" \
    -d '{"name":"release-check"}')"
  token="$(echo "$mint_resp" | jq -r .token)"
  key_id="$(echo "$mint_resp" | jq -r .id)"
  [ -n "$token" ] && [ "$token" != "null" ] || { echo "mint did not return a token: $mint_resp" >&2; exit 1; }
  [ -n "$key_id" ] && [ "$key_id" != "null" ] || { echo "mint did not return an id: $mint_resp" >&2; exit 1; }
  ok "minted key id=${key_id}"

  echo "  driving a real chat-completion request through busbar -> mock upstream..."
  local chat_resp got_text
  chat_resp="$(curl -fsS "http://127.0.0.1:${listen_port}/v1/chat/completions" \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    -d '{"model":"test-model","messages":[{"role":"user","content":"hello"}]}')"
  got_text="$(echo "$chat_resp" | jq -r '.choices[0].message.content')"
  if [ "$got_text" != "$marker" ]; then
    echo "  response text mismatch: expected [${marker}] got [${got_text}] (full body: ${chat_resp})" >&2
    exit 1
  fi
  ok "response body matched the mock upstream's marker exactly: ${marker}"

  echo "  asserting usage was recorded via GET /keys/{id}/usage..."
  local usage_resp requests_before tokens_before
  usage_resp="$(curl -fsS "http://127.0.0.1:${admin_port}/api/v1/admin/keys/${key_id}/usage" \
    -H "Authorization: Bearer release-check-admin")"
  requests_before="$(echo "$usage_resp" | jq -r .requests)"
  tokens_before="$(echo "$usage_resp" | jq -r .tokens)"
  if [ "$requests_before" -lt 1 ] || [ "$tokens_before" -lt 1 ]; then
    echo "  usage not recorded as expected: ${usage_resp}" >&2
    exit 1
  fi
  ok "usage before restart: requests=${requests_before} tokens=${tokens_before}"

  echo "  restarting busbar (${backend_label}) against the SAME store to prove durability..."
  kill "$pid"
  wait "$pid" 2>/dev/null || true
  local pid2; pid2="$(boot_busbar)"
  wait_for_http "http://127.0.0.1:${listen_port}/healthz" 30
  ok "busbar restarted (pid ${pid2}), /healthz green"

  echo "  asserting the key + its usage counters SURVIVED the restart..."
  local get_key_resp usage_resp2 requests_after tokens_after
  get_key_resp="$(curl -fsS "http://127.0.0.1:${admin_port}/api/v1/admin/keys/${key_id}" \
    -H "Authorization: Bearer release-check-admin")"
  echo "$get_key_resp" | jq -e '.id == "'"${key_id}"'"' >/dev/null \
    || { echo "  key did not survive restart: ${get_key_resp}" >&2; exit 1; }
  usage_resp2="$(curl -fsS "http://127.0.0.1:${admin_port}/api/v1/admin/keys/${key_id}/usage" \
    -H "Authorization: Bearer release-check-admin")"
  requests_after="$(echo "$usage_resp2" | jq -r .requests)"
  tokens_after="$(echo "$usage_resp2" | jq -r .tokens)"
  if [ "$requests_after" -lt "$requests_before" ] || [ "$tokens_after" -lt "$tokens_before" ]; then
    echo "  usage regressed after restart: before(requests=${requests_before} tokens=${tokens_before}) after(requests=${requests_after} tokens=${tokens_after})" >&2
    exit 1
  fi
  ok "DURABILITY CONFIRMED (${backend_label}): key + usage survived a real process restart (requests=${requests_after} tokens=${tokens_after})"

  # A second request post-restart, to prove the restarted instance is not just serving stale reads
  # but is a fully live, working lane through the same store.
  local chat_resp2 got_text2
  chat_resp2="$(curl -fsS "http://127.0.0.1:${listen_port}/v1/chat/completions" \
    -H "Authorization: Bearer ${token}" -H "Content-Type: application/json" \
    -d '{"model":"test-model","messages":[{"role":"user","content":"hello again"}]}')"
  got_text2="$(echo "$chat_resp2" | jq -r '.choices[0].message.content')"
  [ "$got_text2" = "$marker" ] || { echo "  post-restart traffic mismatch: ${chat_resp2}" >&2; exit 1; }
  ok "post-restart live traffic confirmed working end-to-end"

  kill "$pid2" 2>/dev/null || true
  wait "$pid2" 2>/dev/null || true
}

# ── Phase 1: SQLite — sibling checkout; store-sqlite now owns 100% of its own logic + release
#    proof. Its own release-check-equivalent lives in ITS repo/CI; this script's job is only to
#    prove busbar's real HTTP + restart-durability story against it when the sibling is available
#    locally (dockerless, fastest feedback loop of the three backends). ────────────────────────────
STORE_SQLITE_SRC="${REPO_ROOT}/../store-sqlite"
if ! phase_selected phase-1-sqlite-binary; then
  record_phase_skip phase-1-sqlite-binary "not-in-segment"
elif [ -d "$STORE_SQLITE_SRC" ]; then
  begin_phase phase-1-sqlite-binary "Phase 1: store-sqlite-plugin — sibling checkout: real busbar, real HTTP traffic, real restart durability"
  note "store-sqlite no longer lives in-tree — it brings 100% of what it needs in its own repo, a"
  note "same-repo 2-crate workspace (busbar-store-sqlite + busbar-store-sqlite-plugin). Its own"
  note "store-sqlite-plugin/tests/e2e.rs already covers the hermetic in-process dlopen ABI path."
  note "This phase builds the plugin cdylib from the sibling checkout and drives it through busbar's"
  note "real end-to-end HTTP + restart-durability story, the same as every other store backend here."
  cargo build --release --manifest-path "${STORE_SQLITE_SRC}/Cargo.toml" -p busbar-store-sqlite-plugin
  SQLITE_LIB="${STORE_SQLITE_SRC}/target/release/${LIBPREFIX}busbar_store_sqlite_plugin.${LIBEXT}"
  [ -f "$SQLITE_LIB" ] || { echo "missing built cdylib: $SQLITE_LIB" >&2; exit 1; }
  "$PACK_BIN" pack \
    --lib "$SQLITE_LIB" \
    --name "busbar-store-sqlite" --alias "sqlite" --kind store \
    --version "$VER" --publisher busbar \
    --description "busbar sqlite governance store plugin" \
    --license Apache-2.0 \
    --out "${PLUGIN_DIST}/busbar-store-sqlite-${VER}-local.tar.gz" \
    --allow-unsigned
  ok "packed busbar-store-sqlite (sibling checkout)"
  SQLITE_DB="$(new_tmpdir)/governance.db"
  run_store_backend_e2e "sqlite" "sqlite" "{ db_path: \"${SQLITE_DB}\" }" 18080 18081 18079
  ok "SQLite phase complete: $(date -u +%H:%M:%S) elapsed=${SECONDS}s"
  end_phase ran
else
  echo "SKIP: ../store-sqlite not present as a sibling checkout on this machine." >&2
  echo "Gate incomplete — SQLite coverage could not run. Check out ../store-sqlite for full" >&2
  echo "coverage before tagging, or confirm that repo's own CI is green." >&2
  SQLITE_SKIPPED=1
  record_phase_skip phase-1-sqlite-binary "sibling-missing"
fi

# ── Phase 2: the registry-driven sibling-suite loop ───────────────────────────────────────────────
#
# Every fully-extracted plugin whose release-gate proof is its own repo's test suite (`gate: suite`
# in plugins.yaml — postgres, mysql, valkey, vault, oidc today) follows ONE uniform pattern:
#   1. if the entry's `service` is not "none", boot that service's real backend container and
#      poll its real readiness probe (no fixed sleeps),
#   2. export that service's BUSBAR_TEST_* connection env,
#   3. run `cargo test --workspace --release` in the sibling checkout ../<dir>.
# Each such repo's own e2e suite already dlopens its REAL built cdylib against the REAL backend —
# genuine, hermetic, real-ABI coverage. Running that suite here (rather than reinventing a second,
# lower-quality proof in-tree) is the correct release-gate check; see each repo's own tests/e2e.rs.
#
# The loop iterates `plugin-registry-check.sh --list` (plugins.yaml, the single source of truth),
# so ADDING a suite-gated plugin = one plugins.yaml entry, zero edits here — unless it introduces
# a brand-new `service` value, in which case the case block below needs one new container-spec arm
# (and the registry gate goes RED until it gets one). `release_gate: required` entries hard-fail
# the whole gate when their sibling checkout is missing; `optional` entries loud-skip instead.
#
# Genuinely-special phases stay explicit and OUT of this loop: sqlite's full-busbar-binary +
# real-HTTP + restart-durability phase above (`gate: binary`), and the hook plugins' --validate
# dlopen smoke tests below (`gate: smoke`). plugin-registry-check.sh enforces that those still
# cover every non-suite registry entry.
phase "Phase 2: registry-driven sibling-suite gates (gate: suite in plugins.yaml)"

# Docker preflight is now scoped to the SELECTED phases: a segment whose suite phases all declare
# `service: none` (e.g. plugin-auth-oidc) genuinely does not need Docker, and must not hard-fail on a
# machine without it. A segment that DOES need a container still fails loudly up front, because
# "gate incomplete" must never look like "gate green".
if ! any_selected_needs_service; then
  note "no selected phase needs a service container — skipping the Docker preflight."
elif [ "$SKIP_DOCKER" = "1" ]; then
  note "SKIP_DOCKER set — suites needing a service container will be skipped. This is NOT a valid release gate run."
else
  if ! docker ps >/dev/null 2>&1; then
    echo "Docker is not available/running (docker ps failed). Service-backed suite phases cannot run." >&2
    echo "This is a REQUIRED part of the release gate — fix Docker and re-run, or pass --skip-docker" >&2
    echo "only for fast local iteration (never as a substitute for a real green gate)." >&2
    exit 1
  fi
fi

SUITE_PASSED=()
SUITE_SKIPPED=()

# REGISTRY_LIST was captured up front (near the phase registry): a parse/shape failure must fail THIS
# gate loudly under set -e, never degrade to an empty loop that looks green.
#
# feed fields: repo dir alias kind service release_gate gate checkout_ref — the suite loop only
# needs repo, dir, service, release_gate, and gate.
while IFS=$'\t' read -r P_REPO P_DIR _ _ P_SERVICE P_RELGATE P_GATE _; do
  [ "$P_GATE" = "suite" ] || continue
  if ! phase_selected "phase-2-suite-${P_REPO}"; then
    record_phase_skip "phase-2-suite-${P_REPO}" "not-in-segment"
    continue
  fi
  SUITE_SRC="${REPO_ROOT}/../${P_DIR}"

  if [ ! -d "$SUITE_SRC" ]; then
    if [ "$P_RELGATE" = "required" ]; then
      echo "../${P_DIR} (GetBusbar/${P_REPO}) is not checked out as a sibling of this repo." >&2
      echo "This is a REQUIRED part of the release gate (release_gate: required in plugins.yaml —" >&2
      echo "its coverage lives in that repo's own test suite) — clone GetBusbar/${P_REPO} to" >&2
      echo "${SUITE_SRC} and re-run." >&2
      exit 1
    fi
    echo "SKIP: ../${P_DIR} not present as a sibling checkout on this machine." >&2
    echo "Gate incomplete — ${P_REPO} coverage could not run. Check out ../${P_DIR} for full" >&2
    echo "coverage before tagging, or confirm that repo's own CI is green." >&2
    SUITE_SKIPPED+=("${P_REPO}")
    record_phase_skip "phase-2-suite-${P_REPO}" "sibling-missing"
    continue
  fi

  if [ "$P_SERVICE" != "none" ] && [ "$SKIP_DOCKER" = "1" ]; then
    note "SKIP (--skip-docker): ${P_REPO} needs a real ${P_SERVICE} container. NOT a valid gate run."
    SUITE_SKIPPED+=("${P_REPO}")
    record_phase_skip "phase-2-suite-${P_REPO}" "skip-docker"
    continue
  fi

  begin_phase "phase-2-suite-${P_REPO}" "suite gate: ${P_REPO} — sibling repo's own test suite (service: ${P_SERVICE})"
  SUITE_CONTAINER=""
  SUITE_ENV=()
  case "$P_SERVICE" in
    none) ;;
    postgres)
      SUITE_CONTAINER="busbar-release-check-pg-$$"
      DOCKER_CONTAINERS+=("$SUITE_CONTAINER")
      docker run -d --rm --name "$SUITE_CONTAINER" \
        -e POSTGRES_USER=busbar -e POSTGRES_PASSWORD=busbar -e POSTGRES_DB=busbar_release_check \
        -p 15432:5432 \
        postgres:16 >/dev/null
      echo "  waiting for postgres to accept connections (pg_isready inside the container)..."
      waited=0
      until docker exec "$SUITE_CONTAINER" pg_isready -U busbar >/dev/null 2>&1; do
        waited=$((waited + 1))
        if [ "$waited" -ge 60 ]; then
          echo "postgres did not become ready within 60s" >&2
          docker logs "$SUITE_CONTAINER" || true
          exit 1
        fi
        sleep 1
      done
      ok "postgres ready after ${waited}s"
      SUITE_ENV=(BUSBAR_TEST_POSTGRES_URL="postgres://busbar:busbar@127.0.0.1:15432/busbar_release_check")
      ;;
    mysql)
      SUITE_CONTAINER="busbar-release-check-mysql-$$"
      DOCKER_CONTAINERS+=("$SUITE_CONTAINER")
      docker run -d --rm --name "$SUITE_CONTAINER" \
        -e MYSQL_ROOT_PASSWORD=busbar -e MYSQL_USER=busbar -e MYSQL_PASSWORD=busbar \
        -e MYSQL_DATABASE=busbar_release_check \
        -p 13306:3306 \
        mysql:8 >/dev/null
      echo "  waiting for mysql to accept connections (mysqladmin ping inside the container)..."
      waited=0
      # MySQL 8's first boot initializes the datadir and restarts once — allow a longer window than
      # postgres, and ping as the busbar user so "ready" means "ready for OUR credentials".
      until docker exec "$SUITE_CONTAINER" mysqladmin ping -h localhost -ubusbar -pbusbar >/dev/null 2>&1; do
        waited=$((waited + 1))
        if [ "$waited" -ge 120 ]; then
          echo "mysql did not become ready within 120s" >&2
          docker logs "$SUITE_CONTAINER" || true
          exit 1
        fi
        sleep 1
      done
      ok "mysql ready after ${waited}s"
      SUITE_ENV=(BUSBAR_TEST_MYSQL_URL="mysql://busbar:busbar@127.0.0.1:13306/busbar_release_check")
      ;;
    valkey)
      SUITE_CONTAINER="busbar-release-check-valkey-$$"
      DOCKER_CONTAINERS+=("$SUITE_CONTAINER")
      docker run -d --rm --name "$SUITE_CONTAINER" -p 16379:6379 valkey/valkey:8 >/dev/null
      echo "  waiting for valkey to accept connections (valkey-cli ping inside the container)..."
      waited=0
      until [ "$(docker exec "$SUITE_CONTAINER" valkey-cli ping 2>/dev/null)" = "PONG" ]; do
        waited=$((waited + 1))
        if [ "$waited" -ge 60 ]; then
          echo "valkey did not become ready within 60s" >&2
          docker logs "$SUITE_CONTAINER" || true
          exit 1
        fi
        sleep 1
      done
      ok "valkey ready after ${waited}s"
      SUITE_ENV=(VALKEY_URL="redis://127.0.0.1:16379")
      ;;
    vault)
      SUITE_CONTAINER="busbar-release-check-vault-$$"
      DOCKER_CONTAINERS+=("$SUITE_CONTAINER")
      docker run -d --rm --name "$SUITE_CONTAINER" --cap-add=IPC_LOCK \
        -e VAULT_DEV_ROOT_TOKEN_ID=root -p 18200:8200 hashicorp/vault >/dev/null
      echo "  waiting for vault to report healthy (/v1/sys/health)..."
      waited=0
      until curl -fsS "http://127.0.0.1:18200/v1/sys/health" >/dev/null 2>&1; do
        waited=$((waited + 1))
        if [ "$waited" -ge 60 ]; then
          echo "vault did not become ready within 60s" >&2
          docker logs "$SUITE_CONTAINER" || true
          exit 1
        fi
        sleep 1
      done
      ok "vault ready after ${waited}s"
      SUITE_ENV=(BUSBAR_TEST_VAULT_ADDR="http://127.0.0.1:18200" BUSBAR_TEST_VAULT_TOKEN="root")
      ;;
    *)
      echo "plugins.yaml declares service '${P_SERVICE}' (${P_REPO}) but release-check.sh has no" >&2
      echo "container spec for it — add a case arm to the suite loop's service block." >&2
      exit 1
      ;;
  esac

  # Build FIRST, then test — mirroring the canonical plugin-ci.yml (`cargo build --all-targets`
  # before `cargo test`). `cargo test` alone builds the rlib for the harness but NOT the crate's
  # cdylib artifact, so a plugin's own e2e suite that dlopens `target/release/<plugin>.{so,dylib}`
  # (discovered relative to the test binary) hard-fails its "cdylib not built under CI" guard.
  # `--all-targets` forces the cdylib crate-type output into target/release/ where the suite looks.
  # Build vs test time are reported separately: the sibling's `cargo build --release` is FIXED SETUP
  # for that plugin's leg (paid again on every cold CI runner), while `cargo test` is the actual
  # coverage. Only the second number shrinks by fanning out further.
  echo "  building GetBusbar/${P_REPO}'s workspace (cdylib artifacts) before its suite in ../${P_DIR}..."
  _b0=$SECONDS
  (
    cd "$SUITE_SRC"
    cargo build --release --workspace --all-targets
  )
  _build_s=$((SECONDS - _b0))
  echo "  running GetBusbar/${P_REPO}'s own cargo test --workspace --release in ../${P_DIR}..."
  _t0=$SECONDS
  (
    cd "$SUITE_SRC"
    env ${SUITE_ENV[@]+"${SUITE_ENV[@]}"} cargo test --workspace --release
  )
  _test_s=$((SECONDS - _t0))
  ok "${P_REPO}: sibling repo's own suite passed (real ABI, service: ${P_SERVICE})"
  echo "  [time] ${P_REPO}: sibling build ${_build_s}s + suite ${_test_s}s (service: ${P_SERVICE})"
  ok "suite gate complete for ${P_REPO}: elapsed=${SECONDS}s"
  SUITE_PASSED+=("${P_REPO}")
  end_phase ran
  if [ -n "$SUITE_CONTAINER" ]; then
    docker rm -f "$SUITE_CONTAINER" >/dev/null 2>&1 || true
  fi
done <<<"$REGISTRY_LIST"

# ── Phase 5: Headroom / Webrequest — local --validate dlopen smoke test ────────────────────────────
phase "Phase 5: headroom-hook / webrequest-hook — local busbar --validate dlopen smoke test"
HEADROOM_SRC="${REPO_ROOT}/../headroom-hook"
WEBREQUEST_SRC="${REPO_ROOT}/../webrequest-hook"

run_validate_smoke() {
  local name="$1" manifest_path="$2" crate_lib_name="$3" kind="$4" needs_flag="${5:-}"
  local work; work="$(new_tmpdir)"
  mkdir -p "${work}/plugins"
  echo "  building ${name} cdylib from ${manifest_path}..."
  cargo build --release --manifest-path "$manifest_path"
  local built_dir; built_dir="$(dirname "$manifest_path")/target/release"
  local lib="${built_dir}/${LIBPREFIX}${crate_lib_name}.${LIBEXT}"
  [ -f "$lib" ] || { echo "expected built cdylib not found: $lib" >&2; exit 1; }
  local pack_extra=()
  [ -n "$needs_flag" ] && pack_extra=(--needs-prompt rw)
  "$PACK_BIN" pack \
    --lib "$lib" \
    --name "busbar-${name}" --alias "${name}" --kind "$kind" \
    --version "$VER" --publisher busbar \
    --description "busbar ${name} hook plugin (local release-check smoke test)" \
    --license Apache-2.0 \
    --out "${work}/plugins/busbar-${name}.tar.gz" \
    "${pack_extra[@]}" \
    --allow-unsigned
  cat >"${work}/config.yaml" <<EOF
listen: "127.0.0.1:0"
plugins:
  enabled: true
  dir: "${work}/plugins"
  trust:
    allow_unsigned: true
providers:
  mock:
    api_key: { env: MOCK_KEY }
models:
  test-model:
    provider: mock
EOF
  cat >"${work}/providers.yaml" <<EOF
mock:
  protocol: anthropic
  base_url: "https://example.invalid"
EOF
  local out
  out="$(BUSBAR_CONFIG="${work}/config.yaml" BUSBAR_PROVIDERS="${work}/providers.yaml" MOCK_KEY=unused \
    "$BUSBAR_BIN" --validate)"
  echo "$out" | grep -q "1 validated" || { echo "  ${name} did not validate as loaded: $out" >&2; exit 1; }
  ok "${name}: busbar --validate confirms the real dlopen'd plugin loads (${out##*$'\n'})"
}

if ! phase_selected phase-5-smoke-headroom; then
  record_phase_skip phase-5-smoke-headroom "not-in-segment"
elif [ -d "$HEADROOM_SRC" ]; then
  begin_phase phase-5-smoke-headroom "Phase 5: headroom-hook — busbar --validate dlopen smoke"
  run_validate_smoke "headroom" "${HEADROOM_SRC}/Cargo.toml" "headroom_hook" hook needs
  end_phase ran
else
  note "SKIP: ../headroom-hook not present as a sibling checkout on this machine."
  record_phase_skip phase-5-smoke-headroom "sibling-missing"
fi

if ! phase_selected phase-5-smoke-webrequest; then
  record_phase_skip phase-5-smoke-webrequest "not-in-segment"
elif [ -d "$WEBREQUEST_SRC" ]; then
  begin_phase phase-5-smoke-webrequest "Phase 5: webrequest-hook — busbar --validate dlopen smoke"
  run_validate_smoke "webrequest" "${WEBREQUEST_SRC}/Cargo.toml" "busbar_webrequest_hook_plugin" hook
  end_phase ran
else
  note "SKIP: ../webrequest-hook not present as a sibling checkout on this machine."
  record_phase_skip phase-5-smoke-webrequest "sibling-missing"
fi

# ── busbar-admin (busbarctl) — the REVERSE of the plugin phases ────────────────────────────────
# The plugin phases prove "a plugin works against busbar". This proves the other client of the
# admin contract still works against the busbar WE JUST BUILT: build the busbar-admin CLI from its
# sibling checkout and run its own scripts/integration.sh (every command, real-effect assertions)
# against the freshly-built engine binary. Catches an admin-API change that would break busbarctl
# BEFORE it ships — bidirectional testing, the same discipline the plugins get.
BUSBAR_ADMIN_SRC="${REPO_ROOT}/../busbar-admin"
if ! phase_selected phase-admin-cli; then
  record_phase_skip phase-admin-cli "not-in-segment"
elif [ -d "$BUSBAR_ADMIN_SRC" ]; then
  begin_phase phase-admin-cli "Phase: busbar-admin CLI — every command driven against the freshly-built busbar"
  cargo build --release --manifest-path "${BUSBAR_ADMIN_SRC}/Cargo.toml"
  ADMIN_BIN="${BUSBAR_ADMIN_SRC}/target/release/busbar-admin"
  [ -x "$ADMIN_BIN" ] || { echo "busbar-admin did not build at $ADMIN_BIN" >&2; exit 1; }
  bash "${BUSBAR_ADMIN_SRC}/scripts/integration.sh" "$BUSBAR_BIN" "$ADMIN_BIN"
  ok "busbar-admin: every command drove the freshly-built busbar end to end"
  end_phase ran
else
  note "SKIP: ../busbar-admin not present as a sibling checkout — busbarctl reverse-direction coverage skipped."
  record_phase_skip phase-admin-cli "sibling-missing"
fi

# ── 1.5.2 feature gate: plugins.fetch (hermetic) + token-exchange cross-repo matrix + admin authz ──
# Runs the NEW-1.5.2-functionality phases as part of this gate. Reuses the busbar binary +
# busbar-plugin-pack already built in Phase 0 (handed down via the exported BUSBAR_BIN/PACK_BIN, so
# it does NOT rebuild). Its token-exchange phase is registry-driven over every kind:auth plugin
# (plugins.yaml), the same single-source-of-truth this script's suite loop uses. Any failure there
# fails the whole gate (its own set -euo pipefail + ERR trap propagate through this invocation).
if ! phase_selected phase-152-feature-gate; then
  record_phase_skip phase-152-feature-gate "not-in-segment"
else
  begin_phase phase-152-feature-gate "1.5.2 feature gate (plugins.fetch + token-exchange matrix + admin authz matrix)"
  BUSBAR_BIN="$BUSBAR_BIN" PACK_BIN="$PACK_BIN" bash "${REPO_ROOT}/scripts/release-check-1.5.2.sh"
  ok "1.5.2 feature gate passed (see its own VERIFIED-AT-INTEGRATION notes above)"
  end_phase ran
fi

phase "RELEASE GATE PASSED${SEGMENT:+ (segment: ${SEGMENT})}"
echo "Total elapsed: ${SECONDS}s"
if [ -n "$SEGMENT" ]; then
  echo "This run covered ONLY segment '${SEGMENT}'. It is NOT the full gate on its own —"
  echo "the union of every segment in the partition is. Run --check-coverage to prove that union."
fi
for p in ${SUITE_PASSED[@]+"${SUITE_PASSED[@]}"}; do
  echo "${p} suite phase passed with real assertions (sibling checkout, registry-driven)."
done
for p in ${SUITE_SKIPPED[@]+"${SUITE_SKIPPED[@]}"}; do
  echo "NOTE: ${p}'s sibling checkout was not present (or --skip-docker suppressed its service) —"
  echo "its coverage was SKIPPED, not passed. Run on a machine with the sibling checked out (and"
  echo "Docker up) for full coverage before tagging, or confirm that repo's own CI is green."
done
if phase_selected phase-1-sqlite-binary; then
  if [ -n "${SQLITE_SKIPPED:-}" ]; then
    echo "NOTE: ../store-sqlite was not present locally — SQLite coverage was skipped, not passed. Run"
    echo "on a machine with ../store-sqlite checked out for full coverage before tagging, or confirm"
    echo "that repo's own CI is green."
  else
    echo "SQLite phase passed with real assertions (sibling checkout)."
  fi
fi
if phase_selected phase-5-smoke-headroom || phase_selected phase-5-smoke-webrequest; then
  if [ ! -d "$HEADROOM_SRC" ] || [ ! -d "$WEBREQUEST_SRC" ]; then
    echo "NOTE: one or both hook-plugin sibling repos were not present locally — that phase was"
    echo "partially or fully skipped. Run on a machine with ../headroom-hook and ../webrequest-hook"
    echo "checked out for full coverage before tagging, or confirm docker.yml's own smoke test is green."
  fi
fi

print_timing_summary
