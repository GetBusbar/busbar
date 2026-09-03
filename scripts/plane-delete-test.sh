#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# plane-delete-test.sh — THE STRONG-FORM DELETION TEST.
#
# WHY THIS EXISTS (docs/design/plane-extraction-design.md §1, §6.1):
#   The owner's literal requirement for a plane P ∈ {llm, mcp, a2a}: run `git rm -r crates/busbar-<P>`
#   and the NEUTRAL crates — busbar-core, busbar-substrate, busbar-api — must STILL COMPILE, and the
#   binary must still boot serving no P protocol. A protocol plane is a self-contained plugin merely
#   compiled in for convenience; take its crate away and core is unmoved.
#
#   ci.yml already runs the WEAK form of this (the `deletion-test-matrix` job): build the neutral
#   crates with a plane's cargo FEATURE off. That proves the neutral crates do not *reference* the
#   plane behind its feature, but it does NOT prove the crate can be *removed* — a `#[path]` witness
#   dual-compile, a dev-dependency back-edge, or a stray `../busbar-<P>/src` include all survive a
#   feature flip and only surface when the directory is actually gone. THIS script is the strong form:
#   it PHYSICALLY REMOVES `crates/busbar-<P>` in a scratch copy of the workspace and asserts the
#   neutral crates + bin still `cargo check`.
#
# THE SCRATCH MECHANISM (why a copy, and why THIS copy):
#   The neutral crates reach the plane sources through RELATIVE `#[path = "../../../busbar-<P>/src/…"]`
#   includes that escape the crate into a sibling directory, so the removal has to be tested against a
#   whole, self-consistent workspace tree — not a single crate in isolation. We build that tree by
#   TAR-COPYING the working tree (excluding target/, .git, .claude) into a fresh scratch dir, then
#   mutate the copy. This is the "cp -r excluding target/" option from the design, done with tar so the
#   exclude is portable to macOS bsdtar (which has no `cp --exclude`) and so a multi-GB target/ is never
#   copied. It is preferred over `git worktree add` for three reasons: it reflects the CURRENT working
#   tree (uncommitted edits included), it needs no git-registry bookkeeping / teardown, and it works
#   from inside a linked worktree where `git worktree add` to an external temp dir is refused. cargo is
#   driven with `--manifest-path "$SCRATCH/Cargo.toml"` so the real tree is never touched and `#[path]`
#   resolution (relative to each source file's own directory, inside the scratch) stays correct.
#
# WHAT IT MUTATES in the scratch, per plane P (the literal `git rm -r` + manifest fixups):
#   (a) rm -rf  crates/busbar-<P>
#   (b) drop    "crates/busbar-<P>"   from the workspace `members` in the root Cargo.toml
#   (c) in the bin (crates/busbar/Cargo.toml): delete the `busbar-<P> = { path = … , optional = true }`
#       dependency, strip the `dep:busbar-<P>` token from the feature that names it (leaving any neutral
#       forward such as `busbar-core/plane-<P>` intact), and drop that feature from `default` so a
#       default build of the bin is coherent without the plane.
#   Then `cargo check` the three neutral crates (with the removed plane's feature off, the others kept)
#   and the bin (default features, now minus the plane). Both compiling = the strong form PASSES for P.
#
# MODES (same posture as scripts/plane-purity-lint.sh — informational until the extraction lands):
#   --selftest        Prove the harness itself works before its verdict is trusted (run FIRST in CI):
#                     that the removal logic really removes the crate/member/dep (grep the scratch), and
#                     that the check-runner reports FAIL on a genuinely-coupled scratch (RED control) and
#                     PASS on a properly-neutralised one (GREEN control). Detects, never hard-codes, which
#                     planes the current tree couples. Green self-test is the acceptance bar.
#   --baseline        INFORMATIONAL. Runs the strong form for all three planes and prints per-plane
#                     PASS/FAIL with evidence. ALWAYS exits 0 — surfaced on every push WITHOUT reddening
#                     CI until the extraction lands, exactly like plane-purity-lint.sh --baseline.
#   <plane>           BLOCKING (fail-closed). Run the strong form for one plane; exit 0 = PASS (neutral
#                     crates + bin compile without the crate), exit 1 = FAIL (still coupled). This is the
#                     permanent per-plane gate the ci.yml matrix leg calls once the extraction is done.
#   --all             BLOCKING for all three planes at once (exit 1 if ANY plane still couples).
#
# WITNESS PROBE (--with-witness, informational): additionally `cargo check` busbar-core with the
#   `test-support` feature on. That turns on the `#[path]` dual-compile of the plane sources, so with the
#   crate gone it FAILS wherever the witness build still reaches around the ABI — the exact PATH-INCLUDE
#   coupling scripts/plane-purity-lint.sh already ledgers. It is reported separately from the shipped-build
#   verdict because a test-only dual-compile is not what "still compile" means to an operator.
#
# Fail-closed bash 3.2 + POSIX (awk for the manifest edits, tar for the copy). No python, no git-write —
# the same bare-runner posture as proto-deletion-gate.sh / plane-purity-lint.sh.
set -uo pipefail
cd "$(dirname "$0")/.."
REPO="$(pwd)"

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

# The plane key set is single-sourced (scripts/plane-keys.sh) so this test cannot silently no-op on
# a plane it was never told about — adding a plane there arms this harness for it automatically.
# shellcheck source=scripts/plane-keys.sh
. "$(dirname "$0")/plane-keys.sh"
PLANES="$PLANE_KEYS"

command -v tar   >/dev/null 2>&1 || { echo "plane-delete-test: tar not found"   >&2; exit 2; }
command -v cargo >/dev/null 2>&1 || { echo "plane-delete-test: cargo not found" >&2; exit 2; }

# ── per-plane metadata ────────────────────────────────────────────────────────────────────────────
# The bin FEATURE that names the plane's `dep:busbar-<P>` (llm rides `proto-llm`; mcp/a2a ride the
# plane-kind name). The NEUTRAL feature set to keep ON for the neutral-crate check (every default plane
# EXCEPT the one being removed) — llm has no neutral-side feature of its own, so removing it keeps both
# plane-mcp and plane-a2a. A crate/feature that appears or moves is a one-line edit here.
# `voice` (busbar-voice, Plane 4) is a SKELETON crate NOT yet wired into the bin: it has no
# `dep:busbar-voice` optional dependency and no bin feature. Its bin_feature is the forward-looking
# `plane-voice` (matches nothing in the bin today, so neutralise_bin is a no-op for it); its
# neutral_keep is the full default plane set (removing voice touches neither mcp nor a2a).
bin_feature() { case "$1" in llm) echo proto-llm ;; mcp) echo plane-mcp ;; a2a) echo plane-a2a ;; voice) echo plane-voice ;; esac; }
neutral_keep() {
  case "$1" in
    llm) echo "plane-mcp,plane-a2a" ;;
    mcp) echo "plane-a2a" ;;
    a2a) echo "plane-mcp" ;;
    voice) echo "plane-mcp,plane-a2a" ;;
  esac
}
valid_plane() { case " $PLANES " in *" $1 "*) return 0 ;; *) return 1 ;; esac; }

# ── scratch lifecycle ─────────────────────────────────────────────────────────────────────────────
# Scratch tree base: TMPDIR by default (CI house-style, same as proto-deletion-gate.sh). Overridable so
# a sandboxed run can put it under the repo's own target/ (which is excluded from the copy, so no
# self-recursion). A SHARED cargo target dir under target/ (gitignored) is reused across planes so the
# ~130 external deps compile once, not once per plane.
SCRATCH_BASE="${PLANE_DELETE_SCRATCH_BASE:-${TMPDIR:-/tmp}}"
CACHE_TARGET="${PLANE_DELETE_CARGO_TARGET:-$REPO/target/plane-delete-cache}"
SCRATCHES=""   # space-separated list of scratch dirs to tear down

cleanup() { local d; for d in $SCRATCHES; do rm -rf "$d" 2>/dev/null; done; }
trap cleanup EXIT
trap 'cleanup; exit 130' INT
trap 'cleanup; exit 143' TERM HUP

# make_scratch → echoes a fresh scratch dir populated with a copy of the working tree.
make_scratch() {
  local s
  s="$(mktemp -d "$SCRATCH_BASE/plane-delete-test.XXXXXX")" || return 1
  SCRATCHES="$SCRATCHES $s"
  # Copy the working tree, excluding the heavy/irrelevant dirs. Excluding ./target also auto-excludes an
  # in-repo SCRATCH_BASE (which lives under target/), so the copy never ingests itself.
  ( cd "$REPO" && tar --exclude='./target' --exclude='./.git' --exclude='./.claude' -cf - . ) \
    | ( cd "$s" && tar -xf - ) || return 1
  printf '%s\n' "$s"
}

# ── the mutations (awk/sed, operating on files INSIDE the scratch) ─────────────────────────────────
# remove_crate_dir  — the literal `git rm -r crates/busbar-<P>`.
remove_crate_dir() { rm -rf "$1/crates/busbar-$2"; }

# drop_member — delete the `"crates/busbar-<P>",` line from the root workspace members.
drop_member() {
  local s="$1" p="$2" f="$1/Cargo.toml" t
  t="$f.plane-delete.tmp"
  awk -v pat="\"crates/busbar-$p\"" '
    index($0, pat) > 0 { next }   # the members entry (only place this exact token appears)
    { print }
  ' "$f" >"$t" && mv "$t" "$f"
}

# neutralise_bin — (c): drop the dep line; strip the `dep:busbar-<P>` token from its feature; strip any
# `busbar-<P>?/…` optional-dep feature reference wherever it appears (e.g. openapi-schema) — those become
# manifest-load ERRORS the moment the optional dep is gone, so they must go too; drop the plane feature
# from `default` so a default bin build is coherent.
neutralise_bin() {
  local s="$1" p="$2" f="$1/crates/busbar/Cargo.toml" t feat
  feat="$(bin_feature "$p")"
  t="$f.plane-delete.tmp"
  awk -v p="$p" -v feat="$feat" '
    function norm(line) {
      gsub(/,[[:space:]]*,/, ", ", line)      # normalise a comma left behind by a stripped token
      gsub(/\[[[:space:]]*,/, "[", line)
      gsub(/,[[:space:]]*\]/, "]", line)
      gsub(/\[[[:space:]]*\]/, "[]", line)
      return line
    }
    BEGIN {
      deppat  = "^busbar-" p "[[:space:]]*=[[:space:]]*\\{[[:space:]]*path[[:space:]]*=[[:space:]]*\"\\.\\./busbar-" p "\""
      featpat = "^" feat "[[:space:]]*=[[:space:]]*\\["
      optpat  = "\"busbar-" p "\\?/[^\"]*\""    # an optional-dep feature ref: "busbar-<P>?/<feature>"
      deptok  = "\"dep:busbar-" p "\""
      feattok = "\"" feat "\""
    }
    { line = $0 }
    line ~ deppat { next }                      # (c1) delete the optional dependency line entirely
    { gsub(optpat, "", line) }                  # (c2) strip busbar-<P>?/… refs (openapi-schema, …)
    line ~ featpat { gsub(deptok, "", line) }   # (c3) strip dep:busbar-<P> from its own feature
    line ~ /^default[[:space:]]*=[[:space:]]*\[/ { gsub(feattok, "", line) }  # (c4) drop from default
    { print norm(line) }
  ' "$f" >"$t" && mv "$t" "$f"
}

# strip_workspace_edges — remove any dangling `busbar-<P> = { path = … }` dependency line from EVERY
# OTHER crate's manifest (normal / dev / build). This is the load-bearing subtlety of the STRONG form:
# `busbar-core` carries a DEV-dependency back-edge on busbar-mcp / busbar-a2a (for its own cross-plane
# integration tests). A plain `cargo check` never COMPILES a dev-dep, but cargo still LOADS every member
# manifest to resolve the virtual workspace, and a path dep whose directory is gone makes it REFUSE
# before compiling a single line — so without this we would measure manifest hygiene, not source
# coupling. Removing a now-dangling path dep is mechanical `git rm -r` cleanup, not a design change; the
# crates that carried such an edge are RECORDED in EDGE_CRATES and reported as residual coupling (a bare
# `git rm -r` would dangle them, so the removal severs the back-edge too (the plane-purity lint ledgers it).
EDGE_CRATES=""
strip_workspace_edges() {
  local s="$1" p="$2" f t base
  EDGE_CRATES=""
  for f in "$s"/crates/*/Cargo.toml; do
    [ "$f" = "$s/crates/busbar/Cargo.toml" ] && continue   # the bin is handled by neutralise_bin
    if grep -q "^busbar-$p[[:space:]]*=[[:space:]]*{" "$f" 2>/dev/null; then
      base="$(basename "$(dirname "$f")")"
      EDGE_CRATES="$EDGE_CRATES $base"
      t="$f.plane-delete.tmp"
      awk -v p="$p" '$0 ~ ("^busbar-" p "[[:space:]]*=[[:space:]]*\\{") { next } { print }' "$f" >"$t" && mv "$t" "$f"
    fi
  done
}

# apply_removal — the literal `git rm -r` reversal for one plane, in one scratch: (a) the crate dir,
# (b) the workspace member, (c) the bin dep + feature, (d) any dangling path-dep back-edge elsewhere.
apply_removal() {
  local s="$1" p="$2"
  remove_crate_dir     "$s" "$p"
  drop_member          "$s" "$p"
  neutralise_bin       "$s" "$p"
  strip_workspace_edges "$s" "$p"
}

# ── the check runner ──────────────────────────────────────────────────────────────────────────────
# run_check <scratch> <logfile> -- <cargo args…>   → returns cargo's exit code.
# A SHARED target dir keeps external-dep artifacts warm across planes. `--locked` is deliberately NOT
# passed: we edited Cargo.toml, so the lock is intentionally a superset and must not gate the build.
run_check() {
  local s="$1" log="$2"; shift 2
  [ "$1" = "--" ] && shift
  CARGO_TARGET_DIR="$CACHE_TARGET" cargo check --manifest-path "$s/Cargo.toml" "$@" >"$log" 2>&1
}

# strong_form <plane>  → 0 (PASS) / 1 (FAIL). Prints the two legs (neutral crates, bin) with evidence.
strong_form() {
  local p="$1" s keep log rc fail=0
  keep="$(neutral_keep "$p")"
  s="$(make_scratch)" || { red "  scratch copy failed"; return 1; }
  apply_removal "$s" "$p"

  # Evidence that the removal is REAL, printed before the compile so a green is never taken on faith.
  local ev_dir ev_mem ev_dep
  ev_dir="$([ -d "$s/crates/busbar-$p" ] && echo PRESENT || echo GONE)"
  ev_mem="$(grep -c "\"crates/busbar-$p\"" "$s/Cargo.toml" 2>/dev/null)"; ev_mem="${ev_mem:-0}"
  ev_dep="$(grep -c "^busbar-$p = " "$s/crates/busbar/Cargo.toml" 2>/dev/null)"; ev_dep="${ev_dep:-0}"
  note "removed: crate dir=$ev_dir  members-refs=$ev_mem  bin-dep-lines=$ev_dep  (all must read GONE/0)"
  if [ -n "$EDGE_CRATES" ]; then
    ylw "  residual manifest back-edge: neutral/other crate(s) declared a path-dep on busbar-$p —${EDGE_CRATES}"
    note "    (stripped as part of the removal; a bare \`git rm -r\` would dangle it)"
  fi

  # Leg 1 — the NEUTRAL crates (the owner's literal requirement).
  log="$CACHE_TARGET/.plane-delete-$p-neutral.log"; mkdir -p "$CACHE_TARGET"
  run_check "$s" "$log" -- -p busbar-core -p busbar-substrate -p busbar-api \
    --no-default-features --features "$keep"; rc=$?
  if [ "$rc" -eq 0 ]; then
    grn "  neutral crates compile without busbar-$p (features: ${keep:-none})"
  else
    fail=1; red "  neutral crates DO NOT compile without busbar-$p — still coupled"
    grep -m4 -E "error(\[|:)|couldn't read" "$log" 2>/dev/null | sed 's/^/      /'
  fi

  # Leg 2 — the composition-root BIN with the plane's feature off (neutral crates + bin).
  log="$CACHE_TARGET/.plane-delete-$p-bin.log"
  run_check "$s" "$log" -- -p busbar; rc=$?
  if [ "$rc" -eq 0 ]; then
    grn "  bin (busbar) compiles with $(bin_feature "$p") off and busbar-$p gone"
  else
    fail=1; red "  bin (busbar) DOES NOT compile without busbar-$p"
    grep -m4 -E "error(\[|:)|couldn't read" "$log" 2>/dev/null | sed 's/^/      /'
  fi

  # Optional witness probe (informational): the test-support #[path] dual-compile.
  if [ "${WITH_WITNESS:-0}" = "1" ]; then
    log="$CACHE_TARGET/.plane-delete-$p-witness.log"
    run_check "$s" "$log" -- -p busbar-core --no-default-features --features "$keep,test-support"; rc=$?
    if [ "$rc" -eq 0 ]; then
      note "witness probe: test-support build ALSO compiles without busbar-$p (no #[path] dual-compile reaches it)"
    else
      ylw "  witness probe: test-support build reaches AROUND the ABI into the removed busbar-$p (PATH-INCLUDE ledger)"
      grep -m2 -E "couldn't read" "$log" 2>/dev/null | sed 's/^/      /'
    fi
  fi

  return "$fail"
}

# ── SELF-TEST — the harness cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "plane-delete-test SELF-TEST (the removal + verdict machinery proves itself)"
  local fail=0 p s

  # (1) REMOVAL EVIDENCE for EVERY plane (fast, no compile): the mutation really removes the crate dir,
  #     the members entry, and the bin dependency line. This is the unfakeable mechanism proof.
  for p in $PLANES; do
    s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
    apply_removal "$s" "$p"
    local ok=1
    [ -d "$s/crates/busbar-$p" ] && { ok=0; note "REMOVAL FAILED ($p): crate dir still present"; }
    [ "$(grep -c "\"crates/busbar-$p\"" "$s/Cargo.toml")" -eq 0 ] || { ok=0; note "REMOVAL FAILED ($p): members entry survives"; }
    [ "$(grep -c "^busbar-$p = " "$s/crates/busbar/Cargo.toml")" -eq 0 ] || { ok=0; note "REMOVAL FAILED ($p): bin dep line survives"; }
    [ "$(grep -c "\"dep:busbar-$p\"" "$s/crates/busbar/Cargo.toml")" -eq 0 ] || { ok=0; note "REMOVAL FAILED ($p): \"dep:busbar-$p\" token survives in a feature"; }
    if [ "$ok" -eq 1 ]; then note "PASS  removal($p): crate dir + members entry + bin dep + dep: token all gone"; else fail=1; fi
    rm -rf "$s"
  done

  # A representative plane for the compile controls (bounded self-test time; the mechanism is identical
  # for all three, proven above). `mcp` keeps the other two planes' shape intact around it.
  local rp=mcp

  # (2) RED CONTROL — a genuinely-coupled scratch MUST report FAIL. We remove the crate dir + member but
  #     DELIBERATELY SKIP the bin neutralisation, so the bin still carries `dep:busbar-<rp>` pointing at a
  #     now-missing path. cargo resolution must fail, and the harness must return non-zero. This proves
  #     the FAIL path fires on real coupling — WITHOUT hard-coding that any particular plane fails today.
  s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
  remove_crate_dir "$s" "$rp"
  drop_member      "$s" "$rp"     # note: neutralise_bin intentionally OMITTED
  local log rc
  log="$CACHE_TARGET/.plane-delete-selftest-red.log"; mkdir -p "$CACHE_TARGET"
  run_check "$s" "$log" -- -p busbar; rc=$?
  if [ "$rc" -ne 0 ]; then
    note "PASS  RED control: dangling dep:busbar-$rp → harness check returns non-zero (coupling → FAIL)"
  else
    fail=1; note "FAIL  RED control: a scratch with a dangling busbar-$rp dep compiled — the gate would miss coupling"
  fi
  rm -rf "$s"

  # (3) GREEN CONTROL — a PROPERLY neutralised scratch MUST report PASS: the full removal, then the
  #     neutral crates compile. This is the positive control mirroring the RED one.
  s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
  apply_removal "$s" "$rp"
  log="$CACHE_TARGET/.plane-delete-selftest-green.log"
  run_check "$s" "$log" -- -p busbar-core -p busbar-substrate -p busbar-api \
    --no-default-features --features "$(neutral_keep "$rp")"; rc=$?
  if [ "$rc" -eq 0 ]; then
    note "PASS  GREEN control: full removal of busbar-$rp → neutral crates compile (verdict machinery clean-passes)"
  else
    fail=1; note "FAIL  GREEN control: neutral crates did not compile after a clean removal of busbar-$rp"
    grep -m4 -E "error(\[|:)|couldn't read" "$log" 2>/dev/null | sed 's/^/      /'
  fi
  rm -rf "$s"

  if [ "$fail" -eq 0 ]; then
    grn "plane-delete-test self-test: ALL GREEN (removal real; FAIL reported on coupling, PASS on a clean removal)"
    return 0
  fi
  red "plane-delete-test self-test: FAILED — do not trust the tree verdict below"
  return 1
}

# ── baseline (informational) ──────────────────────────────────────────────────────────────────────
run_baseline() {
  hdr "STRONG-FORM deletion test — per-plane (INFORMATIONAL: always exits 0)"
  note "each plane: crates/busbar-<P> PHYSICALLY REMOVED, then neutral crates + bin cargo-checked"
  local p any_fail=0
  for p in $PLANES; do
    hdr "plane: $p"
    if strong_form "$p"; then grn "  → $p: STRONG-FORM PASS"; else ylw "  → $p: STRONG-FORM FAIL (still coupled)"; any_fail=1; fi
  done
  hdr "verdict"
  if [ "$any_fail" -eq 0 ]; then
    grn "plane-delete: all three planes are strong-form removable today. Arm the ci.yml matrix leg."
  else
    ylw "plane-delete: at least one plane still couples — a regression (this baseline mode is informational)."
    note "The baseline is informational and never reddens CI; a coupled plane here is a regression to fix."
    note "The blocking gate is \`plane-delete-test.sh <plane>\`, wired per-plane into the ci.yml deletion matrix."
  fi
  return 0
}

# ── modes ─────────────────────────────────────────────────────────────────────────────────────────
case "${1:-}" in
  --selftest) run_selftest; exit $? ;;
  --baseline) run_baseline; exit 0 ;;
  --all)
    fail=0
    for p in $PLANES; do
      hdr "plane: $p"
      strong_form "$p" || fail=1
    done
    hdr "verdict"
    if [ "$fail" -eq 0 ]; then grn "plane-delete gate: PASS — all three planes strong-form removable"; exit 0; fi
    red "plane-delete gate: FAIL — a plane's neutral crates still need its crate to compile"; exit 1
    ;;
  --with-witness) export WITH_WITNESS=1; shift; exec "$0" "${1:---baseline}" ;;
  -h | --help) sed -n '2,60p' "$0" ;;
  "" ) echo "usage: $0 [--selftest | --baseline | --all | <llm|mcp|a2a|voice>] [--with-witness]" >&2; exit 2 ;;
  *)
    if valid_plane "$1"; then
      hdr "STRONG-FORM deletion test — plane: $1"
      if strong_form "$1"; then
        grn "plane-delete gate ($1): PASS — neutral crates + bin compile with busbar-$1 physically gone"
        exit 0
      fi
      red "plane-delete gate ($1): FAIL — a neutral crate or the bin still needs busbar-$1 to compile"
      exit 1
    fi
    echo "usage: $0 [--selftest | --baseline | --all | <llm|mcp|a2a|voice>] [--with-witness]" >&2; exit 2
    ;;
esac
