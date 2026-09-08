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
#   BOOT+SERVE, EVERY PLANE, AGAINST A MEASURED CONTROL (tracker C13): compiling is not booting, so
#   each plane's strong-form removal additionally BUILDS (not just checks) the bin from the same
#   scratch and BOOTS it — twice, since an `mcp:` block forces a closed auth chain and every other
#   plane is probed on an open one. The verdict is never a bare 404: the gate first builds and boots
#   the UNMUTATED tree and MEASURES what each plane's probe answers with its crate present, and a
#   plane's 404 counts only as a DIFFERENCE from that control, with every neighbour still serving.
#   This leg used to exist for `llm` alone, and its one assertion was a 404 that the calibration
#   proved was the answer either way. See `boot_serve` / `judge_codes` below.
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
# Fail-closed bash 3.2 + POSIX (awk for the manifest edits, tar for the copy, python3 stdlib only for
# the llm boot leg's port-pair picker — the same TOCTOU-minimising helper proto-deletion-gate.sh uses).
# No git-write — the same bare-runner posture as proto-deletion-gate.sh / plane-purity-lint.sh.
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
# `voice` (busbar-voice, Plane 4) is WIRED into the bin and DEFAULT-ON, on both of its features: it has
# a `dep:busbar-voice` optional dependency and the `plane-voice` bin feature, whose forwards to the
# plane crate are `dep:busbar-voice`, `busbar-voice?/runtime` and `busbar-voice?/openapi-schema` — all
# three stripped by neutralise_bin. Its bin_feature is `plane-voice`; its neutral_keep is the full
# default plane set (removing voice touches neither mcp nor a2a). Because `root-voice` also ships in
# `default` and FORWARDS to `plane-voice`, the bin's default build is coherent without the crate only
# once both come out — which is what neutralise_bin's forwarding closure is for.
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
# `busbar-<P>/…` feature reference wherever it appears (e.g. openapi-schema, root-llm) — those become
# manifest-load ERRORS the moment the optional dep is gone, so they must go too; drop the plane feature
# from `default` so a default bin build is coherent.
#
# BOTH SPELLINGS of that reference, and the second one is why this note exists. Cargo writes an
# optional dependency's feature as `busbar-<P>?/<feature>` when the reference must not ENABLE the
# dep, and as `busbar-<P>/<feature>` when it may — and the bin uses the second form for `root-llm`
# (`busbar-llm/teller-waist`). A pattern that matched only the `?` form left that one behind, and the
# scratch's manifest then failed to LOAD ("feature `root-llm` includes `busbar-llm/teller-waist`, but
# `busbar-llm` is not a dependency"), which aborts before a single line is compiled — so all three
# legs reported the llm plane as still coupled when what they had measured was the removal's own
# manifest hygiene.
#
# The plane feature leaves `default` together with EVERY DEFAULT FEATURE THAT FORWARDS TO IT.
#
# The closure is the load-bearing word, and it is what an operator doing the literal `git rm -r` has to
# do by hand. Dropping only the plane's own feature leaves any SWITCH-OVER feature that forwards to it
# (`root-<P> = ["plane-<P>"]`) sitting in `default`, quietly turning the plane feature straight back on:
# the crate is gone, the feature is on, and the composition root's module for that plane names a crate
# that no longer exists. That reads as source coupling and is not — it is a manifest the removal left
# half-done. Computed as a fixpoint over the [features] table rather than listed, because a list here
# would be a second answer to "which features reach this plane", and the manifest is the first one.
reaching_features() {
  awk -v feat="$2" '
    /^\[/ { in_f = ($0 ~ /^\[features\]/) }
    !in_f { next }
    /^[A-Za-z0-9_-]+[[:space:]]*=[[:space:]]*\[/ {
      name = $0; sub(/[[:space:]]*=.*/, "", name)
      body = $0;  sub(/^[^\[]*\[/, "", body); sub(/\].*$/, "", body)
      names[++n] = name; bodies[name] = body
    }
    END {
      # The reached set is carried as an ORDERED LIST, not as the keys of an associative array.
      # Reading `a[k]` in awk CREATES `a[k]`, so a membership test written as a lookup quietly
      # enrolls every name it asks about and the closure answers "everything" — which is not a
      # conservative over-approximation here, it is the whole default set deleted.
      rn = 1; rl[1] = feat; is_reached[feat] = 1
      do {
        # Two phases per round: decide, then add. Growing a set mid-scan is a set nobody can
        # predict the contents of.
        add_n = 0
        for (i = 1; i <= n; i++) {
          nm = names[i]
          if (nm == "default" || (nm in is_reached)) continue
          for (j = 1; j <= rn; j++) {
            if (index(bodies[nm], "\"" rl[j] "\"") > 0) { add[++add_n] = nm; break }
          }
        }
        for (i = 1; i <= add_n; i++) { rl[++rn] = add[i]; is_reached[add[i]] = 1 }
      } while (add_n > 0)
      for (j = 1; j <= rn; j++) printf "%s\n", rl[j]
    }
  ' "$1"
}

neutralise_bin() {
  local s="$1" p="$2" f="$1/crates/busbar/Cargo.toml" t feat reach
  feat="$(bin_feature "$p")"
  # SPACE-separated, not newline: `awk -v` refuses a literal newline in an assignment, and a feature
  # name never contains a space, so the flatter list loses nothing.
  reach="$(reaching_features "$f" "$feat" | tr '\n' ' ')"
  t="$f.plane-delete.tmp"
  awk -v p="$p" -v feat="$feat" -v reach="$reach" '
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
      optpat  = "\"busbar-" p "\\??/[^\"]*\""   # a dep feature ref, either spelling: "busbar-<P>[?]/<feature>"
      deptok  = "\"dep:busbar-" p "\""
      nreach  = split(reach, reachtok, " ")
    }
    { line = $0 }
    line ~ deppat { next }                      # (c1) delete the optional dependency line entirely
    { gsub(optpat, "", line) }                  # (c2) strip busbar-<P>[?]/… refs (openapi-schema, root-llm, …)
    line ~ featpat { gsub(deptok, "", line) }   # (c3) strip dep:busbar-<P> from its own feature
    # (c4) drop the removed plane feature AND every feature forwarding to it from `default`
    line ~ /^default[[:space:]]*=[[:space:]]*\[/ {
      for (i = 1; i <= nreach; i++) if (reachtok[i] != "") gsub("\"" reachtok[i] "\"", "", line)
    }
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

# strip_feature_edges — remove any [features]-table entry that NAMES the removed plane crate, in EVERY
# manifest in the scratch (root + every crate, including the bin): the hard forward
# `"busbar-<P>/<feature>"`, the optional forward `"busbar-<P>?/<feature>"`, and the bare optional-dep
# token `"dep:busbar-<P>"`. This is the dangle strip_workspace_edges (path deps only) cannot see: a
# NEUTRAL crate can name the plane in its OWN feature table without the plane ever being a normal
# dependency of that crate — busbar-core's `openapi-schema` forwards to
# `busbar-llm/openapi-schema`, `busbar-mcp/openapi-schema`, `busbar-a2a/openapi-schema` while busbar-core
# depends on those crates only as DEV-dependencies (which strip_workspace_edges already severs). Once the
# crate is gone and its back-edge dep line is stripped, that feature string names a package that is no
# longer ANY dependency of the manifest declaring it, and cargo refuses to load the manifest before a
# single line compiles — the same manifest-load refusal strip_workspace_edges exists to prevent, one
# table over. Removing a now-dangling feature ref is mechanical `git rm -r` cleanup, not a design change;
# the crates that carried one are RECORDED in FEATURE_EDGE_CRATES and reported as residual coupling
# exactly like EDGE_CRATES.
FEATURE_EDGE_CRATES=""
strip_feature_edges() {
  local s="$1" p="$2" f t hit
  FEATURE_EDGE_CRATES=""
  for f in "$s/Cargo.toml" "$s"/crates/*/Cargo.toml; do
    [ -f "$f" ] || continue
    hit="$(grep -c -E "\"busbar-$p\\??/[^\"]*\"|\"dep:busbar-$p\"" "$f" 2>/dev/null)"; hit="${hit:-0}"
    [ "$hit" -eq 0 ] && continue
    FEATURE_EDGE_CRATES="$FEATURE_EDGE_CRATES $(basename "$(dirname "$f")")"
    t="$f.plane-delete.tmp"
    awk -v p="$p" '
      function norm(line) {
        gsub(/,[[:space:]]*,/, ", ", line)
        gsub(/\[[[:space:]]*,/, "[", line)
        gsub(/,[[:space:]]*\]/, "]", line)
        gsub(/\[[[:space:]]*\]/, "[]", line)
        return line
      }
      BEGIN {
        hardpat = "\"busbar-" p "/[^\"]*\""
        optpat  = "\"busbar-" p "\\?/[^\"]*\""
        deptok  = "\"dep:busbar-" p "\""
      }
      {
        line = $0
        gsub(optpat, "", line)
        gsub(hardpat, "", line)
        gsub(deptok, "", line)
        print norm(line)
      }
    ' "$f" >"$t" && mv "$t" "$f"
  done
}

# apply_removal — the literal `git rm -r` reversal for one plane, in one scratch: (a) the crate dir,
# (b) the workspace member, (c) the bin dep + feature, (d) any dangling path-dep back-edge elsewhere,
# (e) any dangling feature-table reference (hard/optional forward or bare `dep:` token) elsewhere.
apply_removal() {
  local s="$1" p="$2"
  remove_crate_dir     "$s" "$p"
  drop_member          "$s" "$p"
  neutralise_bin       "$s" "$p"
  strip_workspace_edges "$s" "$p"
  strip_feature_edges   "$s" "$p"
}

# ── PICKING A FREE PORT PAIR ─────────────────────────────────────────────────────────────────────
# Same TOCTOU-minimising approach as scripts/proto-deletion-gate.sh's `free_port`: bind a
# CONSECUTIVE PAIR (data + admin) low in the range and hold both until the moment we print, so a
# sibling gate's own boot cannot steal the number between our check and busbar's bind.
free_port_pair() {
  python3 - <<'PYEOF' 2>/dev/null
import socket, random
for _ in range(200):
    base = random.randrange(30000, 45000, 2)
    socks = []
    try:
        for port in (base, base + 1):
            s = socket.socket()
            s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 0)
            s.bind(("127.0.0.1", port))
            socks.append(s)
        print(base)
        break
    except OSError:
        continue
    finally:
        for s in socks:
            s.close()
PYEOF
}

# ── BOOT+SERVE LEG, FOR EVERY PLANE, WITH A POSITIVE CONTROL (tracker C13) ───────────────────────
#
# The `strong_form` legs above are cargo-CHECK only — they prove the neutral crates and the bin still
# COMPILE with `crates/busbar-<P>` physically gone. "Compiles" is not "boots and serves", so this
# leg BUILDS the bin for real from the mutated scratch, BOOTS it, and asks the running server
# whether the removed plane's route is actually gone.
#
# TWO THINGS WERE WRONG WITH THE SHAPE THIS REPLACES, and they compounded.
#
#  1. THE LEG EXISTED FOR `llm` ALONE. `strong_form` ran it under `if [ "$p" = "llm" ]`, so mcp, a2a
#     and voice were proven only to COMPILE without their crate. A plane whose crate is gone but
#     whose route is still mounted from somewhere else (a re-exported router, a leftover fallback,
#     a neutral-side registration that outlived the crate) is exactly the coupling this gate exists
#     to catch, and for three of the four planes nothing was looking. Every plane gets the leg now;
#     the probe table below is the only per-plane knowledge.
#
#  2. THE 404 ASSERTION HAD NO POSITIVE CONTROL. The whole claim rested on one line —
#     `POST /v1/chat/completions` answers 404 — and NOTHING anywhere established that this request
#     is non-404 when the plane IS present. A 404 is the answer an HTTP server gives to a great many
#     mistakes: a renamed route, a typo'd path, a wrong method, a config that never mounted the
#     plane in the first place, a body the router rejects before dispatch. Every one of those makes
#     the assertion pass while proving nothing about the deletion. An unfalsifiable green.
#
# THE FIX IS A CALIBRATION, NOT A LIST OF EXPECTED CODES. The gate does not hard-code what a mounted
# plane answers — it MEASURES it. Before any verdict, it builds and boots the UNMUTATED tree and
# probes every plane's route with the byte-identical request it will later send to the mutated
# binary. That run is the CONTROL: it is what "this plane is present" looks like through this exact
# probe, on this exact config, on this exact server. A control code of 404 is itself a hard failure
# — it means the probe cannot tell presence from absence, so no verdict taken with it is worth
# anything, which is the state the gate was silently in.
#
# The verdict for plane P is then a DIFFERENCE against that control, which is the only form in which
# a 404 carries information:
#     control[P] != 404   the probe reaches a real route when P is compiled in  (the positive control)
#     subject[P] == 404   and the same request 404s once P's crate is gone      (the deletion)
#     subject[Q] != 404   while every neighbour Q that the control mounted still serves
# The third line is the neighbour control: it separates "P's route left with P's crate" from "this
# boot mounted nothing / the server is broken / the config was rejected", which produce 404 for
# every plane at once and used to be indistinguishable from a pass.
#
# TWO BOOT CONFIGS, not one, and the reason is auth. An `mcp:` block REFUSES to boot on an open
# chain (config_validate: "auth.chain is empty ... serves the MCP server endpoint to ANONYMOUS
# callers"), so mounting MCP forces a closed `auth: { chain: [keys] }` — under which an
# unauthenticated probe is 401'd before routing is ever consulted, masking "the route is gone"
# behind "the request wasn't authenticated". So MCP is probed on its own closed boot via its one
# unauthenticated route (the protected-resource metadata), and every other plane is probed on an
# OPEN boot where auth cannot be the reason for anything. `plane_probe_boot` says which is which.

# ── THE PER-PLANE PROBE TABLE ────────────────────────────────────────────────────────────────────
# The ONLY per-plane knowledge in this leg: which boot mounts the plane, and the exact request that
# reaches its route. Adding a plane is four lines here. Every code these probes produce is measured,
# never assumed — see the calibration above.
plane_probe_boot() {   # which boot config mounts this plane: `mcp` (closed chain) or `open`
  case "$1" in mcp) echo mcp ;; *) echo open ;; esac
}
# THE LLM PROBE IS A `GET`, AND THAT IS THE WHOLE POINT — see the calibration note below.
plane_probe_method() { case "$1" in mcp | llm) echo GET ;; *) echo POST ;; esac; }
plane_probe_path() {
  case "$1" in
    llm)   echo "/v1/chat/completions" ;;
    mcp)   echo "/.well-known/oauth-protected-resource/mcp" ;;
    a2a)   echo "/a2a" ;;
    voice) echo "/v1/realtime/client_secrets" ;;
  esac
}
plane_probe_body() {
  case "$1" in
    a2a)   printf '{"jsonrpc":"2.0","method":"message/send","id":1}' ;;
    voice) printf '{"model":"gpt-realtime"}' ;;
    llm | mcp) printf '' ;;
  esac
}

# ── WHAT THE CALIBRATION FOUND THE FIRST TIME IT RAN, and why the llm probe is the shape it is ────
#
# The probe this leg INHERITED was `POST /v1/chat/completions` with a chat body. Run against the
# UNMUTATED tree — busbar-llm present, compiled in, its router mounted — it answers **404**. Not
# because the plane is missing: because the request names a model, and this boot deliberately
# configures ZERO models, so the money path answers "no such model" with a 404 envelope.
#
# So the single assertion the old llm leg rested on — "POST /v1/chat/completions is 404, therefore
# the LLM plane's route left with the crate" — was true before the deletion, true after it, and true
# of a binary that never had busbar-llm at all. It could not have failed. It was measured, not
# reasoned: `--probe-control` printed 404 for llm on the first run of this calibration.
#
# `GET /v1/chat/completions` separates the two questions, because axum answers them differently:
#   route mounted, method not allowed  ->  405   (the plane is compiled in)
#   no such route at all               ->  404   (the plane left with its crate)
# It interrogates the SAME money-path route the tracker row names, and its answer moves when — and
# only when — the plane does. The other three planes' probes were measured at the same time and do
# discriminate as written: mcp 200, a2a 503, voice 501, all non-404 with their crates present.
#
# Nothing here is trusted on the strength of that paragraph. Every one of these codes is re-measured
# by `control_codes` on every run, and a probe that has drifted back to 404 fails the positive
# control instead of quietly passing the gate.

# write_boot_config <mode> <dir> <port> <admin_port> — the two configs, written into <dir>.
#   mcp   closed chain (`auth.chain: [keys]`), `mcp:` mounted. Only the metadata route is open.
#   open  no chain at all; `agents:`/`public_url` (A2A) and the realtime block (voice) mounted, so
#         a 404 on this boot can never be an auth refusal in disguise.
# Both name ZERO providers and ZERO models: a plane's ROUTE must mount from its crate being
# compiled in, never from a pool happening to be configured.
write_boot_config() {
  local mode="$1" dir="$2" port="$3" admin_port="$4"
  printf '{}\n' >"$dir/providers.yaml"
  case "$mode" in
    mcp)
      printf 'listen: "127.0.0.1:%s"\nadmin_listen: "127.0.0.1:%s"\npublic_url: https://busbar.example.com\nproviders: {}\nmodels: {}\nidentity-providers:\n  admin-tokens:\n    module: admin-tokens\n    token: { env: BUSBAR_ADMIN_TOKEN }\nauth:\n  signing_key: { env: BUSBAR_SIGNING_KEY }\n  chain: [keys]\n  admin_auth: [admin-tokens]\nmcp:\n  canonical_uri: https://busbar.example.com/mcp\n  authorization_servers:\n    - https://login.example.com\n' \
        "$port" "$admin_port" >"$dir/config.yaml"
      ;;
    open)
      printf 'listen: "127.0.0.1:%s"\nadmin_listen: "127.0.0.1:%s"\npublic_url: https://busbar.example.com\nproviders: {}\nmodels: {}\nagents:\n  probe:\n    url: https://remote-agent.example.com/a2a\n    pin:\n      mechanism: unpinned\n' \
        "$port" "$admin_port" >"$dir/config.yaml"
      ;;
  esac
}

# boot_and_probe <bin> <mode> <label> <outfile>
#   Boot <bin> on the <mode> config, probe EVERY plane whose `plane_probe_boot` is <mode>, and append
#   one `<plane>=<http-code>` line per plane to <outfile>. Returns non-zero only if the binary never
#   came up — the codes themselves are data for the caller to judge, never a verdict taken here.
boot_and_probe() {
  local bin="$1" mode="$2" label="$3" out="$4"
  local ports port admin_port fix pid up probe code p method path body

  ports="$(free_port_pair)"; [ -n "$ports" ] || { red "  boot leg ($label/$mode): no free port pair"; return 1; }
  port="$ports"; admin_port=$((port + 1))
  fix="$(mktemp -d "${TMPDIR:-/tmp}/plane-delete-boot.XXXXXX")" || { red "  boot leg ($label/$mode): mktemp failed"; return 1; }
  write_boot_config "$mode" "$fix" "$port" "$admin_port"

  MOCK_KEY=test-key BUSBAR_SIGNING_KEY=0000000000000000000000000000000000000000000000000000000000000001 \
  BUSBAR_ADMIN_TOKEN=admin-token-for-plane-delete-boot \
  BUSBAR_CONFIG="$fix/config.yaml" BUSBAR_PROVIDERS="$fix/providers.yaml" \
  exec "$bin" >"$fix/boot.log" 2>&1 &
  pid=$!

  # The up-signal is a route no plane owns, so waiting for it never presumes the answer to the
  # question this leg is asking. `/stats` on the open boot; the MCP metadata route on the closed one
  # (the only unauthenticated route that boot has).
  case "$mode" in
    mcp)  probe="http://127.0.0.1:$port/.well-known/oauth-protected-resource/mcp" ;;
    open) probe="http://127.0.0.1:$port/stats" ;;
  esac
  up=""
  for _ in $(seq 1 60); do
    if curl -fsS "$probe" >/dev/null 2>&1; then up=1; break; fi
    kill -0 "$pid" 2>/dev/null || break
    sleep 0.5
  done
  if [ -z "$up" ]; then
    red "  boot leg ($label/$mode): the binary did not come up"
    tail -20 "$fix/boot.log" 2>/dev/null | sed 's/^/      /'
    kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -rf "$fix"
    return 1
  fi

  for p in $PLANES; do
    [ "$(plane_probe_boot "$p")" = "$mode" ] || continue
    method="$(plane_probe_method "$p")"; path="$(plane_probe_path "$p")"; body="$(plane_probe_body "$p")"
    if [ "$method" = "GET" ]; then
      code="$(curl -s -o /dev/null -w '%{http_code}' "http://127.0.0.1:$port$path")"
    else
      code="$(curl -s -o /dev/null -w '%{http_code}' -X "$method" "http://127.0.0.1:$port$path" \
        -H 'content-type: application/json' -d "$body")"
    fi
    printf '%s=%s\n' "$p" "$code" >>"$out"
  done

  kill "$pid" 2>/dev/null; wait "$pid" 2>/dev/null; rm -rf "$fix"
  return 0
}

# build_bin <manifest-dir> <tag> → echoes the path to a built bin COPIED ASIDE under <tag>.
# The copy matters: every build in this script shares one CARGO_TARGET_DIR (so the ~130 external
# deps compile once), which means `debug/busbar` is overwritten by the next build. A control binary
# that has been overwritten by its own subject is not a control.
build_bin() {
  local dir="$1" tag="$2" log rc kept
  log="$CACHE_TARGET/.plane-delete-$tag-build.log"; mkdir -p "$CACHE_TARGET"
  CARGO_TARGET_DIR="$CACHE_TARGET" cargo build --manifest-path "$dir/Cargo.toml" -p busbar >"$log" 2>&1; rc=$?
  if [ "$rc" -ne 0 ]; then
    red "  boot leg ($tag): bin FAILED to build (not just check)"
    grep -m4 -E "error(\[|:)|couldn't read" "$log" | sed 's/^/      /'
    return 1
  fi
  [ -x "$CACHE_TARGET/debug/busbar" ] || { red "  boot leg ($tag): built binary not found"; return 1; }
  kept="$CACHE_TARGET/busbar-$tag"
  cp "$CACHE_TARGET/debug/busbar" "$kept" || return 1
  printf '%s\n' "$kept"
}

# probe_codes <bin> <label> <outfile> — both boots, every plane, one file of `<plane>=<code>` lines.
probe_codes() {
  local bin="$1" label="$2" out="$3" fail=0
  : >"$out"
  boot_and_probe "$bin" mcp  "$label" "$out" || fail=1
  boot_and_probe "$bin" open "$label" "$out" || fail=1
  return "$fail"
}

code_for() { # code_for <file> <plane> → the recorded code, or the empty string
  awk -F= -v p="$2" '$1 == p { print $2; exit }' "$1" 2>/dev/null
}

# ── THE CONTROL: what a MOUNTED plane answers, measured on the unmutated tree ────────────────────
# Built and probed at most ONCE per run and memoised in a file, because it is the same answer for
# every plane and it costs a full bin build plus two boots.
CONTROL_CODES=""
control_codes() {
  local bin
  if [ -n "$CONTROL_CODES" ]; then printf '%s\n' "$CONTROL_CODES"; return 0; fi
  mkdir -p "$CACHE_TARGET"
  local out="$CACHE_TARGET/.plane-delete-control-codes.txt"
  bin="$(build_bin "$REPO" control)" || return 1
  probe_codes "$bin" control "$out" || return 1
  CONTROL_CODES="$out"
  printf '%s\n' "$out"
}

# ── THE VERDICT, AS A PURE FUNCTION OVER TWO CODE FILES ──────────────────────────────────────────
# judge_codes <control-file> <subject-file> <plane> → 0 (PASS) / 1 (FAIL).
#
# Deliberately separated from the booting: the judgement is the part that was WRONG (a bare 404 read
# as proof), and a judgement welded to a full bin build plus four boots is a judgement nobody can
# RED-prove. As a pure function over two files of `<plane>=<code>` lines it is driven directly by
# `--selftest` over planted codes — a vacuous probe, a surviving route, a boot that mounted nothing —
# in milliseconds, with no cargo and no network.
judge_codes() {
  local ctl="$1" sub="$2" p="$3" fail=0 q cc sc

  # THE POSITIVE CONTROL. If the probe for this plane is 404 on a tree where the plane's crate is
  # PRESENT, the probe cannot tell presence from absence and its 404 below would mean nothing.
  cc="$(code_for "$ctl" "$p")"
  if [ -z "$cc" ]; then
    red "  boot leg ($p): the control run recorded no code for this plane — the probe never ran"
    return 1
  fi
  if [ "$cc" = "404" ]; then
    red "  boot leg ($p): POSITIVE CONTROL FAILED — $(plane_probe_method "$p") $(plane_probe_path "$p") is 404"
    note "    on the UNMUTATED tree, where crates/busbar-$p is present and compiled in. A probe that"
    note "    404s whether or not the plane exists proves nothing about the deletion; the 404 assertion"
    note "    below would be unfalsifiable. Fix the probe (path/method/body) or the boot config that"
    note "    is supposed to mount this plane — do not read a 404 here as a pass."
    return 1
  fi
  note "positive control ($p): $(plane_probe_method "$p") $(plane_probe_path "$p") answers $cc with the plane present (non-404)"

  # THE DELETION: the byte-identical request must now 404.
  sc="$(code_for "$sub" "$p")"
  if [ "$sc" = "404" ]; then
    note "boot leg ($p): the same request now answers 404 — the plane's route left with the crate"
  else
    fail=1
    red "  boot leg ($p): $(plane_probe_method "$p") $(plane_probe_path "$p") answered ${sc:-<no answer>}, not 404 — the route survived deletion"
  fi

  # THE NEIGHBOUR CONTROL: every OTHER plane the control mounted must still serve on this binary.
  # Without it, a boot that mounted nothing at all 404s everything and reads as a clean deletion.
  for q in $PLANES; do
    [ "$q" = "$p" ] && continue
    cc="$(code_for "$ctl" "$q")"
    [ "$cc" = "404" ] || [ -z "$cc" ] && continue   # the control never mounted it; it controls nothing
    sc="$(code_for "$sub" "$q")"
    if [ "$sc" = "404" ] || [ -z "$sc" ]; then
      fail=1
      red "  boot leg ($p): neighbour $q answered ${sc:-<no answer>} (control: $cc) — this boot lost a plane it did not delete"
      note "    Every plane 404ing at once is a boot that mounted nothing, not a clean deletion."
    else
      note "boot leg ($p): neighbour $q still serves ($sc, control $cc)"
    fi
  done

  return "$fail"
}

# boot_serve <scratch> <plane> → 0/1. The whole leg for one plane: measure the control (once per
# run), build and boot the mutated bin, then hand both code files to `judge_codes`.
boot_serve() {
  local s="$1" p="$2" bin ctl sub
  ctl="$(control_codes)" || { red "  boot leg ($p): the CONTROL build/boot failed — no verdict is possible"; return 1; }
  bin="$(build_bin "$s" "delete-$p")" || return 1
  sub="$CACHE_TARGET/.plane-delete-$p-codes.txt"
  probe_codes "$bin" "delete-$p" "$sub" || return 1
  if judge_codes "$ctl" "$sub" "$p"; then
    grn "  boot leg ($p): binary BOOTS with busbar-$p physically gone; its route 404s, every neighbour still serves"
    return 0
  fi
  return 1
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

# remove_and_assert <scratch> <plane> → 0 / 1. Performs `apply_removal` and PROVES it happened.
#
# ── THE REMOVAL IS ASSERTED, NOT NOTED ────────────────────────────────────────────────────────────
# This block used to PRINT its evidence ("all must read GONE/0") and check none of it, which made
# the whole gate unfalsifiable in one specific and entirely reachable way: `rm -rf` on a path that
# does not exist succeeds silently, and every manifest stripper is a `grep`/`awk` filter that
# rewrites a file containing no matches into an identical file, also silently. So the moment a
# plane crate is RENAMED — the ordinary outcome of an extraction, which is precisely the work this
# gate exists to police — `apply_removal` removes NOTHING, the neutral crates compile because
# nothing was taken away from them, and the gate reports PASS on a deletion that never happened.
# A green would then mean "busbar-<P> is removable" while `crates/busbar-<P>` sat untouched in the
# scratch. That is the worst verdict a gate can produce, because it is indistinguishable from the
# real one.
#
# Three facts are therefore recorded BEFORE the mutation and asserted AFTER it: the crate directory
# EXISTED and is now gone, no manifest still names it, and the manifests were actually REWRITTEN
# (a byte-identical root manifest means `drop_member` matched nothing). All three are hard
# failures that return before a single `cargo check` runs — a compile result taken on a tree that
# was never mutated says nothing at all, so it must not be printed as if it did.
remove_and_assert() {
  local s="$1" p="$2"
  local pre_dir pre_root pre_bin pre_dep
  pre_dir="$([ -d "$s/crates/busbar-$p" ] && echo PRESENT || echo ABSENT)"
  pre_root="$s/.plane-delete-pre-root.toml"
  pre_bin="$s/.plane-delete-pre-bin.toml"
  cp "$s/Cargo.toml" "$pre_root" 2>/dev/null || { red "  cannot read the scratch's root manifest"; return 1; }
  cp "$s/crates/busbar/Cargo.toml" "$pre_bin" 2>/dev/null || { red "  cannot read the scratch's bin manifest"; return 1; }
  pre_dep="$(grep -c "^busbar-$p = " "$pre_bin" 2>/dev/null)"; pre_dep="${pre_dep:-0}"

  apply_removal "$s" "$p"

  local ev_dir ev_mem ev_dep
  ev_dir="$([ -d "$s/crates/busbar-$p" ] && echo PRESENT || echo GONE)"
  ev_mem="$(grep -c "\"crates/busbar-$p\"" "$s/Cargo.toml" 2>/dev/null)"; ev_mem="${ev_mem:-0}"
  ev_dep="$(grep -c "^busbar-$p = " "$s/crates/busbar/Cargo.toml" 2>/dev/null)"; ev_dep="${ev_dep:-0}"
  note "removed: crate dir=$pre_dir->$ev_dir  members-refs=$ev_mem  bin-dep-lines=$pre_dep->$ev_dep"

  if [ "$pre_dir" != "PRESENT" ]; then
    red "  crates/busbar-$p DID NOT EXIST before the removal — there was nothing to delete."
    note "    \`rm -rf\` on an absent path succeeds, so this run would have compiled an UNMUTATED tree"
    note "    and reported it as proof that busbar-$p is removable. Renamed crate? Fix the plane key"
    note "    in scripts/plane-keys.sh; do not read this as a pass."
    return 1
  fi
  if [ "$ev_dir" != "GONE" ]; then
    red "  crates/busbar-$p is STILL PRESENT after apply_removal — the mutation did not take"
    return 1
  fi
  if [ "$ev_mem" -ne 0 ] || [ "$ev_dep" -ne 0 ]; then
    red "  a manifest still names busbar-$p after removal (members-refs=$ev_mem bin-dep-lines=$ev_dep)"
    return 1
  fi
  if cmp -s "$pre_root" "$s/Cargo.toml"; then
    red "  the root workspace manifest is BYTE-IDENTICAL after the removal — nothing was stripped."
    note "    \`drop_member\` rewrites the file whether or not it matched, so an unchanged manifest is"
    note "    the signature of a member entry that is not spelled \"crates/busbar-$p\"."
    return 1
  fi
  if [ "$pre_dep" -gt 0 ] && cmp -s "$pre_bin" "$s/crates/busbar/Cargo.toml"; then
    red "  the bin manifest declared busbar-$p and is BYTE-IDENTICAL after the removal — nothing was stripped."
    return 1
  fi
  note "  removal ASSERTED: the crate existed, is gone, is named by no manifest, and the manifests changed"
  rm -f "$pre_root" "$pre_bin"
  return 0
}

# strong_form <plane>  → 0 (PASS) / 1 (FAIL). Prints the two legs (neutral crates, bin) with evidence.
strong_form() {
  local p="$1" s keep log rc fail=0
  keep="$(neutral_keep "$p")"
  s="$(make_scratch)" || { red "  scratch copy failed"; return 1; }

  # A compile verdict on a tree that was never mutated is not a verdict. Nothing below this line
  # runs unless the removal is proven to have happened.
  remove_and_assert "$s" "$p" || return 1

  if [ -n "$EDGE_CRATES" ]; then
    ylw "  residual manifest back-edge: neutral/other crate(s) declared a path-dep on busbar-$p —${EDGE_CRATES}"
    note "    (stripped as part of the removal; a bare \`git rm -r\` would dangle it)"
  fi
  if [ -n "$FEATURE_EDGE_CRATES" ]; then
    ylw "  residual feature-table back-edge: manifest(s) named busbar-$p in a [features] entry —${FEATURE_EDGE_CRATES}"
    note "    (stripped as part of the removal; a bare \`git rm -r\` would dangle the feature string)"
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

  # Leg 1b — the CONTRACT PLANE crate itself, ALL TARGETS, with the plugin crate gone.
  #
  # Legs 1 and 2 ask only whether the NEUTRAL crates and the bin survive the removal. They never
  # compile `busbar-plane-<P>`, so a plane crate that reaches into `../busbar-<P>/src` — an
  # `include_str!` in a `#[cfg(test)]` module is the shape that actually occurred, and it is
  # invisible to both the manifest and to `cargo check` without `--all-targets` — passed all the
  # way through a green run. That is a green that says a plane is independently buildable when it
  # is not, and the whole point of the strong form is that it cannot say that. `--all-targets` is
  # load-bearing: a test-only include only exists under it.
  log="$CACHE_TARGET/.plane-delete-$p-plane.log"
  if [ -d "$s/crates/busbar-plane-$p" ]; then
    run_check "$s" "$log" -- -p "busbar-plane-$p" --all-targets; rc=$?
    if [ "$rc" -eq 0 ]; then
      grn "  busbar-plane-$p compiles (all targets) without busbar-$p"
    else
      fail=1; red "  busbar-plane-$p DOES NOT compile without busbar-$p — the plane reaches into the plugin"
      grep -m4 -E "error(\[|:)|couldn't read" "$log" 2>/dev/null | sed 's/^/      /'
    fi
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

  # Leg 3 (EVERY plane, tracker C13) — BOOT+SERVE, not just compile: build the bin for real from
  # this same scratch (crates/busbar-<P> already physically gone) and prove the running server has
  # lost that plane's route and kept every other plane's, judged against the control measured on the
  # unmutated tree. This used to run for `llm` alone, leaving mcp/a2a/voice proven only to compile.
  # Skipped only when leg 2 already failed: a boot leg over a bin that does not compile has nothing
  # to say, and `--skip-boot-leg` exists for the same reason the witness probe is opt-in — it is the
  # expensive half (a full bin build plus boots, plus the one-off control build).
  if [ "$rc" -eq 0 ] && [ "${SKIP_BOOT_LEG:-0}" != "1" ]; then
    boot_serve "$s" "$p" || fail=1
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

# plant_feature_ref — SELF-TEST ONLY: insert a synthetic `plant-feature-ref = [...]` entry naming plane
# $2 (both the hard and optional forward forms) into the `[features]` table of manifest $1 — NOT
# appended at end-of-file, which would land it in whatever table happens to be LAST in the manifest
# (busbar-core's last table is `[dev-dependencies]`, where an array value is a TOML type error of its
# own and would mask the thing being tested).
plant_feature_ref() {
  local f="$1" rp="$2" t
  t="$f.plane-delete.tmp"
  awk -v rp="$rp" '
    { print }
    /^\[features\]/ && !done {
      printf "plant-feature-ref = [\"busbar-%s/plant\", \"busbar-%s?/plant\"]\n", rp, rp
      done = 1
    }
  ' "$f" >"$t" && mv "$t" "$f"
}

# ── SELF-TEST — the harness cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "plane-delete-test SELF-TEST (the removal + verdict machinery proves itself)"
  local fail=0 p s core_toml

  # (1) REMOVAL EVIDENCE for EVERY plane (fast, no compile): the mutation really removes the crate dir,
  #     the members entry, and the bin dependency line. This is the unfakeable mechanism proof, and it
  #     now runs through `remove_and_assert` — the same function `strong_form` uses — rather than a
  #     second, parallel copy of the checks, so the thing proven here is the thing the gate runs.
  for p in $PLANES; do
    s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
    if remove_and_assert "$s" "$p" \
       && [ "$(grep -c "\"dep:busbar-$p\"" "$s/crates/busbar/Cargo.toml")" -eq 0 ]; then
      note "PASS  removal($p): crate dir + members entry + bin dep + dep: token all gone, and asserted"
    else
      fail=1; note "FAIL  removal($p): the removal did not take, or was not proven"
    fi
    rm -rf "$s"
  done

  # (1b) THE RED CONTROL FOR THE REMOVAL ITSELF — a REAL crate planted under a name the harness does
  #      not know, which is exactly what a renamed plane crate looks like from here.
  #
  #      This is the case the old evidence block could not catch, because it PRINTED its evidence and
  #      asserted none of it. `rm -rf crates/busbar-<gone>` on an absent path succeeds; `drop_member`
  #      and `neutralise_bin` rewrite manifests that contain no matches into identical manifests. So
  #      the whole mutation became a no-op, the neutral crates compiled (nothing had been taken from
  #      them), and the gate printed PASS for a deletion that never happened.
  #
  #      The plant is a real, compilable crate directory with a real members entry and a real bin
  #      dependency, registered under `busbar-plantedplane`, and the harness is then asked to remove
  #      `busbar-renamedplane` — the same crate under the name it USED to have. Every stripper
  #      no-ops, and `remove_and_assert` must REFUSE rather than report a clean removal.
  s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
  mkdir -p "$s/crates/busbar-plantedplane/src"
  printf '[package]\nname = "busbar-plantedplane"\nversion = "0.0.0"\nedition = "2021"\n\n[dependencies]\n' \
    >"$s/crates/busbar-plantedplane/Cargo.toml"
  printf 'pub fn planted() -> u8 { 7 }\n' >"$s/crates/busbar-plantedplane/src/lib.rs"
  awk '
    { print }
    /^members = \[/ && !done { print "  \"crates/busbar-plantedplane\","; done = 1 }
  ' "$s/Cargo.toml" >"$s/Cargo.toml.plant" && mv "$s/Cargo.toml.plant" "$s/Cargo.toml"
  printf 'busbar-plantedplane = { path = "../busbar-plantedplane", optional = true }\n' \
    >>"$s/crates/busbar/Cargo.toml"

  # (1b-i) the plant is REAL: removing it by its real name must succeed and be asserted.
  if remove_and_assert "$s" "plantedplane" >/dev/null 2>&1; then
    note "PASS  planted crate: a REAL crate dir + member + bin dep is removed, and the removal is asserted"
  else
    fail=1; note "FAIL  planted crate: the harness could not remove a crate it genuinely planted — the control is broken"
  fi
  rm -rf "$s"

  # (1b-ii) THE RED CONTROL: the same plant, removed under a name nothing in the tree carries.
  s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
  mkdir -p "$s/crates/busbar-plantedplane/src"
  printf '[package]\nname = "busbar-plantedplane"\nversion = "0.0.0"\nedition = "2021"\n' \
    >"$s/crates/busbar-plantedplane/Cargo.toml"
  printf 'pub fn planted() -> u8 { 7 }\n' >"$s/crates/busbar-plantedplane/src/lib.rs"
  if remove_and_assert "$s" "renamedplane" >/dev/null 2>&1; then
    fail=1
    note "FAIL  renamed-crate control: removing an ABSENT crate reported a clean removal."
    note "      Every stripper no-ops on a name the tree does not carry, so the gate would then"
    note "      compile an UNMUTATED tree and report PASS for a deletion that never happened."
  else
    note "PASS  renamed-crate control: a removal with nothing to remove is REFUSED, not reported clean"
  fi
  rm -rf "$s"

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

  # (4) FEATURE-REF PLANT — the manifest-level bug strip_feature_edges exists to close: a NEUTRAL crate's
  #     OWN [features] table can name the removed plane without the plane ever being a normal dependency
  #     of that crate (busbar-core's `openapi-schema` does exactly this for llm/mcp/a2a via a
  #     dev-dependency back-edge). Plant a synthetic feature entry onto busbar-core naming $rp in BOTH
  #     forms — hard `busbar-<rp>/plant` and optional `busbar-<rp>?/plant` — and prove: (RED) the removal
  #     WITHOUT strip_feature_edges leaves it dangling and cargo refuses to load the manifest; (GREEN) the
  #     real apply_removal (which calls strip_feature_edges) strips it and the neutral crate compiles.
  s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
  core_toml="$s/crates/busbar-core/Cargo.toml"
  plant_feature_ref     "$core_toml" "$rp"
  remove_crate_dir      "$s" "$rp"
  drop_member           "$s" "$rp"
  neutralise_bin        "$s" "$rp"
  strip_workspace_edges "$s" "$rp"     # strip_feature_edges DELIBERATELY OMITTED
  log="$CACHE_TARGET/.plane-delete-selftest-featref-red.log"
  run_check "$s" "$log" -- -p busbar-core --no-default-features --features "$(neutral_keep "$rp")"; rc=$?
  if [ "$rc" -ne 0 ]; then
    note "PASS  FEATURE-REF RED control: a planted busbar-$rp feature ref, left unstripped, → harness check returns non-zero"
  else
    fail=1; note "FAIL  FEATURE-REF RED control: a planted busbar-$rp feature ref compiled without being stripped — the gate would miss this class of coupling"
  fi
  rm -rf "$s"

  s="$(make_scratch)" || { red "scratch copy failed"; return 1; }
  core_toml="$s/crates/busbar-core/Cargo.toml"
  plant_feature_ref "$core_toml" "$rp"
  apply_removal "$s" "$rp"
  if grep -qE "\"busbar-$rp/plant\"|\"busbar-$rp\\?/plant\"" "$core_toml"; then
    fail=1; note "FAIL  FEATURE-REF GREEN control: apply_removal left the planted busbar-$rp feature ref in place"
  else
    log="$CACHE_TARGET/.plane-delete-selftest-featref-green.log"
    run_check "$s" "$log" -- -p busbar-core --no-default-features --features "$(neutral_keep "$rp")"; rc=$?
    if [ "$rc" -eq 0 ]; then
      note "PASS  FEATURE-REF GREEN control: apply_removal strips the planted busbar-$rp feature ref, neutral crate compiles"
    else
      fail=1; note "FAIL  FEATURE-REF GREEN control: planted-then-stripped feature ref still fails to compile"
      grep -m4 -E "error(\[|:)|couldn't read" "$log" 2>/dev/null | sed 's/^/      /'
    fi
  fi
  rm -rf "$s"

  # (5) THE BOOT LEG'S JUDGEMENT — the part that used to be a bare, unfalsifiable 404.
  #
  #     `judge_codes` is a pure function over two files of `<plane>=<code>` lines (the control run on
  #     the unmutated tree, and the subject run on the plane-deleted one), so every way it must go
  #     RED is provable here in milliseconds — no cargo, no boot, no network. These are the cases
  #     that had NO instrument at all before: the leg existed for `llm` only, and its single
  #     assertion was "the route answered 404", which is also what a typo'd path, a wrong method, a
  #     plane the config never mounted, and a server that mounted nothing all answer.
  local jd ctl sub
  jd="$(mktemp -d "${TMPDIR:-/tmp}/plane-delete-judge.XXXXXX")" || { red "mktemp failed"; return 1; }
  ctl="$jd/control.txt"; sub="$jd/subject.txt"

  # (5a) GREEN: the plane was mounted (200), is now gone (404), neighbours untouched.
  printf 'llm=200\nmcp=200\na2a=200\nvoice=200\n' >"$ctl"
  printf 'llm=404\nmcp=200\na2a=200\nvoice=200\n' >"$sub"
  if judge_codes "$ctl" "$sub" llm >/dev/null 2>&1; then
    note "PASS  boot-judge GREEN: mounted-then-404 with neighbours serving is a clean deletion"
  else
    fail=1; note "FAIL  boot-judge GREEN: refused a textbook clean deletion"
  fi

  # (5b) RED — THE VACUOUS PROBE. The control itself 404s, i.e. the request never reached a route
  #      even with the plane compiled in. The old leg had no such check, so this state read as PASS.
  printf 'llm=404\nmcp=200\na2a=200\nvoice=200\n' >"$ctl"
  printf 'llm=404\nmcp=200\na2a=200\nvoice=200\n' >"$sub"
  if judge_codes "$ctl" "$sub" llm >/dev/null 2>&1; then
    fail=1
    note "FAIL  boot-judge POSITIVE CONTROL: a probe that 404s on the UNMUTATED tree was accepted."
    note "      A 404 that is the answer whether or not the plane exists proves nothing; this is the"
    note "      exact unfalsifiable green the positive control exists to make impossible."
  else
    note "PASS  boot-judge POSITIVE CONTROL: a probe that 404s with the plane PRESENT is refused"
  fi

  # (5c) RED — the control never ran for this plane at all (no line recorded).
  printf 'mcp=200\na2a=200\nvoice=200\n' >"$ctl"
  printf 'llm=404\nmcp=200\na2a=200\nvoice=200\n' >"$sub"
  if judge_codes "$ctl" "$sub" llm >/dev/null 2>&1; then
    fail=1; note "FAIL  boot-judge: accepted a verdict with no control measurement for the plane"
  else
    note "PASS  boot-judge: a plane the control never probed is refused, not assumed"
  fi

  # (5d) RED — THE ROUTE SURVIVED: the deleted plane still answers non-404.
  printf 'llm=200\nmcp=200\na2a=200\nvoice=200\n' >"$ctl"
  printf 'llm=200\nmcp=200\na2a=200\nvoice=200\n' >"$sub"
  if judge_codes "$ctl" "$sub" llm >/dev/null 2>&1; then
    fail=1; note "FAIL  boot-judge: a route that still serves after its crate was deleted was accepted"
  else
    note "PASS  boot-judge: a surviving route is refused"
  fi

  # (5e) RED — THE NEIGHBOUR CONTROL: a boot that mounted NOTHING 404s every plane at once, which
  #      under the old single-assertion shape is indistinguishable from a clean deletion.
  printf 'llm=200\nmcp=200\na2a=200\nvoice=200\n' >"$ctl"
  printf 'llm=404\nmcp=404\na2a=404\nvoice=404\n' >"$sub"
  if judge_codes "$ctl" "$sub" llm >/dev/null 2>&1; then
    fail=1
    note "FAIL  boot-judge NEIGHBOUR CONTROL: a boot where EVERY plane 404s was read as a clean deletion."
    note "      That is a server that mounted nothing, not a plane whose route left with its crate."
  else
    note "PASS  boot-judge NEIGHBOUR CONTROL: every-plane-404 is refused, not read as a deletion"
  fi

  # (5f) a neighbour the CONTROL never mounted controls nothing, and must not manufacture a failure.
  printf 'llm=200\nmcp=200\na2a=200\nvoice=404\n' >"$ctl"
  printf 'llm=404\nmcp=200\na2a=200\nvoice=404\n' >"$sub"
  if judge_codes "$ctl" "$sub" llm >/dev/null 2>&1; then
    note "PASS  boot-judge: a neighbour the control never mounted is excluded from the neighbour control"
  else
    fail=1; note "FAIL  boot-judge: an unmounted neighbour was treated as a lost plane"
  fi
  rm -rf "$jd"

  # (6) THE PROBE TABLE COVERS EVERY PLANE. The leg is only universal if the table is: a plane with
  #     no path/method/body is a plane the boot leg silently never probes — the same class of
  #     no-op as the llm-only `if` this replaced, one layer down.
  for p in $PLANES; do
    if [ -z "$(plane_probe_path "$p")" ] || [ -z "$(plane_probe_method "$p")" ] || [ -z "$(plane_probe_boot "$p")" ]; then
      fail=1; note "FAIL  probe table: plane '$p' has no probe (path/method/boot) — the boot leg would skip it silently"
    else
      note "PASS  probe table($p): $(plane_probe_method "$p") $(plane_probe_path "$p") on the $(plane_probe_boot "$p") boot"
    fi
  done

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
  # DIAGNOSTIC: build and boot the UNMUTATED tree and print what each plane's probe answers with its
  # crate present. This is the calibration every boot-leg verdict is taken against, so being able to
  # look at it directly is how a failing positive control gets diagnosed (bad path? bad method? a
  # config that never mounted the plane?) without deleting anything.
  --probe-control)
    hdr "boot-leg CONTROL — every plane's probe against the UNMUTATED tree"
    ctl="$(control_codes)" || { red "control build/boot failed"; exit 1; }
    for p in $PLANES; do
      code="$(code_for "$ctl" "$p")"
      if [ "$code" = "404" ] || [ -z "$code" ]; then
        red "  $p: $(plane_probe_method "$p") $(plane_probe_path "$p") -> ${code:-<no answer>} (VACUOUS: cannot tell presence from absence)"
      else
        grn "  $p: $(plane_probe_method "$p") $(plane_probe_path "$p") -> $code (non-404: the probe reaches a real route)"
      fi
    done
    exit 0
    ;;
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
  # The boot leg is the expensive half (a bin build per plane plus the one-off control build and two
  # boots each). It is ON by default — it is the only leg that can tell a mounted route from a
  # deleted one — and this flag turns it off for a compile-only pass on a machine that cannot boot.
  --skip-boot-leg) export SKIP_BOOT_LEG=1; shift; exec "$0" "${1:---baseline}" ;;
  -h | --help) sed -n '2,60p' "$0" ;;
  "" ) echo "usage: $0 [--selftest | --baseline | --all | <llm|mcp|a2a|voice>] [--with-witness] [--skip-boot-leg]" >&2; exit 2 ;;
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
