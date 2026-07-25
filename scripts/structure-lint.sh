#!/usr/bin/env bash
# Structure lint — enforces the code-layout invariants in docs/code-layout.md so the tree stays
# navigable ("I'm looking for X, I know where it is") instead of drifting back to giant, inconsistent
# files. Three checks, all greppable, no external deps. Exit non-zero on any violation.
set -euo pipefail
cd "$(dirname "$0")/.."

# Impl files target ~1,500 lines; the hard ceiling forbids genuine MONSTER files (the thing that
# makes a codebase unnavigable) rather than micromanaging cohesive units. Test files are exempt from
# the size cap: they are located by name (foo/tests/<what>.rs), not read top-to-bottom, so the
# navigability the cap protects is already served by the tests/ folder convention + one-module-per-file.
MAX_LINES_IMPL=2500
fail=0

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ── Invariant 1: no hybrids — a module is a file OR a folder, never both (`admin.rs` + `admin/`). ──
hdr "no hybrid modules (foo.rs beside foo/)"
while IFS= read -r d; do
  base="${d%/}"
  if [ -f "${base}.rs" ]; then
    note "HYBRID: ${base}.rs coexists with ${base}/ — fold ${base}.rs into ${base}/mod.rs"
    fail=1
  fi
done < <(find crates -type d)
[ "$fail" -eq 0 ] && note "ok"

# ── Invariant 2: no monster impl files — split by area. Test files (under a tests/ dir) are exempt. ─
hdr "no impl .rs file over ${MAX_LINES_IMPL} lines (test files exempt)"
big=0
while IFS= read -r f; do
  case "$f" in */tests/*) continue ;; esac   # test files are name-navigated → exempt from the cap
  n=$(wc -l < "$f")
  if [ "$n" -gt "$MAX_LINES_IMPL" ]; then note "OVERSIZED: $f ($n lines)"; fail=1; big=1; fi
done < <(find crates -name '*.rs')
[ "$big" -eq 0 ] && note "ok"

# ── Invariant 3: tests live in foo/tests/. The trigger is an inline test module BODY — a
#    `#[cfg(test)] mod X { ... }` (note the brace). A one-line `#[cfg(test)] #[path=...] mod X;`
#    DECLARATION is fine and expected: it keeps X a direct child so `use super::*` still resolves,
#    while the body lives in tests/X.rs. A folder-module hub (mod.rs) may carry those declarations
#    but no inline body; and no file may carry more than one inline body (the split trigger). A leaf
#    file (not a mod.rs) may keep a single inline body. ────────────────────────────────────────────
hdr "test locality (no inline test bodies in mod.rs; <=1 inline test body per file)"
loc=0
# Count inline test module BODIES: a `#[cfg(test)]` line whose next `mod X` line opens a brace.
inline_bodies() { awk '
  /^[[:space:]]*#\[cfg\(test\)\]/ { armed=1; next }
  armed && /^[[:space:]]*mod [A-Za-z0-9_]+[[:space:]]*\{/ { c++ }
  armed { armed=0 }
  END { print c+0 }' "$1"; }
while IFS= read -r f; do
  bodies=$(inline_bodies "$f")
  if [ "$(basename "$f")" = "mod.rs" ] && [ "$bodies" -ge 1 ]; then
    note "TESTS-IN-HUB: $f is a mod.rs with an inline test body — move it to tests/ (keep a #[path] decl)"
    fail=1; loc=1
  elif [ "$bodies" -ge 2 ]; then
    note "MULTI-TEST-MOD: $f has ${bodies} inline test bodies — give each its own tests/<name>.rs"
    fail=1; loc=1
  fi
done < <(find crates -name '*.rs')
[ "$loc" -eq 0 ] && note "ok"

# ── Invariant 4: ONE durable-write choke point. Every durable file publish goes through
#    `crate::durable::write` (crates/busbar/src/durable.rs). Outside the primitive, the ephemeral
#    plugin-loader staging (no rename-to-publish, no durability intent), and #[cfg(test)] code, NO
#    source file may hand-roll a `std::fs::rename(` used to publish or a `.sync_all(` for durability.
#    This is the "no-hack" guarantee: a 5th call-site that re-hand-rolls the atomic-write dance fails
#    CI instead of silently re-introducing whichever facet (parent fsync / temp cleanup / …) its
#    author forgets — it must route through the choke point. See crates/busbar/src/durable.rs. ──────
hdr "one durable-write choke point (no hand-rolled rename-to-publish / sync_all outside durable.rs)"
# The only files permitted to publish via rename or fsync for durability. Keep this list to the
# primitive alone; the ephemeral stager uses neither call.
ALLOW_DURABLE='crates/busbar/src/durable.rs'
dur=0
# awk skips lines inside a `#[cfg(test)]`-gated region (tracked by brace depth) and `//` comment
# lines, then flags a `std::fs::rename(` or `.sync_all(` in the remaining production code.
scan_durable() { awk '
  # Enter a #[cfg(test)] region: the NEXT brace-opening line starts a test scope we ignore until it
  # closes. Track nested braces so we resume exactly when the test module/fn ends.
  /#\[cfg\(test\)\]/ { pending_test=1 }
  {
    line=$0
    # Count braces to know when a test region ends (`close` is an awk builtin — use `nclose`).
    nopen=gsub(/\{/, "{", line); nclose=gsub(/\}/, "}", line)
    if (pending_test && nopen>0) { in_test=1; pending_test=0 }
    if (in_test) { depth += nopen - nclose; if (depth<=0) { in_test=0; depth=0 }; next }
  }
  /^[[:space:]]*\/\// { next }                       # skip whole-line comments (incl doc comments)
  /std::fs::rename\(/  { printf "%s:%d: hand-rolled rename-to-publish\n", FILENAME, NR }
  /\.sync_all\(/       { printf "%s:%d: hand-rolled sync_all durability\n", FILENAME, NR }
' "$1"; }
while IFS= read -r f; do
  case "$f" in */tests/*) continue ;; esac          # test files are exempt (name-navigated)
  [ "$f" = "$ALLOW_DURABLE" ] && continue            # the primitive itself
  hits=$(scan_durable "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do note "DURABLE-BYPASS: $h — route through crate::durable::write"; done <<<"$hits"
    fail=1; dur=1
  fi
done < <(find crates -name '*.rs')
[ "$dur" -eq 0 ] && note "ok"

# ── Invariant 5: ONE plugin-export choke point. Every plugin `cdylib` gets its six `extern
#    "C-unwind"` symbols ONLY from `export_*_plugin!`, which routes them through the boundary wrapper
#    (null-out-guard-before-alloc, mandatory catch_unwind, total status map — crates/plugin-sdk/
#    src/boundary.rs). A hand-written `#[no_mangle]` in a plugin crate would skip those guards, so it
#    is a build failure. Combined with the DUPLICATE-SYMBOL linker error a second `busbar_*` export
#    triggers, this is the "no-hack" guarantee: a future export CANNOT skip the boundary. The ONLY
#    file permitted a literal `#[no_mangle]` is the SDK macro that DEFINES the choke point. #[cfg(test)]
#    and test files are exempt (name-navigated; they never ship in the cdylib's export table). ──────
hdr "one plugin-export choke point (no hand-rolled #[no_mangle] outside export_*_plugin!)"
# The macro that stamps the six symbols; it is the choke point, so it alone may name #[no_mangle].
ALLOW_EXPORT='crates/plugin-sdk/src/lib.rs'
exp=0
# awk skips #[cfg(test)]-gated regions (brace-tracked) and comment lines, then flags a bare
# #[no_mangle] in the remaining production code. Same skipping shape as Invariant 4's scanner.
scan_export() { awk '
  /#\[cfg\(test\)\]/ { pending_test=1 }
  {
    line=$0
    nopen=gsub(/\{/, "{", line); nclose=gsub(/\}/, "}", line)
    if (pending_test && nopen>0) { in_test=1; pending_test=0 }
    if (in_test) { depth += nopen - nclose; if (depth<=0) { in_test=0; depth=0 }; next }
  }
  /^[[:space:]]*\/\// { next }                       # skip whole-line comments (incl doc comments)
  /#\[no_mangle\]/    { printf "%s:%d: hand-rolled #[no_mangle]\n", FILENAME, NR }
' "$1"; }
while IFS= read -r f; do
  case "$f" in */tests/*) continue ;; esac          # test files are exempt (name-navigated)
  [ "$f" = "$ALLOW_EXPORT" ] && continue             # the choke-point macro itself
  hits=$(scan_export "$f")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do note "EXPORT-BYPASS: $h — define exports via export_*_plugin!, never by hand"; done <<<"$hits"
    fail=1; exp=1
  fi
done < <(find crates -name '*.rs')
[ "$exp" -eq 0 ] && note "ok"

# ── Invariant 6: ONE config-mutation choke point. Every admin config mutation runs inside
#    `config_transaction` (crates/busbar/src/admin/v1/json/txn.rs), which owns the file-private
#    `CONFIG_MUTATION_LOCK`, hands the body a FRESH post-lock snapshot, forces store/disk work onto
#    spawn_blocking, and applies the plan through `AppHandle::commit_and_swap`. Two bypasses are
#    build failures outside txn.rs: naming a `CONFIG_MUTATION_LOCK` (a second config lock re-opens
#    lock-then-arbitrary-code, which visibility already forbids for THIS one), and calling
#    `handle.swap(` / `.commit_and_swap(` directly (a swap outside the section is the lost-update the
#    lock exists to prevent). `state.rs` defines both methods, so it is allowed alongside txn.rs.
#    #[cfg(test)] regions and test files are exempt (name-navigated; they drive the primitives
#    directly). See crates/busbar/src/admin/v1/json/txn.rs. ──────────────────────────────────────
hdr "one config-mutation choke point (no raw config lock / swap outside txn.rs)"
# txn.rs is the choke point; state.rs DEFINES swap/commit_and_swap (and calls swap from within
# commit_and_swap), so both may name them.
ALLOW_TXN='crates/busbar/src/admin/v1/json/txn.rs'
ALLOW_SWAP='crates/busbar/src/state.rs'
txnfail=0
scan_txn() { awk -v allow_swap="$2" '
  /#\[cfg\(test\)\]/ { pending_test=1 }
  {
    line=$0
    nopen=gsub(/\{/, "{", line); nclose=gsub(/\}/, "}", line)
    if (pending_test && nopen>0) { in_test=1; pending_test=0 }
    if (in_test) { depth += nopen - nclose; if (depth<=0) { in_test=0; depth=0 }; next }
  }
  /^[[:space:]]*\/\// { next }                       # skip whole-line comments (incl doc comments)
  /CONFIG_MUTATION_LOCK/ { printf "%s:%d: names the config mutation lock\n", FILENAME, NR }
  allow_swap == "1" { next }
  /\.commit_and_swap\(/ { printf "%s:%d: direct commit_and_swap outside a transaction\n", FILENAME, NR }
  /handle\.swap\(/      { printf "%s:%d: direct handle.swap outside a transaction\n", FILENAME, NR }
' "$1"; }
while IFS= read -r f; do
  case "$f" in */tests/*) continue ;; esac          # test files are exempt (name-navigated)
  [ "$f" = "$ALLOW_TXN" ] && continue                # the choke point itself
  allow_swap=0
  [ "$f" = "$ALLOW_SWAP" ] && allow_swap=1           # the file that DEFINES swap/commit_and_swap
  hits=$(scan_txn "$f" "$allow_swap")
  if [ -n "$hits" ]; then
    while IFS= read -r h; do note "MUTATION-BYPASS: $h — route through json::txn::config_transaction"; done <<<"$hits"
    fail=1; txnfail=1
  fi
done < <(find crates -name '*.rs')
[ "$txnfail" -eq 0 ] && note "ok"

hdr "result"
if [ "$fail" -ne 0 ]; then note "structure-lint FAILED — see docs/code-layout.md"; exit 1; fi
note "structure-lint passed"
