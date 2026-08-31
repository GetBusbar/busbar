#!/usr/bin/env bash
# bolt-pass.sh — post-link binary layout optimization (LLVM BOLT) for a busbar release binary.
#
# WHAT THIS IS. PGO (scripts/pgo-build.sh) decides layout from compiler instrumentation; BOLT
# re-lays-out the LINKED binary from a sampled hardware profile, which sees what the compiler
# cannot: the final inlined, linked code at its real addresses. Measured on an aarch64 (Graviton)
# host against the emit-relocs release binary, this exact recipe delivered +38% req/s on the
# benchmark mix (92,046 vs 66,723 req/s, zero failed requests) with iTLB-load-misses down 83%.
#
# THE DIVISION OF LABOUR, STATED HONESTLY. GitHub-hosted runners expose no usable PMU, so
# `perf record` cannot sample there. The RECORDING half of this pass therefore runs on real
# hardware (the EC2 benchmark host): plain cycles sampling — Graviton has no LBR, and SPE branch
# stacks are not available to perf there, which is why the conversion below passes `-nl`
# (no-LBR mode). The REWRITE half (perf2bolt + llvm-bolt) needs no PMU and runs anywhere the
# tools exist, GitHub runners included — .github/workflows/bolt-pass.yml orchestrates that half.
#
# FAIL-CLOSED, NO KNOBS. The BOLT flags below are the proven recipe and they are constants, not
# options. Every precondition that has an observed failure behind it is checked loudly:
#   * the input binary MUST carry relocations (.rela.text / .rel.text). Linked without
#     --emit-relocs, llvm-bolt on aarch64 exits green and emits a binary that SEGFAULTS — the
#     silent kind of broken this script exists to make impossible. pgo-build.sh links every Linux
#     release binary with --emit-relocs precisely so this check passes on real release bytes.
#   * the profile must be non-empty, the tools must exist, and the OUTPUT binary must actually
#     execute (`--build-info`, which needs no config and exits 0) before success is declared —
#     which also means this script must run on a host of the binary's own architecture.
#
# Usage:
#   scripts/bolt-pass.sh --binary <path> (--fdata <path> | --perf-data <path>) --out <path>
#
#   --binary     the emit-relocs release binary to optimize
#   --fdata      a BOLT profile already converted on the recording host, OR
#   --perf-data  a raw `perf record` capture; the perf2bolt conversion runs here instead
#   --out        where the optimized binary is written
#
# Requires: llvm-bolt + perf2bolt (Ubuntu 24.04: the `bolt-20` package; detection below also scans
# /usr/lib/llvm-*/bin for installs that never symlinked into /usr/bin) and readelf (binutils).
set -euo pipefail
cd "$(dirname "$0")/.."

die() {
  echo "[bolt-pass] ############################################################" >&2
  echo "[bolt-pass] # FAILED (FAIL-CLOSED): $*" >&2
  echo "[bolt-pass] # No optimized binary was produced. Fix the cause and re-run;" >&2
  echo "[bolt-pass] # the un-BOLTed release binary remains valid to ship as-is." >&2
  echo "[bolt-pass] ############################################################" >&2
  exit 1
}
log() { echo "[bolt-pass] $*"; }

BINARY="" FDATA="" PERF_DATA="" OUT=""
while [ $# -gt 0 ]; do
  case "$1" in
    --binary)    BINARY="${2:?--binary needs a path}"; shift 2 ;;
    --fdata)     FDATA="${2:?--fdata needs a path}"; shift 2 ;;
    --perf-data) PERF_DATA="${2:?--perf-data needs a path}"; shift 2 ;;
    --out)       OUT="${2:?--out needs a path}"; shift 2 ;;
    *) die "unknown argument '$1' (usage: bolt-pass.sh --binary <path> (--fdata <path> | --perf-data <path>) --out <path>)" ;;
  esac
done
[ -n "$BINARY" ] || die "--binary is required"
[ -n "$OUT" ] || die "--out is required"
# Exactly one profile source: two would mean this script silently chose, and choosing is a knob.
if [ -n "$FDATA" ] && [ -n "$PERF_DATA" ]; then
  die "--fdata and --perf-data are mutually exclusive: pass the converted profile OR the raw capture, not both"
fi
[ -n "$FDATA" ] || [ -n "$PERF_DATA" ] || die "one of --fdata or --perf-data is required"
[ -f "$BINARY" ] || die "no binary at $BINARY"

# ── tool detection ──────────────────────────────────────────────────────────────────────────────
# PATH first; otherwise scan the versioned LLVM trees (/usr/lib/llvm-NN/bin) and versioned names
# (/usr/bin/<tool>-NN), highest version winning — Ubuntu's bolt-NN packages install the real
# binaries under /usr/lib/llvm-NN/bin and do not always land an unversioned name on PATH.
find_tool() { # find_tool <name> -> path on stdout, empty if absent
  local name="$1" hit
  hit="$(command -v "$name" 2>/dev/null || true)"
  if [ -z "$hit" ]; then
    # shellcheck disable=SC2012  # fixed system globs (no exotic filenames); ls -1 | sort -V is the version pick
    hit="$(ls -1 /usr/lib/llvm-*/bin/"$name" /usr/bin/"$name"-[0-9]* 2>/dev/null | sort -V | tail -n 1 || true)"
  fi
  printf '%s' "$hit"
}
LLVM_BOLT="$(find_tool llvm-bolt)"
[ -n "$LLVM_BOLT" ] || die "llvm-bolt not found on PATH or under /usr/lib/llvm-*/bin. On Ubuntu 24.04: apt-get install bolt-20 (provides /usr/lib/llvm-20/bin/llvm-bolt and perf2bolt)."
if [ -n "$PERF_DATA" ]; then
  PERF2BOLT="$(find_tool perf2bolt)"
  [ -n "$PERF2BOLT" ] || die "perf2bolt not found on PATH or under /usr/lib/llvm-*/bin. On Ubuntu 24.04: apt-get install bolt-20 (provides /usr/lib/llvm-20/bin/llvm-bolt and perf2bolt)."
fi
command -v readelf >/dev/null 2>&1 || die "readelf not found (install binutils) - the relocation guard below cannot run without it, and running without the guard is how a segfaulting binary ships green"
log "llvm-bolt: $LLVM_BOLT"

# ── THE SEGFAULT GUARD: refuse a binary linked without --emit-relocs ────────────────────────────
# llvm-bolt does not fail on such a binary; it produces one that crashes at runtime (observed on
# aarch64). The relocation sections are the difference, so their absence is a hard refusal here,
# before any rewrite happens. Both spellings are accepted: .rela.text (RELA targets - x86_64,
# aarch64) and .rel.text, so the guard cannot false-negative on a REL-flavoured ELF.
if ! readelf -S "$BINARY" | grep -Eq '\.rela?\.text'; then
  die "$BINARY carries no .rela.text/.rel.text section, i.e. it was NOT linked with --emit-relocs. BOLT over such a binary emits output that segfaults on aarch64 while llvm-bolt itself exits green. Rebuild via scripts/pgo-build.sh (or release-build.sh), which links every Linux release binary with -Clink-arg=-Wl,--emit-relocs for exactly this reason."
fi
log "relocation guard: $BINARY carries relocation sections (emit-relocs link confirmed)"

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ── profile: convert the raw capture if that is what arrived ────────────────────────────────────
# `-nl`: treat the capture as plain-cycles samples, no LBR - the only mode the recording host
# supports (see the header). Without it perf2bolt looks for branch-stack data the capture does not
# have and produces a useless profile.
if [ -n "$PERF_DATA" ]; then
  [ -s "$PERF_DATA" ] || die "perf capture at $PERF_DATA is missing or empty"
  FDATA="$WORK/profile.fdata"
  log "converting $PERF_DATA -> $FDATA (perf2bolt -nl)"
  "$PERF2BOLT" -nl -p "$PERF_DATA" -o "$FDATA" "$BINARY" \
    || die "perf2bolt conversion failed - most commonly the capture was recorded against a DIFFERENT build of the binary; record and rewrite must use the same bytes"
fi
[ -s "$FDATA" ] || die "BOLT profile at $FDATA is missing or empty - an empty profile would make every flag below a no-op and ship an unoptimized binary as an optimized one"

# ── the rewrite: the exact proven recipe, no variations ─────────────────────────────────────────
#   -reorder-blocks=ext-tsp    basic-block layout by extended TSP over the measured edge counts
#   -reorder-functions=cdsort  function order by call-distance sort (hot callers adjacent)
#   -split-functions           move never-sampled tails of hot functions out of line
#   -split-all-cold            and every fully-cold function too, shrinking the hot text that has
#                              to fit in iTLB (the -83% iTLB-load-misses is this line's work)
#   -use-gnu-stack             reuse the PT_GNU_STACK slot instead of growing the program-header
#                              table, which not every loader tolerates moving
log "rewriting $BINARY -> $OUT"
"$LLVM_BOLT" "$BINARY" -data "$FDATA" -o "$OUT" \
  -reorder-blocks=ext-tsp \
  -reorder-functions=cdsort \
  -split-functions \
  -split-all-cold \
  -use-gnu-stack \
  || die "llvm-bolt rewrite failed"
[ -s "$OUT" ] || die "llvm-bolt exited 0 but produced nothing at $OUT"
chmod +x "$OUT"

# ── POSITIVE VERIFICATION: the output must EXECUTE before success is declared ───────────────────
# The observed failure mode is precisely a green rewrite whose output crashes, so an exit-0 from
# llvm-bolt proves nothing. `--build-info` needs no config, no network and no state (it prints the
# build-provenance stamp and exits 0), which makes it the minimal real execution of the rewritten
# startup path. This requires running on the binary's own architecture - deliberate, not a bug.
# A bare filename must exec as a path, never resolve via PATH lookup.
case "$OUT" in */*) RUN="$OUT" ;; *) RUN="./$OUT" ;; esac
INFO="$("$RUN" --build-info)" \
  || die "the BOLTed binary at $OUT failed to execute --build-info. This is the segfault signature; the output is broken and MUST NOT ship. (If the failure is exec-format, this host is not the binary's architecture - run the pass on a matching host.)"
[ -n "$INFO" ] || die "the BOLTed binary executed but printed an empty build-provenance stamp"
log "verified: $OUT executes (build: $INFO)"
log "done: $OUT"
echo "$OUT"
