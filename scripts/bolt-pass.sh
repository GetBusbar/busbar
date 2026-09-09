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
# THE PROFILE FLOOR, AND WHY `[ -s ]` WAS NOT ONE. The only thing this script used to require of a
# BOLT profile was that the file be non-empty — one byte cleared it. That is the same vacuous pass
# the relocation guard above exists to refuse, one input over: a profile with a handful of rows makes
# every flag below a no-op on all but a few functions, llvm-bolt exits 0, the output executes, and an
# essentially UNOPTIMIZED binary ships wearing the +38% claim. The failure is silent by construction,
# because a BOLTed binary built from a near-empty profile behaves exactly like a correct one — just
# slower. So the profile is now held to a FLOOR of real content ([`MIN_PROFILE_ROWS`] sampled rows
# over [`MIN_PROFILE_FUNCS`] distinct functions), and `--selftest` proves that floor refuses the
# profiles that used to pass.
#
# Usage:
#   scripts/bolt-pass.sh --binary <path> (--fdata <path> | --perf-data <path>) --out <path>
#   scripts/bolt-pass.sh --selftest
#
#   --binary     the emit-relocs release binary to optimize
#   --fdata      a BOLT profile already converted on the recording host, OR
#   --perf-data  a raw `perf record` capture; the perf2bolt conversion runs here instead
#   --out        where the optimized binary is written
#   --selftest   prove the preconditions REFUSE what they are supposed to refuse, on constructed
#                fixtures. Needs no llvm-bolt, no perf, no binary and no network.
#
# Requires: llvm-bolt + perf2bolt (Ubuntu 24.04: the `bolt-20` package; detection below also scans
# /usr/lib/llvm-*/bin for installs that never symlinked into /usr/bin) and readelf (binutils).
set -euo pipefail
cd "$(dirname "$0")/.."

# ── THE PROFILE FLOOR ────────────────────────────────────────────────────────────────────────────
# A BOLT no-LBR fdata row is `<flags> <function> <offset> … <count>`; the rows ARE the samples, so
# their number is how much the rewrite has to go on and the distinct function count is how much of
# the binary it can reach. Both are `readonly` with no environment override, for the same reason
# every other floor in this tree is: a floor a caller can lower is a floor a caller can turn off,
# and the caller here is a release workflow.
#
# The numbers are deliberately LOW. This is not a quality bar on the capture — that would need a
# calibration against real recordings this script cannot see. It is the "did anything actually get
# recorded" bar: it must refuse an empty capture, a one-row capture and a capture that saw a single
# function spin, and it must not second-guess a legitimately short benchmark run.
readonly MIN_PROFILE_ROWS=100
readonly MIN_PROFILE_FUNCS=10

die() {
  echo "[bolt-pass] ############################################################" >&2
  echo "[bolt-pass] # FAILED (FAIL-CLOSED): $*" >&2
  echo "[bolt-pass] # No optimized binary was produced. Fix the cause and re-run;" >&2
  echo "[bolt-pass] # the un-BOLTed release binary remains valid to ship as-is." >&2
  echo "[bolt-pass] ############################################################" >&2
  exit 1
}
log() { echo "[bolt-pass] $*"; }

# assert_profile <path> — the floor, as a function so the self-test can drive it directly.
# Prints the reason and returns 1 on refusal; prints the measurement and returns 0 on acceptance.
assert_profile() {
  local f="$1" rows funcs
  if [ ! -f "$f" ]; then
    echo "BOLT profile at $f does not exist"; return 1
  fi
  if [ ! -s "$f" ]; then
    echo "BOLT profile at $f is empty - an empty profile makes every BOLT flag a no-op and ships an unoptimized binary as an optimized one"
    return 1
  fi
  # A row is any non-blank, non-comment line. The FUNCTION is the field a no-LBR fdata row carries
  # after its flags; counting distinct values of it is what separates "the capture saw the program"
  # from "the capture saw one function spin".
  rows="$(grep -cvE '^[[:space:]]*(#|$)' "$f" || true)"; rows="${rows:-0}"
  funcs="$(grep -vE '^[[:space:]]*(#|$)' "$f" | awk '{ for (i = 1; i <= NF; i++) if ($i !~ /^[0-9]+$/) { print $i; break } }' | sort -u | wc -l | tr -d ' ')"
  funcs="${funcs:-0}"
  if [ "$rows" -lt "$MIN_PROFILE_ROWS" ]; then
    echo "BOLT profile at $f carries $rows sampled row(s), floor is $MIN_PROFILE_ROWS. A near-empty profile is not an empty file: llvm-bolt exits 0, the output executes, and an essentially UNOPTIMIZED binary ships wearing the measured +38%. Non-empty was never the same as usable."
    return 1
  fi
  if [ "$funcs" -lt "$MIN_PROFILE_FUNCS" ]; then
    echo "BOLT profile at $f names $funcs distinct function(s), floor is $MIN_PROFILE_FUNCS. A capture that saw one function spin cannot lay out a binary; the rewrite would be a no-op everywhere else and would still report success."
    return 1
  fi
  echo "profile floor: $rows sampled row(s) over $funcs distinct function(s) (floors $MIN_PROFILE_ROWS/$MIN_PROFILE_FUNCS)"
  return 0
}

# ── SELF-TEST ────────────────────────────────────────────────────────────────────────────────────
# The preconditions in this script are the whole script: every one of them exists because its
# absence produced a binary that shipped broken or shipped slow while every tool involved exited 0.
# Until this existed, NONE of them had ever been shown to refuse anything. It runs anywhere — no
# llvm-bolt, no perf, no ELF, no network — because it drives the guards over constructed fixtures.
selftest() {
  local work fails=0
  work="$(mktemp -d)"
  # shellcheck disable=SC2064  # $work is expanded now on purpose
  trap "rm -rf '$work'" RETURN

  # A profile that clears the floor: 200 rows over 20 functions.
  : >"$work/good.fdata"
  local i fn
  for i in $(seq 1 200); do
    fn=$((i % 20))
    printf '1 busbar_fn_%s/1 %s 1 %s\n' "$fn" "$i" "$i" >>"$work/good.fdata"
  done
  # THE ONE THAT USED TO PASS: non-empty, and useless. This is the exact input `[ -s ]` accepted.
  printf '1 busbar_fn_0/1 0 1 1\n' >"$work/onerow.fdata"
  # Plenty of rows, ONE function: a capture that watched a single loop spin.
  : >"$work/onefunc.fdata"
  for i in $(seq 1 200); do
    printf '1 busbar_only_fn/1 %s 1 %s\n' "$i" "$i" >>"$work/onefunc.fdata"
  done
  : >"$work/empty.fdata"

  probe() { # probe <want-rc> <label> <file>
    local want="$1" label="$2" file="$3" rc=0 out
    out="$(assert_profile "$file")" || rc=$?
    if [ "$rc" -eq "$want" ]; then
      echo "  ok   $label"
    else
      echo "  FAIL $label -> rc=$rc (expected $want): $out"
      fails=$((fails + 1))
    fi
  }

  echo "== bolt-pass SELF-TEST (the preconditions are proven to refuse) =="
  echo "-- the profile floor --"
  # GREEN FIRST: a guard that refuses everything proves nothing when it refuses a defect.
  probe 0 "a real profile (200 rows, 20 functions) is ACCEPTED"        "$work/good.fdata"
  probe 1 "an EMPTY profile is refused"                                "$work/empty.fdata"
  probe 1 "a NEAR-EMPTY profile (one row) is refused - \`[ -s ]\` accepted this" "$work/onerow.fdata"
  probe 1 "a profile naming ONE function is refused"                   "$work/onefunc.fdata"
  probe 1 "a profile that does not exist is refused"                   "$work/no-such.fdata"

  echo "-- the argument contract --"
  argprobe() { # argprobe <label> <args...>
    local label="$1"; shift
    if "$0" "$@" >/dev/null 2>&1; then
      echo "  FAIL $label was ACCEPTED"; fails=$((fails + 1))
    else
      echo "  ok   $label is refused"
    fi
  }
  argprobe "--binary with no profile source"      --binary /bin/sh --out "$work/o"
  argprobe "both --fdata and --perf-data"         --binary /bin/sh --fdata "$work/good.fdata" --perf-data "$work/good.fdata" --out "$work/o"
  argprobe "no --out"                             --binary /bin/sh --fdata "$work/good.fdata"
  argprobe "no --binary"                          --fdata "$work/good.fdata" --out "$work/o"
  argprobe "an unknown argument"                  --binary /bin/sh --fdata "$work/good.fdata" --out "$work/o" --reorder-blocks=none
  argprobe "a --binary that does not exist"       --binary "$work/no-such-binary" --fdata "$work/good.fdata" --out "$work/o"

  echo "-- the segfault guard (a binary carrying no relocation sections) --"
  # A text file is not an ELF, so readelf reports no .rela.text and the guard must refuse it. This
  # is the guard whose absence produced a green rewrite and a SEGFAULTING binary on aarch64.
  printf 'not an ELF\n' >"$work/notelf"
  if command -v readelf >/dev/null 2>&1; then
    argprobe "a binary with no .rela.text/.rel.text" --binary "$work/notelf" --fdata "$work/good.fdata" --out "$work/o"
  else
    echo "  skip readelf is absent on this host (the guard itself refuses to run without it)"
  fi

  if [ "$fails" -ne 0 ]; then
    echo ""
    echo "bolt-pass self-test: RED - $fails expectation(s) did not hold. No BOLT output from this" >&2
    echo "script is trustworthy until they do." >&2
    return 1
  fi
  echo ""
  echo "bolt-pass self-test: PASS."
  return 0
}

if [ "${1:-}" = "--selftest" ]; then
  selftest
  exit $?
fi

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
FLOOR_REPORT="$(assert_profile "$FDATA")" || die "$FLOOR_REPORT"
log "$FLOOR_REPORT"

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
