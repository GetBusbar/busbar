#!/usr/bin/env bash
# TRAINER-DRIFT DETECTOR: does the PGO trainer still exercise what production exercises?
#
# The PGO trainer (scripts/pgo-build.sh) self-trains on every build, so the classic PGO failure
# mode - a stale checked-in profile - cannot happen here. The failure mode that CAN happen is
# trainer-SHAPE drift: the product grows a new hot path (a new translation dialect, a new auth
# arm, a heavier serializer) and the trainer's fixed scenario mix silently stops covering it.
# The optimized build still succeeds, the marker still says pgo=true, but the layout is guided
# by yesterday's traffic shape. This script makes that drift measurable: it compares
#
#   (A) the trainer's view: hot functions in the build's merged.profdata
#       (llvm-profdata counter weights - what the trainer actually executed, and how much)
#   (B) production's view: a folded-stacks file (perf script | FlameGraph stackcollapse-perf.pl,
#       as produced on the profiling box) from real or bench traffic
#
# and reports:
#
#   1. OVERLAP (the gate): what fraction of the trainer's top-N hot functions appear anywhere
#      in production's top-3N by inclusive stack weight. Asymmetric on purpose - the comparison
#      set on the production side is 3x wide and inclusive-weighted, both generous to the
#      trainer, because the trainer running EXTRA code production rarely hits is mostly
#      harmless; what the gate catches is the trainer's own heat concentrating in code
#      production does not recognize at all, i.e. training for traffic that does not exist.
#   2. MISSING TABLE (the actionable signal): production's top-N self-weight (leaf-cycle)
#      symbols that the trainer NEVER executed - not merely "not hot", but zero counter weight
#      across the trainer's ENTIRE profile. Each row is a hard trainer-scenario gap: production
#      burns real cycles there and the trainer cannot have laid it out hot, so it names a shape
#      to add to pgo-build.sh's phase-2 mix. (Membership is tested against the full profile,
#      not a top slice, because the two sides weigh differently - see below - and "below the
#      trainer's top slice" would flag half of production's wrapper frames as false gaps.)
#
# Ranking choices (deliberate): the trainer side ranks by llvm-profdata's max internal block
# count - its native hotness measure. The folded side uses INCLUSIVE weight for the broad
# top-3N containment set but SELF weight for the missing table (a missing entry must be an
# actual cycle-eater, not a wrapper that merely sits above one, or the table would be noise).
#
# KNOWN STRUCTURAL SKEW (why healthy overlap is far below 100%): the two measures disagree by
# construction. profdata weight is IR block iteration count, which concentrates in small tight
# loops (field arithmetic, hex encode) - many of which INLINE AWAY in the optimized production
# binary and thus never appear as perf frames; perf self weight concentrates in large
# monomorphized poll/parse state machines. Precompiled std code (e.g. core::fmt) is never
# instrumented at all (-Cprofile-generate does not rebuild std). The gate threshold below is
# calibrated on real data WITH this skew included; do not expect 90% overlap from a healthy
# trainer, and re-calibrate if either side's measurement method changes.
#
# Usage:
#   scripts/pgo-drift-check.sh --folded /path/to/folded.txt \
#       [--profdata target/pgo-profiles/merged.profdata] [--top 40] [--min-overlap 10]
#
# Exit codes (distinct so CI can tell "broken" from "drifted"):
#   0  overlap >= --min-overlap
#   1  DRIFT: overlap below --min-overlap
#   2  environment/usage error (missing file, missing tool, unparsable input) - fail closed,
#      never report "no drift" on inputs it could not actually read
#
# --min-overlap default (10) provenance: measured 2026-08-28 on real artifacts - this tree's
# 3-run pgo-build.sh merged.profdata against the w6 production-shaped bench folded profile -
# which scored 27% overlap at --top 40 (and 39/40 production-hot symbols trainer-covered).
# 27% is a HEALTHY reading here: the structural skew above accounts for most of the distance
# from 100, and the w6 capture predates signed-key bench traffic while the trainer's top slice
# is ed25519/curve25519-heavy. Default = measured 27 minus 17 points of noise headroom per the
# calibration rule (healthy-measured minus 15-20). Re-measure and raise the bar once a folded
# capture of governed (signed-key) production traffic exists - against such a capture the
# expected healthy overlap is substantially higher than 27%.
#
# SYMBOL NORMALIZATION (the whole game - the two sides name functions differently):
#   * profdata names are raw Rust v0 mangled symbols, sometimes prefixed "cgu-object;"; the
#     folded file carries demangled perf frames. We demangle the profdata side with rustfilt if
#     installed, else c++filt IF a probe shows it understands Rust v0 (Apple/LLVM ones do), else
#     fail with exit 2 - heuristic un-mangling of v0 symbols cannot produce names comparable to
#     perf's demangler, and a detector silently comparing demangled apples to mangled oranges
#     would report 0% overlap as "drift".
#   * both sides then: strip legacy ::h<16-hex> hash suffixes and .llvm.<N> suffixes, drop
#     ::{closure#N}/{{closure}} components (an async fn's body is a closure frame in perf but
#     must match its fn), strip &/mut/dyn sigils and all whitespace (demanglers disagree on
#     "Type, Type" vs "Type,Type"), and trim the trailing comma a perf-truncated frame ends on.
#   * matching is exact OR prefix (>= 25 chars, either direction): perf truncates long
#     monomorphized names mid-generics, so a folded frame is often a strict prefix of the full
#     demangled profdata name.
#
# SHARED DENY-LIST (applied identically to BOTH sides - see deny() below for the per-entry
# rationale): kernel/libc/vdso/[unknown] frames, comm-name roots, tokio runtime plumbing,
# std thread bootstrap, allocator shims, compiler drop-glue, uninstrumentable std internals.
#
# No knobs beyond the four flags. Requires: llvm-profdata (rustup llvm-tools), awk, sort,
# and rustfilt or a Rust-v0-capable c++filt.
set -uo pipefail
cd "$(dirname "$0")/.." || exit 2

# Defaults. --profdata default is THE path pgo-build.sh merges to (PROF_DIR/merged.profdata).
PROFDATA_FILE="target/pgo-profiles/merged.profdata"
FOLDED_FILE=""
TOP=40
MIN_OVERLAP=10

usage() {
  echo "usage: $0 --folded <stackcollapse.txt> [--profdata <merged.profdata>] [--top N] [--min-overlap PCT]" >&2
  exit 2
}
# Environment/usage failure: loud and exit 2, so CI can distinguish "the check could not run"
# from "the check ran and found drift" (exit 1). NEVER exit 0 without a real comparison.
die() { echo "[pgo-drift] ERROR: $*" >&2; exit 2; }

while [ $# -gt 0 ]; do
  case "$1" in
    --profdata)    [ $# -ge 2 ] || usage; PROFDATA_FILE="$2"; shift 2 ;;
    --folded)      [ $# -ge 2 ] || usage; FOLDED_FILE="$2"; shift 2 ;;
    --top)         [ $# -ge 2 ] || usage; TOP="$2"; shift 2 ;;
    --min-overlap) [ $# -ge 2 ] || usage; MIN_OVERLAP="$2"; shift 2 ;;
    *) usage ;;
  esac
done
[ -n "$FOLDED_FILE" ] || usage
case "$TOP" in ''|*[!0-9]*) die "--top must be a positive integer, got '$TOP'" ;; esac
case "$MIN_OVERLAP" in ''|*[!0-9]*) die "--min-overlap must be an integer percentage, got '$MIN_OVERLAP'" ;; esac
[ "$TOP" -ge 1 ] || die "--top must be >= 1"
[ -s "$PROFDATA_FILE" ] || die "profdata missing/empty at $PROFDATA_FILE (run scripts/pgo-build.sh, or pass --profdata)"
[ -s "$FOLDED_FILE" ] || die "folded stacks missing/empty at $FOLDED_FILE"

# llvm-profdata: same discovery as pgo-build.sh (the rustup llvm-tools component), so both
# scripts agree on the tool version that reads the profile format the trainer wrote.
LLVM_PROFDATA="$(find "$(rustc --print sysroot)" -name llvm-profdata -type f 2>/dev/null | head -1)"
[ -n "$LLVM_PROFDATA" ] || die "llvm-profdata not found in the rust sysroot (rustup component add llvm-tools)"

# ---- demangler selection (fail closed - see header) ------------------------------------------
# Probe with a canonical v0 symbol: a demangler that understands Rust v0 turns it into a ::
# path; one that does not echoes it back (c++filt's behavior for symbols it can't demangle).
DEMANGLE_PROBE="_RNvC6_123foo3bar"
if command -v rustfilt >/dev/null 2>&1; then
  DEMANGLER=rustfilt
elif command -v c++filt >/dev/null 2>&1 \
  && [ "$(printf '%s\n' "$DEMANGLE_PROBE" | c++filt)" != "$DEMANGLE_PROBE" ]; then
  DEMANGLER=c++filt
else
  die "no Rust-v0-capable demangler (install rustfilt: cargo install rustfilt)"
fi

WORK="$(mktemp -d)"
trap 'rm -rf "$WORK"' EXIT

# ---- shared normalizer + deny-list (one awk library, prepended to every extractor) -----------
# One definition used by both sides so a rule change cannot desynchronize them. norm() is the
# comparison key; the human-readable pre-norm name is carried alongside for reporting.
AWK_LIB='
# deny(sym): 1 = excluded from BOTH the trainer and production rankings. Rationale per entry:
function deny(s) {
  # Unresolved/synthetic perf frames ([unknown], [[vdso]], [module]): nothing to match or act on.
  if (s == "[unknown]" || s ~ /^\[\[?[a-z]/) return 1
  # Frames with no "::" are not Rust functions: kernel symbols (tcp_sendmsg, el0_svc, ...),
  # libc/vdso (memcpy, __clock_gettime), outline-atomics (__aarch64_*), jemalloc C (_rjem_*),
  # and stackcollapse comm-name roots (busbar-core-0). None can be a trainer-scenario gap:
  # the trainer only shapes Rust code, and kernel/libc heat follows whatever Rust drives it.
  if (s !~ /::/) return 1
  # tokio runtime plumbing (task poll harness, park/unpark, scheduler, timer wheel): present in
  # every async workload in roughly the same places regardless of scenario mix - carries no
  # drift signal, but its inclusive weight would crowd real symbols out of the folded top set.
  if (s ~ /tokio::runtime/) return 1
  # std thread bootstrap / backtrace scaffolding: the frames every thread stack starts with.
  if (s ~ /^<?std::(sys|thread|rt)::/ || s ~ /__rust_begin_short_backtrace/) return 1
  # Allocator shims: __rustc::__rust_alloc etc. just forward to the allocator; alloc pressure
  # is real but its actionable signal lives in the Rust CALLERS, which rank on their own.
  if (s ~ /^__rustc::/) return 1
  # Compiler-generated drop glue: hotness tracks which types get dropped, not which scenario
  # ran; its monomorphized names rarely survive normalization across builds anyway.
  if (s ~ /core::ptr::drop_glue/) return 1
  # Non-generic precompiled std (core::fmt machinery is the one that recurs hot in perf):
  # -Cprofile-generate does not rebuild std, so these CANNOT appear on the trainer side -
  # flagging them as gaps would be permanent false positives no trainer scenario can fix.
  if (s ~ /^<?core::fmt::/) return 1
  return 0
}
# norm(sym): the shared canonical comparison form (see header contract).
function norm(s) {
  gsub(/::h[0-9a-f]{16}/, "", s)          # legacy-mangling hash suffixes
  gsub(/\.llvm\.[0-9]+/, "", s)           # LLVM-appended disambiguators
  gsub(/::\{closure#[0-9]+\}/, "", s)     # perf closure frames -> their owning fn
  gsub(/\{\{closure\}\}/, "", s)          # rustfilt spelling of the same
  gsub(/[&]|dyn |mut /, "", s)            # reference/dyn sigils: demangler-dependent
  gsub(/[ \t]+/, "", s)                   # whitespace: demangler-dependent
  sub(/,+$/, "", s)                       # perf mid-generics truncation leaves a bare comma
  return s
}
'

# ---- side A: trainer functions from merged.profdata ------------------------------------------
# ONE full text-dump pass yields every function with its max internal block count (the counter
# weight). Format: mangled-name line, "# Func Hash:", hash, "# Num Counters:", n, "# Counter
# Values:", n values, then optional value-profile sections. This full list serves two roles:
# the ranked hot slice (sorted head) and the complete never-executed membership test for the
# missing table. Zero-weight functions are dropped: linked but never run by the trainer.
"$LLVM_PROFDATA" show --all-functions --text "$PROFDATA_FILE" 2>/dev/null | awk '
  /^# Func Hash:/ { fname = prev; next }
  /^# Counter Values:/ { incnt = 1; max = 0; next }
  /^#/ || /^$/ { if (incnt && fname != "") { if (max > 0) printf "%d\t%s\n", max, fname
                                             fname = "" }
                 incnt = 0; next }
  incnt { if ($1 + 0 > max) max = $1 + 0; next }
  { prev = $0 }
  END { if (incnt && fname != "" && max > 0) printf "%d\t%s\n", max, fname }
' > "$WORK/train.raw"
[ -s "$WORK/train.raw" ] || die "no nonzero function counters in $PROFDATA_FILE (wrong file, or llvm-profdata/profile version mismatch)"

# Cross-check the ranking against llvm-profdata's own --topn when this llvm-profdata has it
# (detected, not assumed - older builds lack the flag): --topn ranks by the same max internal
# block count, so its #1 function must appear in our parse with the same weight. This guards
# the text-dump parser against silent format drift in future llvm versions. When --topn is
# absent the parse stands alone (it IS the documented text format), just unverified.
if "$LLVM_PROFDATA" show --help 2>&1 | grep -q -- '--topn'; then
  TOPLINE="$("$LLVM_PROFDATA" show --topn=1 "$PROFDATA_FILE" 2>/dev/null \
    | sed -n 's/^  \(.*\), max count = \([0-9][0-9]*\)$/\2\t\1/p')"
  [ -n "$TOPLINE" ] || die "llvm-profdata --topn produced no parsable ranking line (format drift?)"
  grep -qF "$TOPLINE" "$WORK/train.raw" \
    || die "text-dump parse disagrees with llvm-profdata --topn on the hottest function (parser drift - fix this script before trusting its verdict)"
fi

# Strip the "cgu-object;" prefix profdata prepends to internal-linkage symbols, demangle the
# bare symbol column (weights pass through untouched), then normalize/filter/aggregate.
# Aggregation is MAX across CGU copies, not sum: the copies are the same code laid out twice,
# and the hotter copy is the honest hotness estimate. Output: weight \t norm-key \t display.
sed 's/^\([0-9]*\)\t.*;/\1\t/' "$WORK/train.raw" | "$DEMANGLER" | awk -F'\t' "$AWK_LIB"'
  { s = norm($2); if (s == "" || deny(s)) next
    if ($1 + 0 > w[s]) { w[s] = $1 + 0; disp[s] = $2 } }
  END { for (s in w) printf "%d\t%s\t%s\n", w[s], s, disp[s] }
' | sort -rn > "$WORK/train.all"
head -n "$TOP" "$WORK/train.all" > "$WORK/train.top"
[ -s "$WORK/train.top" ] || die "trainer hot set empty after normalization/deny-filter (profile from a non-Rust binary?)"

# ---- side B: production hot sets from the folded stacks --------------------------------------
# One pass computes both weights per frame. Line format: "comm;frame1;...;frameN count".
# Frame 1 is stackcollapse's comm name, dropped unconditionally. Inclusive weight counts each
# frame once per stack (dedup within the line, so recursion does not double-count); self weight
# goes to the leaf frame only. Output: incl \t self \t norm-key \t display.
awk "$AWK_LIB"'
  { c = $NF + 0; sub(/[ \t]+[0-9]+[ \t]*$/, "")
    n = split($0, f, ";")
    delete seen
    for (i = 2; i <= n; i++) {
      s = norm(f[i]); if (s == "" || deny(s)) continue
      if (!(s in seen)) { seen[s] = 1; incl[s] += c; if (!(s in disp)) disp[s] = f[i] }
      if (i == n) { self[s] += c; total += c }
    } }
  END { for (s in incl) printf "%d\t%d\t%s\t%s\n", incl[s], self[s], s, disp[s]
        printf "TOTALSELF\t%d\n", total > "/dev/stderr" }
' "$FOLDED_FILE" > "$WORK/prod.norm" 2> "$WORK/prod.meta"
[ -s "$WORK/prod.norm" ] || die "no usable frames in $FOLDED_FILE (is it stackcollapse output: 'comm;frames;...;leaf count' lines?)"
TOTAL_SELF="$(awk -F'\t' '$1 == "TOTALSELF" { print $2 }' "$WORK/prod.meta")"
[ -n "$TOTAL_SELF" ] && [ "$TOTAL_SELF" -gt 0 ] || die "folded file has zero counted self weight after filtering"

sort -rn "$WORK/prod.norm" | head -n $((TOP * 3)) | cut -f3 > "$WORK/prod.broad"   # by inclusive
sort -t"$(printf '\t')" -k2,2rn "$WORK/prod.norm" | head -n "$TOP" \
  | awk -F'\t' '{ printf "%d\t%s\t%s\n", $2, $3, $4 }' > "$WORK/prod.top"          # by self

# ---- compare ---------------------------------------------------------------------------------
# matches(): exact on norm keys, or >=25-char prefix either way (perf truncation - see header).
# Overlap gate: trainer top-N found anywhere in production's inclusive top-3N.
# Missing table: production self top-N with ZERO presence in the trainer's full profile.
RESULT="$(awk -F'\t' '
  function matches(a, b) {
    if (a == b) return 1
    if (length(a) >= 25 && index(b, a) == 1) return 1
    if (length(b) >= 25 && index(a, b) == 1) return 1
    return 0
  }
  FILENAME == ARGV[1] { pbroad[++np] = $1; next }
  FILENAME == ARGV[2] { tall[++nt] = $2; next }
  FILENAME == ARGV[3] { ttop[++nc] = $2; next }
  FILENAME == ARGV[4] { pw[++nq] = $1; ptop[nq] = $2; pdisp[nq] = $3; next }
  END {
    hit = 0
    for (i = 1; i <= nc; i++) {
      found = 0
      for (j = 1; j <= np && !found; j++) if (matches(ttop[i], pbroad[j])) found = 1
      if (found) hit++
    }
    printf "OVERLAP\t%d\t%d\t%d\n", int(hit * 100 / nc), hit, nc
    for (i = 1; i <= nq; i++) {
      found = 0
      for (j = 1; j <= nt && !found; j++) if (matches(ptop[i], tall[j])) found = 1
      if (!found) printf "MISS\t%d\t%s\n", pw[i], pdisp[i]
    }
  }
' "$WORK/prod.broad" "$WORK/train.all" "$WORK/train.top" "$WORK/prod.top")"

OVERLAP_PCT="$(printf '%s\n' "$RESULT" | awk -F'\t' '$1 == "OVERLAP" { print $2 }')"
OVERLAP_HIT="$(printf '%s\n' "$RESULT" | awk -F'\t' '$1 == "OVERLAP" { print $3 }')"
OVERLAP_OF="$(printf '%s\n' "$RESULT" | awk -F'\t' '$1 == "OVERLAP" { print $4 }')"
[ -n "$OVERLAP_PCT" ] || die "internal: comparison produced no overlap line"
MISS_COUNT="$(printf '%s\n' "$RESULT" | grep -c '^MISS' || true)"
PROD_N="$(wc -l < "$WORK/prod.top" | tr -d ' ')"

echo "[pgo-drift] trainer profile : $PROFDATA_FILE ($(wc -l < "$WORK/train.all" | tr -d ' ') executed functions)"
echo "[pgo-drift] production folded: $FOLDED_FILE"
echo "[pgo-drift] demangler=$DEMANGLER top=$TOP broad=3x=$((TOP * 3))"
echo "[pgo-drift]"
echo "[pgo-drift] trainer-heat overlap: ${OVERLAP_PCT}% (${OVERLAP_HIT}/${OVERLAP_OF} of the trainer's top-$TOP appear in production's inclusive top-$((TOP * 3)))"
echo "[pgo-drift] trainer coverage    : $((PROD_N - MISS_COUNT))/$PROD_N of production's self-weight top-$TOP were executed by the trainer"
echo "[pgo-drift]"
if [ "$MISS_COUNT" -eq 0 ]; then
  echo "[pgo-drift] every production-hot symbol was executed by the trainer: no scenario gaps."
else
  echo "[pgo-drift] production-hot symbols the trainer NEVER executed - each is a trainer-scenario gap"
  echo "[pgo-drift] (ranked by production self weight; % is share of production's total counted self weight):"
  printf '%s\n' "$RESULT" | awk -F'\t' -v total="$TOTAL_SELF" '
    $1 == "MISS" { printf "[pgo-drift]   %6.2f%%  %14d  %s\n", $2 * 100 / total, $2, $3 }'
fi
echo "[pgo-drift]"
if [ "$OVERLAP_PCT" -lt "$MIN_OVERLAP" ]; then
  echo "[pgo-drift] DRIFT: overlap ${OVERLAP_PCT}% < required ${MIN_OVERLAP}% - the trainer's heat no longer" >&2
  echo "[pgo-drift] resembles production traffic. Update the phase-2 shapes in scripts/pgo-build.sh" >&2
  echo "[pgo-drift] (the missing table above names what production runs that the trainer does not)." >&2
  exit 1
fi
echo "[pgo-drift] OK: overlap ${OVERLAP_PCT}% >= ${MIN_OVERLAP}%"
exit 0
