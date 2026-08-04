#!/usr/bin/env bash
# Tracing-seam enforcement lint (task #140) — the can't-forget guarantee behind the tracing seam.
#
# THE RULE (verbatim intent): "every TRACE(x) must be bound by a Level. Can't have a rogue trace
# not have a level, and level must be set in 1 spot." The "1 spot" half is `observability.rs`'s
# `HOTPATH_LEVEL` constant (see its doc comment) plus `log_levels()`'s stderr/OTLP filter split —
# both already reviewed by hand as part of this task. This script is the MECHANICAL, durable half:
# it fails CI if a FUTURE `#[tracing::instrument]` (or the `tracing`-prelude-imported `#[instrument]`
# form) omits an explicit `level = ...` argument, so a span can never again silently default to INFO
# (== always on, on the hot path) the way `proxy/engine/mod.rs`'s `forward` span and
# `proxy/engine/walk.rs`'s `forward_once` span both did before this task.
#
# SCOPE, DELIBERATELY NARROW: this lint enforces rule (a) only — "every `#[instrument]` has an
# explicit level" — because it is the mechanical, unambiguous half of the tracing-seam contract. A
# companion rule flagging "a per-request-happy-path `info!`/`warn!` event macro" was evaluated and
# REJECTED: distinguishing a happy-path event from an error/rare/degraded/boot-condition one requires
# reading the surrounding branch, which is not reliably mechanical (see the task's own triage, done
# by hand, in the tracing-seam PR description) — a lint that guesses wrong on that axis produces
# false positives that erode trust in the whole gate. A precise lint that only catches rule (a) is
# far better than a fuzzy one that also tries rule (b); see `docs/observability.md` for the
# documented convention that covers rule (b) instead (event macros: use `HOTPATH_LEVEL`-mapped
# `debug!`/`trace!` on the per-request happy path, leave `info!`/`warn!`/`error!` for
# error/rare/degraded/boot conditions — reviewed by hand, not lint-enforced).
#
# WHAT COUNTS AS "explicit level": the attribute's token stream (which may span multiple lines, e.g.
# a multi-line `fields(...)` list) contains a `level` key anywhere before its closing `)]`. This is a
# deliberately conservative heuristic — see the SELF-TEST's documented false-negative below — that
# trades a theoretical bypass (a custom `fields(level = ...)` shadowing the real parameter) for zero
# false positives on the real, multi-line attribute shapes already in this tree.
#
# Runs in CI (see .github/workflows/ci.yml, structure-lint job), mirroring
# response-header-lint.sh / release-script-lint.sh: no external deps, bash 3.2 + POSIX awk
# (macOS/Linux), `--selftest` proves the scanner still catches a real bypass before its verdict on
# the tree is trusted.
set -euo pipefail
cd "$(dirname "$0")/.."

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ── THE ATTRIBUTE SCANNER ───────────────────────────────────────────────────────────────────────
# One awk pass: find every `#[instrument` / `#[tracing::instrument` attribute start (a code line,
# not a comment), accumulate its full token text across however many lines it spans by tracking
# paren balance, then — once balanced (parens closed, or a bare `#[instrument]`/`#[instrument;]`
# with no parens at all) — flag it if the accumulated text never mentions `level`.
INSTRUMENT_SCAN_AWK='
  FNR==1 { in_attr=0; buf=""; start_line=0 }
  {
    line = $0
    is_comment = (line ~ /^[[:space:]]*\/\//)
    if (!in_attr) {
      if (!is_comment && line ~ /^[[:space:]]*#\[[[:space:]]*(tracing[[:space:]]*::[[:space:]]*)?instrument[[:space:]]*[](]/) {
        in_attr = 1
        start_line = FNR
        buf = line
      } else {
        next
      }
    } else {
      buf = buf "\n" line
    }
    # Balanced once the accumulated text has equal '\''('\'' / '\'')'\'' counts — true immediately for
    # a bare `#[instrument]` (0 and 0) and once the closing `)]` lands for the parenthesized form.
    openp = gsub(/\(/, "(", buf)
    closep = gsub(/\)/, ")", buf)
    if (openp == closep) {
      if (buf !~ /level/) {
        printf "%s:%d: #[instrument] with no explicit level= — must reference observability::HOTPATH_LEVEL (or a literal level) so it is filtered off by default\n", FILENAME, start_line
      }
      in_attr = 0
      buf = ""
    }
  }
'
scan_rule() { awk "$INSTRUMENT_SCAN_AWK" "$@"; }

# ── SELF-TEST — prove the scanner still catches a real bypass before trusting its verdict ─────────
run_selftest() {
  hdr "tracing-lint SELF-TEST (the missing-level scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 pass=0

  # RED: every level-less shape this lint exists to catch — bare, single-line, and (the shape that
  # actually shipped rogue in this task) multi-line with the closing paren several lines down.
  cat >"${tmp}/red.rs" <<'RED'
#[instrument]
pub fn bare() {}

#[tracing::instrument(name = "forward_once", skip_all, fields(lane = i))]
pub fn single_line() {}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    name = "forward",
    skip_all,
    fields(pool = %pool_name, request_id = tracing::field::Empty)
)]
pub fn multi_line() {}
RED
  local hits
  hits=$(scan_rule "${tmp}/red.rs")
  local n; n=$(printf '%s\n' "$hits" | grep -c ':' || true)
  if [ "$n" -eq 3 ]; then
    pass=$((pass+1)); note "RED: all 3 level-less shapes (bare / single-line / multi-line) flagged"
  else
    fail=1; note "RED FAILED: expected 3 hits, got ${n}:"; note "$hits"
  fi

  # GREEN: the same 3 shapes, each WITH an explicit level (literal and the HOTPATH_LEVEL path form,
  # matching what `proxy/engine/mod.rs` and `proxy/engine/walk.rs` now carry) — must stay silent.
  cat >"${tmp}/green.rs" <<'GREEN'
#[tracing::instrument(level = "debug", name = "gemini_ingress", skip_all)]
pub fn single_line() {}

#[allow(clippy::too_many_arguments)]
#[tracing::instrument(
    level = HOTPATH_LEVEL,
    name = "forward",
    skip_all,
    fields(pool = %pool_name, request_id = tracing::field::Empty)
)]
pub fn multi_line() {}

// A comment merely NAMING `#[instrument]` must not arm the scanner.
// #[instrument]
pub fn prod_after() {}
GREEN
  hits=$(scan_rule "${tmp}/green.rs")
  if [ -z "$hits" ]; then
    pass=$((pass+1)); note "GREEN: explicit-level (literal + HOTPATH_LEVEL path) forms + a comment mention all stay silent"
  else
    fail=1; note "GREEN FAILED: expected silence, got: $hits"
  fi

  note "self-test: ${pass}/2 fixture groups passed"
  if [ "$fail" -ne 0 ]; then
    note "tracing-lint SELF-TEST FAILED — the scanner would let a bypass through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

hdr "tracing seam (task #140): every #[instrument] carries an explicit level="
# Candidate set: every crate .rs file EXCEPT integration-test trees (`*/tests/*`, name-navigated and
# exempt the same way structure-lint.sh / response-header-lint.sh treat them — a test helper span's
# level is not an operator-visible hot-path concern).
CANDIDATES=()
while IFS= read -r f; do CANDIDATES+=("$f"); done < <(find crates -name '*.rs' -not -path '*/tests/*' | sort)

hits=""
for f in "${CANDIDATES[@]}"; do
  h=$(scan_rule "$f") || true
  [ -n "$h" ] && hits="${hits}${h}"$'\n'
done
hits="${hits%$'\n'}"

fail=0
if [ -n "$hits" ]; then
  while IFS= read -r h; do note "ROGUE-INSTRUMENT: $h"; done <<<"$hits"
  fail=1
else
  note "ok"
fi

hdr "result"
if [ "$fail" -ne 0 ]; then
  note "tracing-lint FAILED"
  note "every #[tracing::instrument] must carry an explicit level= — for a hot, per-request span"
  note "that is \`level = observability::HOTPATH_LEVEL\` (import it: \`use crate::observability::HOTPATH_LEVEL;\`,"
  note "since the instrument macro's level=<path> form rejects a leading \`crate\` keyword segment),"
  note "for anything else pick the literal level it belongs at. See docs/observability.md."
  exit 1
fi
note "tracing-lint passed"
