#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# no-deferral-gate.sh — THE NO-DEFERRAL GATE.
#
# WHY THIS EXISTS (docs/design/playbook/gate-no-deferral.md — the authoritative spec):
#   The single claim of this gate is: THE SHIPPED SOURCE TREE CONTAINS NOTHING KNOWN-AND-DEFERRED.
#   Every capability the tree DECLARES, it also IMPLEMENTS — no `todo!()` a caller can reach, no
#   self-labelled "SKELETON / dev-only until DoD" that a shipping feature depends on. It is a witness
#   in the same family as scripts/plane-purity-lint.sh: it greps a precisely-scoped file set for a
#   precisely-defined marker set, asserts the set is EXACTLY the committed allowlist floor, and fails
#   loudly (and by default) on any drift. It cannot be satisfied by renaming a marker:
#   over- AND under-count are both RED.
#
# TWO ORTHOGONAL DETECTORS:
#   Class A — deferral MACRO invocations a caller can reach. Matched only as a STATEMENT at line
#             start (after optional leading whitespace / `pub …`), on COMMENT-STRIPPED code, so a
#             `// … unimplemented!() …` prose mention (the busbar-core/plane_host anti-markers that
#             assert the ABSENCE of a stub) does NOT count. `unreachable!()` is deliberately NOT
#             banned — it asserts an invariant, not a deferral.
#               regex:  ^\s*(pub\s+\S+\s+)?(unimplemented|todo|unreachable_placeholder)!\s*\(
#   Class B — deferral PHRASE labels the author self-declares, usually in comments (so matched on the
#             RAW line, comments included — that is the whole point):
#               SKELETON          (CASE-SENSITIVE, word-boundary — the uppercase debt label; the
#                                  lowercase domain word "skeleton"/"message skeleton" is NOT a marker)
#               dev-only until     until DoD     HONEST PENDING     PlaneDecl::STUB
#
# FILE SCOPE: every workspace member's shipped source —
#   INCLUDE  crates/*/src/**/*.rs
#   EXCLUDE  **/tests/**  **/*test*.rs  (unit-test-heavy modules)   [+ a #[cfg(test)] mod { … } block]
#            docs/**  *.md are never under crates/*/src, so they are out of scope structurally.
# A marker inside a test tree or a cfg(test) block is legitimate (a fixture may name a "skeleton
# config"); only SHIPPED source is scanned.
#
# THE ALLOWLIST — scripts/no-deferral.waivers (committed, single-sourced). Each non-blank, non-`#`
# row is:  <MATCHER><whitespace><reason>.  MATCHER is either an EXACT `path:line`, or a PATH GLOB
# (any matcher without a trailing `:<digits>` — e.g. `crates/busbar-plugin/src/hot/*`). A marker is
# WAIVED when an exact row equals its `file:line` OR a glob row matches its file. The allowlist is a
# FLOOR CHECKED BOTH WAYS:
#   * any marker NOT waived            → RED (a new/undeclared deferral; over-count).
#   * any waiver matching ZERO markers → RED (a stale exemption whose marker was resolved; under-count).
# So a deferral cannot be laundered by moving it into a file that already had exemptions, and a
# resolved marker cannot leave a lying waiver behind.
#
# MODES:
#   --selftest      Run FIRST in CI, like every sibling *-lint.sh. Plants RED fixtures (a line-start
#                   todo!(), a raw SKELETON) and GREEN fixtures (the SAME tokens in a comment, in a
#                   #[cfg(test)] block, in a tests/ file) and proves the scanner flags the first and
#                   NOT the second — the scanner cannot be lied to.
#   --check | ""    BLOCKING. RED on any marker not in the allowlist, or any allowlist row that
#                   matches nothing. This is the permanent gate.
#   --strict-done   --check PLUS: RED if the allowlist carries ANY non-`*/hot/*` row. The hot/*
#                   foundation fixtures (additive/unused compile-surface, out-of-1.6.0 scope) are the
#                   ONLY permanent exemptions; the voice skeleton markers are TRACKED 1.6.0 debt that
#                   MUST be gone before 1.6.0 is done. This is the mode scripts/verify-1.6.0-done.sh
#                   calls, so "1.6.0 done" mechanically requires voice's markers cleared.
#
# bash 3.2 + POSIX awk (macOS/Linux), the same bare-runner posture as plane-purity-lint.sh.
set -uo pipefail
cd "$(dirname "$0")/.."

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

WAIVERS_FILE="${NO_DEFERRAL_WAIVERS:-$(dirname "$0")/no-deferral.waivers}"

# Every workspace member's shipped source. A crate that appears/disappears is picked up automatically
# (find over crates/*/src), so a plane this gate never lists is never a plane it scans zero files of.
src_files() {
  find crates/*/src -name '*.rs' 2>/dev/null \
    | grep -vE '/tests/|/test_support/|_tests?\.rs$' | sort
}

# ── THE SCANNER (one copy; the self-test drives THIS function, never a duplicate) ─────────────────
# Emits one TSV line per marker:  CLASS<TAB>file:line<TAB>trimmed-source   (CLASS = A | B)
# It strips comments for Class A (respecting string literals, so a `//` inside a string is not a
# comment), matches Class B on the RAW line (comments are where the labels live), and — for BOTH
# classes — excludes a `#[cfg(test)] mod { … }` block, so test scaffolding is never a shipped deferral.
scan() {
  [ "$#" -gt 0 ] || return 0
  awk '
    # Strip // line-comments and /* block */ comments, respecting string literals. inblk persists
    # across lines; instr is per-line (Rust string literals are overwhelmingly single-line). Lifted
    # verbatim in spirit from scripts/plane-purity-lint.sh so the two gates strip comments identically.
    function strip(line,   res, i, n, c, c2, instr) {
      res = ""; n = length(line); i = 1; instr = 0
      while (i <= n) {
        c = substr(line, i, 1); c2 = substr(line, i, 2)
        if (inblk) { if (c2 == "*/") { inblk = 0; i += 2 } else { i++ } continue }
        if (instr) {
          res = res c
          if (c == "\\") { res = res substr(line, i + 1, 1); i += 2; continue }
          if (c == "\"") { instr = 0 }
          i++; continue
        }
        if (c2 == "/*") { inblk = 1; i += 2; continue }
        if (c2 == "//") { break }
        if (c == "\"") { instr = 1; res = res c; i++; continue }
        res = res c; i++
      }
      return res
    }
    function trim(s) { sub(/^[[:space:]]+/, "", s); sub(/[[:space:]]+$/, "", s); return s }
    function emit(cls, text) { printf "%s\t%s:%d\t%s\n", cls, FILENAME, FNR, trim(text) }

    FNR == 1 { inblk = 0; testdepth = 0; pend = 0 }

    {
      raw  = $0
      code = strip($0)
      nopen = gsub(/[{]/, "{", code); nclose = gsub(/[}]/, "}", code)

      # ── #[cfg(test)] mod { … } block tracking (unit-test scaffolding excluded from BOTH classes) ──
      lc = tolower(code)
      is_cfgtest = (code ~ /#\[cfg\(/ && (lc ~ /[^a-z0-9_]test[^a-z0-9_]/))
      has_mod    = (code ~ /(^|[^A-Za-z0-9_])mod([^A-Za-z0-9_])/)
      entered = 0
      if (is_cfgtest && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && has_mod) {
        testdepth = nopen - nclose; if (testdepth < 0) testdepth = 0; entered = (testdepth > 0); pend = 0
      } else if (pend && code ~ /[^[:space:]]/ && !is_cfgtest) {
        pend = 0
      } else if (testdepth > 0) {
        testdepth += nopen - nclose; if (testdepth < 0) testdepth = 0
      }
      if (is_cfgtest && !has_mod) pend = 1
      if (testdepth > 0 || entered) next          # inside a cfg(test) block — skip both classes

      # ── Class A: deferral MACRO invocation as a line-start statement, on stripped code ──
      if (code ~ /^[[:space:]]*(pub[[:space:]]+[A-Za-z0-9_]+[[:space:]]+)?(unimplemented|todo|unreachable_placeholder)![[:space:]]*\(/)
        emit("A", code)

      # ── Class B: deferral PHRASE labels, on the RAW line (comments included). SKELETON is
      #    CASE-SENSITIVE + word-bounded so the lowercase domain word "skeleton" is not a marker. ──
      if (raw ~ /(^|[^A-Za-z0-9_])SKELETON([^A-Za-z0-9_]|$)/ \
       || raw ~ /dev-only[[:space:]]+until/ \
       || raw ~ /until[[:space:]]+DoD/ \
       || raw ~ /HONEST[[:space:]]+PENDING/ \
       || raw ~ /PlaneDecl::STUB/)
        emit("B", raw)
    }
  ' "$@"
}

# ── WAIVERS ───────────────────────────────────────────────────────────────────────────────────────
# Load the committed allowlist into three parallel shell arrays: matcher, reason, and a "hot" flag
# (1 when the matcher path is under a */hot/* tree). bash 3.2 has no assoc arrays, so parallel arrays.
WV_MATCH=(); WV_REASON=(); WV_ISHOT=()
load_waivers() {
  WV_MATCH=(); WV_REASON=(); WV_ISHOT=()
  [ -f "$WAIVERS_FILE" ] || { red "no-deferral gate: waivers file $WAIVERS_FILE is missing"; return 1; }
  local line m rest
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|\#*) continue;; esac
    m="${line%%[[:space:]]*}"
    rest="${line#"$m"}"
    rest="${rest#"${rest%%[![:space:]]*}"}"     # ltrim the reason
    if [ -z "$rest" ]; then
      red "no-deferral gate: waiver row has no reason: '$line'"; return 1
    fi
    WV_MATCH+=("$m"); WV_REASON+=("$rest")
    case "$m" in */hot/*) WV_ISHOT+=(1);; *) WV_ISHOT+=(0);; esac
  done < "$WAIVERS_FILE"
  return 0
}

# Is a "file:line" marker location waived? A matcher with a trailing `:<digits>` is exact; anything
# else is a shell glob matched against the marker's FILE path. Sets WV_HIT[i]=1 for the matching row.
WV_HIT=()
marker_waiver_index() {   # $1 = file:line  → echoes matching waiver index, or nothing
    local loc="$1" file="${1%:*}" i m
    for i in "${!WV_MATCH[@]}"; do
      m="${WV_MATCH[$i]}"
      if printf '%s' "$m" | grep -qE ':[0-9]+$'; then
        [ "$m" = "$loc" ] && { echo "$i"; return; }
      else
        # shellcheck disable=SC2053
        case "$file" in $m) echo "$i"; return;; esac
      fi
    done
}

# ── SELF-TEST — the scanner cannot be lied to ─────────────────────────────────────────────────────
run_selftest() {
  hdr "no-deferral-gate SELF-TEST (the deferral scanner cannot be lied to)"
  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local fail=0 out

  # ── RED: a planted line-start todo!() (Class A) and a raw SKELETON label (Class B) MUST flag. ──
  cat >"$tmp/red.rs" <<'RED'
pub fn pump() -> u8 {
    todo!("the duplex pump body")
}
// SKELETON: this plane mounts nothing yet
fn helper() -> u8 {
    unimplemented!()
}
RED
  out="$(scan "$tmp/red.rs")"
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="A"{n++} END{print n+0}')" -ge 2 ]; then
    note "RED: flagged both Class-A macro invocations (todo!(), unimplemented!())"
  else
    fail=1; note "RED FAILED: Class-A macros not both flagged (got: $out)"
  fi
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="B"{n++} END{print n+0}')" -ge 1 ]; then
    note "RED: flagged the Class-B SKELETON label"
  else
    fail=1; note "RED FAILED: Class-B SKELETON not flagged (got: $out)"
  fi

  # ── GREEN (comment): the SAME Class-A tokens inside a `//` / block comment (the plane_host
  #    anti-markers that DENY a stub) must NOT flag; a lowercase domain "skeleton" must NOT flag. ──
  cat >"$tmp/green_comment.rs" <<'GREEN'
// no `unimplemented!()` stub remains — the Phase-1 fan-out filled every slot.
/* a design note mentioning todo!() in prose is not a deferral */
fn writer() { let _ = "the full message skeleton is emitted here"; }
GREEN
  out="$(scan "$tmp/green_comment.rs")"
  if [ -z "$out" ]; then
    note "GREEN comment: anti-marker unimplemented!()/todo!() prose + lowercase 'skeleton' flagged none"
  else
    fail=1; note "GREEN comment FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── GREEN (cfg(test) block): a todo!() and a SKELETON inside a #[cfg(test)] mod are scaffolding. ──
  cat >"$tmp/green_cfgtest.rs" <<'GREEN'
#[cfg(test)]
mod tests {
    // SKELETON fixture below
    fn f() { todo!() }
}
GREEN
  out="$(scan "$tmp/green_cfgtest.rs")"
  if [ -z "$out" ]; then
    note "GREEN cfg(test): a todo!()/SKELETON inside #[cfg(test)] mod flagged none"
  else
    fail=1; note "GREEN cfg(test) FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
  fi

  # ── GREEN (tests file): the discovery step EXCLUDES a tests/ path and a *_tests.rs file. ──
  mkdir -p "$tmp/crates/x/src/tests"
  printf 'fn f() { todo!() } // SKELETON\n' > "$tmp/crates/x/src/tests/foo.rs"
  printf 'fn g() { unimplemented!() } // SKELETON\n' > "$tmp/crates/x/src/bar_tests.rs"
  local discovered
  discovered="$(cd "$tmp" && find crates/*/src -name '*.rs' 2>/dev/null | grep -vE '/tests/|/test_support/|_tests?\.rs$')"
  if [ -z "$discovered" ]; then
    note "GREEN tests-file: a tests/ path and a *_tests.rs file are EXCLUDED from discovery"
  else
    fail=1; note "GREEN tests-file FAILED: discovery did not exclude the test locations: $discovered"
  fi

  # ── Discovery must find a non-trivial file set on the real tree (unknown is not green). ──
  local realn; realn="$(src_files | grep -c . || true)"
  if [ "$realn" -ge 50 ]; then
    note "discovery: $realn shipped source files found on the real tree (floor 50)"
  else
    fail=1; note "discovery FAILED: only $realn source files found — the scan would pass vacuously"
  fi

  if [ "$fail" -ne 0 ]; then
    red "no-deferral-gate SELF-TEST FAILED — the scanner would let a deferral through, or a real one out"
    return 1
  fi
  grn "no-deferral-gate self-test: ALL GREEN (Class A/B RED+GREEN discipline proven)"
  return 0
}

# ── THE REAL RUN ──────────────────────────────────────────────────────────────────────────────────
run_check() {
  local strict="$1"
  load_waivers || return 2

  local tmp; tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' RETURN
  local files; files="$(src_files)"
  : >"$tmp/markers"
  # shellcheck disable=SC2086
  [ -n "$files" ] && scan $files >"$tmp/markers"

  local total; total="$(grep -c . "$tmp/markers" || true)"
  hdr "no-deferral scan — shipped source markers"
  note "waivers:  $WAIVERS_FILE  (${#WV_MATCH[@]} row(s))"
  note "markers found: $total   (A = reachable macro deferral, B = self-declared debt label)"

  # Reconcile every marker against the allowlist; collect the un-waived ones, and tally per waiver.
  WV_HIT=(); local i
  for i in "${!WV_MATCH[@]}"; do WV_HIT[$i]=0; done
  : >"$tmp/unwaived"
  local loc idx
  while IFS=$'\t' read -r _cls loc _text; do
    [ -n "$loc" ] || continue
    idx="$(marker_waiver_index "$loc")"
    if [ -n "$idx" ]; then WV_HIT[$idx]=1; else printf '%s\n' "$loc" >>"$tmp/unwaived"; fi
  done < "$tmp/markers"

  local rc=0

  # (1) OVER-COUNT: a marker nobody waived is a new/undeclared deferral.
  local n_unwaived; n_unwaived="$(grep -c . "$tmp/unwaived" || true)"
  if [ "$n_unwaived" -ne 0 ]; then
    rc=1; hdr "UN-WAIVED deferral markers (RED — a shipped capability is deferred)"
    while IFS= read -r loc; do
      note "$loc   $(awk -F'\t' -v L="$loc" '$2==L{print $1": "$3; exit}' "$tmp/markers")"
    done < "$tmp/unwaived"
  fi

  # (2) UNDER-COUNT: a waiver that matches no marker is a stale exemption.
  local stale=0
  for i in "${!WV_MATCH[@]}"; do
    if [ "${WV_HIT[$i]}" -eq 0 ]; then
      [ "$stale" -eq 0 ] && hdr "STALE waivers (RED — the marker was resolved; drop the row)"
      stale=1; rc=1; note "${WV_MATCH[$i]}   ${WV_REASON[$i]}"
    fi
  done

  # (3) STRICT-DONE: the only permanent exemptions are the hot/* foundation fixtures. Any other
  #     (i.e. voice skeleton) waiver present means 1.6.0's one tracked debt has NOT cleared.
  if [ "$strict" -eq 1 ]; then
    local nonhot=0
    for i in "${!WV_MATCH[@]}"; do
      if [ "${WV_ISHOT[$i]}" -eq 0 ]; then
        [ "$nonhot" -eq 0 ] && hdr "STRICT-DONE: non-hot/* waivers still present (RED — voice debt not cleared)"
        nonhot=1; rc=1; note "${WV_MATCH[$i]}   ${WV_REASON[$i]}"
      fi
    done
    [ "$nonhot" -eq 0 ] && note "strict-done: every waiver is a */hot/* foundation fixture (voice markers cleared)"
  fi

  hdr "verdict"
  if [ "$rc" -eq 0 ]; then
    grn "no-deferral gate: PASS — every marker is a floor-checked allowlist entry ($total marker(s), ${#WV_MATCH[@]} waiver(s))"
    [ "$strict" -eq 1 ] && grn "  strict-done: the tree carries ONLY the permanent hot/* foundation fixtures."
  else
    red "no-deferral gate: FAIL — the shipped tree defers something the allowlist does not account for."
    note "A new marker → implement it or add a justified waiver row. A stale waiver → the marker is gone, drop the row."
    [ "$strict" -eq 1 ] && note "strict-done → voice's SKELETON/dev-only-until-DoD markers must be REMOVED (and its state assertion armed) before 1.6.0 is done."
  fi
  return "$rc"
}

case "${1:-}" in
  --selftest)    run_selftest; exit $? ;;
  --strict-done) run_check 1; exit $? ;;
  --check | "")  run_check 0; exit $? ;;
  -h | --help)   sed -n '2,60p' "$0" ;;
  *) echo "usage: $0 [--selftest | --check | --strict-done]" >&2; exit 2 ;;
esac
