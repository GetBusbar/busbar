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
#   Class A — deferral MACRO invocations a caller can reach. Matched ANYWHERE on the line, on
#             COMMENT-STRIPPED code, so a `// … unimplemented!() …` prose mention (the
#             busbar-core/plane_host anti-markers that assert the ABSENCE of a stub) does NOT count.
#             It is the comment strip that excludes prose, never a position anchor: an anchor at
#             line start also excluded `_ => todo!(…)` and `let v = unimplemented!()`, which are
#             reachable deferrals and are how most of them are actually written.
#             `unreachable!()` is deliberately NOT banned — it asserts an invariant, not a deferral.
#               regex:  (^|[^A-Za-z0-9_.])(unimplemented|todo|unreachable_placeholder)!\s*\(
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
# An unchecked `cd` is the cheapest way to reach the vacuous pass this file guards against below:
# there is no `set -e`, so a failed cd would leave the scan pointed at whatever directory the caller
# happened to be in, find no crates/*/src, and report a clean tree.
cd "$(dirname "$0")/.." || { echo "no-deferral gate: cannot cd to the repository root" >&2; exit 2; }

# THE DISCOVERY FLOOR. A scan of zero files is not a clean tree, it is an unproven one. The self-test
# has asserted this floor on the real tree since it was written — but only in the self-test, and the
# self-test is not the mode CI and verify-1.6.0-done.sh run. `--check` and `--strict-done` scanned
# whatever discovery handed them, so an empty (or wrongly-rooted) tree with an empty waivers file
# printed PASS, and --strict-done went on to certify "the tree carries ONLY the permanent hot/*
# foundation fixtures" over nothing at all. Both modes share the floor now.
DISCOVERY_FLOOR=50

red()  { printf '\033[31m%s\033[0m\n' "$*"; }
grn()  { printf '\033[32m%s\033[0m\n' "$*"; }
ylw()  { printf '\033[33m%s\033[0m\n' "$*"; }
note() { printf '  %s\n' "$*"; }
hdr()  { printf '\n== %s ==\n' "$*"; }

WAIVERS_FILE="${NO_DEFERRAL_WAIVERS:-$(dirname "$0")/no-deferral.waivers}"
# Where a waiver's `[retires: <ID>]` is looked up. An expiry that names nothing is not an expiry.
TRACKER_DOC="${NO_DEFERRAL_TRACKER:-$(dirname "$0")/../docs/design/1.6.0-TRACKER.md}"

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
      # THE PREDICATE IS MATCHED EXACTLY, NOT AS A SUBSTRING. This was a substring hunt for the word
      # "test" anywhere inside any `#[cfg(...)]`, which made `#[cfg(not(test))]` — the attribute
      # whose entire meaning is "this is the code that SHIPS" — look like test scaffolding and
      # excluded the whole module from both classes. `#[cfg(feature = "test-util")]` matched too. A
      # module carrying a line-start todo!() and a raw SKELETON label under `not(test)` scanned to
      # zero markers and the gate printed PASS. Only a bare `test` predicate, alone or as a member of
      # an all()/any() list, is scaffolding.
      # A BARE `test` predicate token, in any all()/any() nesting, is scaffolding — unless it is
      # NEGATED, in which case the block is the shipped arm. `#[cfg(all(test, not(target_env=…)))]`
      # is still scaffolding: what disqualifies is `not(` wrapping the TEST predicate itself.
      bare_test = (code ~ /#\[cfg\(/ && code ~ /[(,][[:space:]]*test[[:space:]]*[,)]/)
      neg_test  = (code ~ /not\([[:space:]]*test[[:space:]]*\)/ \
                || code ~ /not\((any|all)\([[:space:]]*test[[:space:]]*[,)]/)
      is_cfgtest = (bare_test && !neg_test)
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

      # ── Class A: a deferral MACRO invocation ANYWHERE in the stripped code ──
      # This used to be anchored to the start of the line. The anchor bought nothing the comment
      # strip above does not already provide, and it hid the most ordinary way a reachable deferral
      # is actually written: `_ => todo!("not wired yet"),`, `let v = unimplemented!();`,
      # `fn f() -> u8 { todo!() }`. A file carrying all three scanned to zero markers and the gate
      # printed PASS. The word-boundary prefix keeps `my_todo!()` and `x.todo!()` from matching.
      if (code ~ /(^|[^A-Za-z0-9_.])(unimplemented|todo|unreachable_placeholder)![[:space:]]*\(/)
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
    # ── EVERY WAIVER CARRIES AN EXPIRY, AND THE EXPIRY MUST EXIST ─────────────────────────────────
    # A reason says why a marker is exempt today; it says nothing about when it stops being exempt.
    # One un-expiring glob covered all 52 markers of a whole directory and would have covered any
    # number more, forever, because nothing in the file could go out of date. So each row names the
    # tracker row that retires it, and that row is looked up: a `[retires: X]` pointing at nothing is
    # a promise nobody made.
    local tid
    tid="$(printf '%s' "$rest" | sed -n 's/.*\[retires:[[:space:]]*\([A-Za-z0-9._-]\{1,\}\)\].*/\1/p')"
    if [ -z "$tid" ]; then
      red "no-deferral gate: waiver row carries no expiry: '$line'"
      note "Every row must end in \`[retires: <TRACKER-ID>]\` naming the $TRACKER_DOC row that"
      note "retires it. A waiver that cannot expire is a permanent unreviewed exemption."
      return 1
    fi
    if [ ! -f "$TRACKER_DOC" ]; then
      red "no-deferral gate: the tracker $TRACKER_DOC is missing, so no waiver's expiry can be checked"
      return 1
    fi
    if ! grep -qE "^- \[[ x]\] ${tid}[[:space:]]" "$TRACKER_DOC"; then
      red "no-deferral gate: waiver names expiry \`${tid}\`, which is not a row in $TRACKER_DOC: '$line'"
      note "The waiver outlived the work that was supposed to retire it, or the id is a typo."
      return 1
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

  # ── RED: a deferral macro that is NOT at the start of its line is still reachable. ──
  # Every one of these compiles, ships, and panics when a caller gets there. The scanner used to
  # anchor Class A to line start and reported this whole file as zero markers.
  cat >"$tmp/red_inline.rs" <<'RED'
pub fn dispatch(kind: u8) -> u8 {
    match kind {
        0 => 1,
        _ => todo!("the duplex dialect is not wired yet"),
    }
}
pub fn other() -> u8 { let v = unimplemented!(); v }
pub fn third() -> u8 { todo!() }
RED
  out="$(scan "$tmp/red_inline.rs")"
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="A"{n++} END{print n+0}')" -ge 3 ]; then
    note "RED inline: a match arm, an initialiser and a one-line fn body all flag as Class A"
  else
    fail=1; note "RED inline FAILED: a deferral macro away from line start was not flagged (got: $out)"
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

  # ── RED: `#[cfg(not(test))]` is the code that SHIPS, so it is scanned, not excluded. ──
  # Same for a feature whose NAME merely contains "test". The cfg(test) exclusion above is for
  # scaffolding; a substring hunt for "test" turned it into a way to hide a deferral in plain sight.
  cat >"$tmp/red_notcfgtest.rs" <<'RED'
#[cfg(not(test))]
mod production {
    // SKELETON: the real duplex session is not implemented
    pub fn q() -> u8 {
        todo!("dev-only until DoD")
    }
}
#[cfg(feature = "test-util")]
mod shipped_helper {
    pub fn r() -> u8 { todo!() }
}
RED
  out="$(scan "$tmp/red_notcfgtest.rs")"
  if [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="A"{n++} END{print n+0}')" -ge 2 ] \
  && [ "$(printf '%s\n' "$out" | awk -F'\t' '$1=="B"{n++} END{print n+0}')" -ge 1 ]; then
    note "RED not(test): a cfg(not(test)) module and a test-NAMED feature module are both scanned"
  else
    fail=1; note "RED not(test) FAILED: shipped code was excluded as test scaffolding (got: $out)"
  fi

  # ── GREEN: `#[cfg(all(test, unix))]` IS scaffolding and stays excluded (the rule did not widen
  #    into "scan everything"). ──
  cat >"$tmp/green_cfgtest_all.rs" <<'GREEN'
#[cfg(all(test, unix))]
mod tests {
    // SKELETON fixture
    fn f() { todo!() }
}
GREEN
  out="$(scan "$tmp/green_cfgtest_all.rs")"
  if [ -z "$out" ]; then
    note "GREEN cfg(all(test,…)): a genuine test module is still excluded"
  else
    fail=1; note "GREEN cfg(all(test,…)) FAILED: expected 0, got:"; printf '%s\n' "$out" | sed 's/^/    /'
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
  if [ "$realn" -ge "$DISCOVERY_FLOOR" ]; then
    note "discovery: $realn shipped source files found on the real tree (floor $DISCOVERY_FLOOR)"
  else
    fail=1; note "discovery FAILED: only $realn source files found — the scan would pass vacuously"
  fi

  # ── THE FLOOR IS ON THE RUN PATH, NOT JUST HERE. The assertion above proves the REAL tree is big
  #    enough; it says nothing about what --check does when discovery comes back empty, and for a
  #    long time the answer was "prints PASS". Drive the real run_check and --strict-done against a
  #    tree with no crates/ at all and require a refusal from BOTH. ──
  local vt="$tmp/vacuous"
  mkdir -p "$vt/scripts" "$vt/docs/design"
  cp "$0" "$vt/scripts/no-deferral-gate.sh"
  : >"$vt/scripts/no-deferral.waivers"
  : >"$vt/docs/design/1.6.0-TRACKER.md"
  local vrc vout
  vout="$( (cd "$vt" && bash scripts/no-deferral-gate.sh --check) 2>&1 )"; vrc=$?
  if [ "$vrc" -ne 0 ] && printf '%s' "$vout" | grep -q "UNPROVEN"; then
    note "VACUOUS: --check over a tree with zero shipped source files refuses ($vrc), it does not PASS"
  else
    fail=1; note "VACUOUS FAILED: --check reported rc=$vrc over an EMPTY tree: $vout"
  fi
  vout="$( (cd "$vt" && bash scripts/no-deferral-gate.sh --strict-done) 2>&1 )"; vrc=$?
  if [ "$vrc" -ne 0 ]; then
    note "VACUOUS: --strict-done cannot certify '1.6.0 done' over an empty tree ($vrc)"
  else
    fail=1; note "VACUOUS FAILED: --strict-done certified done over an EMPTY tree: $vout"
  fi

  # ── THE EXPIRY. A waiver that cannot expire is a permanent unreviewed exemption, and one glob
  # with no expiry covered a whole directory's 52 markers. Each case drives the REAL `load_waivers`.
  printf 'crates/x/src/a.rs:1\ta reason with no expiry at all\n' >"$tmp/no-expiry.waivers"
  if ( WAIVERS_FILE="$tmp/no-expiry.waivers" load_waivers ) >/dev/null 2>&1; then
    fail=1; note "EXPIRY FAILED: a waiver row carrying no [retires: …] was accepted"
  else
    note "EXPIRY: a waiver row that names no expiry is refused"
  fi
  printf 'crates/x/src/a.rs:1\ta reason [retires: ZZ999]\n' >"$tmp/bad-expiry.waivers"
  if ( WAIVERS_FILE="$tmp/bad-expiry.waivers" load_waivers ) >/dev/null 2>&1; then
    fail=1; note "EXPIRY FAILED: an expiry naming a tracker row that does not exist was accepted"
  else
    note "EXPIRY: an expiry naming a tracker row that does not exist is refused"
  fi
  printf 'crates/x/src/a.rs:1\ta reason [retires: H5]\n' >"$tmp/good-expiry.waivers"
  if ( WAIVERS_FILE="$tmp/good-expiry.waivers" load_waivers ) >/dev/null 2>&1; then
    note "EXPIRY: an expiry naming a real tracker row is accepted (the rule is not 'refuse everything')"
  else
    fail=1; note "EXPIRY FAILED: a waiver naming a real tracker row was refused"
  fi
  # And the committed file itself: every row carries an expiry that resolves, and no row is a glob.
  local globrows
  globrows="$(grep -vE '^[[:space:]]*(#|$)' "$WAIVERS_FILE" | grep -cvE '^[^[:space:]]+:[0-9]+[[:space:]]' || true)"
  if [ "$globrows" -eq 0 ]; then
    note "EXPIRY: every committed waiver row is an exact file:line, not a directory glob"
  else
    fail=1; note "EXPIRY FAILED: $globrows committed waiver row(s) are globs — a glob absorbs new markers in silence"
  fi
  if ( load_waivers ) >/dev/null 2>&1; then
    note "EXPIRY: every committed waiver row's expiry resolves to a tracker row"
  else
    fail=1; note "EXPIRY FAILED: the committed waivers file does not load (a row's expiry does not resolve)"
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

  # UNPROVEN, NOT PASS. See DISCOVERY_FLOOR at the top of this file.
  local nfiles; nfiles="$(printf '%s\n' "$files" | grep -c . || true)"
  if [ "$nfiles" -lt "$DISCOVERY_FLOOR" ]; then
    red "no-deferral gate: discovery found only $nfiles shipped source file(s) (floor $DISCOVERY_FLOOR)"
    note "Broken discovery reports a clean tree. This verdict is UNPROVEN, not PASS."
    note "Expected crates/*/src/**/*.rs under $(pwd)."
    return 2
  fi

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
