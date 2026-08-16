#!/usr/bin/env bash
# Structure lint — enforces the code-layout invariants in docs/code-layout.md so the tree stays
# navigable ("I'm looking for X, I know where it is") instead of drifting back to giant, inconsistent
# files, plus the behavioural invariants that only a structural read of the tree can catch: the
# choke-point registry, request-path purity, plane coherence, axis purity, decision-input purity and
# the declaration census.
# Nine checks, all greppable, no external deps. Exit non-zero on any violation.
set -euo pipefail
cd "$(dirname "$0")/.."

# ── THE TWO SOURCE ROOTS ─────────────────────────────────────────────────────────────────────────
# Step 3.7 of 1.6.0 splits `crates/busbar` into `busbar-core` (the library) and `busbar` (the thin
# binary). Every row below names the root it governs THROUGH these two variables, so the file move
# is a one-variable flip of CORE rather than 46 silently stale paths — and each row's choice of
# $CORE vs $BIN is a signed decision about which side of the seam that invariant watches. The
# `boot-starts-the-quarantine-sweep` census row and the grandfathered `main.rs` are the two that
# stay on $BIN: their whole job is to watch the binary. Census and axis rows whose subject is "the
# tree" scope over BOTH roots as a comma-separated list.
CORE=crates/busbar-core/src
BIN=crates/busbar/src
# The extracted protocol crates (step 4 of 1.6.0; anthropic is the first). They are proto ARMS by
# definition, so the axis rows scope over them WITH themselves in the allow list — the point of
# scanning them is that the scan follows the files out of core rather than silently shrinking, and
# a future non-arm file appearing in one of these crates still cannot branch on a foreign axis.
PROTO_ANTHROPIC=crates/busbar-proto-anthropic/src
# The second extracted protocol crate. Scanned on the same terms as the first: a protocol crate IS
# the operation/transport axis's own arm, so the scan follows the files out of core rather than
# losing the row the day a dialect stops being a core module.
PROTO_MCP=crates/busbar-proto-mcp/src
# The dialect crates that followed anthropic out of core (extraction order: openai_chat, gemini).
# Scanned on the same terms and for the same reason: the row must follow the files, not vanish with
# them.
PROTO_OPENAI_CHAT=crates/busbar-proto-openai-chat/src
PROTO_GEMINI=crates/busbar-proto-gemini/src

# Impl files target ~1,500 lines; the hard ceiling forbids genuine MONSTER files (the thing that
# makes a codebase unnavigable) rather than micromanaging cohesive units. Test files are exempt from
# the size cap: they are located by name (foo/tests/<what>.rs), not read top-to-bottom, so the
# navigability the cap protects is already served by the tests/ folder convention + one-module-per-file.
MAX_LINES_IMPL=2500
fail=0

note() { printf '  %s\n' "$1"; }
hdr()  { printf '\n== %s ==\n' "$1"; }

# ══ THE ONE ANSWER TO "IS THIS LINE TEST CODE?" ══════════════════════════════════════════════════
#
# A line wrongly called "test" is a line EXEMPT from every bypass rule, so the choke-point registry
# scanner below needs one authoritative answer to this question. It lives here ONCE, as an awk
# prelude the scanner prepends; there is no second copy to drift.
#
# It sets two variables per input line:
#   is_comment — the line is a whole-line `//` / `///` / `//!` comment (prose, never code).
#   gated      — the line is `#[cfg(test)]` machinery or lies inside a `#[cfg(test)]` item body.
#
# What the OLD version got wrong (both bugs were provably exploitable, see --selftest):
#   1. It armed on a BARE regex match anywhere on the line, and skipped whole-line comments only
#      AFTERWARDS — so a doc comment merely MENTIONING `#[cfg(test)]` armed the state machine and
#      shadowed the production item that followed it.
#   2. Once armed it stayed armed until the next line containing `{` ANYWHERE, at arbitrary distance
#      — so `#[cfg(test)]` on a BRACE-LESS item (`mod tests;`, `use ...;`, a `const`) latched onto
#      the NEXT braced item, which is production code, and skipped all of it.
# Both are fixed by (a) reading the attribute only off a line that IS the attribute, and (b)
# resolving the attribute against the item it actually applies to, brace-less items included.
TEST_SCOPE_AWK='
  # The code content of a line: empty for a whole-line comment, and with a trailing `//` comment
  # stripped when the line holds no string literal (so `// }` in a trailer cannot skew brace depth).
  function _codeof(s,   c) {
    if (s ~ /^[[:space:]]*\/\//) return ""
    c = s
    if (index(c, "\"") == 0) sub(/\/\/.*$/, "", c)
    return c
  }
  # Net brace delta of a line (`s` is a by-value copy, so gsub may chew it up).
  function _braces(s,   o, c) { o = gsub(/\{/, "{", s); c = gsub(/\}/, "}", s); return o - c }

  FNR==1 { in_test=0; pending=0; pend_age=0; depth=0 }   # per-file reset (one awk pass, many files)
  {
    is_comment = ($0 ~ /^[[:space:]]*\/\//)
    code = _codeof($0)
    gated = 0

    if (in_test) {                                   # inside a braced #[cfg(test)] item body
      gated = 1
      depth += _braces(code)
      if (depth <= 0) { in_test = 0; depth = 0 }
    } else if (pending) {                            # attribute seen; find the item it applies to
      gated = 1
      if (code ~ /^[[:space:]]*$/ || code ~ /^[[:space:]]*#\[/) {
        pend_age++                                   # blank / comment / stacked attribute
      } else if (index(code, "{") > 0) {
        pending = 0                                  # braced item: enter its body
        depth = _braces(code)
        if (depth > 0) in_test = 1; else depth = 0
      } else if (code ~ /;[[:space:]]*$/) {
        pending = 0                                  # BRACE-LESS item: gates this line and no more
      } else {
        pend_age++                                   # multi-line signature, keep looking
      }
      # An attribute never applies across arbitrary distance. If the item cannot be resolved in a
      # handful of lines the file is shaped in a way this scanner does not model, so fail CLOSED:
      # drop the arm and go back to scanning as production rather than shadowing the rest of the file.
      if (pending && pend_age > 10) { pending = 0; pend_age = 0 }
    }

    # Arm only on a line that IS the attribute: anchored at the start of a CODE line, with `test` as
    # a cfg predicate (`#[cfg(test)]`, `#[cfg(all(test, ...))]`) — never `#[cfg(not(test))]` (that is
    # production-only code) and never `#[cfg(feature = "test-utils")]` (that is not a test gate).
    if (!in_test && !pending && code ~ /^[[:space:]]*#\[cfg\(/ \
        && code ~ /[(,][[:space:]]*test[[:space:]]*[,)]/ \
        && code !~ /not[[:space:]]*\([[:space:]]*test[[:space:]]*\)/) {
      gated = 1
      rest = code
      sub(/^[[:space:]]*#\[cfg\(.*\)\][[:space:]]*/, "", rest)
      if (rest ~ /^[[:space:]]*$/)      { pending = 1; pend_age = 0 }   # item is on a later line
      else if (index(rest, "{") > 0)    { depth = _braces(rest); if (depth > 0) in_test = 1; else depth = 0 }
      else if (rest ~ /;[[:space:]]*$/) { }                             # `#[cfg(test)] use x;`
      else                              { pending = 1; pend_age = 0 }
    }
  }
'

# ── The single generic scanner. One awk pass per rule over every candidate file. ─────────────────
# Skips `#[cfg(test)]`-gated lines (TEST_SCOPE_AWK above) and whole-line comments, then flags the
# rule's pattern in the remaining production code. The pattern is handed over via the environment
# (NOT -v) so awk performs no escape processing on it and the ERE arrives verbatim.
scan_rule() { awk "$TEST_SCOPE_AWK"'
  gated || is_comment { next }
  # `unless` is the rule OPT-OUT for a shape that shares the pattern but not the hazard (the atomic
  # `.swap(x, Ordering::…)` idiom, say). Empty = no opt-out.
  ENVIRON["LINT_UNLESS"] != "" && $0 ~ ENVIRON["LINT_UNLESS"] { next }
  # FNR (not NR): one awk pass spans many files, so the report must carry the PER-FILE line number.
  $0 ~ ENVIRON["LINT_PAT"] { printf "%s:%d: %s\n", FILENAME, FNR, ENVIRON["LINT_WHAT"] }
' "$@"; }

# ══ THE INLINE-TEST SCANNER ══════════════════════════════════════════════════════════════════════
#
# THE RULE, owner: "tests in their own file always", because it "keeps code file length honest and
# easier to compare". That rationale is not decoration; it already corrupted an investigation. A
# reviewer compared `config/overlay.rs` at 2,111 lines against `config/migrate.rs` at 2,379 and drew
# a conclusion from the pair. The real implementation figure for overlay.rs was 607 lines; the rest
# was inline test bodies. Two files whose stated sizes are measuring different things cannot be
# compared, and nothing in the file tells you that.
#
# So: an implementation file carries NO inline test body. The body lives at `foo/tests/<what>.rs`
# and the impl file keeps the one-line declaration that leaves it a direct child, which is what
# preserves `use super::*` reaching private items:
#
#     #[cfg(test)]
#     #[path = "tests/overlay_tests.rs"]
#     mod tests;
#
# WHAT COUNTS AS A VIOLATION, precisely: a `#[cfg(test)]`-gated region that contains a test-function
# attribute (`#[test]`, `#[tokio::test]`, `#[rstest]`, …). "Gated" is answered by TEST_SCOPE_AWK
# above and by nothing else, so this rule and the choke-point registry can never disagree about what
# test code is. Two shapes deliberately do NOT trip it, because neither is a test:
#   - the `#[path]` DECLARATION above (brace-less; gates its own line and stops);
#   - a `#[cfg(test)]` support module or helper fn that declares no test (a log tap, a serialising
#     mutex). Those are production-side hooks, not tests, and they have no own-file to move to.
# Files under a `tests/` dir are skipped: they ARE the own-file, and a `#[cfg(test)]` wrapper inside
# one is idiomatic.
#
# THE ALLOW MARKER, and why it is shaped the way it is: the marker must NAME ITS REASON. A bare
# allow is the permission-to-ignore mechanism this project banned outright ("0 permission ever on
# anything"), so a marker with no reason is not a weaker pass, it is its own violation:
#
#     // structure-lint: allow inline-test: <why this body cannot move>
#
# It must sit in the comment block directly above the `#[cfg(test)]`; any code between detaches it.
INLINE_TEST_ATTR='^[[:space:]]*#\[((tokio|async_std|actix_rt|serial_test)::)?(test|rstest|test_case|bench|proptest)[]([:space:]]'
INLINE_ALLOW_RE='structure-lint:[[:space:]]*allow[[:space:]]+inline-test'

scan_inline_tests() { awk "$TEST_SCOPE_AWK"'
  function flush_marker() { marker = 0; reason = "" }
  FNR==1 { arm=0; armline=0; emitted=0; a_marker=0; a_reason=""; flush_marker() }
  {
    # A file that IS the own-file is not in scope; the wrapper inside it is idiomatic. (A `next`
    # rather than `nextfile`: the latter is a GNU extension and this script runs on macOS awk too.)
    if (FILENAME ~ /\/tests\//) next
    # (1) region bookkeeping. The report points at the `#[cfg(test)]` that opened the region, which
    #     is the line a reader has to act on, not the individual test attribute inside it.
    if (gated && !arm)      { arm=1; armline=FNR; emitted=0; a_marker=marker; a_reason=reason }
    else if (!gated && arm) { arm=0 }

    # (2) the trigger: a test-function attribute anywhere inside the gated region. Report once.
    if (arm && !emitted && $0 ~ ENVIRON["INLINE_TEST_ATTR"]) {
      emitted=1
      if (!a_marker)
        printf "%s:%d: INLINE-TEST: an inline #[cfg(test)] test body in an implementation file — move it to tests/<what>.rs and leave a #[path] declaration\n", FILENAME, armline
      else if (a_reason == "")
        printf "%s:%d: ALLOW-WITHOUT-REASON: `structure-lint: allow inline-test` with no reason after it — a bare allow is permission to ignore; name why this body cannot move\n", FILENAME, armline
    }

    # (3) marker adjacency, evaluated AFTER the region test so the marker on the line above is the
    #     one that applies. Any line that is not a comment and not blank detaches it.
    if (!gated) {
      if ($0 ~ ENVIRON["INLINE_ALLOW_RE"]) {
        marker=1; reason=$0
        sub(/^.*structure-lint:[[:space:]]*allow[[:space:]]+inline-test/, "", reason)
        gsub(/^[[:space:]:.-]+|[[:space:]]+$/, "", reason)
        if (length(reason) < 12) reason = ""     # a token like "yes" names nothing
      } else if (!is_comment && $0 !~ /^[[:space:]]*$/) flush_marker()
    }
  }
' "$@"; }

# ══ THE FUNCTION-BODY SCANNER (invariant 5's engine) ═════════════════════════════════════════════
#
# Some invariants are not "this call appears nowhere in the tree" — they are "this call appears
# nowhere in THIS FUNCTION". `GovState::try_admit` may not touch the store; every other function in
# the same file may. A file-wide grep cannot express that, so this scanner extracts ONE named
# function's body by brace depth and applies the rule inside it.
#
# It reads the CODE portion of each line (the `code` variable from TEST_SCOPE_AWK, which is empty
# for a whole-line comment and has a trailing `// …` stripped when the line holds no string
# literal). That matters here more than anywhere else: the function this was written for has a doc
# comment that says the words "no store round-trip", and a scanner that read `$0` would report the
# PROSE PROMISING the invariant as a violation OF it.
#
# Output: one `file:line: what` per hit, plus a trailing `#SPAN <first> <last>` per definition found.
# The caller REQUIRES at least one `#SPAN`: a rule whose function was renamed away silently scans
# nothing and reports nothing, which is indistinguishable from a pass. That is the false green this
# project has already been burned by twice, so "function not found" is RED.
scan_fn_body() {   # $1 = file; env: RP_FN, LINT_PAT, LINT_WHAT, LINT_UNLESS
  awk "$TEST_SCOPE_AWK"'
  FNR==1 { infn=0; depth=0; opened=0; start=0 }
  {
    c = code
    # Arm on the DEFINITION line: `fn <name>` followed by `(` or `<` (a generic parameter list).
    # `pub(crate)`, `async`, `unsafe` and `const` prefixes are all accepted; indentation is not
    # constrained, because the function may be a free fn or a method inside an impl block.
    if (!infn && !gated && c ~ ("^[[:space:]]*(pub[[:space:]]*(\\([^)]*\\)[[:space:]]*)?)?((async|unsafe|const)[[:space:]]+)*fn[[:space:]]+" ENVIRON["RP_FN"] "[[:space:]]*[(<]")) {
      infn = 1; depth = 0; opened = 0; start = FNR
    }
    if (infn) {
      d = _braces(c)
      depth += d
      if (d != 0) opened = 1
      if (ENVIRON["LINT_UNLESS"] != "" && c ~ ENVIRON["LINT_UNLESS"]) { }
      else if (c ~ ENVIRON["LINT_PAT"]) printf "%s:%d: %s\n", FILENAME, FNR, ENVIRON["LINT_WHAT"]
      # A signature spanning several lines has not opened its body yet, so `opened` gates the close.
      if (opened && depth <= 0) { infn = 0; printf "#SPAN %d %d\n", start, FNR }
    }
  }
  END { if (infn) printf "#SPAN %d %d\n", start, FNR }   # unterminated: report what was scanned
' "$1"; }

# ══ THE PLANE DECLARATION SCANNER (invariant 6's engine) ═════════════════════════════════════════
#
# Prints one `symbol<TAB>file:line` per TOP-LEVEL declaration — a free `fn`, or a `struct` / `enum`
# / `trait` / `union` — in the files handed to it. `#[cfg(test)]`-gated regions and whole-line
# comments are excluded by TEST_SCOPE_AWK, which is what keeps the A6.1 finding from becoming a
# false positive: the word `breaker` appears under `mcp/` and `a2a/` only as PROSE IN COMMENTS, and
# prose is not a declaration.
#
# TOP-LEVEL — anchored at column 0 — is the whole trick, and it is why this rule is usable at all.
# A method inside an `impl` block is indented, and its name is scoped by its type, so `fn new`,
# `fn fmt`, `fn len` and `fn default` (which collide across every pair of modules in any Rust
# codebase) never reach the comparison. What survives is a free function or a type: a name its
# author CHOSE, at file scope, with nothing scoping it. Two planes choosing the same one is the
# signal.
scan_plane_decls() {   # $1.. = files
  awk "$TEST_SCOPE_AWK"'
  gated || is_comment { next }
  {
    if (match($0, /^(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?((async|unsafe|const)[[:space:]]+)*fn[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
      s = substr($0, RSTART, RLENGTH); sub(/^.*fn[[:space:]]+/, "", s)
      printf "%s\t%s:%d\n", s, FILENAME, FNR; next
    }
    if (match($0, /^(pub[[:space:]]*(\([^)]*\)[[:space:]]*)?)?(struct|enum|trait|union)[[:space:]]+[A-Za-z_][A-Za-z0-9_]*/)) {
      s = substr($0, RSTART, RLENGTH); sub(/^.*[[:space:]]/, "", s)
      printf "%s\t%s:%d\n", s, FILENAME, FNR; next
    }
  }' "$@"; }

# Collates `scan_plane_decls` output across N planes and prints, for every symbol declared at top
# level in TWO OR MORE of them, one line: `symbol<TAB>plane:file:line[ plane:file:line …]`.
# Arguments are `<plane-key>=<dir>` pairs, so the self-test can point it at a fixture corpus and
# exercise the REAL collation rather than a copy of it.
plane_dup_table() {   # $1.. = plane=dir
  local spec plane dir f
  for spec in "$@"; do
    plane="${spec%%=*}"; dir="${spec#*=}"
    [ -d "$dir" ] || continue
    local files=()
    while IFS= read -r f; do files+=("$f"); done < <(find "$dir" -name '*.rs' -not -path '*/tests/*' | sort)
    [ ${#files[@]} -eq 0 ] && continue
    scan_plane_decls "${files[@]}" | sed "s|^\([^	]*\)	|\1	${plane}	|"
  done | awk -F'\t' '
    { key = $1 SUBSEP $2
      if (!(key in seenplane)) { seenplane[key] = 1; planes[$1]++ }
      where[$1] = where[$1] (where[$1] == "" ? "" : " ") $2 ":" $3 }
    END { for (s in planes) if (planes[s] >= 2) printf "%s\t%s\n", s, where[s] }' | sort
}

# The same question asked of FILE NAMES rather than symbols, because a concern can be duplicated
# without a single name colliding. `mcp/config.rs` and `a2a/config.rs` are two implementations
# of "the plane's config" whatever they call their types, and the module name is the author's own
# statement of which concern the file is. `mod.rs` is excluded: it is Rust's spelling of "this
# directory", not a concern.
plane_dup_modules() {   # $1.. = plane=dir
  local spec plane dir
  for spec in "$@"; do
    plane="${spec%%=*}"; dir="${spec#*=}"
    [ -d "$dir" ] || continue
    find "$dir" -name '*.rs' -not -path '*/tests/*' \
      | sed "s|^\(.*/\([^/]*\.rs\)\)$|\2	${plane}	\1|" | grep -v '^mod\.rs	' | sort -u
  done | awk -F'\t' '
    { key = $1 SUBSEP $2
      if (key in seenplane) next
      seenplane[key] = 1
      n[$1]++; where[$1] = where[$1] (where[$1] == "" ? "" : " ") $2 ":" $3 }
    END { for (m in n) if (n[m] >= 2) printf "%s\t%s\n", m, where[m] }' | sort
}

# ══ THE CENSUS VERDICT (invariant 9's decision) ══════════════════════════════════════════════════
#
# Three arms, and the middle one is the reason the whole invariant exists. `$1` = the count found,
# `$2` = the count declared.
#
#   MISSING — found NOTHING. Not a pass: it is a rule whose subject was renamed, moved or deleted,
#             scanning the whole tree and asserting nothing. Reported as its own verdict rather than
#             folded into WRONG because the remedy is different — you re-point the row, you do not
#             go looking for a duplicate that is not there.
#   WRONG   — found some, but not the declared number. A second spelling, or a second decision.
#   OK      — exactly the declared number.
#
# It lives here as a function so `--selftest` exercises the REAL verdict rather than a copy of it: a
# gate proven against a different predicate from the one that ships is not proven.
census_verdict() {   # $1 = got, $2 = want
  if [ "$1" -eq 0 ]; then printf 'MISSING\n'
  elif [ "$1" -ne "$2" ]; then printf 'WRONG\n'
  else printf 'OK\n'; fi
}

# ══ SELF-TEST: the scanner that guards the tree is itself guarded ════════════════════════════════
#
# `scripts/structure-lint.sh --selftest` runs the REAL `scan_rule` above (not a copy) over a fixture
# corpus of Rust files whose every shape is a known way to LIE about being test code. A scanner with
# a bypass is worse than no scanner: it reports "ok, no bypass" while the bypass sits in production.
# So each fixture plants a bypass (`std::fs::rename(`) and declares the verdict it must get.
#
# Fixture format: a Rust source with one probe line per hazard. `//= HIT` / `//= MISS` trailing a
# probe line declares whether the registry scanner MUST flag it.
selftest_case() {   # $1 = name, stdin = fixture source
  local name="$1" src want_hit got_hit
  src="$SELFTEST_DIR/$name.rs"
  cat > "$src"
  selftest_ran=$((selftest_ran+1))
  # A fixture that did not reach disk must be RED, never a silent skip. A case that "passes" because
  # its input vanished is the exact false green this project has already been burned by.
  if [ ! -s "$src" ]; then
    note "SELFTEST FAIL [$name] registry: fixture is missing or empty at $src"
    selftest_fail=1; return 0
  fi
  LINT_PAT='std::fs::rename\('; LINT_WHAT='probe'; LINT_UNLESS=''
  export LINT_PAT LINT_WHAT LINT_UNLESS
  got_hit=$(scan_rule "$src" | cut -d: -f2 | sort -n | tr '\n' ' ')
  want_hit=$({ grep -n '//= HIT' "$src" || true; } | cut -d: -f1 | sort -n | tr '\n' ' ')
  if [ "$got_hit" != "$want_hit" ]; then
    note "SELFTEST FAIL [$name] registry: flagged lines {${got_hit}} but expected {${want_hit}}"
    selftest_fail=1
  else selftest_pass=$((selftest_pass+1)); fi
  unset LINT_PAT LINT_WHAT LINT_UNLESS
  return 0
}

# The inline-test rule's fixture helper. `$1` is the fixture's path RELATIVE to the corpus root, so
# a case can be placed under a `tests/` dir and prove the rule MISSES a legitimately test-only file.
# A probe line declares its verdict with a trailing `//= INLINE`, `//= NOREASON` or `//= OK`; the
# expectation is read off the fixture itself, so a fixture and its expectation cannot drift.
selftest_inline_case() {   # $1 = relative path, stdin = fixture source
  local rel="$1" src want got
  src="$SELFTEST_DIR/$rel"
  mkdir -p "$(dirname "$src")"
  cat > "$src"
  selftest_ran=$((selftest_ran+1))
  if [ ! -s "$src" ]; then
    note "SELFTEST FAIL [$rel] inline-test: fixture is missing or empty at $src"
    selftest_fail=1; return 0
  fi
  export INLINE_TEST_ATTR INLINE_ALLOW_RE
  got=$(scan_inline_tests "$src" | awk -F: '{ split($3, a, " "); printf "%s=%s ", $2, a[1] }')
  want=$({ grep -nE '//= (INLINE|NOREASON)' "$src" || true; } \
        | sed -E 's|^([0-9]+):.*//= |\1=|' | tr '\n' ' ')
  # Normalise: the scanner prints `INLINE-TEST` / `ALLOW-WITHOUT-REASON`, the fixture says
  # `INLINE` / `NOREASON`.
  got=$(printf '%s' "$got" | sed 's/=INLINE-TEST/=INLINE/g; s/=ALLOW-WITHOUT-REASON/=NOREASON/g')
  if [ "$got" != "$want" ]; then
    note "SELFTEST FAIL [$rel] inline-test: reported {${got}} but expected {${want}}"
    selftest_fail=1
  else selftest_pass=$((selftest_pass+1)); fi
  return 0
}

# Invariant 5's fixture helper. `$1` = case name, `$2` = the function the rule is scoped to, stdin =
# the fixture. A probe line declares its verdict with a trailing `//= HIT`; a fixture that expects
# the function NOT to be found anywhere says so with a `//= NOFN` line, which is how the false-green
# arm (the rule silently scanning nothing) is itself tested.
selftest_fnbody_case() {   # $1 = name, $2 = fn, stdin = fixture source
  local name="$1" fn="$2" src want got out spans
  src="$SELFTEST_DIR/$name.rs"
  cat > "$src"
  selftest_ran=$((selftest_ran+1))
  if [ ! -s "$src" ]; then
    note "SELFTEST FAIL [$name] fn-body: fixture is missing or empty at $src"
    selftest_fail=1; return 0
  fi
  RP_FN="$fn"
  LINT_PAT='[^A-Za-z0-9_][Ss]tore[^A-Za-z0-9_]'; LINT_WHAT='probe'; LINT_UNLESS=''
  export RP_FN LINT_PAT LINT_WHAT LINT_UNLESS
  out=$(scan_fn_body "$src")
  got=$({ printf '%s\n' "$out" | grep -v '^#SPAN' || true; } | cut -d: -f2 | sort -n | tr '\n' ' ')
  want=$({ grep -n '//= HIT' "$src" || true; } | cut -d: -f1 | sort -n | tr '\n' ' ')
  spans=$({ printf '%s\n' "$out" | grep -c '^#SPAN ' || true; } | tr -d ' ')
  # `printf` of an empty capture still emits one blank line, so an empty result arrives as a lone
  # space. Trim both sides or "no hits" and "no hits" compare unequal and every clean case fails.
  got=$(printf '%s' "$got" | sed 's/^ *//; s/ *$//')
  want=$(printf '%s' "$want" | sed 's/^ *//; s/ *$//')
  unset RP_FN LINT_PAT LINT_WHAT LINT_UNLESS
  if [ "$got" != "$want" ]; then
    note "SELFTEST FAIL [$name] fn-body: flagged lines {${got}} but expected {${want}}"
    selftest_fail=1; return 0
  fi
  if grep -q '//= NOFN' "$src"; then
    if [ "$spans" != "0" ]; then
      note "SELFTEST FAIL [$name] fn-body: expected the function NOT to be found, but ${spans} definition(s) were scanned"
      selftest_fail=1; return 0
    fi
  elif [ "$spans" = "0" ]; then
    note "SELFTEST FAIL [$name] fn-body: the function was never found, so the case asserted nothing"
    selftest_fail=1; return 0
  fi
  selftest_pass=$((selftest_pass+1))
  return 0
}

# Invariant 6's fixture helper. `$1` = case name; the remaining arguments are `<relative path>` files
# read from a single here-doc separated by lines reading `--- <path>`, which keeps a whole two-plane
# corpus in one readable block. Expectations live IN the corpus: `//= DUP <symbol>` and
# `//= DUPMOD <file.rs>` name what the collation MUST report, and anything else it reports is a
# false positive that fails the case.
selftest_plane_case() {   # $1 = name, stdin = corpus (`--- <path>` separated)
  local name="$1" root cur want got wantm gotm
  root="$SELFTEST_DIR/planes/$name"
  rm -rf "$root"; mkdir -p "$root/p1" "$root/p2"
  cur=""
  while IFS= read -r line; do
    case "$line" in
      '--- '*) cur="$root/${line#--- }"; mkdir -p "$(dirname "$cur")"; : > "$cur" ;;
      *) [ -n "$cur" ] && printf '%s\n' "$line" >> "$cur" ;;
    esac
  done
  selftest_ran=$((selftest_ran+1))
  if [ -z "$(find "$root" -name '*.rs')" ]; then
    note "SELFTEST FAIL [$name] plane: corpus is empty at $root"
    selftest_fail=1; return 0
  fi
  got=$(plane_dup_table   "p1=$root/p1" "p2=$root/p2" | cut -f1 | sort | tr '\n' ' ')
  gotm=$(plane_dup_modules "p1=$root/p1" "p2=$root/p2" | cut -f1 | sort | tr '\n' ' ')
  want=$({ grep -rh '//= DUP '    "$root" || true; } | sed -E 's|.*//= DUP ||;s|[[:space:]]+$||' | sort -u | tr '\n' ' ')
  wantm=$({ grep -rh '//= DUPMOD ' "$root" || true; } | sed -E 's|.*//= DUPMOD ||;s|[[:space:]]+$||' | sort -u | tr '\n' ' ')
  if [ "$got" != "$want" ] || [ "$gotm" != "$wantm" ]; then
    note "SELFTEST FAIL [$name] plane: symbols {${got}} expected {${want}}; modules {${gotm}} expected {${wantm}}"
    selftest_fail=1; return 0
  fi
  selftest_pass=$((selftest_pass+1))
  return 0
}

# Invariant 9's fixture helper. `$1` = case name, `$2` = the awk ERE to count, `$3` = the count the
# row declares; stdin = the fixture. The fixture states the verdict it must get with a line reading
# `//= VERDICT <OK|WRONG|MISSING>`, so the fixture and its expectation cannot drift apart. It runs
# the REAL `scan_rule` and the REAL `census_verdict`, which is the only reason it proves anything.
selftest_census_case() {   # $1 = name, $2 = pattern, $3 = want, stdin = fixture source
  local name="$1" pat="$2" want="$3" src want_verdict got_verdict got
  src="$SELFTEST_DIR/$name.rs"
  cat > "$src"
  selftest_ran=$((selftest_ran+1))
  if [ ! -s "$src" ]; then
    note "SELFTEST FAIL [$name] census: fixture is missing or empty at $src"
    selftest_fail=1; return 0
  fi
  LINT_PAT="$pat"; LINT_WHAT='census'; LINT_UNLESS=''
  export LINT_PAT LINT_WHAT LINT_UNLESS
  got=$({ scan_rule "$src" || true; } | grep -c . || true)
  got=$(printf '%s' "$got" | tr -d ' ')
  got_verdict=$(census_verdict "$got" "$want")
  unset LINT_PAT LINT_WHAT LINT_UNLESS
  want_verdict=$({ grep -o '//= VERDICT [A-Z]*' "$src" || true; } | sed 's|//= VERDICT ||' | head -1)
  if [ -z "$want_verdict" ]; then
    note "SELFTEST FAIL [$name] census: the fixture declares no \`//= VERDICT\`, so it asserted nothing"
    selftest_fail=1; return 0
  fi
  if [ "$got_verdict" != "$want_verdict" ]; then
    note "SELFTEST FAIL [$name] census: counted ${got} against a declared ${want} and returned ${got_verdict}, expected ${want_verdict}"
    selftest_fail=1; return 0
  fi
  selftest_pass=$((selftest_pass+1))
  return 0
}

run_selftest() {
  hdr "structure-lint SELF-TEST (the test-scope scanner cannot be lied to)"
  SELFTEST_DIR=$(mktemp -d); trap 'rm -rf "$SELFTEST_DIR"' EXIT
  selftest_fail=0; selftest_pass=0; selftest_ran=0

  # ① The shadow bug that was PROVEN exploitable: a doc comment that merely NAMES the attribute.
  selftest_case doc_comment_mentions_attr <<'RS'
/// The wire bytes are identical - the tag is `#[cfg(test)]`.
pub(crate) fn prod() {
    let _ = std::fs::rename("a", "b");                               //= HIT
}
RS

  # ② The other proven shadow: the attribute on a BRACE-LESS item. It must gate that item ONLY, and
  #    must NOT latch onto the next braced item at arbitrary distance.
  selftest_case braceless_items <<'RS'
#[cfg(test)]
#[path = "tests/unit.rs"]
mod unit;

#[cfg(test)]
use std::fs::rename;

#[cfg(test)]
const FIXTURE: &str = "x";

pub fn prod() {
    let _ = std::fs::rename("a", "b");                               //= HIT
}
RS

  # ③ A genuine inline test body is still exempt, nesting and all — and the production item AFTER it
  #    is scanned again (the region must CLOSE).
  selftest_case real_test_body <<'RS'
#[cfg(test)]
mod tests {
    use super::*;
    #[test]
    fn t() {
        if true {
            let _ = std::fs::rename("a", "b");
        }
    }
}

pub fn prod_after() {
    let _ = std::fs::rename("a", "b");                               //= HIT
}
RS

  # ④ `#[cfg(test)]` on a method INSIDE a production impl block gates only that method.
  selftest_case gated_method_in_impl <<'RS'
impl Foo {
    #[cfg(test)]
    fn helper(&self) -> u32 {
        let _ = std::fs::rename("a", "b");
        1
    }

    #[cfg(test)]
    fn oneliner(&self) -> u32 { let _ = std::fs::rename("a", "b"); 1 }

    pub fn prod(&self) {
        let _ = std::fs::rename("a", "b");                           //= HIT
    }
}
RS

  # ⑤ cfg predicates that are NOT a test gate must not exempt anything; `all(test, ...)` must.
  selftest_case cfg_predicate_shapes <<'RS'
#[cfg(not(test))]
pub fn prod_only() {
    let _ = std::fs::rename("a", "b");                               //= HIT
}

#[cfg(feature = "test-utils")]
pub fn feature_gated() {
    let _ = std::fs::rename("a", "b");                               //= HIT
}

#[cfg(all(test, feature = "x"))]
mod t {
    fn f() { let _ = std::fs::rename("a", "b"); }
}
RS

  # ⑥ A multi-line signature still resolves to its brace; an UNRESOLVABLE arm must fail CLOSED
  #    (drop the arm) rather than shadow the rest of the file forever.
  selftest_case unresolvable_arm_fails_closed <<'RS'
#[cfg(test)]
fn wrapped(
    a: u32,
    b: u32,
) -> u32 {
    let _ = std::fs::rename("a", "b");
    a + b
}

#[cfg(test)]
























pub fn far_away() {
    let _ = std::fs::rename("a", "b");                               //= HIT
}
RS

  # ══ the inline-test rule (invariant 3) ═════════════════════════════════════════════════════════
  # Verdict markers sit on the `#[cfg(test)]` line, which is where the scanner reports.

  # ⑦ The plain violation: an inline test body in an implementation file.
  selftest_inline_case inline_body.rs <<'RS'
pub fn prod() -> u32 { 1 }

#[cfg(test)]                                                         //= INLINE
mod tests {
    use super::*;
    #[test]
    fn t() { assert_eq!(prod(), 1); }
}
RS

  # ⑧ MUST MISS. The CORRECT shape: the body lives in tests/, the impl file keeps the declaration.
  #    Also here: a `#[cfg(test)]` support module that declares no test is not a test and has no
  #    own-file to move to, and a `#[cfg(test)]` helper method inside a production impl likewise.
  selftest_inline_case correct_shapes.rs <<'RS'
#[cfg(test)]
#[path = "tests/thing_tests.rs"]
mod tests;

#[cfg(test)]
pub(crate) mod log_tap {
    pub(crate) fn install() {}
}

impl Foo {
    #[cfg(test)]
    fn probe(&self) -> u32 { 7 }
}
RS

  # ⑨ MUST MISS. A legitimately test-only file: it IS the own-file, so the wrapper inside it is
  #    idiomatic. If this case ever HITS, the rule has started forbidding the very shape it demands.
  selftest_inline_case tests/already_own_file.rs <<'RS'
#[cfg(test)]
mod inner {
    #[test]
    fn t() { assert!(true); }
}

#[test]
fn top_level() { assert!(true); }
RS

  # ⑩ The allow marker. With a reason it permits the body; with NO reason it is its own violation.
  #    A bare allow is the permission-to-ignore mechanism this project banned, so it may not be a
  #    quieter pass than the thing it was suppressing.
  selftest_inline_case allow_marker.rs <<'RS'
// structure-lint: allow inline-test: exercises a macro that only expands at this scope
#[cfg(test)]
mod ok_with_reason {
    #[test]
    fn t() { assert!(true); }
}

// structure-lint: allow inline-test
#[cfg(test)]                                                         //= NOREASON
mod bare_allow {
    #[test]
    fn t() { assert!(true); }
}

// structure-lint: allow inline-test: yes
#[cfg(test)]                                                         //= NOREASON
mod too_short_to_be_a_reason {
    #[test]
    fn t() { assert!(true); }
}
RS

  # ⑪ Marker adjacency. A marker is spent on the region directly below it: any code between them
  #    detaches it, so an allow written for one body cannot silently cover a later one.
  selftest_inline_case marker_adjacency.rs <<'RS'
// structure-lint: allow inline-test: this reason belongs to the item below, not to the tests
pub fn prod() -> u32 { 1 }

#[cfg(test)]                                                         //= INLINE
mod tests {
    #[test]
    fn t() { assert!(true); }
}
RS

  # ⑫ Attribute flavours: async and non-std test attributes are tests too, and a body reported once
  #    is reported once however many tests it holds.
  selftest_inline_case attr_flavours.rs <<'RS'
#[cfg(test)]                                                         //= INLINE
mod a {
    #[tokio::test]
    async fn t1() {}
    #[test]
    fn t2() {}
}

#[cfg(test)]                                                         //= INLINE
mod b {
    #[rstest]
    fn t3() {}
}
RS

  # ══ the request-path rule (invariant 5) ════════════════════════════════════════════════════════
  # The probe is a `store` reference; `//= HIT` marks the lines the rule MUST flag. Every case here
  # is a way the function-scoped scanner could scan the wrong lines and still report a pass.

  # ⑬ SCOPE. The rule is scoped to ONE function: its body is scanned and its neighbours are not,
  #    even though the same call in the same file is entirely legitimate one function down.
  selftest_fnbody_case fnbody_scope try_admit <<'RS'
fn before(&self) {
    let _ = self.store.get("x");
}

pub(crate) fn try_admit(&self, now: u64) -> bool {
    let _ = self.store.get("x");                                     //= HIT
    if now > 0 {
        let _ = Store::get(&self.store, "y");                        //= HIT
    }
    true
}

fn after(&self) {
    let _ = self.store.get("x");
}
RS

  # ⑭ PROSE IS NOT CODE, and this is the case that made the scanner read `code` rather than `$0`:
  #    the real function's own doc comment PROMISES "no store round-trip", and a scanner that read
  #    the raw line would report the promise as a breach of itself. A trailing comment on a code
  #    line is stripped for the same reason. `restore_from_store` is a whole-word test: it CONTAINS
  #    `store` and must not trip.
  selftest_fnbody_case fnbody_prose try_admit <<'RS'
/// SYNCHRONOUS and INFALLIBLE: no store round-trip, no await, ever.
pub(crate) fn try_admit(&self) -> bool {
    // A store call here would be a latency regression on every request.
    let n = self.cells.len();                                        // no store on this path
    let _ = self.restore_from_store_count;
    let _ = self.store.get("x");                                     //= HIT
    n > 0
}
RS

  # ⑮ A MULTI-LINE SIGNATURE still resolves to its own body, and the body still CLOSES — otherwise
  #    the scanner runs to end-of-file and every later function is reported as this one's.
  selftest_fnbody_case fnbody_multiline_sig try_admit <<'RS'
pub(crate) fn try_admit(
    &self,
    key: &VirtualKey,
    now: u64,
) -> Result<Grant, Blocked> {
    let _ = self.store.get("x");                                     //= HIT
    Ok(Grant::default())
}

fn unrelated() {
    let _ = self.store.get("x");
}
RS

  # ⑯ PREFIX SAFETY. A rule written for `try_admit` must not arm on `try_admit_breaker`; if it did,
  #    the invariant would be enforced against a function it was never written about and would go
  #    red for the wrong reason (or, worse, green because the real one was never reached).
  selftest_fnbody_case fnbody_prefix try_admit <<'RS'
//= NOFN
fn try_admit_breaker(&self, pool: &str) -> bool {
    let _ = self.store.get("x");
    true
}
RS

  # ⑰ THE FALSE-GREEN ARM. The function has been renamed away. The scanner must find NOTHING, so
  #    the caller can turn "nothing scanned" into RED instead of into a pass. This is the shape the
  #    project has already been burned by: an unarmed gate reporting success.
  selftest_fnbody_case fnbody_renamed_away try_admit <<'RS'
//= NOFN
pub(crate) fn try_admit_v2(&self) -> bool {
    let _ = self.store.get("x");
    true
}
RS

  # ══ the plane-coherence rule (invariant 6) ═════════════════════════════════════════════════════
  # `//= DUP <symbol>` / `//= DUPMOD <file>` in the corpus name exactly what the collation must
  # report. Anything else it reports is a false positive and fails the case.

  # ⑱ THE SIGNAL, and the four shapes that must NOT be it. GOAL §A6.1 is the reason the third one
  #    is here: the circuit breaker is NOT duplicated, and the `breaker` mentions under `mcp/` and
  #    `a2a/` are PROSE IN COMMENTS. A lint that grepped for the word would have reported a
  #    duplicate breaker and been wrong about the one thing the goal had just verified in code.
  selftest_plane_case signal_and_its_lookalikes <<'RS'
--- p1/chain.rs
//= DUP compute_hash
//= DUP ChainBreak
fn compute_hash(row: &Row) -> String { String::new() }

pub(crate) enum ChainBreak {
    Missing,
}

// This plane has no breaker; try_admit_breaker lives in the LLM plane and is called from
// proxy/engine/walk.rs. Naming it here is prose, not a declaration.
impl Chain {
    fn new() -> Self { Chain }
    fn len(&self) -> usize { 0 }
}

#[cfg(test)]
fn only_in_tests() -> u32 { 0 }
--- p2/provenance.rs
fn compute_hash(row: &Row) -> String { String::new() }

pub(crate) enum ChainBreak {
    Missing,
}

// The breaker is keyed by (pool, lane) and this plane does not have lanes, so try_admit_breaker
// is not called here either.
impl Chain {
    fn new() -> Self { Chain }
    fn len(&self) -> usize { 0 }
}

#[cfg(test)]
fn only_in_tests() -> u32 { 0 }
RS

  # ⑲ MODULE NAMES. A concern can be duplicated without one symbol colliding, so the file name is a
  #    second, independent signal. `mod.rs` names a directory rather than an idea and is exempt;
  #    files under a `tests/` dir are not implementations and are exempt too.
  selftest_plane_case module_names <<'RS'
--- p1/catalogue.rs
//= DUPMOD catalogue.rs
pub(crate) struct ToolEntry;
--- p1/mod.rs
pub(crate) mod catalogue;
--- p1/tests/shared_tests.rs
fn helper() {}
--- p2/catalogue.rs
pub(crate) struct AgentCandidate;
--- p2/mod.rs
pub(crate) mod catalogue;
--- p2/tests/shared_tests.rs
fn helper() {}
RS

  # ══ the declaration census (invariant 9) ═══════════════════════════════════════════════════════
  # `//= VERDICT <word>` in the fixture names the answer the REAL census must return for it.

  # ⑳ THE PROSE TRAP, and it is the one that would have broken this invariant on its first run. A
  #    census over a wire word has to be documented, and documenting it means WRITING THE WORD —
  #    twice in the block comment above the constant, once more in a `#[cfg(test)]` fixture. A
  #    census that counted raw text would report its own documentation as a duplicate spelling and
  #    fail on the very file that defines the single spelling correctly. Exactly one CODE line
  #    carries it, so the verdict is OK.
  selftest_census_case census_prose_is_not_a_spelling '"mcp-protocol-version"' 1 <<'RS'
//= VERDICT OK
// The header is "mcp-protocol-version" and it is written here once. This comment says the word
// twice — "mcp-protocol-version" again — and neither mention is a second spelling of it.
/// Doc comments are prose too: "mcp-protocol-version".
pub(crate) const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";

#[cfg(test)]
mod tests {
    #[test]
    fn t() {
        let _ = "mcp-protocol-version";
    }
}
RS

  # ㉑ THE DUPLICATE. A second spelling in real code is the drift the deleted symmetry test existed
  #    to catch: two directions, each internally consistent with its own copy, disagreeing silently.
  selftest_census_case census_second_spelling '"mcp-protocol-version"' 1 <<'RS'
//= VERDICT WRONG
pub(crate) const H_PROTOCOL_VERSION: &str = "mcp-protocol-version";

pub fn outbound() -> (String, String) {
    ("mcp-protocol-version".to_string(), "2026-07-28".to_string())
}
RS

  # ㉒ THE FALSE-GREEN ARM, and the reason this invariant is a census and not another ban. The
  #    subject has been renamed away. A ban would scan every file, match nothing, print nothing and
  #    read exactly like a pass. The census must say MISSING instead — a distinct verdict from
  #    WRONG, because the remedy is to re-point the row, not to hunt a duplicate that is not there.
  selftest_census_case census_subject_renamed_away '"mcp-protocol-version"' 1 <<'RS'
//= VERDICT MISSING
pub(crate) const H_PROTOCOL_VERSION: &str = "mcp-protocol-version-v2";

pub fn outbound() -> String {
    H_PROTOCOL_VERSION.to_string()
}
RS

  # A self-test that asserted nothing would report exactly what a passing one reports. So the count
  # of cases actually EXECUTED is itself an assertion: zero cases is RED, not "ok, nothing to do".
  if [ "$selftest_ran" -eq 0 ]; then
    note "SELFTEST FAIL: no fixture cases ran — a self-test that executes nothing proves nothing"
    selftest_fail=1
  fi
  note "self-test: ${selftest_pass}/${selftest_ran} fixture case(s) passed"
  if [ "$selftest_fail" -ne 0 ]; then
    note "structure-lint SELF-TEST FAILED — the scanner would let a bypass through"
    return 1
  fi
  note "ok"
  return 0
}

if [ "${1:-}" = "--selftest" ]; then run_selftest; exit $?; fi

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

# PRE-EXISTING DEBT, GRANDFATHERED — this ran for the first time against `dev`'s real content on
# 2026-08-02 (ci.yml had never triggered on dev before; see that commit's message) and immediately
# found 5 files that were already over the cap and 6 pre-existing test-locality violations, none
# introduced by anything that landed same-day. Splitting a 4900-line hot file under release pressure
# is how you introduce a REAL regression while chasing a lint; that's a real, separate refactor this
# list exists to make visible and trackable, not to hide. Shrinking this list is the only permitted
# edit to it — a PR that ADDS an entry here for NEW code is not a fix, it's evading the check.
GRANDFATHERED_OVERSIZED="
${CORE}/admin/v1/json/handlers.rs
${CORE}/config/mod.rs
${CORE}/proxy/engine/mod.rs
"
# There is no grandfathered list for test locality. There was one, of 7 files, and it was deleted
# rather than shrunk: the rule it was suspending is "tests in their own file always", every entry on
# it was moved, and an exception list for a mechanical change is only a way of never doing it.
is_grandfathered() { printf '%s\n' "$2" | grep -qx "$1"; }

# Candidate set, computed once and shared by invariants 3 and 4: every crate .rs outside a tests/
# or benches/ dir. (Built with a read loop rather than `mapfile` so the script still runs on the
# bash 3.2 that ships with macOS.)
#
# `benches/` is excluded for the SAME reason `tests/` is, not as a convenience: a criterion bench is
# harness code that drives the primitives directly — it writes its own fixture directories, spawns
# the binary, and is never compiled into the shipped artifact (`cargo build --release` does not
# resolve a dev-dependency). Holding it to the choke-point registry would report a bench's
# `create_dir_all` of a temp fixture as a durability bypass, which is the lint being right about a
# pattern and wrong about the file — the exact failure mode the `tests/` carve-out already exists to
# avoid. If a bench ever needs to be held to a production rule, the answer is that the logic does
# not belong in a bench.
CANDIDATES=()
while IFS= read -r f; do CANDIDATES+=("$f"); done < <(find crates -name '*.rs' -not -path '*/tests/*' -not -path '*/benches/*' | sort)

# ── Invariant 2: no monster impl files — split by area. Test files (under a tests/ dir) are exempt. ─
hdr "no impl .rs file over ${MAX_LINES_IMPL} lines (test files exempt)"
big=0
while IFS= read -r f; do
  case "$f" in */tests/*) continue ;; esac   # test files are name-navigated → exempt from the cap
  n=$(wc -l < "$f")
  if [ "$n" -gt "$MAX_LINES_IMPL" ]; then
    if is_grandfathered "$f" "$GRANDFATHERED_OVERSIZED"; then
      note "OVERSIZED (grandfathered, pre-existing debt): $f ($n lines)"
    else
      note "OVERSIZED: $f ($n lines)"; fail=1; big=1
    fi
  fi
done < <(find crates -name '*.rs')
[ "$big" -eq 0 ] && note "ok"

# ── Invariant 3: tests live in foo/tests/, ALWAYS. See scan_inline_tests above for the rule, the
#    two shapes that are deliberately not violations, and the allow marker. ────────────────────────
hdr "test locality (tests in their own file always; no inline test body in an impl file)"
loc=0
export INLINE_TEST_ATTR INLINE_ALLOW_RE
inline_hits=$(scan_inline_tests "${CANDIDATES[@]}")
if [ -n "$inline_hits" ]; then
  while IFS= read -r h; do note "$h"; done <<<"$inline_hits"
  note "$(printf '%s\n' "$inline_hits" | wc -l | tr -d ' ') inline test body/bodies — see docs/code-layout.md § 2"
  fail=1; loc=1
fi
[ "$loc" -eq 0 ] && note "ok"

# ══ Invariant 4: THE CHOKE-POINT REGISTRY ════════════════════════════════════════════════════════
#
# A "choke point" is the single place a whole class of hazard is handled correctly ONCE, so a future
# sibling cannot re-introduce the class by hand-rolling its own copy. The remediation contract
# (docs/testing.md § "The remediation contract") says a finding with a sibling is not a bug, it is a
# missing choke point — and the fix is the choke point plus ONE class-level test.
#
# This is the machine-readable ledger of that contract: ONE declarative table, not N bespoke awk
# passes. Every row is a complete choke point. Adding the next one is a ONE-ROW addition — no new
# scanner, no new loop, no new exit path.
#
# ── Row format (fields separated by `|`, in this order) ──────────────────────────────────────────
#   1. id        — the choke point's stable name (also the docs/testing.md anchor).
#   2. tag       — the violation label printed on a bypass (e.g. DURABLE-BYPASS).
#   3. owner     — the module/API that OWNS the choke point (where the correct implementation lives).
#   4. classtest — `<path>::<fn>`: the ONE class-level test; the lint fails if it disappears.
#   5. remedy    — the one-line "route through X" instruction printed with every violation.
#   6. rules     — `;`-separated banned patterns that BYPASS the choke point. Each rule is
#                  `<awk-ERE>>><what it is>>><allowed-exception paths>[>><unless-ERE>]`, where the
#                  optional trailing `unless` opts out lines that share the pattern but not the
#                  hazard (an atomic `.swap(x, Ordering::…)`, say).
#                  A literal `-` means "no greppable bypass" (see the note on differently-enforced
#                  choke points below).
#   7. rationale — one line: why this class needs a single point of truth.
#
# ── What the scan covers ──────────────────────────────────────────────────────────────────────────
# Every `crates/**/*.rs` EXCEPT: files under a `tests/` dir (name-navigated; they drive the
# primitives directly), `#[cfg(test)]`-gated regions (same reason), whole-line `//` comments (prose
# may name the banned call), and the rule's own allowed-exception paths.
#
# ── Differently-enforced choke points ─────────────────────────────────────────────────────────────
# A row with `rules = -` has NO greppable bypass: it is enforced in the type system or at runtime
# instead (D's router layer PANICS on an under-claim, and its class test fails on an over-claim).
# Those rows are still listed here so the registry is a COMPLETE map of every choke point in the
# tree — you should never have to ask "is there a choke point for X?" anywhere but this table.
CHOKE_POINTS=(
  # ── A ── persistence: one durable-write primitive. A 5th call site that re-hand-rolls the
  #         atomic-write dance would silently drop whichever facet (parent fsync / temp cleanup /
  #         0600 mode) its author forgot.
  'A-persistence|DURABLE-BYPASS|crates/api/src/durable.rs (durable::write / write_with; AppHandle::commit_and_swap)|crates/api/src/tests/durable_tests.rs::fault_matrix_returns_err_untouched_target_no_temp_leak|route through crate::durable::write|fs::rename\(>>hand-rolled rename-to-publish>>crates/api/src/durable.rs;sync_[ad]>>hand-rolled fsync durability (sync_all/sync_data)>>crates/api/src/durable.rs;fs::create_dir_all\(>>directory creation that leaves the new entry non-durable>>crates/api/src/durable.rs,'"$CORE"'/test_support/mod.rs|persist-then-swap is only atomic if EVERY writer does the identical fsync/rename/cleanup dance'

  # ── B ── plugin FFI/ABI: one export boundary. A hand-written #[no_mangle] skips the
  #         null-out-guard-before-alloc, the mandatory catch_unwind, and the total status map.
  'B-plugin-export|EXPORT-BYPASS|crates/plugin-sdk/src/boundary.rs (via the export_*_plugin! macro)|crates/plugin-sdk/tests/boundary_class.rs::null_out_pointer_never_leaks|define exports via export_*_plugin!, never by hand|#\[(unsafe\()?no_mangle>>hand-rolled #[no_mangle] export>>crates/plugin-sdk/src/lib.rs;#\[(unsafe\()?export_name>>hand-rolled #[export_name] export>>crates/plugin-sdk/src/lib.rs|an unwind or a written-then-failed out-param crossing the C ABI is UB, so no export may skip the wrapper'

  # ── C ── admin config mutation: one transaction. A raw lock re-opens lock-then-arbitrary-code; a
  #         swap outside the section IS the lost update the lock exists to prevent. state.rs DEFINES
  #         swap/commit_and_swap, so it is allowed alongside txn.rs.
  'C-config-mutation|MUTATION-BYPASS|'"$CORE"'/admin/v1/json/txn.rs (config_transaction)|'"$CORE"'/admin/v1/json/tests/txn_tests.rs::concurrent_transactions_never_lose_a_swap|route through json::txn::config_transaction|CONFIG_MUTATION_LOCK>>names the config mutation lock>>'"$CORE"'/admin/v1/json/txn.rs;commit_and_swap\(>>direct commit_and_swap outside a transaction>>'"$CORE"'/admin/v1/json/txn.rs,'"$CORE"'/state.rs;\.swap\(>>direct swap on an AppHandle outside a transaction>>'"$CORE"'/admin/v1/json/txn.rs,'"$CORE"'/state.rs>>Ordering::;AppHandle::swap\(>>direct AppHandle::swap outside a transaction>>'"$CORE"'/admin/v1/json/txn.rs,'"$CORE"'/state.rs|a fresh post-lock snapshot + one persist-then-swap is the only way concurrent mutations cannot lose an update'

  # ── D ── OpenAPI error taxonomy: one declaration the generator PROJECTS. Enforced differently —
  #         there is no pattern to ban, because the hazard is an endpoint emitting an ErrKind the
  #         declaration omits. The v1 router's recording layer PANICS on that under-claim at the
  #         moment of emission, and the class test fails on the mirror-image over-claim.
  'D-openapi-taxonomy|TAXONOMY-BYPASS|'"$CORE"'/admin/v1/contract/taxonomy.rs (declared_errors)|'"$CORE"'/admin/tests/tests.rs::declared_error_set_is_exactly_what_the_handlers_emit|declare the ErrKind in contract::taxonomy::declared_errors|-|openapi.json must be a PROJECTION of one declaration, never a hand-maintained parallel list'

  # ── E ── core route admission: one table, declared AT the mount. Enforced differently — there is
  #         no pattern to ban, because the hazard is a route mounted with no declared bar, and
  #         `CoreRouter::route` is the only way core routes reach a router and it cannot be called
  #         without one. The class test walks the resulting table and asserts the property over
  #         EVERY route, so a new route joins the assertion instead of escaping it.
  # ── F ── the trusted-upstream trust LIFECYCLE: one plane-neutral machine, the pinned artifact a
  #         type parameter. Enforced differently — the hazard is not a call somebody hand-rolls, it
  #         is a plane's VOCABULARY leaking into the machine, after which the sibling plane can no
  #         longer parameterise it and writes a parallel copy instead. The class test reads the
  #         module's own code and fails on any plane noun in it.
  'F-trust-lifecycle|TRUST-PLANE-LEAK|'"$CORE"'/trust/mod.rs (Approval / TrustState / Drift, generic over PinnedArtifact)|'"$CORE"'/trust/tests/genericity_tests.rs::the_lifecycle_names_no_plane_in_its_code|keep the plane noun in the artifact, the capability name or the caller, never in the lifecycle|-|the registry is being written generic on its FIRST build because there is no first use to extract a trait from later, so genericity has to be a test rather than a review habit'

  # -- G -- the same choke point from the OTHER side: a plane PARAMETERISES the lifecycle, it never
  #         re-declares one. F stops a plane's vocabulary leaking INTO the machine; this stops a copy
  #         of the machine leaking OUT into a plane. Enforced differently, for the same reason F is:
  #         the hazard is a declaration, not a call somebody hand-rolls. The class test reads the
  #         plane's own production code and fails on any re-declaration of the machine's types or
  #         verbs.
  'G-trust-parameterised|TRUST-MACHINE-FORK|'"$CORE"'/a2a/pin.rs (CardPin, the artifact, plus the one plane-specific refusal)|'"$CORE"'/a2a/tests/reuse_tests.rs::the_a2a_plane_declares_no_trust_state_of_its_own|supply an artifact implementing trust::PinnedArtifact; never re-declare TrustState, Drift, Approval or their verbs|-|two planes carrying two copies of one lifecycle disagree the first time either copy is fixed, and the disagreement surfaces as a registration dispatch serves while the operator view calls it quarantined'

  # ── H ── THE OPERATOR-AUTHORED ASK: one origin for the bytes busbar puts its own name to. This is
  #         the second half of a two-part control whose first half is in the TYPE SYSTEM, and neither
  #         half is a source scan — which is the point, because the source scan it replaces
  #         (`tests/callerask_tests.rs::callerask_names_nothing_upstream_derived`) grepped a file
  #         path that is being deleted.
  #
  #         HALF ONE, the compiler: `CallerAsk` lives in the private `callerask::authored` module
  #         with all three fields private to it and exactly one constructor, `from_config(&str,
  #         &AskEntryCfg)`. Nothing in the crate can build a `CallerAsk` from anything else — no
  #         struct literal, no `From` impl, no field assignment. The invariant is unrepresentable
  #         rather than merely untested.
  #
  #         HALF TWO, this row: that leaves `AskEntryCfg` itself as the way in. An `AskEntryCfg`
  #         is DESERIALISED from the operator's YAML (or from the admin write path, which validates
  #         identically); it is never assembled at runtime. A hand-built one is how upstream text
  #         would reach `params` after half one closed every other door, and the resulting ask would
  #         be busbar demanding authority from its own caller in busbar's name, on an upstream's
  #         behalf. Construction is therefore allowed only in the module that defines it.
  'H-operator-authored-ask|ASK-NOT-OPERATOR-AUTHORED|'"$CORE"'/mcp/config.rs (AskEntryCfg, deserialised from operator YAML) + '"$CORE"'/mcp/callerask.rs (the private `authored` module, sole constructor)|'"$CORE"'/mcp/tests/callerask_tests.rs::the_asks_params_are_the_operators_bytes_and_nothing_else|let the operator write the ask: an AskEntryCfg is deserialised, never assembled|AskEntryCfg[[:space:]]*\{>>an AskEntryCfg built in code rather than deserialised from operator configuration>>'"$CORE"'/mcp/config.rs|the text and schema a caller is shown when busbar asks it to confirm something must be bytes the operator wrote; the moment a value can flow from an upstream response into that ask, busbar is laundering an upstream demand for authority under its own name'

  # ── I ── THE ONE TRUST COMPARISON, negative half. `Approval::serves` is the single answer to "may
  #         this upstream serve this capability at this digest?" and invariant 9's census keeps it
  #         single. This row stops the other shape of the same defect: not a second `fn serves`, but
  #         a call site re-deriving the answer INLINE from the raw registration fields, which is what
  #         the deleted `the_catalogue_holds_no_second_may_this_serve_comparison` scanned
  #         `mcp/catalogue.rs` for. Its banned spellings are kept verbatim, and they are kept because
  #         the fields are still there: `catalogue.rs` still carries `schema_hash: Option<String>`,
  #         so `schema_hash.is_some()` is still exactly the convenience somebody would reach for.
  #         `Approval`'s own `pin` is private to `trust/mod.rs`, so `.pin.is_none()` outside it is
  #         either a second copy of the machine or a plane-local pin field pretending to be one.
  #         Both are the fail-OPEN divergence: one copy gets fixed and the other does not, and it
  #         surfaces as a call that served after the operator quarantined the upstream.
  'I-trust-serve-derivation|TRUST-COMPARISON-BYPASS|'"$CORE"'/trust/mod.rs (Approval::serves)|'"$CORE"'/mcp/tests/trust_gate_tests.rs::the_routed_gate_answers_exactly_what_the_deleted_inline_decision_answered|ask crate::trust::Approval::serves; never re-derive the answer from the raw registration fields|schema_hash[[:space:]]*\.is_some>>an inline "is there an approved digest?" test;schema_hash[[:space:]]*\.is_none>>an inline "is there no approved digest?" test;\.pin[[:space:]]*\.is_some>>an inline "is this upstream pinned?" test>>'"$CORE"'/trust/mod.rs;\.pin[[:space:]]*\.is_none>>an inline "is this upstream unpinned?" test>>'"$CORE"'/trust/mod.rs|a second answer to "may this serve?" diverges from the first the moment either is fixed, and the divergence is discovered as an in-flight call that served after the operator revoked it'

  # ── J ── A DECISION MADE AT OPEN AND TRUSTED WHILE OPEN. Enforced differently, and the reason is
  #         the reason F and G are: the hazard is a FIELD, not a call somebody hand-rolls. A
  #         `GovCtx` — or the `Arc<VirtualKey>` inside one — carried into a `'static` future is an
  #         identity resolved once and believed for the whole life of the response, and it looks
  #         exactly like every other captured value at the call site.
  #
  #         MEASURED, and this is why the row exists: `subscriptions/listen` re-read the CATALOGUE
  #         from the live handle on every 250ms poll and carried the KEY from open. So a revoked
  #         approval bit within one poll and a key deleted for compromise did not bite at all — and
  #         the module's own comment read as though it re-checked the grant, because it re-checked
  #         the half it could see. `crate::trust::validate::Standing` is the owner: it holds the
  #         principal's ID and re-resolves it from the live registry, which is an in-memory index
  #         read and therefore affordable four times a second.
  #
  #         THE CLASS PERMITS TWO STATES, re-resolve or freeze-and-disclose, and the class test
  #         requires every long-lived response to be in one of them. The second state is a judgement
  #         rather than a loophole: the detached MCP task runner charges its caller once at creation,
  #         so re-resolving mid-run would re-derive a grant against a settled charge. It therefore
  #         freezes, and it names `TASK_TTL_MS` in the same doc comment — a bound nobody wrote down
  #         is a bound the next edit raises.
  'J-standing-permission|OPEN-AND-TRUSTED|'"$CORE"'/trust/validate.rs (Standing::opened / still_permitted)|'"$CORE"'/trust/tests/validate_tests.rs::the_long_lived_response_holds_no_principal_it_resolved_at_open|hold a trust::validate::Standing and re-resolve the principal per frame; if you must freeze it, disclose the freeze beside the bound it trades on|-|a principal resolved at open and carried into a long-lived response is an identity a revocation cannot reach, and the failure is silent because everything else about the response is re-derived correctly'

  'E-core-route-auth|ROUTE-AUTH-BYPASS|'"$CORE"'/core_routes.rs (CoreRouter::route / CoreRouteTable::declared_auth)|'"$CORE"'/auth/tests/tests.rs::test_mcp_token_is_confined_to_the_mcp_plane|mount core routes through core_routes::CoreRouter::route, which takes the RouteAuth with the handler|-|a route whose admission bar lives in the middleware rather than at the mount is a bar that drifts, and a per-process bypass leaks onto planes that never mount the route'
)

hdr "choke-point registry (every hazard class has ONE owner; no hand-rolled bypass)"
ck=0
for row in "${CHOKE_POINTS[@]}"; do
  IFS='|' read -r cp_id cp_tag cp_owner cp_test cp_remedy cp_rules cp_why extra <<<"$row"

  # (0) ROW INTEGRITY. `|` is the field separator, so a `|` that leaks into a rule's ERE silently
  #     shifts every field right: the pattern gets truncated, the allowed-exception list empties, and
  #     the OWNER file starts reporting itself as a bypass. That is a lint that lies, so it is a hard
  #     error. Write alternation as a character class (`sync_[ad]`) or as a second `;` rule.
  if [ -n "$extra" ] || [ -z "$cp_why" ] || [ -z "$cp_rules" ]; then
    note "MALFORMED-ROW: ${cp_id} — a field contains a literal '|' (the row separator). Rewrite the"
    note "  pattern without alternation, or split it into another ';'-separated rule."
    fail=1; ck=1
    continue
  fi

  # (i) the class-level test must exist. A choke point whose one class test was deleted or renamed
  #     is a choke point nothing proves; the contract requires the pair, so the lint requires it too.
  cp_test_file="${cp_test%%::*}"; cp_test_fn="${cp_test##*::}"
  if [ ! -f "$cp_test_file" ]; then
    note "MISSING-CLASS-TEST: ${cp_id} — ${cp_test_file} does not exist (${cp_why})"
    fail=1; ck=1
  elif ! grep -qE "fn[[:space:]]+${cp_test_fn}[[:space:]]*\(" "$cp_test_file"; then
    note "MISSING-CLASS-TEST: ${cp_id} — ${cp_test_file} has no \`fn ${cp_test_fn}\` (${cp_why})"
    fail=1; ck=1
  fi

  # (ii) no production file outside the allowed exceptions may hand-roll a bypass.
  [ "$cp_rules" = "-" ] && continue                  # differently-enforced (see the header note)
  IFS=';' read -r -a rules <<<"$cp_rules"
  for rule in "${rules[@]}"; do
    # `pat>>what>>allow` → collapse the `>>` separators to a single `>` and split on it.
    IFS='>' read -r LINT_PAT LINT_WHAT rule_allow LINT_UNLESS <<<"${rule//>>/>}"
    export LINT_PAT LINT_WHAT LINT_UNLESS
    # An allowed-exception path names the file that OWNS the correct implementation. If it moved,
    # the row is pointing at nothing: the ban silently widens to cover the owner's new home, and the
    # first thing that breaks is the owner reporting itself as a bypass — a lint that lies. Say so
    # here, where the fix is one path, rather than there, where it reads as a real violation.
    if [ -n "$rule_allow" ]; then
      IFS=',' read -r -a cp_allowlist <<<"$rule_allow"
      for p in "${cp_allowlist[@]}"; do
        if [ ! -e "$p" ]; then
          note "ALLOWED-PATH-MISSING: ${cp_id} — \`${p}\` does not exist; point the row at the owner's new home"
          fail=1; ck=1
        fi
      done
    fi
    files=()
    for f in "${CANDIDATES[@]}"; do
      case ",${rule_allow}," in *",${f},"*) continue ;; esac   # the owner / definer files
      files+=("$f")
    done
    [ ${#files[@]} -eq 0 ] && continue
    hits=$(scan_rule "${files[@]}")
    if [ -n "$hits" ]; then
      while IFS= read -r h; do note "${cp_tag}: $h — ${cp_remedy}"; done <<<"$hits"
      fail=1; ck=1
    fi
  done
done
unset LINT_PAT LINT_WHAT LINT_UNLESS
[ "$ck" -eq 0 ] && note "ok (${#CHOKE_POINTS[@]} choke points registered, class tests present, no bypass)"

# ══ Invariant 5: THE REQUEST PATH DOES NOT TOUCH THE STORE (GOAL §A7) ════════════════════════════
#
# `GovState::try_admit` makes ZERO store calls. The store is a DURABILITY SINK — the ledger flushes
# to it behind the request — and it is never on the path a request waits on. That is not a nicety:
# every published latency number depends on it, and the function's own doc comment states it
# ("SYNCHRONOUS and INFALLIBLE (in-memory cells; no store round-trip, no await)").
#
# It was true on the day this check was written and NOTHING ENFORCED IT. A doc comment is not an
# enforcement mechanism; the first `self.store.get_…()` added inside the admission path to answer
# "what was this key's spend yesterday?" would be correct-looking, would pass every test, and would
# put a network round-trip under every admitted request.
#
# WHY A FUNCTION-SCOPED RULE AND NOT A CHOKE POINT ROW: the choke-point registry bans a pattern
# TREE-WIDE with a list of allowed files. Here the same call is entirely legitimate one function
# further down the same file — `flush_durable` exists to make store calls. The unit of the rule is
# the function, so the rule needs `scan_fn_body`, not `scan_rule`.
#
# ── Row format (fields separated by `|`) ─────────────────────────────────────────────────────────
#   1. id       — stable name for the invariant.
#   2. tag      — the violation label.
#   3. file     — the file holding the function.
#   4. fn       — the function name, as an awk ERE fragment (usually a literal).
#   5. rules    — `;`-separated `<awk-ERE>>><what it is>[>><unless-ERE>]`.
#   6. remedy   — the one-line instruction printed with every violation.
#   7. why      — one line: why this function in particular may not do that.
REQUEST_PATH=(
  # `store` / `Store` as a WHOLE WORD, so `restore_from_store` and `store_id` do not trip it while
  # `self.store`, `store.get(`, `&dyn Store` and `Store::` all do. Word boundaries are spelled with
  # explicit non-identifier classes because `\b`/`\<` are not portable across the awks this script
  # runs on, and the mid-line and end-of-line cases are two rules because `|` is the row separator
  # (see MALFORMED-ROW below). A line inside a function body always has leading whitespace, so the
  # start-of-line case cannot arise. `.await` rides the same row because it is the same invariant
  # seen from the other side: the reason the store may not appear here is that nothing on this path
  # may suspend, and an `.await` is how a round-trip gets in.
  'A7-govstate-try-admit|STORE-ON-REQUEST-PATH|'"$CORE"'/governance/state.rs|try_admit|[^A-Za-z0-9_][Ss]tore[^A-Za-z0-9_]>>a store reference inside the admission path;[^A-Za-z0-9_][Ss]tore$>>a store reference inside the admission path;\.await>>an await inside the admission path (it is declared SYNCHRONOUS and INFALLIBLE)|keep the store off this path: admission reads in-memory cells only, and durability is flushed BEHIND the request (governance::state::flush / the ledger sink), never in front of it|the store is a durability sink, never on the request path — every latency figure busbar publishes is measured on an admission that does no I/O'
  # THE PROTOCOL LOOKUP ALLOCATES NOTHING. `decl_for` is the one by-name protocol resolution in
  # busbar and it is called several times per request, by each layer that resolves the protocol it
  # needs from a name string. The `match` it replaced returned an OWNED `Protocol` and therefore
  # allocated a `Box<dyn ProtocolReader>` + a `Box<dyn ProtocolWriter>` on EVERY call — including
  # the many calls that only wanted a `&'static` constant off the declaration. Everything reachable
  # through a `ProtocolDecl` is `&'static`, so this function has no legitimate reason to allocate,
  # own a string, or suspend; a row here fails on the day one of those appears rather than on the
  # day somebody profiles it. `Box::new`/`Vec::`/`to_string`/`String::` are the three ways the old
  # cost could come back, and `.await` rides along for the same reason it does above.
  'A8-protocol-decl-for|ALLOC-ON-PROTOCOL-LOOKUP|'"$CORE"'/proto/registry.rs|decl_for|Box::new>>a box allocated while resolving a protocol name;Vec::>>a vector allocated while resolving a protocol name;to_string>>an owned string allocated while resolving a protocol name;String::>>an owned string allocated while resolving a protocol name;\.await>>an await inside the by-name protocol lookup|read the `&'"'"'static` declaration and hand it back: every fact on a `ProtocolDecl` is a constant the protocol declared, so nothing on this path needs to be built|it is called several times per request, and the match it replaced allocated two vtable boxes on every call to answer a static question'
)

# ══ THE FUNCTION-SCOPED RULE RUNNER ══════════════════════════════════════════════════════════════
#
# Invariants 5 and 8 are the same SHAPE — "this call appears nowhere inside THIS function" — over
# two different subjects, so they share one runner rather than two copies of a forty-line loop that
# would drift the first time either was fixed. It sets `fail` directly, which is why it is called
# plainly and never on the right-hand side of a pipe: a subshell's `fail=1` dies with the subshell.
#
# `$1` is the noun for the closing ok-line; the rest are rows in the format documented above.
run_fn_scoped() {
  local label="$1"; shift
  local rp=0 row rp_id rp_tag rp_file rp_fn rp_rules rp_remedy rp_why extra rp_span rule hits out s
  local -a rp_rulelist
  local n_rows=$#
  for row in "$@"; do
  IFS='|' read -r rp_id rp_tag rp_file rp_fn rp_rules rp_remedy rp_why extra <<<"$row"
  if [ -n "$extra" ] || [ -z "$rp_why" ] || [ -z "$rp_rules" ]; then
    note "MALFORMED-ROW: ${rp_id} — a field contains a literal '|' (the row separator). Rewrite the"
    note "  pattern without alternation, or split it into another ';'-separated rule."
    fail=1; rp=1
    continue
  fi
  # The subject must EXIST. A rule pointed at a file that was moved, or a function that was renamed,
  # scans nothing and prints nothing — which reads exactly like a pass. It is not one.
  if [ ! -f "$rp_file" ]; then
    note "SUBJECT-MISSING: ${rp_id} — ${rp_file} does not exist; point the row at the function's new home"
    fail=1; rp=1
    continue
  fi
  IFS=';' read -r -a rp_rulelist <<<"$rp_rules"
  rp_span=""
  for rule in "${rp_rulelist[@]}"; do
    IFS='>' read -r LINT_PAT LINT_WHAT LINT_UNLESS <<<"${rule//>>/>}"
    export LINT_PAT LINT_WHAT LINT_UNLESS
    RP_FN="$rp_fn"; export RP_FN
    out=$(scan_fn_body "$rp_file")
    rp_span=$(printf '%s\n' "$out" | grep '^#SPAN ' || true)
    hits=$(printf '%s\n' "$out" | grep -v '^#SPAN ' | grep -v '^$' || true)
    if [ -n "$hits" ]; then
      while IFS= read -r h; do note "${rp_tag}: $h — ${rp_remedy}"; done <<<"$hits"
      fail=1; rp=1
    fi
  done
  if [ -z "$rp_span" ]; then
    note "SUBJECT-MISSING: ${rp_id} — ${rp_file} declares no \`fn ${rp_fn}\`, so this invariant scanned"
    note "  NOTHING and would have reported a pass. Point the row at the function's new name (${rp_why})."
    fail=1; rp=1
  else
    while IFS= read -r s; do
      set -- $s
      note "scanned ${rp_file}::${rp_fn} lines $2-$3 ($(( $3 - $2 + 1 )) lines)"
    done <<<"$rp_span"
  fi
  done
  unset LINT_PAT LINT_WHAT LINT_UNLESS RP_FN
  # A table that ran zero rows would print the same ok-line a clean run prints. It is not clean, it
  # is unarmed — the same false green the SUBJECT-MISSING arms above exist to refuse.
  if [ "$n_rows" -eq 0 ]; then
    note "NO-ROWS: the ${label} table is empty, so this invariant scanned NOTHING"
    fail=1; rp=1
  fi
  if [ "$rp" -eq 0 ]; then note "ok (${n_rows} ${label} enforced)"; fi
}

hdr "request-path purity (the store is a durability sink, never on the request path)"
run_fn_scoped "request-path invariant(s)" "${REQUEST_PATH[@]}"

# ══ Invariant 8: A DECISION NEVER READS ATTACKER-AUTHORED TEXT ════════════════════════════════════
#
# WHAT THIS REPLACES, and why the replacement is shaped differently. Until 2026-08-12 this invariant
# was `mcp/client/tests/routing_key_tests.rs::dispatch_never_reads_a_tool_description`: a test that
# `include_str!`-ed `client/dispatch.rs` and failed on the word `description` in any code line, with
# a companion (`the_description_scan_would_catch_a_violation`) proving the predicate bit. It was a
# good check with one fatal property: its SUBJECT was a file path, and `mcp/` is being deleted and
# rebuilt. A test whose subject stops existing does not fail — it stops being compiled, and an
# absent control has no failing test.
#
# THE INVARIANT ITSELF IS NOT GOING ANYWHERE: a route is decided on BOUND IDENTITY — registered
# server, namespaced tool, approved digest — and never on an upstream's free text. An upstream
# rewrites its own description at will; a router that reads one is a router the upstream steers,
# which is the confused-deputy half of every MCP tool-poisoning writeup. Moving it here does not make
# it path-independent, but it makes the path a DECLARED FACT that goes RED when it is wrong: point a
# row at a file that moved, or a function that was renamed, and `run_fn_scoped` prints
# SUBJECT-MISSING and fails. The rebuild cannot take this control out of the tree by accident; it can
# only take it out by editing a row that is telling it not to.
#
# WHY FUNCTION-SCOPED AND NOT A TREE-WIDE BAN: `description` is a legitimate word almost everywhere.
# The catalogue stores one, the admin projection renders one, the listing publishes the OPERATOR's
# one. It is illegitimate in exactly one place — the code that decides WHERE A CALL GOES — and the
# unit of that rule is the function.
#
# Same row format as REQUEST_PATH above; same runner.
DECISION_INPUT=(
  # The three functions that turn a caller's request into a destination, or decide what a caller is
  # allowed to see. `resolve` maps a namespaced name to a bound identity, `revalidate` re-checks that
  # identity against the live snapshot immediately before the call goes out, and `visible_catalogue`
  # decides which capabilities a caller is shown. None of the three may consult free text.
  'B10-routing-reads-no-description|DESCRIPTION-ON-ROUTING-PATH|'"$CORE"'/mcp/client/dispatch.rs|resolve|description>>a tool description read while deciding a route|route on the bound identity alone — registered server, namespaced tool, approved digest — and never on text the upstream authors|an upstream rewrites its own description at will, so a router that reads one is a router the upstream steers'
  'B10-revalidate-reads-no-description|DESCRIPTION-ON-ROUTING-PATH|'"$CORE"'/mcp/client/dispatch.rs|revalidate|description>>a tool description read while re-validating a route|re-validate on the bound identity and the snapshot generation, never on text the upstream authors|the pre-dispatch re-check is the last gate an in-flight call passes; a hostile description reaching it would undo the resolve-time rule one line before the call goes out'
  'B10-visibility-reads-no-description|DESCRIPTION-ON-ROUTING-PATH|'"$CORE"'/mcp/client/dispatch.rs|visible_catalogue|description>>a tool description read while deciding what a caller may see|filter the catalogue on the caller grant and the approval, never on text the upstream authors|what a caller is shown is an authorisation answer, and an upstream that could influence it would be choosing its own audience'
)

hdr "decision-input purity (a routing decision never reads attacker-authored text)"
run_fn_scoped "decision-input invariant(s)" "${DECISION_INPUT[@]}"

# ══ Invariant 6: NO PLANE-LOCAL REIMPLEMENTATION OF A SHARED CONCERN (GOAL §A6) ══════════════════
#
# THE RULE: a property that holds on one plane holds on all of them, or the difference is written
# down and defended. Three of this release's security defects came from one concern implemented two
# or three times — one copy gets fixed, the other does not, and the divergence surfaces as a hole.
#
# THE MECHANISM, and it is deliberately mechanical rather than clever. Two signals, both of them
# facts about the source and neither of them a judgement call:
#
#   SYMBOL — the same TOP-LEVEL name (a free `fn`, or a `struct`/`enum`/`trait`) declared in two
#            planes. Top-level is what makes this usable: methods inside `impl` blocks are scoped by
#            their type, so `new`, `fmt`, `len` and `default` never reach the comparison. A free
#            `fn compute_hash` in `mcp/` and a free `fn compute_hash` in `a2a/` is two authors
#            naming the same idea at file scope, twice.
#   MODULE — the same file name in two planes. A concern can be duplicated without one name
#            colliding; `mcp/config.rs` beside `a2a/config.rs` is the author's own statement
#            of which concern each file is. `mod.rs` is excluded — it names a directory, not an idea.
#
# COMMENTS ARE NOT DECLARATIONS, and that is load-bearing here. GOAL §A6.1 records that the circuit
# breaker is NOT duplicated: there is exactly one `try_admit_breaker`, and the `breaker` mentions
# under `mcp/` and `a2a/` are PROSE IN COMMENTS. A grep-for-the-word lint would have reported a
# duplicate breaker and been wrong. This one reads declarations, through TEST_SCOPE_AWK, so prose
# and `#[cfg(test)]` code are both invisible to it.
#
# ── THE LEDGER, and why the lint ships with one ──────────────────────────────────────────────────
# Every row below is duplication that EXISTS TODAY. The lint was proven red against exactly this
# list before the list was written (see the commit message); the ledger records the debt so `dev` is
# green while the unification is done concern by concern, and so a SEVENTH duplicate cannot be added
# quietly. Two rules make it a ledger and not an amnesty:
#
#   * A ledger row that no longer matches is a HARD ERROR ("STALE-LEDGER"), so the row cannot rot,
#     and the moment a unification lands the lint tells you to delete its row.
#   * ADDING a row for NEW code is not a fix, it is evading the check. Shrinking is the only
#     permitted edit, exactly as for GRANDFATHERED_OVERSIZED above.
#
# Class `DEBT` is duplication that is owed a unification, and its concern id names what is owed.
# Class `DISTINCT` is a name two unrelated concerns happen to share; it must still be written down,
# because "these two are unrelated" is a claim, and an undocumented one is indistinguishable from
# duplication nobody noticed.
#
# Row format:  <symbol-or-module> | DEBT|DISTINCT | <concern id, or - for DISTINCT> | <note>
PLANE_ROOTS="mcp=${CORE}/mcp a2a=${CORE}/a2a"

# The concerns, and where each one's single implementation should end up. `-` for an owner means
# THERE IS NO SHARED HOME YET, which is itself the finding: the concern has only plane-local copies.
# RETIRED 2026-08-13: `guarded-fetch`. The unification it named is DONE and was done by an earlier
# unit: `crate::net_guard` owns the strict URL recogniser, the scheme judgement, the structural name
# refusals, EXACTLY ONE resolution, the judgement of every answered address, the pin, the redirect
# refusal, the hop bound and the body cap, and both planes reach it through thin wrappers that keep
# only their own WORDING (`mcp/client/ssrf.rs`, `a2a/fetch.rs`). Its last row, `transport.rs`, turned
# out not to be a second guarded fetch at all: the two files sit at DIFFERENT LAYERS and share no
# operation, which is what the DISTINCT row below records and why the row was reclassified rather
# than paid. Deleted rather than left with an empty row list, for the reason the `ingress` note
# gives.
# RETIRED 2026-08-13: `trust-pinning`. It owned ONE row — `declared_pin` — and GOAL §A2.2 scoped it
# as "resolve the bare-name collision, then parameterise the one trust lifecycle". Both halves are
# done: the bare name is gone from both planes, and `crate::trust::declared` now owns the SEQUENCE a
# declaration is read in (is the mechanism a root at all, then is the material actually there) while
# a plane supplies one `Declares` impl — its mechanism type, which of them are roots, and its
# artifact for each reading. The blank-key refusal was MCP's alone before the move and is now both
# planes', which is a narrowing. `a_third_plane_costs_one_declares_impl_and_nothing_else` drives the
# whole reader from a plane busbar does not have. Deleted rather than left with an empty row list,
# for the reason the `ingress` note below gives.
# RETIRED 2026-08-13: `ingress`. It owned FIVE rows — `rpc`, `refuse`, `not_found`, `metadata` and
# the `ingress.rs` module itself — and it is the first concern to empty. `crate::ingress::protocol`
# now owns the sequence (nine of the thirteen steps two JSON-RPC ingresses ran between them, five
# of which `ingress/jsonrpc.rs` had already taken); a protocol supplies a `Words` impl, its RFC 9728
# facts and its verb dispatch. Neither plane has an ingress module any more: `mcp/envelope.rs` is
# this revision's envelope rules and `a2a/receive.rs` is that plane's receiving hot path, which is
# what each was always about once the ingress left. The concern is deleted rather than left with an
# empty row list, because a concern with nothing owed is a heading somebody adds a row under.
# RETIRED 2026-08-14: `plane-config`. It owned ONE row — `config.rs` — and the row was TWO claims
# wearing one name. The first was real and is now PAID: the section SPLIT (refuse a reserved key
# holding a mapping BEFORE the typed lifts, lift `hooks`, lift `upstream_credentials`, then walk the
# remainder refusing a reserved NAME, parse, run the plane's value rules) was written THREE times —
# `config/mod.rs`'s `PoolsCfg`, `mcp/config.rs`'s `ToolsCfg`, `a2a/config.rs`'s `AgentsCfg` — and is
# now `crate::plane::config::split_section`, which owns the ORDER and every SENTENCE while a plane
# supplies only which plane it is, the type one registration parses into and its own value rules.
# The reserved word space went the same way: one declaration, aliased nowhere, so the two per-plane
# constants and the two tests that compared them are gone. The second claim was that a shared
# FILENAME is a shared concern, and it is not — see the DISTINCT row below, which is what is left
# once the duplication is actually gone. Deleted rather than left with an empty row list, for the
# reason the `ingress` note gives.
PLANE_CONCERNS=(
  'outbound-credentials|'"$CORE"'/egress_auth|one lease/mint with the grant kinds as parameters, not a copy per plane'
  'metering|'"$CORE"'/governance|one attribution + admission, taken from governance rather than restated per plane'
  'plane-admin-verbs|'"$CORE"'/admin|one admin verb surface parameterised by plane, not one handler set per plane'
)

PLANE_LEDGER="
config.rs|DISTINCT|-|The parse ORDER these two files shared is gone: plane::config::split_section owns the reserved-key refusals, the two typed lifts and the sequence they run in, and all THREE plane sections (pools:, tools:, agents:) are read through it, so the pre-lift refusal cannot be present on one plane and missing on another. What is left in each file is that plane's GRAMMAR and nothing else. mcp/config.rs declares tools: a stdio/http/sse transport, a spawned child's environment and argv, an OAuth token exchange, the tools_allow, prompts and resources maps, and the server-underscore-tool published-name collision check. a2a/config.rs declares agents: a four-mechanism card pin, busbar's own client TLS identity, a re-verification cadence with a recovery backoff, and the refusal of upstream_credentials: passthrough. They share no type, no field, no value rule, no sentence and no caller; what they share is a filename, which on every plane says the same true and un-actionable thing - this is where that section's grammar is written. Renaming either would move the noun without moving a decision, which is why this is a signed claim and not a rename.
transport.rs|DISTINCT|-|mcp/client/transport.rs is JSON-RPC FRAMING on one carrier: it composes a POST from a WireLeg, classifies the server-originated frames on an SSE answer and reduces that answer to its last data payload. It builds no client, resolves no name and pins no address — it asks super::pool for both. a2a/transport.rs is CLIENT CONSTRUCTION: it pins the host to the address net_guard already judged, replaces the client's resolver with one that refuses every name, offers busbar's client certificate and reads the peer SPKI off the accepted handshake. It frames nothing and parses no JSON-RPC. Two LAYERS, one noun — MCP's counterpart of the second is mcp/client/pool.rs and A2A's counterpart of the first is a2a/relay.rs, and neither pair collides. The guarded-fetch decision the row was opened for is already net_guard's on both planes: one resolver, one pin, one redirect refusal, one body cap.
judge|DISTINCT|-|mcp/client/argguard.rs judges whether an ARGUMENT is a URL-ish SSRF hazard; a2a/registry.rs judges whether an AGENT CARD matches a task shape. Same verb, unrelated subjects.
revalidate|DISTINCT|-|mcp/client/dispatch.rs re-checks a catalogue GENERATION before dispatch; a2a/pushnotify.rs re-resolves a pinned CALLBACK's DNS answer. Both re-check something pinned, but neither shares an input, an output or a failure mode with the other.
Transport|DISTINCT|-|mcp/config.rs is a config ENUM naming stdio/http/sse; a2a/fetch.rs is a TRAIT abstracting the HTTP client for tests. Unrelated shapes that share a noun.
"

# `plane_dup_*` are pure functions of the tree; this walks their output against the ledger.
# `$1` = what kind of duplicate ("symbol"/"module"), stdin = the table. It is called with its input
# REDIRECTED rather than piped, so it runs in this shell and its `fail=1` survives; the same loop on
# the right-hand side of a pipe would set `fail` in a subshell and the violation would vanish.
check_plane_dups() {
  local kind="$1" sym where row class concern note_txt owner remedy
  while IFS=$'\t' read -r sym where; do
    [ -z "$sym" ] && continue
    printf '%s\n' "$sym" >> "$PLANE_SEEN"
    row=$(printf '%s\n' "$PLANE_LEDGER" | grep "^${sym}|" || true)
    if [ -z "$row" ]; then
      note "PLANE-DUPLICATE (${kind}): \`${sym}\` — ${where}"
      printf 'x\n' >> "$PLANE_UNLEDGERED"
      fail=1; pl=1
      continue
    fi
    IFS='|' read -r _ class concern note_txt <<<"$row"
    case "$class" in
      DEBT)
        if ! printf '%s\n' "${PLANE_CONCERNS[@]}" | grep -q "^${concern}|"; then
          note "MALFORMED-LEDGER: \`${sym}\` names concern \`${concern}\`, which is not in PLANE_CONCERNS"
          fail=1; pl=1
          continue
        fi
        owner=$(printf '%s\n' "${PLANE_CONCERNS[@]}" | grep "^${concern}|" | cut -d'|' -f2)
        remedy=$(printf '%s\n' "${PLANE_CONCERNS[@]}" | grep "^${concern}|" | cut -d'|' -f3)
        [ "$owner" = "-" ] && owner="NO SHARED HOME YET"
        printf '%s|%s|%s|%s|%s\n' "$concern" "$sym" "$where" "$owner" "$remedy" >> "$PLANE_DEBT"
        ;;
      DISTINCT) : ;;
      *)
        note "MALFORMED-LEDGER: \`${sym}\` has class \`${class}\`; it must be DEBT or DISTINCT"
        fail=1; pl=1
        ;;
    esac
  done
}

hdr "plane coherence (no plane-local reimplementation of a shared concern)"
pl=0
PLANE_TMP=$(mktemp -d); PLANE_SEEN="$PLANE_TMP/seen"; PLANE_DEBT="$PLANE_TMP/debt"
PLANE_UNLEDGERED="$PLANE_TMP/unledgered"
: > "$PLANE_SEEN"; : > "$PLANE_DEBT"; : > "$PLANE_UNLEDGERED"
# shellcheck disable=SC2086  # PLANE_ROOTS is a deliberate `plane=dir` word list
check_plane_dups symbol < <(plane_dup_table   $PLANE_ROOTS)
# shellcheck disable=SC2086
check_plane_dups module < <(plane_dup_modules $PLANE_ROOTS)

# The remedy is printed ONCE per run rather than once per hit: a wall of repeated instructions is
# how a reader learns to scroll past the list instead of reading it.
if [ -s "$PLANE_UNLEDGERED" ]; then
  note "$(wc -l < "$PLANE_UNLEDGERED" | tr -d ' ') name(s) above are declared in two planes and are NOT on the ledger."
  note "  A shared concern grew a second, plane-local implementation — the shape that produced three of"
  note "  this release's security defects, because one copy gets fixed and the other does not."
  note "  HOW TO FIX, in order of preference:"
  note "    1. Move the one implementation to the concern's shared owner and call it from both planes."
  note "    2. Parameterise the shared one over the plane. The spine is ${CORE}/plane/mod.rs"
  note "       and choke points F and G above are the shape that already works."
  note "    3. If the two really are UNRELATED, add a DISTINCT row to PLANE_LEDGER in this script"
  note "       naming why — a one-line claim you are willing to sign, not a bare exemption."
  note "  Adding a DEBT row for NEW code is not a fix; it is evading the check. The ledger only shrinks."
fi

# THE LEDGER MAY NOT ROT, and it may not be sloppy either. A row for duplication that is no longer
# there is a row nobody will delete, and a ledger nobody prunes stops being a debt list and becomes a
# permanent exemption. A row with a missing field, or a second row for a name already listed, is a
# row that reads as an exemption while asserting nothing.
while IFS='|' read -r sym class concern note_txt extra; do
  [ -z "$sym" ] && continue
  if [ -n "$extra" ] || [ -z "$note_txt" ] || [ -z "$class" ]; then
    note "MALFORMED-LEDGER: \`${sym}\` — a row is \`name|DEBT-or-DISTINCT|concern-or-dash|why\`, four"
    note "  fields, and the WHY may not be empty. (A literal '|' in the note shifts every field.)"
    fail=1; pl=1
  fi
  if [ "$class" = "DISTINCT" ] && [ "$concern" != "-" ]; then
    note "MALFORMED-LEDGER: \`${sym}\` is DISTINCT, so its concern field must be \`-\`, not \`${concern}\`"
    fail=1; pl=1
  fi
  if [ "$(printf '%s\n' "$PLANE_LEDGER" | grep -c "^${sym}|")" -gt 1 ]; then
    note "MALFORMED-LEDGER: \`${sym}\` has more than one row; one name, one verdict"
    fail=1; pl=1
  fi
  if ! grep -qx "$sym" "$PLANE_SEEN"; then
    note "STALE-LEDGER: \`${sym}\` is on PLANE_LEDGER but is no longer duplicated across planes."
    note "  If you unified it — thank you — DELETE its row from PLANE_LEDGER in scripts/structure-lint.sh."
    fail=1; pl=1
  fi
done <<<"$PLANE_LEDGER"

# The debt is REPORTED, every run, grouped by concern. A debt list nobody prints is a debt list
# nobody pays; this is the §A6 catalogue, generated from the tree rather than transcribed from it.
if [ -s "$PLANE_DEBT" ]; then
  n_concerns=$(cut -d'|' -f1 "$PLANE_DEBT" | sort -u | wc -l | tr -d ' ')
  n_rows=$(wc -l < "$PLANE_DEBT" | tr -d ' ')
  note "known duplication, ledgered and owed a unification: ${n_rows} name(s) across ${n_concerns} concern(s)"
  while IFS= read -r c; do
    owner=$(grep "^${c}|" "$PLANE_DEBT" | head -1 | cut -d'|' -f4)
    remedy=$(grep "^${c}|" "$PLANE_DEBT" | head -1 | cut -d'|' -f5)
    note "  [${c}] shared owner: ${owner}"
    note "      remedy: ${remedy}"
    while IFS='|' read -r _ sym where _ _; do
      note "      · ${sym} — ${where}"
    done < <(grep "^${c}|" "$PLANE_DEBT")
  done < <(cut -d'|' -f1 "$PLANE_DEBT" | sort -u)
fi
rm -rf "$PLANE_TMP"
if [ "$pl" -eq 0 ]; then note "ok (no unledgered cross-plane duplication)"; fi

# ══ Invariant 7: NOTHING BRANCHES ON AN AXIS OUTSIDE THAT AXIS'S OWN ARMS ════════════════════════
#
# THE RULE, owner's ruling: an `if transport ==` outside a `proto/` arm, its handler and its codec
# means THE DESIGN FAILED AT THAT POINT — fix the model, not the protocol. The matrix is
# `protocol × operation × transport`; a cell of it is selected by lookup, never by a branch in the
# agnostic core. Every core-side decision a transport influences is a VTABLE fact, exactly as
# `ingress_is_eventstream()` and `has_model_in_url()` replaced `if ingress_protocol == "bedrock"`.
#
# WHY THIS EXISTS THE DAY THE AXIS DOES, and not later. `Transport` has ONE variant today, so a
# branch on it is trivially constant and a reviewer would wave it through — which is precisely when
# the first one gets written, and it is then load-bearing by the time a second variant makes it
# wrong. The lint costs nothing now and is the only thing that will be watching when `Stdio` and
# `Grpc` arm. `mcp/config.rs` is the exhibit: it already carries a `Some(Transport::Stdio)` branch
# guarding a supervisor that no dispatch arm can reach, which is what a transport question looks
# like when there is no axis to ask it on.
#
# WHY VALUE USE IS FINE AND ONLY COMPARISON IS BANNED: naming `Transport::Http` at an arrival is a
# STATEMENT OF FACT — an axum handler does know it is HTTP — and threading or labelling the value
# costs nothing later. Comparing it is what forks the core.
#
# THE OTHER TWO AXES ARE NOT ARMED HERE, deliberately and with the reason recorded rather than
# silently: `if protocol ==` and `match plane` are RED on `dev` today (the dialect branches in
# `proxy/hooks.rs` that U5 deletes, and `plane/mod.rs`'s dispatch). Arming them in this commit would
# either fail the gate or need an exemption list long enough to be an amnesty. They arm in their own
# units — U5/U6 — against a tree that can pass them. A row here is one line when that day comes.
#
# ── Row format (fields separated by `|`) ─────────────────────────────────────────────────────────
#   1. axis     — the axis's name (also the exception ledger's key).
#   2. tag      — the violation label.
#   3. scope    — the path prefix the axis GOVERNS. The matrix is busbar's, and the word "transport"
#                 is not: `plugin-loader` compares a plugin-ABI `transport` VERSION number, an
#                 unrelated noun that a type-blind grep cannot tell apart from the axis. Scoping by
#                 root is how PLANE_ROOTS answers the same question, and it is honest about the
#                 blind spot — narrowing the PATTERN instead would have quietly stopped catching
#                 `if transport ==`, which is the exact line this invariant exists to catch.
#   4. rules    — `;`-separated `<awk-ERE>>><what it is>`. NO `|` alternation: `|` is the row
#                 separator, so write alternatives as separate `;` rules.
#   5. allowed  — comma-separated path PREFIXES where a branch on this axis is legitimate: the
#                 axis's own module, the `proto/` arms, and the handlers that hold the codecs.
#   6. remedy   — the one-line instruction printed with every violation.
#   7. why      — one line: why the core may not ask this question.
#
# THE OPERATION AXIS ARMS IN 1.6.0, and it could only arm once the axis was SPLIT. It was thirteen
# flat variants, seven of them named for one protocol family's endpoints, and every `RequestHandler`
# carried a thirteen-arm `match` on it — so a rule banning "a match on the operation axis" outside
# the axis's own arms would have needed an allowlist the length of `handlers/`, which is an amnesty
# rather than a lint. `Operation` is now `Verb { op: OpShape, name }`: a protocol's verbs are rows in
# its OWN table (`handlers::Cell`) and the core decides on the SHAPE, which has exactly one
# comparison left in the whole tree and it is inside a protocol arm. So the row costs no exemptions,
# which is the bar the transport row set for itself.
AXIS_BRANCH=(
  'operation|OPERATION-BRANCH|'"$CORE"'/,'"$BIN"'/,'"$PROTO_ANTHROPIC"'/,'"$PROTO_MCP"'/,'"$PROTO_OPENAI_CHAT"'/,'"$PROTO_GEMINI"'/|[Oo]peration(\(\))?[[:space:]]*==>>a comparison against an operation;[Oo]peration(\(\))?[[:space:]]*!=>>a comparison against an operation;match[[:space:]]+[A-Za-z0-9_.:]*[Oo]peration(\(\))?[[:space:]]*\{>>a match on the operation axis;match[[:space:]]+[A-Za-z0-9_.:]*shape\(\)[[:space:]]*\{>>a match on the operation axis'"'"'s shape;matches!\([^)]*OpShape::>>a matches! on an operation shape;if[[:space:]]+let[[:space:]]+[A-Za-z0-9_:]*OpShape::>>an if-let on an operation shape;matches!\([^)]*Operation::>>a matches! on an operation verb|'"$CORE"'/operation.rs,'"$CORE"'/proto/,'"$CORE"'/handlers/,'"$PROTO_ANTHROPIC"'/,'"$PROTO_MCP"'/,'"$PROTO_OPENAI_CHAT"'/,'"$PROTO_GEMINI"'/|put the decision on the OperationHandler vtable, or ask the SHAPE a named question on `OpShape` (as `OpDispatch::wants_stream` asks `may_stream`); never ask an operation its identity in the agnostic core|`Operation` is the vocabulary the plugin ABI carries across a dlopen boundary, so a core that can compare one has learned a protocol'"'"'s method names and the deletion test fails on line one'
  'transport|TRANSPORT-BRANCH|'"$CORE"'/,'"$BIN"'/,'"$PROTO_ANTHROPIC"'/,'"$PROTO_MCP"'/,'"$PROTO_OPENAI_CHAT"'/,'"$PROTO_GEMINI"'/|[Tt]ransport(\(\))?[[:space:]]*==>>a comparison against a transport;[Tt]ransport(\(\))?[[:space:]]*!=>>a comparison against a transport;match[[:space:]]+[A-Za-z0-9_.:]*[Tt]ransport(\(\))?[[:space:]]*\{>>a match on the transport axis;matches!\([^)]*Transport::>>a matches! on a transport variant;if[[:space:]]+let[[:space:]]+[A-Za-z0-9_:]*Transport::>>an if-let on a transport variant|'"$CORE"'/transport.rs,'"$CORE"'/proto/,'"$CORE"'/handlers/,'"$PROTO_ANTHROPIC"'/,'"$PROTO_MCP"'/,'"$PROTO_OPENAI_CHAT"'/,'"$PROTO_GEMINI"'/|put the decision on the codec/writer vtable and let the framing answer it, or take the branch inside the proto arm that owns the wire; never ask the transport its identity in the agnostic core|the six LLM protocols are six dialects over one transport and A2A is one dialect over three, so a core that can see the transport forks three ways the moment the second one arms'
)

# THE EXCEPTION LEDGER. Same two rules as PLANE_LEDGER, for the same reason: a row that no longer
# matches is a HARD ERROR (a ledger nobody prunes becomes a permanent exemption), and ADDING a row
# for NEW code is evading the check rather than passing it. Shrinking is the only permitted edit.
# Row format:  <axis> | <file> | <why this one branch is allowed to exist, and when it goes>
# EMPTY, and it got here the way the rules say a row leaves: the branch went. The one row this
# ledger ever carried was `mcp/config.rs`'s `Some(Transport::Stdio)` — the pre-axis branch guarding a
# crash-loop supervisor with no dispatch arm to reach it. `Transport::Stdio` is now a real arm of the
# axis, `mcp/config.rs` asks the transport ONE question through a method on the type
# (`Transport::spawns_child`) instead of comparing it, and the supervisor has a production caller. A
# row is added here only by a change that cannot avoid a branch, and SHRINKING is still the only
# permitted edit.
AXIS_EXCEPTIONS="
"

hdr "axis purity (nothing branches on an axis outside that axis's own arms)"
ax=0
AX_TMP=$(mktemp -d); AX_HIT="$AX_TMP/exception_hit"; : > "$AX_HIT"
for row in "${AXIS_BRANCH[@]}"; do
  IFS='|' read -r ax_axis ax_tag ax_scope ax_rules ax_allow ax_remedy ax_why extra <<<"$row"
  if [ -n "$extra" ] || [ -z "$ax_why" ] || [ -z "$ax_rules" ] || [ -z "$ax_allow" ] || [ -z "$ax_scope" ]; then
    note "MALFORMED-ROW: ${ax_axis} — a field contains a literal '|' (the row separator). Rewrite the"
    note "  pattern without alternation, or split it into another ';'-separated rule."
    fail=1; ax=1
    continue
  fi
  # The allowed set must EXIST. A prefix pointing at a moved module silently widens the ban to a
  # legitimate arm — a lint that reports a violation where the design is correct teaches people to
  # add exceptions, which is worse than not having the lint.
  IFS=',' read -r -a ax_allowlist <<<"$ax_allow"
  # `scope` may be a comma-separated prefix list (both sides of the core/bin seam); every listed
  # prefix must exist, same rule as the census's.
  IFS=',' read -r -a ax_scopes <<<"$ax_scope"
  ax_scope_missing=0
  for sp in "${ax_scopes[@]}"; do
    if [ ! -e "$sp" ]; then
      note "SCOPE-MISSING: ${ax_axis} — \`${sp}\` does not exist; point the row at the axis's new root"
      fail=1; ax=1; ax_scope_missing=1
    fi
  done
  [ "$ax_scope_missing" -ne 0 ] && continue
  for p in "${ax_allowlist[@]}"; do
    if [ ! -e "$p" ]; then
      note "ALLOWED-PATH-MISSING: ${ax_axis} — \`${p}\` does not exist; point the row at the arm's new home"
      fail=1; ax=1
    fi
  done
  # The files in scope: every production .rs except the axis's own arms. Exception rows stay IN
  # scope on purpose — their hits are counted (so a stale row is detectable) and then suppressed.
  ax_files=()
  for f in "${CANDIDATES[@]}"; do
    in_scope=0
    for sp in "${ax_scopes[@]}"; do
      case "$f" in "$sp"*) in_scope=1; break ;; esac
    done
    [ "$in_scope" -eq 0 ] && continue
    skip=0
    for p in "${ax_allowlist[@]}"; do
      case "$f" in "$p"*) skip=1; break ;; esac
    done
    [ "$skip" -eq 0 ] && ax_files+=("$f")
  done
  if [ ${#ax_files[@]} -eq 0 ]; then
    note "NO-SUBJECT: ${ax_axis} — the allowed prefixes cover the whole tree, so this invariant scanned"
    note "  NOTHING and would have reported a pass. That is the false green, not a clean bill."
    fail=1; ax=1
    continue
  fi
  IFS=';' read -r -a ax_rulelist <<<"$ax_rules"
  for rule in "${ax_rulelist[@]}"; do
    IFS='>' read -r LINT_PAT LINT_WHAT LINT_UNLESS <<<"${rule//>>/>}"
    export LINT_PAT LINT_WHAT LINT_UNLESS
    hits=$(scan_rule "${ax_files[@]}" || true)
    [ -z "$hits" ] && continue
    while IFS= read -r h; do
      [ -z "$h" ] && continue
      hit_file="${h%%:*}"
      exc=$(printf '%s\n' "$AXIS_EXCEPTIONS" | grep "^${ax_axis}|${hit_file}|" || true)
      if [ -n "$exc" ]; then
        printf '%s|%s\n' "$ax_axis" "$hit_file" >> "$AX_HIT"
        continue
      fi
      note "${ax_tag}: $h — ${ax_remedy}"
      note "  (${ax_why})"
      fail=1; ax=1
    done <<<"$hits"
  done
done
unset LINT_PAT LINT_WHAT LINT_UNLESS

# The ledger may not rot, and it is REPORTED every run: a debt nobody prints is a debt nobody pays.
while IFS='|' read -r e_axis e_file e_why extra; do
  [ -z "$e_axis" ] && continue
  if [ -n "$extra" ] || [ -z "$e_why" ] || [ -z "$e_file" ]; then
    note "MALFORMED-LEDGER: \`${e_axis}|${e_file}\` — a row is \`axis|file|why\`, three fields, and the"
    note "  WHY may not be empty. (A literal '|' in the note shifts every field.)"
    fail=1; ax=1
    continue
  fi
  if ! grep -q "^${e_axis}|${e_file}$" "$AX_HIT" 2>/dev/null; then
    note "STALE-LEDGER: \`${e_file}\` is on AXIS_EXCEPTIONS for the ${e_axis} axis but no longer"
    note "  branches on it. If you removed the branch — thank you — DELETE its row from"
    note "  AXIS_EXCEPTIONS in scripts/structure-lint.sh."
    fail=1; ax=1
  else
    note "ledgered ${e_axis}-axis branch: ${e_file} — ${e_why}"
  fi
done <<<"$AXIS_EXCEPTIONS"
rm -rf "$AX_TMP"
if [ "$ax" -eq 0 ]; then
  note "ok (${#AXIS_BRANCH[@]} axis/axes enforced over ${#ax_files[@]} production file(s))"
fi

# ══ Invariant 9: THE DECLARATION CENSUS ═════════════════════════════════════════════════════════
#
# Every rule above this one is a BAN: "this pattern appears nowhere". A ban has a blind spot that
# this project has now been bitten by twice, and it is the same blind spot every time — a ban over a
# pattern that no longer exists scans the whole tree, matches nothing, prints nothing, and reads
# exactly like a clean bill of health. The bug is not in the scanner; it is that "zero" is the
# passing answer AND the answer you get when the subject is gone.
#
# A CENSUS fixes that by making the expected answer a NUMBER THAT IS NOT ZERO. Each row declares a
# pattern and how many production code lines must carry it. Too many is a duplicate — a second
# spelling of a wire word, a second implementation of a decision. Too few is the false green: the
# subject was renamed, moved, or deleted, and the row says so out loud instead of passing.
#
# WHAT THIS REPLACES. Three of the nine source-scanning tests under `mcp/` were census questions
# wearing a scan's clothes:
#
#   * `client/tests/wire_tests.rs::the_client_and_the_ingress_agree_on_every_wire_literal`
#     `include_str!`-ed `ingress.rs` and asserted the five shared wire words appeared in BOTH
#     directions' source. It was comparing two copies. The copies are gone — `client/jsonrpc.rs`
#     now `use`s the ingress's constants — so the question is no longer "do the two agree?" but
#     "is there still exactly one?", which is a census row and needs no file path at all.
#   * `tests/trust_gate_tests.rs::the_catalogue_holds_no_second_may_this_serve_comparison` had a
#     positive half — `assert_eq!(serves_calls, 1)` — asserting the dispatch gate had not been
#     routed somewhere else. Its negative half is choke point I below; this is the positive half,
#     asked of the DECLARATION rather than of one file's call sites, so it survives the rebuild.
#   * `tests/quarantine_boot_tests.rs::the_boot_path_starts_the_refresh_job` read `main.rs` looking
#     for the call that spawns the quarantine sweep, because `run()` binds real listeners and no
#     test can reach it. A sweep nothing spawns is a defence that does not run, and that was the
#     exact hole `mcp::connect::refresh` had when its only caller was a human pressing a button.
#
# THE TRAP THIS AVOIDS, the same one the rest of this script does: it counts CODE lines. Comments
# and `#[cfg(test)]` regions are invisible to `scan_rule`, so a doc comment quoting a wire word — and
# the ones above this line quote all five — is not a second spelling of it. A census that read raw
# text would report its own documentation as a duplicate.
#
# ── Row format (fields separated by `|`) ─────────────────────────────────────────────────────────
#   1. id      — stable name for the census question.
#   2. tag     — the violation label.
#   3. pattern — awk ERE, counted over production code lines. NO `|` alternation (row separator).
#   4. count   — the exact number of production code lines that must match. Never 0: a row whose
#                honest answer is zero is a BAN, and bans belong in the choke-point registry.
#   5. scope   — path prefix the census covers.
#   6. why     — one line: what a wrong count means.
DECLARATION_CENSUS=(
  # ── The five shared MCP wire words. One definition each, in `mcp/ingress.rs`; the outbound client
  #    imports them. A second occurrence is a second copy that can drift silently in the one
  #    direction no single-sided test can see — busbar refusing a request busbar sent. Zero
  #    occurrences means the word left the tree, which for a protocol constant is a rebuild that
  #    quietly stopped speaking the protocol.
  'wire-word-meta-protocol-version|WIRE-WORD-RESPELT|"io\.modelcontextprotocol/protocolVersion"|1|'"$CORE"'/,'"$BIN"'/|the `_meta` protocol-version key must have exactly one spelling in the tree: the ingress REQUIRES it and the client EMITS it, and two copies disagree in the direction where each side is internally consistent with itself'
  'wire-word-meta-client-capabilities|WIRE-WORD-RESPELT|"io\.modelcontextprotocol/clientCapabilities"|1|'"$CORE"'/,'"$BIN"'/|the `_meta` client-capabilities key is REQUIRED on the way in and written on the way out; a second copy is a request busbar would send and then refuse'
  'wire-word-header-protocol-version|WIRE-WORD-RESPELT|"mcp-protocol-version"|1|'"$CORE"'/,'"$BIN"'/|the protocol-version header name is read by the ingress and written by the client from one constant; a second literal is the drift the deleted symmetry test existed to catch'
  'wire-word-header-method|WIRE-WORD-RESPELT|"mcp-method"|1|'"$CORE"'/,'"$BIN"'/|the method-mirror header name is required inbound and emitted outbound from one constant'
  'wire-word-header-name|WIRE-WORD-RESPELT|"mcp-name"|1|'"$CORE"'/,'"$BIN"'/|the target-name header is required inbound on the three addressed methods and emitted outbound from one constant'

  # ── THE ONE TRUST COMPARISON. `Approval::serves` is the single answer to "may this upstream serve
  #    this capability at this digest?", and its fields (`pin`, `capabilities`, `suspension`) are
  #    private to `trust/mod.rs`, so no plane can ask the question any other way. A SECOND `fn
  #    serves` is the divergence: two answers to one question, and the failure mode of a second
  #    answer is silent drift in the fail-OPEN direction, discovered as an in-flight call that
  #    served after the operator quarantined it. Zero is the rebuild routing the gate somewhere
  #    else, which is what the deleted test's `assert_eq!(serves_calls, 1)` was watching for.
  'trust-serve-decision|TRUST-DECISION-RESPELT|fn[[:space:]]+serves[[:space:]]*\(|1|'"$CORE"'/,'"$BIN"'/|there is exactly ONE may-this-serve comparison in busbar; a second is two answers to one question and they diverge the first time either is fixed, and zero means the dispatch gate was routed somewhere this row cannot see'

  # ── THE BOOT PATH STARTS THE QUARANTINE SWEEP. Scoped to `main.rs` on purpose: the question is not
  #    "does this function exist" (a census over the whole tree would answer yes to a function
  #    nothing calls) but "does BOOT call it". `run()` binds real listeners and joins them, so no
  #    test can reach this call site; reading it is the only way to pin it, and this row is that
  #    read moved out of a test whose file is being deleted. Zero is the whole point: a sweep
  #    nothing spawns is a defence that does not run, which is exactly the state `mcp::connect::
  #    refresh` was in when its only caller was a human pressing an admin button.
  # ── THE ONE ORDERED REQUEST VALIDATOR. `identity -> grant -> artifact -> generation` is asked of
  #    every request on every plane, and before `trust::validate` it was asked in several places with
  #    several coverages: one plane wrote the sequence down once and stamped a generation onto its
  #    resolved candidate; the sibling plane repeated the trust half at THREE call sites and had no
  #    generation check at all. A SECOND `fn validate_request` is that defect returning — two answers
  #    to "may this proceed", diverging the first time either is fixed, discovered as a call that
  #    served after the operator revoked it. ZERO is the false green this row exists for: the order is
  #    a FUNCTION, so a rebuild that inlines it back into a plane leaves a ban that reads as a pass
  #    because its subject vanished. This row says so out loud instead.
  # ── THE VALIDATOR'S REFUSAL WORDS HAVE ONE HOME, and this row is here because this unit ALREADY
  #    got it wrong once. `crate::trust::validate` defined its own `reason` module carrying the same
  #    tokens `crate::audit::vocab` had just unified — two homes for one vocabulary, argued for in
  #    almost identical words on both sides, and the merge is what surfaced it. Both arguments were
  #    right about the principle, which is exactly why there cannot be two: a chain that answers an
  #    operator differently depending on which module a plane imported from is the defect the audit
  #    unification existed to end.
  #
  #    `audit::vocab` is the home — the words are the tokens a chained record carries, so they belong
  #    to the evidence rather than to whichever gate produced them — and the validator RE-EXPORTS.
  #    A string literal here is a definition wearing a re-export's clothes; zero means the word left
  #    the tree and every query written against it silently stopped matching.
  'refusal-word-identity-not-live|REFUSAL-WORD-RESPELT|"identity_not_live"|1|'"$CORE"'/,'"$BIN"'/|the ordered validator'"'"'s identity refusal has one spelling, defined in crate::audit::vocab and re-exported; a second definition is two homes for one vocabulary, which is what this unit'"'"'s own merge conflict was'
  'refusal-word-not-serving|REFUSAL-WORD-RESPELT|"not_serving"|1|'"$CORE"'/,'"$BIN"'/|the registration-level refusal has one spelling; a plane may render it more finely under its own words, but it may not respell this one'
  'refusal-word-artifact-drifted|REFUSAL-WORD-RESPELT|"artifact_drifted"|1|'"$CORE"'/,'"$BIN"'/|the rug-pull refusal has one spelling: it is the one word that indicts the UPSTREAM rather than the config or the grant, and a second copy is two answers to who is at fault'
  'refusal-word-generation-moved|REFUSAL-WORD-RESPELT|"generation_moved"|1|'"$CORE"'/,'"$BIN"'/|the lifecycle-race refusal has one spelling across both planes; two copies is the in-flight-outliving-an-approval story told two ways'

  # ── THE FAILOVER SEAM'S REFUSAL WORDS, and they are here for the reason the four above are: the
  #    seam is CORE, so its words are core's, and a plane that renders a refusal must render THIS
  #    word rather than invent a near-synonym. One production occurrence each, in
  #    `crate::audit::vocab`; `crate::failover` names the CONST. A second string literal is a second
  #    home for one vocabulary — the defect the validator's own merge conflict already was, once —
  #    and zero means the word left the tree and every query written against it stopped matching.
  'refusal-word-no-upstream-left|REFUSAL-WORD-RESPELT|"no_upstream_left"|1|'"$CORE"'/,'"$BIN"'/|the nowhere-left-to-send refusal has one spelling across every plane that fails over; a second copy is one outage recorded under two words'
  'refusal-word-not-interchangeable|REFUSAL-WORD-RESPELT|"not_interchangeable"|1|'"$CORE"'/,'"$BIN"'/|the pins-disagree refusal has one spelling: it is the one word that indicts the CONFIGURATION rather than the caller or the upstream, and a second copy is two answers to who is at fault'
  'refusal-word-not-repeatable|REFUSAL-WORD-RESPELT|"not_repeatable"|1|'"$CORE"'/,'"$BIN"'/|the safety rule'"'"'s refusal has one spelling; it is the one outcome an operator may deliberately want to change, and a second copy is a change they would make in one place and not the other'

  'the-one-ordered-request-validator|VALIDATOR-RESPELT|fn[[:space:]]+validate_request[^a-zA-Z0-9_]|1|'"$CORE"'/,'"$BIN"'/|there is exactly ONE ordered request validator in busbar and every protocol reaches it; a second is a protocol that has acquired its own order, and zero means the order was inlined back into a plane where nothing owns it'

  # ── THE ONE GENERATION SOURCE. A generation only has to be DIFFERENT after a change, so a second
  #    counter buys nothing and adds a second thing to keep monotonic — and a plane that took its
  #    generations from a private counter would compare its own numbers against a shared one the day
  #    somebody unified them. Zero means no snapshot in the tree is versioned any more, which is the
  #    in-flight-outliving-the-approval window standing wide open with every test still green.
  'the-one-generation-source|GENERATION-SOURCE-FORKED|fn[[:space:]]+next_generation[^a-zA-Z0-9_]|1|'"$CORE"'/,'"$BIN"'/|every versioned snapshot in the process takes its generation from one monotonic source; a second source is two numbering schemes that compare equal by accident, and zero means nothing is versioned'

  # ── THE THIRD CATALOGUE WALK, RECORDED BECAUSE PLANE_LEDGER STRUCTURALLY CANNOT HOLD IT.
  #    `crate::catalogue` unified the two INBOUND catalogues — walk an inventory, hand what each item
  #    declares to the ordered gate, keep the entitled subset, render it — and retired the
  #    `catalogue` concern from PLANE_CONCERNS. It did NOT unify the third one:
  #    `mcp/client/dispatch.rs::visible_catalogue` walks the OUTBOUND leg's live upstream snapshot
  #    applying the caller's grants, through `egress::authorise_tool_egress` rather than through
  #    `trust::validate`. Same question — what may this caller SEE — third answer.
  #
  #    IT CANNOT BE A PLANE_LEDGER ROW. That ledger's entire mechanism is CROSS-plane duplication:
  #    `check_plane_dups` only ever sees a symbol declared in BOTH `mcp/` and `a2a/`, and a row for a
  #    name that is not is a hard STALE-LEDGER error. `visible_catalogue` exists once, in `mcp/`, so
  #    the row would fail the moment it was written — verified 2026-08-13 by writing it and reading
  #    the failure. A duplication the ledger cannot express is exactly the kind that gets forgotten,
  #    so it is expressed here instead, where the instrument fits: a count of the subject itself.
  #
  #    THE TARGET IS THIS ROW'S DELETION, not its count. One is today's honest number. When the walk
  #    is routed through `crate::catalogue::visible` the function goes and the count becomes zero,
  #    which fails — and the failure is the instruction to delete the row, exactly as a paid-off
  #    PLANE_LEDGER row is. A SECOND `visible_catalogue` fails for the ordinary reason.
  #
  #    It is not fixed in this unit for two reasons, both stated rather than implied: the file is
  #    held by another unit mid-rebase, and the function has no production caller today
  #    (`dispatch.rs` is `#![allow(dead_code)]`), so it is a third IMPLEMENTATION and not yet a third
  #    live answer. The second reason is why it is debt and not a defect; the first is why it is
  #    debt today.
  'the-third-catalogue-walk|THIRD-CATALOGUE-WALK|fn[[:space:]]+visible_catalogue[^a-zA-Z0-9_]|1|'"$CORE"'/,'"$BIN"'/|the outbound client leg still walks its own catalogue instead of crate::catalogue, filtering through the egress gate rather than the ordered validator; this row is that debt, and the count is 1 until somebody routes it through the one walk and deletes the row'

  'boot-starts-the-quarantine-sweep|SWEEP-NOT-SPAWNED|spawn_refresh_job\(|1|'"$BIN"'/main.rs|the sweep is the only thing that quarantines a drifted upstream with no operator present; if boot stops calling it the defence is still fully implemented, fully tested, and never runs'

  # ── THE ONE PARSE-TIME PLANE-BOUNDARY RULE. `refuse_cross_plane_reference` decides whether a hook
  #    reference reaches onto another config section, and `validate_section_hooks` applies it to a
  #    whole attach list. Both lived TWICE — `a2a/config.rs` and `mcp/config.rs` each carried a
  #    byte-identical copy, each with its own hardcoded `["pools", "tools", "agents", "export",
  #    "identity-providers"]` in a protocol-local file no compiler links to the other. They agreed
  #    because one was pasted from the other, which is not a mechanism. One copy now lives in
  #    `plane/config.rs` and takes its section list as a DERIVED parameter. These rows are what
  #    stops a third copy appearing on the next plane, and what catches the rule being deleted.
  #
  #    NOT the same as `PlaneSections::resolve`'s `RefError::CrossPlane`, which is a SECOND,
  #    STRUCTURAL cross-plane refusal at RESOLVE time on a name that exists. Two checks, two
  #    moments; merging them would delete one rather than deduplicate it.
  'one-parse-time-plane-boundary|PLANE-BOUNDARY-RULE-RESPELT|fn[[:space:]]+refuse_cross_plane_reference[[:space:]]*\(|1|'"$CORE"'/,'"$BIN"'/|there is exactly ONE parse-time answer to "does this hook reference reach onto another plane"; a second is two answers that drift the first time either is fixed, and zero means the rule left the tree and every dotted reference is now silently accepted'
  'one-section-attach-validator|PLANE-BOUNDARY-RULE-RESPELT|fn[[:space:]]+validate_section_hooks[[:space:]]*\(|1|'"$CORE"'/,'"$BIN"'/|the SECTION-level attach list must be judged by the same rule one entry is; a second copy is the place a looser rule grows, and it is the list an operator uses to attach a control to everything'

  # ── THE ONE BY-NAME PROTOCOL RESOLUTION. Before the registry there were THREE: `protocol_for`'"'"'s
  #    match, `handlers::request_handler`'"'"'s match, and `ProtocolRegistry::with_builtins`'"'"'s match,
  #    each a list of protocol names core had been edited to know. They are one `fn decl_for` now,
  #    and the census is what keeps them one: a SECOND by-name resolution is a second place a
  #    protocol can be known, and the failure mode is a protocol that resolves for routing and not
  #    for dispatch (or the reverse), discovered as a 404 on a path that is mounted. Zero is the
  #    other failure: the lookup was renamed or inlined and every ban above it scans nothing.
  'protocol-name-resolution|PROTOCOL-LOOKUP-RESPELT|fn[[:space:]]+decl_for[[:space:]]*\(|1|'"$CORE"'/,'"$BIN"'/|there is exactly ONE by-name protocol resolution in busbar, and a second one is a second answer to which protocols exist'

  # ── THE BUILT-IN DECLARATION TABLE. One slice, and it is DATA rather than a match — the whole
  #    point of the step (`design/protocol-plugin-abi.md` §8.1: a registry whose population is a
  #    match in core has not removed the match, it has moved it). A second table is a second answer
  #    to which protocols ship; zero means the table was inlined back into a constructor, which is
  #    how the match would return.
  'protocol-builtin-table|PROTOCOL-TABLE-RESPELT|static[[:space:]]+BUILTIN_DECLS|1|'"$CORE"'/,'"$BIN"'/|the set of built-in protocols is declared in exactly one place, as data; a second table or none at all is the match coming back'
)

hdr "declaration census (a shared decision, and each shared wire word, exists EXACTLY once)"
cs=0
for row in "${DECLARATION_CENSUS[@]}"; do
  IFS='|' read -r cs_id cs_tag cs_pat cs_want cs_scope cs_why extra <<<"$row"
  if [ -n "$extra" ] || [ -z "$cs_why" ] || [ -z "$cs_scope" ] || [ -z "$cs_want" ] || [ -z "$cs_pat" ]; then
    note "MALFORMED-ROW: ${cs_id} — a field contains a literal '|' (the row separator). Rewrite the"
    note "  pattern without alternation, or split it into another census row."
    fail=1; cs=1
    continue
  fi
  # A census row whose expected count is zero is a BAN wearing a census's clothes, and it reintroduces
  # the exact false green this whole invariant exists to remove: zero would then be both the passing
  # answer and the answer a vanished subject gives.
  case "$cs_want" in
    ''|*[!0-9]*) note "MALFORMED-ROW: ${cs_id} — count \`${cs_want}\` is not a number"; fail=1; cs=1; continue ;;
    0) note "MALFORMED-ROW: ${cs_id} — a census count of 0 is a BAN; put it in CHOKE_POINTS instead"; fail=1; cs=1; continue ;;
  esac
  # `scope` may be a comma-separated list of prefixes (a subject that lives on both sides of the
  # core/bin seam is scanned on both). EVERY listed prefix must exist — a missing one is a row
  # pointing at nothing, which is the false green this whole invariant refuses.
  IFS=',' read -r -a cs_scopes <<<"$cs_scope"
  cs_scope_missing=0
  for sp in "${cs_scopes[@]}"; do
    if [ ! -e "$sp" ]; then
      note "SCOPE-MISSING: ${cs_id} — \`${sp}\` does not exist; point the row at the subject's new root"
      fail=1; cs=1; cs_scope_missing=1
    fi
  done
  [ "$cs_scope_missing" -ne 0 ] && continue
  cs_files=()
  for f in "${CANDIDATES[@]}"; do
    for sp in "${cs_scopes[@]}"; do
      case "$f" in "$sp"*) cs_files+=("$f"); break ;; esac
    done
  done
  if [ ${#cs_files[@]} -eq 0 ]; then
    note "NO-SUBJECT: ${cs_id} — \`${cs_scope}\` holds no production .rs file, so this census counted"
    note "  NOTHING. That is the false green, not a clean bill."
    fail=1; cs=1
    continue
  fi
  LINT_PAT="$cs_pat"; LINT_WHAT="census"; LINT_UNLESS=''
  export LINT_PAT LINT_WHAT LINT_UNLESS
  cs_hits=$(scan_rule "${cs_files[@]}" || true)
  cs_got=$({ printf '%s' "$cs_hits" | grep -c . || true; } | tr -d ' ')
  case "$(census_verdict "$cs_got" "$cs_want")" in
    MISSING)
      note "SUBJECT-MISSING: ${cs_id} — \`${cs_pat}\` occurs NOWHERE in production code under"
      note "  ${cs_scope}, so this row scanned the whole tree and asserted nothing. Expected ${cs_want}."
      note "  (${cs_why})"
      fail=1; cs=1
      ;;
    WRONG)
      note "${cs_tag}: ${cs_id} — expected ${cs_want} production occurrence(s) of \`${cs_pat}\`, found ${cs_got}:"
      while IFS= read -r h; do [ -n "$h" ] && note "    ${h%%: census}"; done <<<"$cs_hits"
      note "  (${cs_why})"
      fail=1; cs=1
      ;;
  esac
done
unset LINT_PAT LINT_WHAT LINT_UNLESS
if [ ${#DECLARATION_CENSUS[@]} -eq 0 ]; then
  note "NO-ROWS: the census table is empty, so this invariant counted NOTHING"
  fail=1; cs=1
fi
[ "$cs" -eq 0 ] && note "ok (${#DECLARATION_CENSUS[@]} census row(s), every count exact)"

hdr "result"
if [ "$fail" -ne 0 ]; then note "structure-lint FAILED — see docs/code-layout.md"; exit 1; fi
note "structure-lint passed"
