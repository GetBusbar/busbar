#!/usr/bin/env bash
# Structure lint — enforces the code-layout invariants in docs/code-layout.md so the tree stays
# navigable ("I'm looking for X, I know where it is") instead of drifting back to giant, inconsistent
# files. Four checks, all greppable, no external deps. Exit non-zero on any violation.
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
  LINT_PAT='std::fs::rename\('; LINT_WHAT='probe'; LINT_UNLESS=''
  export LINT_PAT LINT_WHAT LINT_UNLESS
  got_hit=$(scan_rule "$src" | cut -d: -f2 | sort -n | tr '\n' ' ')
  want_hit=$({ grep -n '//= HIT' "$src" || true; } | cut -d: -f1 | sort -n | tr '\n' ' ')
  if [ "$got_hit" != "$want_hit" ]; then
    note "SELFTEST FAIL [$name] registry: flagged lines {${got_hit}} but expected {${want_hit}}"
    selftest_fail=1
  else selftest_pass=$((selftest_pass+1)); fi
  return 0
}

run_selftest() {
  hdr "structure-lint SELF-TEST (the test-scope scanner cannot be lied to)"
  SELFTEST_DIR=$(mktemp -d); trap 'rm -rf "$SELFTEST_DIR"' EXIT
  selftest_fail=0; selftest_pass=0

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

  note "self-test: ${selftest_pass} fixture(s) passed"
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
crates/busbar/src/admin/v1/service.rs
crates/busbar/src/admin/v1/json/handlers.rs
crates/busbar/src/config/mod.rs
crates/busbar/src/proxy/engine/mod.rs
crates/busbar/src/main.rs
"
GRANDFATHERED_LOCALITY="
crates/busbar/src/proto/stream.rs
crates/busbar/src/admin/mod.rs
crates/busbar/src/admin/v1/service.rs
crates/busbar/src/config/secret.rs
crates/busbar/src/config/overlay.rs
crates/busbar/src/governance/mod.rs
crates/busbar/src/proxy/engine/mod.rs
"
is_grandfathered() { printf '%s\n' "$2" | grep -qx "$1"; }

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
    if is_grandfathered "$f" "$GRANDFATHERED_LOCALITY"; then
      note "TESTS-IN-HUB (grandfathered, pre-existing debt): $f"
    else
      note "TESTS-IN-HUB: $f is a mod.rs with an inline test body — move it to tests/ (keep a #[path] decl)"
      fail=1; loc=1
    fi
  elif [ "$bodies" -ge 2 ]; then
    if is_grandfathered "$f" "$GRANDFATHERED_LOCALITY"; then
      note "MULTI-TEST-MOD (grandfathered, pre-existing debt): $f (${bodies} inline test bodies)"
    else
      note "MULTI-TEST-MOD: $f has ${bodies} inline test bodies — give each its own tests/<name>.rs"
      fail=1; loc=1
    fi
  fi
done < <(find crates -name '*.rs')
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
  'A-persistence|DURABLE-BYPASS|crates/busbar/src/durable.rs (durable::write / write_with; AppHandle::commit_and_swap)|crates/busbar/src/durable.rs::fault_matrix_returns_err_untouched_target_no_temp_leak|route through crate::durable::write|fs::rename\(>>hand-rolled rename-to-publish>>crates/busbar/src/durable.rs;sync_[ad]>>hand-rolled fsync durability (sync_all/sync_data)>>crates/busbar/src/durable.rs;fs::create_dir_all\(>>directory creation that leaves the new entry non-durable>>crates/busbar/src/durable.rs,crates/busbar/src/test_support/mod.rs|persist-then-swap is only atomic if EVERY writer does the identical fsync/rename/cleanup dance'

  # ── B ── plugin FFI/ABI: one export boundary. A hand-written #[no_mangle] skips the
  #         null-out-guard-before-alloc, the mandatory catch_unwind, and the total status map.
  'B-plugin-export|EXPORT-BYPASS|crates/plugin-sdk/src/boundary.rs (via the export_*_plugin! macro)|crates/plugin-sdk/tests/boundary_class.rs::null_out_pointer_never_leaks|define exports via export_*_plugin!, never by hand|#\[(unsafe\()?no_mangle>>hand-rolled #[no_mangle] export>>crates/plugin-sdk/src/lib.rs;#\[(unsafe\()?export_name>>hand-rolled #[export_name] export>>crates/plugin-sdk/src/lib.rs|an unwind or a written-then-failed out-param crossing the C ABI is UB, so no export may skip the wrapper'

  # ── C ── admin config mutation: one transaction. A raw lock re-opens lock-then-arbitrary-code; a
  #         swap outside the section IS the lost update the lock exists to prevent. state.rs DEFINES
  #         swap/commit_and_swap, so it is allowed alongside txn.rs.
  'C-config-mutation|MUTATION-BYPASS|crates/busbar/src/admin/v1/json/txn.rs (config_transaction)|crates/busbar/src/admin/v1/json/tests/txn_tests.rs::concurrent_transactions_never_lose_a_swap|route through json::txn::config_transaction|CONFIG_MUTATION_LOCK>>names the config mutation lock>>crates/busbar/src/admin/v1/json/txn.rs;commit_and_swap\(>>direct commit_and_swap outside a transaction>>crates/busbar/src/admin/v1/json/txn.rs,crates/busbar/src/state.rs;\.swap\(>>direct swap on an AppHandle outside a transaction>>crates/busbar/src/admin/v1/json/txn.rs,crates/busbar/src/state.rs>>Ordering::;AppHandle::swap\(>>direct AppHandle::swap outside a transaction>>crates/busbar/src/admin/v1/json/txn.rs,crates/busbar/src/state.rs|a fresh post-lock snapshot + one persist-then-swap is the only way concurrent mutations cannot lose an update'

  # ── D ── OpenAPI error taxonomy: one declaration the generator PROJECTS. Enforced differently —
  #         there is no pattern to ban, because the hazard is an endpoint emitting an ErrKind the
  #         declaration omits. The v1 router's recording layer PANICS on that under-claim at the
  #         moment of emission, and the class test fails on the mirror-image over-claim.
  'D-openapi-taxonomy|TAXONOMY-BYPASS|crates/busbar/src/admin/v1/contract/taxonomy.rs (declared_errors)|crates/busbar/src/admin/tests/tests.rs::declared_error_set_is_exactly_what_the_handlers_emit|declare the ErrKind in contract::taxonomy::declared_errors|-|openapi.json must be a PROJECTION of one declaration, never a hand-maintained parallel list'
)

# Candidate set, computed once: every crate .rs outside a tests/ dir. (Built with a read loop rather
# than `mapfile` so the script still runs on the bash 3.2 that ships with macOS.)
CANDIDATES=()
while IFS= read -r f; do CANDIDATES+=("$f"); done < <(find crates -name '*.rs' -not -path '*/tests/*' | sort)

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

hdr "result"
if [ "$fail" -ne 0 ]; then note "structure-lint FAILED — see docs/code-layout.md"; exit 1; fi
note "structure-lint passed"
