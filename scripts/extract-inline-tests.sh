#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# extract-inline-tests.sh -- MOVE AN INLINE `#[cfg(test)] mod … { … }` OUT TO THE TREE'S CONVENTION.
#
# THE OWNER'S RULING: "all tests are in `_tests.rs` for easy ignoring". A test module written
# INLINE in a production file defeats it -- the file's production size becomes unmeasurable without
# a bespoke script, which is exactly how "1.6.0 is 2.08x of 1.5.5" and "1.6.0 is 2.90x of 1.5.5"
# could both be said of the same tree.
#
# THE CONVENTION, derived from the tree (not invented here). See
# crates/busbar-core-admin/src/v1/service.rs:2733, crates/busbar-kernel/src/auth/mod.rs:2149,
# crates/busbar-kernel-ledger/src/lib.rs:122:
#
#     production file `<dir>/<stem>.rs` keeps, at its top level:
#
#         #[cfg(test)]
#         #[path = "tests/<stem>_tests.rs"]
#         mod tests;
#
#     and the body moves, VERBATIM, to `<dir>/tests/<stem>_tests.rs` under the SPDX header and a
#     one-line `//!` saying what it tests. `#[path]` resolves relative to the declaring file's own
#     directory, so a `mod.rs` or `lib.rs` names `tests/tests.rs` and a module named something
#     other than `tests` keeps its own name (`tests/<modname>.rs`).
#
# WHY THAT IS A SAFE MOVE. The block becomes a `#[path]` child of the SAME parent module it was an
# inline child of, so `use super::*`, `crate::…` and every private item it reached resolve exactly
# as before. Nothing about name resolution changes -- which is the whole reason this is mechanical.
#
#   (no flag)    report only: what WOULD move, and every block refused with the reason
#   --apply      write it
#   --support    also list the `#[cfg(test)]` items that deliberately STAY (see below)
#   --selftest   prove the transform on planted fixtures before trusting it on the tree
#
# WHAT DELIBERATELY STAYS. `#[cfg(test)]` on a `fn`/`use`/`impl`/`static`/`struct` -- 409 of them in
# this tree -- is test SUPPORT sitting in the production file on purpose: it is reached by path from
# elsewhere, and relocating it changes name resolution. The tool reports those and never touches
# them. It also REFUSES, by name, any block it cannot move safely (a target that already exists, a
# body that is not uniformly indented one level, a nested block).
#
# bash 3.2 + python3 (stdlib) -- the bare-runner posture of the sibling gates.
set -uo pipefail
cd "$(dirname "$0")/.."

PY=python3
WORKER="scripts/extract-inline-tests.py"

usage() { sed -n '5,40p' "$0"; }

# ── SELF-TEST ───────────────────────────────────────────────────────────────────────────────────
# Every case plants a FIXTURE TREE in a scratch dir, runs the worker with --apply over it, and
# asserts on the bytes that land. The cases that matter are the ones the header of the worker calls
# "the cases that will bite": a raw string whose `}` would close the module early, a multi-line
# literal whose indentation is the literal's own content, a second block in one file, a block that
# is not at EOF, `#[cfg(all(test, …))]`, and the ones that must be REFUSED rather than guessed.
selftest() {
  echo "== extract-inline-tests SELF-TEST (the tool proves itself before it rewrites anything) =="
  local tmp fails=0 cases=0
  tmp="$(mktemp -d "${TMPDIR:-/tmp}/extract-inline-selftest.XXXXXX")" || return 2
  trap 'rm -rf "$tmp"' RETURN
  say() { printf '  %-4s %s\n' "$1" "$2"; cases=$((cases+1)); [ "$1" = PASS ] || fails=$((fails+1)); }

  # plant <name> <file-body>   -> $tmp/<name>/src/thing.rs
  plant() {
    mkdir -p "$tmp/$1/src"
    cat > "$tmp/$1/src/thing.rs"
  }
  run() { "$PY" "$WORKER" --root "$tmp/$1" --apply "src" 2>&1; }
  report() { "$PY" "$WORKER" --root "$tmp/$1" "src" 2>&1; }

  # ── (a) the ordinary case: body moves verbatim, decl left behind ────────────────────────────
  plant a <<'EOF'
pub fn keep() -> u8 { 1 }

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn it_works() {
        assert_eq!(keep(), 1);
    }
}
EOF
  run a >/dev/null
  if [ -f "$tmp/a/src/tests/thing_tests.rs" ] \
     && grep -q '#\[path = "tests/thing_tests.rs"\]' "$tmp/a/src/thing.rs" \
     && grep -q '^mod tests;$' "$tmp/a/src/thing.rs" \
     && ! grep -q 'it_works' "$tmp/a/src/thing.rs" \
     && grep -q '^fn it_works() {$' "$tmp/a/src/tests/thing_tests.rs"; then
    say PASS "a block moves out, dedented one level, leaving \`#[cfg(test)] mod tests;\`"
  else
    say FAIL "the ordinary move"; sed 's/^/        /' "$tmp/a/src/thing.rs"
  fi

  # ── (b) A RAW STRING CONTAINING `}` must not close the module early ─────────────────────────
  # This is the fault that makes a naive brace counter mis-attribute every line after it.
  plant b <<'EOF'
pub fn keep() {}

#[cfg(test)]
mod tests {
    #[test]
    fn braces_in_a_raw_string() {
        let s = r#"a } b { c"#;
        assert!(s.contains('}'));
    }
}

pub fn after_the_block() {}
EOF
  run b >/dev/null
  if grep -q 'after_the_block' "$tmp/b/src/thing.rs" \
     && grep -q 'r#"a } b { c"#' "$tmp/b/src/tests/thing_tests.rs" \
     && ! grep -q 'after_the_block' "$tmp/b/src/tests/thing_tests.rs"; then
    say PASS "a \`}\` inside a raw string does not close the module early"
  else
    say FAIL "raw-string brace handling"; sed 's/^/        /' "$tmp/b/src/thing.rs"
  fi

  # ── (c) A MULTI-LINE LITERAL's own indentation is content, and must survive byte-identically ─
  plant c <<'EOF'
pub fn keep() {}

#[cfg(test)]
mod tests {
    #[test]
    fn literal_indent_is_content() {
        let s = "line one
    indented by the literal
";
        assert!(s.contains("indented"));
    }
}
EOF
  run c >/dev/null
  if grep -q '^    indented by the literal$' "$tmp/c/src/tests/thing_tests.rs"; then
    say PASS "a multi-line literal's own indentation is copied verbatim, never dedented"
  else
    say FAIL "multi-line literal bytes changed"; sed 's/^/        /' "$tmp/c/src/tests/thing_tests.rs"
  fi

  # ── (d) TWO blocks in one file, neither at EOF ───────────────────────────────────────────────
  plant d <<'EOF'
pub fn a() {}

#[cfg(test)]
mod first_tests {
    #[test]
    fn one() {}
}

pub fn b() {}

#[cfg(test)]
mod second_tests {
    #[test]
    fn two() {}
}

pub fn c() {}
EOF
  run d >/dev/null
  if [ -f "$tmp/d/src/tests/first_tests.rs" ] && [ -f "$tmp/d/src/tests/second_tests.rs" ] \
     && grep -q '^pub fn c() {}$' "$tmp/d/src/thing.rs" \
     && grep -q '^mod first_tests;$' "$tmp/d/src/thing.rs" \
     && grep -q '^mod second_tests;$' "$tmp/d/src/thing.rs"; then
    say PASS "two blocks in one file, neither at EOF, both move and both leave a decl"
  else
    say FAIL "multiple non-EOF blocks"; sed 's/^/        /' "$tmp/d/src/thing.rs"
  fi

  # ── (e) `#[cfg(all(test, …))]` keeps its OWN predicate on the declaration ────────────────────
  plant e <<'EOF'
pub fn keep() {}

#[cfg(all(test, feature = "teller-waist"))]
mod tests {
    #[test]
    fn gated() {}
}
EOF
  run e >/dev/null
  if grep -q '^#\[cfg(all(test, feature = "teller-waist"))\]$' "$tmp/e/src/thing.rs" \
     && grep -q '^mod tests;$' "$tmp/e/src/thing.rs"; then
    say PASS "\`#[cfg(all(test, feature = …))]\` is preserved verbatim on the declaration"
  else
    say FAIL "cfg predicate not preserved"; sed 's/^/        /' "$tmp/e/src/thing.rs"
  fi

  # ── (f) `#[cfg(test)]` on a NON-mod item is support: it STAYS, untouched ─────────────────────
  plant f <<'EOF'
pub struct S;

impl S {
    #[cfg(test)]
    pub(crate) fn probe(&self) -> u8 { 7 }
}

#[cfg(test)]
pub(crate) use helper::thing;

#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}
EOF
  run f >/dev/null
  if grep -q 'pub(crate) fn probe' "$tmp/f/src/thing.rs" \
     && grep -q 'pub(crate) use helper::thing;' "$tmp/f/src/thing.rs" \
     && [ -f "$tmp/f/src/tests/thing_tests.rs" ]; then
    say PASS "a cfg(test) \`fn\`/\`use\` stays put, and does not block the real block from moving"
  else
    say FAIL "support items"; sed 's/^/        /' "$tmp/f/src/thing.rs"
  fi

  # ── (g) REFUSALS: a target that already exists is named, not overwritten ─────────────────────
  plant g <<'EOF'
pub fn keep() {}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}
EOF
  mkdir -p "$tmp/g/src/tests"; echo "// already here" > "$tmp/g/src/tests/thing_tests.rs"
  out="$(run g)"
  if printf '%s' "$out" | grep -q 'REFUSED' \
     && printf '%s' "$out" | grep -q 'already exists' \
     && grep -q 'already here' "$tmp/g/src/tests/thing_tests.rs" \
     && grep -q 'mod tests {' "$tmp/g/src/thing.rs"; then
    say PASS "a target that already exists is REFUSED by name; neither file is touched"
  else
    say FAIL "collision refusal"; printf '%s\n' "$out" | sed 's/^/        /'
  fi

  # ── (h) REFUSAL: a body that is not uniformly indented one level ─────────────────────────────
  plant h <<'EOF'
pub fn keep() {}

#[cfg(test)]
mod tests {
#[test]
fn flush_left() {}
}
EOF
  out="$(run h)"
  if printf '%s' "$out" | grep -q 'REFUSED' \
     && printf '%s' "$out" | grep -q 'not uniformly indented' \
     && grep -q 'fn flush_left' "$tmp/h/src/thing.rs"; then
    say PASS "a body that is not indented one level is REFUSED rather than re-indented"
  else
    say FAIL "indent refusal"; printf '%s\n' "$out" | sed 's/^/        /'
  fi

  # ── (i) the ALREADY-COMPLIANT declaration form is left completely alone ──────────────────────
  # This is the case the "first #[cfg(test)] to EOF" heuristic scored as thousands of lines of
  # inline test code. It is zero.
  plant i <<'EOF'
pub fn keep() {}

#[cfg(test)]
#[path = "tests/thing_tests.rs"]
mod tests;
EOF
  before="$(cat "$tmp/i/src/thing.rs")"
  out="$(run i)"
  if [ "$before" = "$(cat "$tmp/i/src/thing.rs")" ] \
     && ! printf '%s' "$out" | grep -q 'MOVE'; then
    say PASS "an already-compliant \`#[cfg(test)] mod x;\` declaration is not touched or counted"
  else
    say FAIL "compliant form disturbed"; printf '%s\n' "$out" | sed 's/^/        /'
  fi

  # ── (j) REPORT MODE WRITES NOTHING ───────────────────────────────────────────────────────────
  plant j <<'EOF'
pub fn keep() {}

#[cfg(test)]
mod tests {
    #[test]
    fn t() {}
}
EOF
  before="$(cat "$tmp/j/src/thing.rs")"
  report j >/dev/null
  if [ "$before" = "$(cat "$tmp/j/src/thing.rs")" ] && [ ! -d "$tmp/j/src/tests" ]; then
    say PASS "report mode (the default) writes nothing"
  else
    say FAIL "report mode wrote to the tree"
  fi

  if [ "$fails" -eq 0 ]; then echo "extract-inline-tests selftest: GREEN (${cases} cases)"; return 0; fi
  echo "extract-inline-tests selftest: RED (${fails}/${cases} cases failed)"; return 1
}

case "${1:-}" in
  --selftest) selftest; exit $? ;;
  -h|--help)  usage; exit 0 ;;
  "")         usage; exit 2 ;;
esac

exec "$PY" "$WORKER" "$@"
