#!/usr/bin/env bash
# THE SUITE-REGISTRY CHECK, DRIVEN IN BOTH DIRECTIONS — because a check nobody has watched refuse
# anything is indistinguishable from no check at all.
#
# `bin/mcp-battery.mjs` holds its DECLARED suite list to the `*.mjs` files on disk and requires every
# declared suite to register at least one test. That rule replaces five bare `import` lines that
# nothing checked: deleting one silently deleted its scenarios from every number the battery prints,
# with no SKIP, no FAIL and no trace — the same class of hole as an unarmed role, and worse, because
# a role at least has a name in the report.
#
# The rule is worth nothing unless it BITES, and the only run that would otherwise exercise it is one
# where somebody has already made the mistake. So it is driven here, against a COPY of the tree, in
# the three shapes that matter, plus the pristine shape it must stay silent on.
#
# Exit 0 if every fixture behaved as declared; 1 otherwise.
set -euo pipefail
cd "$(dirname "$0")/.."
BATTERY="$(pwd)"

failures=0
tmp="$(mktemp -d)"
trap 'rm -rf "$tmp"' EXIT

say() { printf '%s\n' "$*"; }

# A working copy of the battery: sources only, no reports, no venv, no node_modules. `list` needs
# nothing else, and it is the cheapest command that loads the whole registry.
copy_tree() {
  local dest="$1"
  mkdir -p "$dest"
  tar -C "$BATTERY" -cf - bin src package.json | tar -C "$dest" -xf -
}

# Run `list` in a tree and answer whether it was ACCEPTED (exit 0) or REFUSED (anything else).
verdict_of() {
  if ( cd "$1" && node bin/mcp-battery.mjs list ) >/dev/null 2>&1; then
    printf 'accept'
  else
    printf 'refuse'
  fi
}

check() {  # check <name> <tree> <want:accept|refuse>
  local name="$1" tree="$2" want="$3" got
  got="$(verdict_of "$tree")"
  if [ "$got" = "$want" ]; then
    say "  ok: $name -> $got"
  else
    say "  MISS: $name -> $got (wanted $want)"
    failures=$((failures + 1))
  fi
}

say "== mcp battery SUITE-REGISTRY self-test (the inventory cannot be lied to) =="

# GREEN: the tree as shipped. If this were refused, every RED below would prove only that the check
# refuses everything, which is the same disease wearing the opposite coat.
pristine="$tmp/pristine"; copy_tree "$pristine"
check "the tree as shipped" "$pristine" accept

# RED 1: a suite FILE on disk that nobody imported. This is the hole arriving from the direction
# nobody watches — the scenarios are written, reviewed, committed, and never once executed.
unimported="$tmp/unimported"; copy_tree "$unimported"
cat >"$unimported/src/suites/ghost.mjs" <<'JS'
import { test } from '../core/runner.mjs';
test({
  id: 'GHOST.NEVER-RUNS',
  title: 'a scenario in a suite nobody imported',
  role: 'server', area: 'conformance', tier: 'push', peer: 'fake',
  catches: 'A suite added to the tree and never registered, so its scenarios never enter any number.',
  run: () => {},
});
JS
check "a suite file on disk that nobody imported" "$unimported" refuse

# RED 2: a DECLARED suite that registers nothing. The module loads, the import line is right there in
# the diff, and the suite contributes zero scenarios — the shape a commented-out body produces.
emptied="$tmp/emptied"; copy_tree "$emptied"
: >"$emptied/src/suites/seam.mjs"
check "a declared suite that registers nothing" "$emptied" refuse

# RED 3: a declared suite whose file is GONE. It must name itself rather than dying as an opaque
# module-resolution stack trace three frames into the loader.
missing="$tmp/missing"; copy_tree "$missing"
rm -f "$missing/src/suites/server-concurrency.mjs"
check "a declared suite whose file is gone" "$missing" refuse

# GREEN 2: a suite that registers exactly ONE test is enough. The floor is "at least one", never a
# number somebody has to keep in step with the tree by hand — a hand-maintained count is a second
# thing that can drift, and it drifts in the direction of being loosened.
minimal="$tmp/minimal"; copy_tree "$minimal"
cat >"$minimal/src/suites/seam.mjs" <<'JS'
import { test } from '../core/runner.mjs';
test({
  id: 'SEAM.MINIMAL',
  title: 'one registration is a registered suite',
  role: 'seam', area: 'seam', tier: 'pr', peer: 'real',
  catches: 'Nothing; this is a self-test fixture proving the floor is one, not a hand-kept count.',
  run: () => {},
});
JS
check "a suite that registers exactly one test" "$minimal" accept

if [ "$failures" -ne 0 ]; then
  printf 'FAIL: %s registry self-test fixture(s) did not behave as declared\n' "$failures" >&2
  exit 1
fi
say "  registry self-test: 5 fixture(s) passed"
