#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# One landing, the same way every time: cherry-pick a hand-back from an agent worktree onto the
# integration branch, then prove it — the crates it touched, the construction gate rows it names,
# and the oracle families it can move. Stops at the first red and leaves the picks in place so the
# integrator can look; never rewrites history, never pushes.
#
#   scripts/land.sh [--tests "pkg pkg"] [--families 'regex'] [--gate 'rule|rule'] <hash>...
#
# --tests     cargo packages to test after the picks (default: the packages whose files the picks
#             touched, by crate directory).
# --families  a record.sh --filter regex; when given, the candidate binary is rebuilt and those
#             families are recorded on the ports below and diffed against the golden.
# --gate      construction-gate rows (an egrep over the FAIL column) that must not be red after.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
tests=""; families=""; gate=""; prove=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tests) tests="$2"; shift 2 ;;
    --families) families="$2"; shift 2 ;;
    --gate) gate="$2"; shift 2 ;;
    # --prove: pick nothing; prove the tip as it stands (a landing whose picks are already on
    # the tree but whose legs were never run to green).
    --prove) prove=1; shift ;;
    *) break ;;
  esac
done
[ $# -gt 0 ] || [ "$prove" = 1 ] || { echo "land.sh: no hashes" >&2; exit 2; }

# The lock file drifts between worktrees; a pick must never fail on it.
git -C "$here" checkout -- Cargo.lock 2>/dev/null || true
for h in "$@"; do
  git -C "$here" cherry-pick -x "$h" >/dev/null || {
    echo "land.sh: RED — cherry-pick $h conflicted; resolve, then re-run with the remaining hashes" >&2
    git -C "$here" status --short | head -20 >&2
    exit 1
  }
done
echo "land.sh: picked $# commit(s); tip $(git -C "$here" rev-parse --short HEAD)"

# The plugin batteries refuse to skip when their cdylib is absent, so the example plugins are
# built before any test leg; a green here must mean the ABI-crossing cells actually ran.
plog="$here/target/land-plugins-$(date +%H%M%S).log"
if ! (cd "$here" && cargo build -p busbar-hook-test-plugin -p busbar-auth-static-plugin -p busbar-store-example-plugin -p busbar-export-example-plugin -p busbar-secret-example-plugin >"$plog" 2>&1); then
  grep -E '^error' "$plog" | head -5 >&2
  echo "land.sh: RED — example plugin cdylibs did not build (log: $plog)" >&2; exit 1
fi

if [ -z "$tests" ] && [ $# -gt 0 ]; then
  tests="$(git -C "$here" diff --name-only "HEAD~$#" HEAD | grep -o '^crates/[^/]*' | sort -u \
    | while read -r d; do grep -m1 '^name = ' "$here/$d/Cargo.toml" 2>/dev/null | sed 's/name = "\(.*\)"/\1/'; done | tr '\n' ' ')"
fi
if [ -n "$tests" ]; then
  args=""; for p in $tests; do args="$args -p $p"; done
  echo "land.sh: cargo test $args"
  # cargo's own exit status is the verdict; the grep only names the red lines. A pipeline here
  # would let pipefail turn a failing cargo into a skipped check.
  log="$here/target/land-$(date +%H%M%S).log"
  # shellcheck disable=SC2086
  if ! (cd "$here" && cargo test $args >"$log" 2>&1); then
    grep -E '^test result:.* [1-9][0-9]* failed|^error(\[|:)|^---- .* stdout ----|panicked at' "$log" | head -20 >&2
    echo "land.sh: RED — tests failed in: $tests (log: $log)" >&2; exit 1
  fi
  # shellcheck disable=SC2086
  if ! (cd "$here" && cargo clippy $args --all-targets -- -D warnings >"$log" 2>&1); then
    grep -E '^(warning|error)' "$log" | head -5 >&2
    echo "land.sh: RED — clippy (log: $log)" >&2; exit 1
  fi
  echo "land.sh: tests and clippy green for: $tests"
fi

if [ -n "$gate" ]; then
  # The gate's own exit status is not the verdict here (its verdict covers every rule); what this
  # leg proves is that the named rows were MEASURED and are not red. A gate that produced no rows
  # at all (missing python, missing ceilings file) is red, not green.
  glog="$here/target/land-gate-$(date +%H%M%S).log"
  "$here/scripts/construction-gate.sh" >"$glog" 2>&1 || true
  rows="$(grep -cE '^(PASS|FAIL)  ' "$glog" || true)"
  [ "${rows:-0}" -gt 0 ] || { echo "land.sh: RED — construction gate produced no rows (log: $glog)" >&2; exit 1; }
  named="$(grep -E '^(PASS|FAIL)  ' "$glog" | awk '{print $2}' | grep -E "$gate" || true)"
  [ -n "$named" ] || { echo "land.sh: RED — no gate row matches '$gate' (renamed rule?)" >&2; exit 1; }
  red="$(grep -E '^FAIL  ' "$glog" | awk '{print $2}' | grep -E "$gate" || true)"
  [ -z "$red" ] || { echo "land.sh: RED — construction gate rows still red: $red" >&2; exit 1; }
  echo "land.sh: gate rows green: $gate"
fi

if [ -n "$families" ]; then
  # cargo's exit status is the verdict (a pipe into grep would let pipefail invert it).
  blog="$here/target/land-build-$(date +%H%M%S).log"
  if ! (cd "$here" && cargo build --release -p busbar >"$blog" 2>&1); then
    grep -E '^error' "$blog" | head -5 >&2
    echo "land.sh: RED — release build (log: $blog)" >&2; exit 1
  fi
  out="$here/target/oracle/recordings/land-$(date +%H%M%S)"
  ORACLE_LISTEN_PORT=49901 ORACLE_ADMIN_PORT=49902 ORACLE_MOCK_PORT=49911 \
    "$here/testing/shadow-oracle/record.sh" --plane all --bin "$here/target/release/busbar" --filter "$families" \
    --out "$out" >"$out.log" 2>&1 || { echo "land.sh: RED — record.sh (see $out.log)" >&2; exit 1; }
  # The same regex selects the cells on both sides (an ID filter, the domain record.sh --filter
  # uses), and --strict makes the differ's exit code carry the verdict for this subset: zero owed
  # cells, an unaccepted divergence, or an owed cell missing from the candidate is red.
  python3 "$here/testing/shadow-oracle/diff-cells.py" --golden "$here/target/oracle/recordings/golden" \
    --candidate "$out" --out "$out.report" --allow-harness-skew --id-filter "$families" --strict \
    || { echo "land.sh: RED — oracle families: $families (see $out.report)" >&2; exit 1; }
  echo "land.sh: oracle green on: $families ($(grep -c . "$out.report/owed.txt" 2>/dev/null || echo '?') owed)"
fi
echo "land.sh: GREEN — landed $# commit(s) at $(git -C "$here" rev-parse --short HEAD)"
