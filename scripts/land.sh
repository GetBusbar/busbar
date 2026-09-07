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
tests=""; families=""; gate=""; prove=0; selftest=0
while [ $# -gt 0 ]; do
  case "$1" in
    --tests) tests="$2"; shift 2 ;;
    --families) families="$2"; shift 2 ;;
    --gate) gate="$2"; shift 2 ;;
    # --prove: pick nothing; prove commits that are ALREADY on the tree (a landing whose picks
    # landed but whose legs were never run to green). Any hashes given name WHAT to prove — they are
    # not picked. With none, the tip commit alone is the subject.
    --prove) prove=1; shift ;;
    --selftest) selftest=1; shift ;;
    # AN UNRECOGNISED FLAG IS REFUSED, NOT CHERRY-PICKED. `*) break` sent anything that was not a
    # known flag to the pick loop as a REVISION, so a typo (`--familes`), a flag from a newer copy of
    # this script, or `--selftest` before it existed all reached `git cherry-pick -x --familes`.
    # That fails, and it fails saying "cherry-pick … conflicted; resolve, then re-run with the
    # remaining hashes" — a message about a conflict there is no conflict in, pointing the reader at
    # the commits instead of at their own command line.
    --*) echo "land.sh: unknown option '$1' (see the header for the flags this script takes)" >&2; exit 2 ;;
    *) break ;;
  esac
done
[ "$selftest" = 1 ] || [ $# -gt 0 ] || [ "$prove" = 1 ] || { echo "land.sh: no hashes" >&2; exit 2; }

# ONE STAMP FOR EVERY PATH THIS RUN WRITES, and it carries the date and the pid.
#
# `%H%M%S` alone names a time of day, so a landing at 14:32:07 today writes exactly where yesterday's
# 14:32:07 landing wrote. That is harmless for the logs (they are truncated by `>`), and it is NOT
# harmless for the recording: record.sh only does `mkdir -p` on its `--out`, so a directory left by
# an earlier run keeps its cells, and `diff-cells.py --strict` then reads a mixture of this
# candidate and a stale one. A recording that is partly somebody else's is the one artifact in this
# script whose verdict is attributed to the picked commits.
#
# The pid is there for the second collision: two worktrees landing in the same second.
stamp="$(date +%Y%m%d-%H%M%S)-$$"

# ── --selftest ────────────────────────────────────────────────────────────────────────────────────
# THIS SCRIPT IS THE ONE GATE SCRIPT ITS OWN GATE-TREE LEG COULD NOT PROVE. That leg parses every
# touched shell file and runs the self-test of every touched script that advertises one — and
# land.sh advertised none, so a landing that touched land.sh proved that land.sh still PARSED and
# nothing else. The script whose job is to decide whether other people's changes are proven was the
# one change nobody could prove.
#
# What is proven here is what can be proven without picking a commit: the argument contract (an
# unknown flag is refused rather than treated as a revision, `--prove` picks nothing), and the
# advertisement grep the gate-tree leg leans on — the check that decides, for every gate script in
# the tree, whether its self-test runs at all. A grep that stopped matching would silently reduce
# every landing to a parse check, which is the state this file was in.
if [ "$selftest" = 1 ]; then
  bad=0
  tmp="$(mktemp -d)"

  # THE ADVERTISEMENT GREP, driven over fixtures rather than asserted. A script ADVERTISES a
  # self-test when it HANDLES the flag, not when its prose mentions one.
  advertises() { grep -qE -- "(--selftest\)|[\"']--selftest[\"'])" "$1"; }
  printf '%s\n' 'case "$1" in' '  --selftest) run ;;' 'esac' >"$tmp/has-arm.sh"
  printf '%s\n' 'if [ "$1" = "--selftest" ]; then run; fi' >"$tmp/has-compare.sh"
  printf '%s\n' '# run this with --selftest before believing it' 'echo hi' >"$tmp/only-prose.sh"
  printf '%s\n' 'echo "usage: foo.sh [--selftest]"' >"$tmp/only-usage.sh"
  for f in has-arm has-compare; do
    if advertises "$tmp/$f.sh"; then echo "land.sh selftest: ok — $f is detected as advertising a self-test"
    else echo "land.sh selftest: FAILED — $f handles --selftest and was NOT detected; its self-test would never run" >&2; bad=1; fi
  done
  for f in only-prose only-usage; do
    if advertises "$tmp/$f.sh"; then echo "land.sh selftest: FAILED — $f only MENTIONS --selftest and was detected; landing it would run a flag it does not handle" >&2; bad=1
    else echo "land.sh selftest: ok — $f only mentions a self-test and is not detected"; fi
  done
  # …and against the real tree, which is the number that decides something: every shipped script
  # this grep claims advertises a self-test must actually accept the flag, and the count must not be
  # zero — a grep that matched nothing would turn every landing into a parse check in silence.
  n_adv=0
  for f in "$here"/scripts/*.sh "$here"/testing/*/*.sh; do
    [ -f "$f" ] && advertises "$f" && n_adv=$((n_adv + 1))
  done
  if [ "$n_adv" -ge 10 ]; then echo "land.sh selftest: ok — $n_adv shipped script(s) advertise a self-test (floor 10)"
  else echo "land.sh selftest: FAILED — only $n_adv shipped script(s) matched the advertisement grep; a landing would run almost no self-test" >&2; bad=1; fi

  # THE ARGUMENT CONTRACT. Both cases used to end at `git cherry-pick -x <the flag>`.
  # THIS script, not the one at the well-known path: a cell that always launches
  # `$here/scripts/land.sh` proves whatever is committed there rather than whatever is being run,
  # so the argument contract could be edited away and these cells would still pass off the shipped
  # copy. (Proven by removing the unknown-option arm from a copy and watching the cell go red.)
  case "$0" in /*) self="$0" ;; *) self="$(cd "$(dirname "$0")" && pwd)/$(basename "$0")" ;; esac
  if (cd "$here" && bash "$self" --familes 'x' >"$tmp/typo.log" 2>&1); then
    echo "land.sh selftest: FAILED — a mistyped flag was accepted" >&2; bad=1
  elif grep -q "unknown option" "$tmp/typo.log"; then
    echo "land.sh selftest: ok — a mistyped flag is refused by name, not cherry-picked as a revision"
  else
    echo "land.sh selftest: FAILED — a mistyped flag was refused, but not as an unknown option: $(head -1 "$tmp/typo.log")" >&2; bad=1
  fi
  if (cd "$here" && bash "$self" >"$tmp/noargs.log" 2>&1); then
    echo "land.sh selftest: FAILED — a bare invocation with no hashes was accepted" >&2; bad=1
  else
    echo "land.sh selftest: ok — no hashes and no --prove is refused"
  fi
  # `--prove` must not move HEAD. Run it against a subject that proves nothing, so it stops at the
  # bottom refusal rather than building anything, and check the tip is where it was.
  head_before="$(git -C "$here" rev-parse HEAD)"
  (cd "$here" && bash "$self" --prove --tests '' >"$tmp/prove.log" 2>&1) || true
  if [ "$(git -C "$here" rev-parse HEAD)" = "$head_before" ]; then
    echo "land.sh selftest: ok — --prove left HEAD where it found it"
  else
    echo "land.sh selftest: FAILED — --prove moved HEAD; it picked something" >&2; bad=1
  fi

  rm -rf "$tmp"
  [ "$bad" = 0 ] || { echo "land.sh selftest: FAILED" >&2; exit 1; }
  echo "land.sh selftest: PASS"
  exit 0
fi

# THE PORTS ARE DEFAULTS, NOT PINS. The landing queue relies on this triple, so it stays the
# default; but two worktrees recording at once on one host would both bind it, and record.sh's own
# occupied-port guard would turn that collision into a RED attributed to whichever commits happened
# to be picked. An operator running a second landing sets these in the environment and gets a
# recording of their own binary; the RED path below prints the triple so a collision reads as one.
ORACLE_LISTEN_PORT="${ORACLE_LISTEN_PORT:-49901}"
ORACLE_ADMIN_PORT="${ORACLE_ADMIN_PORT:-49902}"
ORACLE_MOCK_PORT="${ORACLE_MOCK_PORT:-49911}"

# `--prove` PICKS NOTHING, WHICH IS WHAT IT SAYS. The pick loop ran unconditionally, so
# `land.sh --prove <hash>` — the obvious way to say "prove these commits, they are already here" —
# picked them a second time. The contract in the header ("pick nothing; prove the tip as it stands")
# was true only when no hash was given.
if [ "$prove" = 0 ]; then
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
else
  echo "land.sh: --prove: picking nothing; proving $([ $# -gt 0 ] && echo "$# named commit(s)" || echo "the tip commit") at $(git -C "$here" rev-parse --short HEAD)"
fi

# The plugin batteries refuse to skip when their cdylib is absent, so the example plugins are
# built before any test leg; a green here must mean the ABI-crossing cells actually ran.
plog="$here/target/land-plugins-$stamp.log"
if ! (cd "$here" && cargo build -p busbar-hook-test-plugin -p busbar-auth-static-plugin -p busbar-store-example-plugin -p busbar-export-example-plugin -p busbar-secret-example-plugin >"$plog" 2>&1); then
  grep -E '^error' "$plog" | head -5 >&2
  echo "land.sh: RED — example plugin cdylibs did not build (log: $plog)" >&2; exit 1
fi

# WHAT THE PICKS ACTUALLY TOUCHED. Used twice: to pick the cargo packages, and — the part that was
# missing — to prove the picks that touch NO crate at all.
#
# UNDER `--prove`, THE SUBJECT IS THE COMMITS NAMED, NOT `HEAD~1`. `--prove` exists for a landing
# whose picks are already on the tree — plural — and the range was `HEAD~1..HEAD` whatever was
# named, so `--prove h1 h2 h3` measured the last commit and reported green over the other two. The
# crates the first two touched were never tested and no line said so; the GREEN line at the bottom
# named the legs that ran without naming how much of the landing they covered. Naming the hashes now
# means what it reads as: the union of what those commits touched is the subject.
if [ "$prove" = 1 ] && [ $# -gt 0 ]; then
  touched="$(for h in "$@"; do git -C "$here" show --name-only --pretty=format: "$h" 2>/dev/null; done | grep . | sort -u)"
  [ -n "$touched" ] || { echo "land.sh: RED — --prove named $# commit(s) and none of them names a file this repository has; a landing proved over an empty file set is a landing proved by nothing" >&2; exit 1; }
else
  picked_range="HEAD~$#"
  [ "$#" -gt 0 ] || picked_range="HEAD~1"
  touched="$(git -C "$here" diff --name-only "$picked_range" HEAD 2>/dev/null || true)"
fi

if [ -z "$tests" ] && [ $# -gt 0 ]; then
  tests="$(printf '%s\n' "$touched" | grep -o '^crates/[^/]*' | sort -u \
    | while read -r d; do grep -m1 '^name = ' "$here/$d/Cargo.toml" 2>/dev/null | sed 's/name = "\(.*\)"/\1/'; done | tr '\n' ' ')"
fi

# ── THE GATE-TREE LEGS ────────────────────────────────────────────────────────────────────────────
# A landing whose picks touch only `scripts/`, `.github/` or `testing/` selects NO cargo package —
# the crate-directory grep above matches nothing — so `$tests` is empty, the test and clippy legs are
# skipped, and with no `--gate` and no `--families` this script reached its final line having
# executed not one check. It then printed `land.sh: GREEN — landed N commit(s)`, which is the exact
# sentence an integrator reads as "these commits were proven". Landing a change to the GATES
# THEMSELVES was the one case with no proof at all, which is precisely backwards: a broken gate
# script is invisible to every other leg here, because every other leg is about the crates.
#
# So every touched shell/python/workflow file is parsed, and every touched script that advertises a
# `--selftest` runs it. These are cheap (seconds) and they catch the two failures that actually
# happen to a picked gate script: it no longer parses, and its own red-before-green cases no longer
# hold. What ran is NAMED in the GREEN line at the bottom, so the word "green" carries its scope.
proof_notes=""
gate_files="$(printf '%s\n' "$touched" | grep -E '^(scripts|testing|\.github)/.*\.(sh|py|mjs|yml|yaml)$' || true)"
n_parsed=0; n_selftests=0
if [ -n "$gate_files" ]; then
  while IFS= read -r f; do
    [ -n "$f" ] && [ -f "$here/$f" ] || continue
    case "$f" in
      *.sh)
        bash -n "$here/$f" || { echo "land.sh: RED — $f does not parse (bash -n)" >&2; exit 1; }
        n_parsed=$((n_parsed + 1)) ;;
      *.py)
        python3 -m py_compile "$here/$f" || { echo "land.sh: RED — $f does not compile (py_compile)" >&2; exit 1; }
        n_parsed=$((n_parsed + 1)) ;;
      *.yml|*.yaml)
        case "$f" in
          .github/workflows/*)
            if command -v actionlint >/dev/null 2>&1; then
              (cd "$here" && actionlint "$f") || { echo "land.sh: RED — actionlint $f" >&2; exit 1; }
              n_parsed=$((n_parsed + 1))
            else
              python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$here/$f" \
                || { echo "land.sh: RED — $f is not valid YAML" >&2; exit 1; }
              n_parsed=$((n_parsed + 1))
            fi ;;
        esac ;;
      *.mjs)
        if command -v node >/dev/null 2>&1; then
          node --check "$here/$f" || { echo "land.sh: RED — $f does not parse (node --check)" >&2; exit 1; }
          n_parsed=$((n_parsed + 1))
        fi ;;
    esac
    # …and its own self-test, where it has one. A gate script that has stopped discriminating is
    # worse than one that fails to parse: it lands green and goes on reporting green forever.
    slog="$here/target/land-selftest-$stamp.log"
    case "$f" in
      *.sh)
        # A script ADVERTISES a self-test when it handles the flag (a `case` arm or a quoted
        # comparison), not when its prose merely mentions one.
        if grep -qE -- "(--selftest\)|[\"']--selftest[\"'])" "$here/$f"; then
          if ! (cd "$here" && bash "$f" --selftest >"$slog" 2>&1); then
            tail -20 "$slog" >&2
            echo "land.sh: RED — $f --selftest failed (log: $slog)" >&2; exit 1
          fi
          n_selftests=$((n_selftests + 1))
        fi ;;
      *.py)
        if grep -qE -- "[\"']--selftest[\"']" "$here/$f"; then
          if ! (cd "$here" && python3 "$f" --selftest >"$slog" 2>&1); then
            tail -20 "$slog" >&2
            echo "land.sh: RED — $f --selftest failed (log: $slog)" >&2; exit 1
          fi
          n_selftests=$((n_selftests + 1))
        fi ;;
    esac
  done <<EOF
$gate_files
EOF
  proof_notes="${n_parsed} gate file(s) parsed, ${n_selftests} self-test(s) green"
  echo "land.sh: $proof_notes"
fi
if [ -n "$tests" ]; then
  args=""; for p in $tests; do args="$args -p $p"; done
  echo "land.sh: cargo test $args"
  # cargo's own exit status is the verdict; the grep only names the red lines. A pipeline here
  # would let pipefail turn a failing cargo into a skipped check.
  log="$here/target/land-$stamp.log"
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
  glog="$here/target/land-gate-$stamp.log"
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
  blog="$here/target/land-build-$stamp.log"
  if ! (cd "$here" && cargo build --release -p busbar >"$blog" 2>&1); then
    grep -E '^error' "$blog" | head -5 >&2
    echo "land.sh: RED — release build (log: $blog)" >&2; exit 1
  fi
  out="$here/target/oracle/recordings/land-$stamp"
  # record.sh only `mkdir -p`s its --out, so the directory is cleared HERE. A recording the differ
  # reads must contain this candidate's cells and nothing else.
  rm -rf "$out" "$out.report"
  ORACLE_LISTEN_PORT="$ORACLE_LISTEN_PORT" ORACLE_ADMIN_PORT="$ORACLE_ADMIN_PORT" ORACLE_MOCK_PORT="$ORACLE_MOCK_PORT" \
    "$here/testing/shadow-oracle/record.sh" --plane all --bin "$here/target/release/busbar" --filter "$families" \
    --out "$out" >"$out.log" 2>&1 || {
      echo "land.sh: RED — record.sh on ports $ORACLE_LISTEN_PORT/$ORACLE_ADMIN_PORT/$ORACLE_MOCK_PORT (see $out.log)" >&2
      echo "land.sh:       if another landing is recording on this host, set ORACLE_LISTEN_PORT/ORACLE_ADMIN_PORT/ORACLE_MOCK_PORT and re-run" >&2
      exit 1
    }
  # The same regex selects the cells on both sides (an ID filter, the domain record.sh --filter
  # uses), and --strict makes the differ's exit code carry the verdict for this subset: zero owed
  # cells, an unaccepted divergence, or an owed cell missing from the candidate is red.
  python3 "$here/testing/shadow-oracle/diff-cells.py" --golden "$here/target/oracle/recordings/golden" \
    --candidate "$out" --out "$out.report" --allow-harness-skew --id-filter "$families" --strict \
    || { echo "land.sh: RED — oracle families: $families (see $out.report)" >&2; exit 1; }
  echo "land.sh: oracle green on: $families ($(grep -c . "$out.report/owed.txt" 2>/dev/null || echo '?') owed)"
fi
# ── THE GREEN LINE NAMES ITS SCOPE ────────────────────────────────────────────────────────────────
# It used to read "GREEN — landed N commit(s)" whatever had run, including nothing. A verdict that
# does not say what it measured is read as having measured everything.
proved=""
[ -n "$tests" ]       && proved="$proved cargo test+clippy ($tests);"
[ -n "$proof_notes" ] && proved="$proved $proof_notes;"
[ -n "$gate" ]        && proved="$proved construction rows ($gate);"
[ -n "$families" ]    && proved="$proved oracle families ($families);"
if [ -z "$proved" ]; then
  echo "land.sh: RED — nothing was proven. The picks touched no crate, no gate script, no workflow" >&2
  echo "land.sh:       and no oracle family, and no --tests/--gate/--families was given, so every" >&2
  echo "land.sh:       leg above was skipped. A landing that ran no check is not a green landing —" >&2
  echo "land.sh:       name what should have proven it, or say why the picks need proving by nothing." >&2
  exit 1
fi
# "landed" is what the pick loop did. Under `--prove` it picked nothing, and saying it landed N
# commits is the one sentence an integrator reads as "these are now on the branch because of this
# run".
if [ "$prove" = 1 ]; then
  echo "land.sh: GREEN — proved $([ $# -gt 0 ] && echo "$# already-landed commit(s)" || echo "the tip commit") at $(git -C "$here" rev-parse --short HEAD); nothing was picked"
else
  echo "land.sh: GREEN — landed $# commit(s) at $(git -C "$here" rev-parse --short HEAD)"
fi
echo "land.sh: proven by:$proved and nothing else. A green here is exactly that list."
