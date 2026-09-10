#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# One landing, the same way every time: cherry-pick a hand-back from an agent worktree onto the
# integration branch, then prove it — the crates it touched, the construction gate rows it names,
# and the oracle families it can move. Stops at the first red and leaves the picks in place so the
# integrator can look; never rewrites history, never pushes.
#
#   scripts/land.sh [--tests "pkg pkg"] [--features "f,f"] [--families 'regex'] [--gate 'rule|rule'] <hash>...
#   scripts/land.sh --batch <file>          # N landing lines, proven ONCE, bisected on red
#   scripts/land.sh --selftest              # prove this script's own refusals
#
# --tests     cargo packages to test after the picks (default: the packages whose files the picks
#             touched, by crate directory).
# --families  a record.sh --filter regex; when given, the candidate binary is rebuilt and those
#             families are recorded on the ports below and diffed against the golden.
# --gate      construction-gate rows (an egrep over the FAIL column) that must not be red after.
#
# ── WHY A BATCH ───────────────────────────────────────────────────────────────────────────────────
# One landing is a build, a test leg, a clippy leg, the gates and an oracle recording: 25–40 minutes,
# almost all of it fixed cost that does not care how many commits are on the tree. Landing N queue
# lines serially pays that fixed cost N times to prove N disjoint claims that a SINGLE run of the
# same legs over the UNION would prove at once. `--batch` pays it once.
#
# The whole difficulty of batching is what a red means. A red over a union names the union, not the
# line, and "the batch is red so nothing lands" would trade throughput for a worse answer than the
# serial queue gave. So a red batch is BISECTED: the tree is reset to the batch's base, the lines are
# split in half, and each half is re-applied and re-proven on its own, recursively, until every line
# is either inside a half that went green or is alone in a half that went red. The invariant that
# makes the result mean the same thing as N serial landings is:
#
#     NO LINE IS EVER MARKED GREEN EXCEPT BY A PROOF RUN AT A TIP THAT CONTAINS ITS PICKS.
#
# There is no inference step, no "the other half was red so this one must be green". A green half is
# proven green by its own run of the same legs a serial landing would have run, over the union of
# exactly the lines in it.
set -uo pipefail
here="$(cd "$(dirname "$0")/.." && pwd)"
# The selftest drives this whole engine against a scratch repository; everything below reads $here.
[ -n "${LAND_SELFTEST_ROOT:-}" ] && here="$LAND_SELFTEST_ROOT"

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

# THE PORTS ARE DEFAULTS, NOT PINS. The landing queue relies on this triple, so it stays the
# default; but two worktrees recording at once on one host would both bind it, and record.sh's own
# occupied-port guard would turn that collision into a RED attributed to whichever commits happened
# to be picked. An operator running a second landing sets these in the environment and gets a
# recording of their own binary; the RED path below prints the triple so a collision reads as one.
#
# ONE KNOB MOVES ALL OF THEM. K disjoint shards each bind a six-port block inside a 20-wide range
# derived from LAND_ORACLE_PORT_BASE: shard k takes base+20k+{1,2,11,13,14} (and base+20k+3 for the
# script cells' mock, which record.sh derives as ADMIN+1). The first three blocks are therefore
# 49901/49902/49911, 49921/49922/49931 and 49941/49942/49951 — the triples the landing queue has
# always used — and `LAND_ORACLE_PORT_BASE=49700` moves EVERY shard, including the single-shard
# case. It did not, once: the k=1 path read ORACLE_LISTEN_PORT's own default and went on binding
# 49911 while the operator believed the whole run had been moved out of the way, which is how a
# port collision with a neighbouring worktree gets recorded as a red attributed to the picks.
LAND_ORACLE_SHARDS="${LAND_ORACLE_SHARDS:-3}"
LAND_ORACLE_PORT_BASE="${LAND_ORACLE_PORT_BASE:-49900}"
ORACLE_LISTEN_PORT="${ORACLE_LISTEN_PORT:-$((LAND_ORACLE_PORT_BASE + 1))}"
ORACLE_ADMIN_PORT="${ORACLE_ADMIN_PORT:-$((LAND_ORACLE_PORT_BASE + 2))}"
ORACLE_MOCK_PORT="${ORACLE_MOCK_PORT:-$((LAND_ORACLE_PORT_BASE + 11))}"
# merged (default): one diff over `busbar-oracle merge`d parts, so --strict's "zero owed cells" is
# asked of the whole requested set at once. per-shard: one diff per shard against that shard's own
# id filter, red if ANY shard is red — the honest fallback when a merge is refused.
LAND_ORACLE_DIFF="${LAND_ORACLE_DIFF:-merged}"

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# ARGUMENT PARSING, as a function so a batch line is parsed by the same code as a command line.
# Sets P_tests P_features P_families P_gate P_prove P_hashes.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
land_parse_args() {
  P_tests=""; P_features=""; P_families=""; P_gate=""; P_prove=0; P_hashes=""; P_batch=""; P_selftest=0
  P_preprove=0
  P_remote="${P_remote:-}"
  # --to is a POSTURE for the whole run, the same way --remote is a HOST for the whole run: a batch
  # LINE cannot pick its own destination any more than it can pick its own box, because the tree is
  # proven once and either promoted whole or not at all. So --to is preserved across the per-line
  # re-parse in land_run_batch exactly the way --remote is, by reading its own prior value as the
  # default instead of the flat "" every other P_ variable resets to.
  P_to="${P_to:-}"
  while [ $# -gt 0 ]; do
    case "$1" in
      --tests) P_tests="$2"; shift 2 ;;
      # --features: cargo features the tests and clippy legs compile with. A cell behind a
      # feature that the proof never enables is a cell the proof never ran: the root mount cells
      # (root-a2a-serve, root-mcp-serve) were 60 tests that `cargo test -p busbar` never compiled.
      # Comma-separated; a batch unions them (a feature set is additive).
      --features) P_features="$2"; shift 2 ;;
      --families) P_families="$2"; shift 2 ;;
      --gate) P_gate="$2"; shift 2 ;;
      --batch) P_batch="$2"; shift 2 ;;
      --selftest) P_selftest=1; shift ;;
      # --remote: honoured ONLY at the top level (see MAIN). land_parse_args also parses every
      # batch LINE, and a line cannot choose its own host — the whole batch is proven on one tree.
      --remote) P_remote="$2"; shift 2 ;;
      # --prove: pick nothing; prove the tip as it stands (a landing whose picks are already on
      # the tree but whose legs were never run to green).
      --prove) P_prove=1; shift ;;
      # --to: which line this run is landing TOWARD — dev (default), qa or main. It does not choose
      # what gets run; every posture runs the identical legs. What it changes is documented next to
      # land_construction_standing_reds and land_refuse_red_overrides: qa/main refuse the standing-red
      # allowance and refuse every environment override that could turn a red into a land. Validated
      # in MAIN, not here, so land_parse_args stays a pure "read the flags" function and the refusal
      # (with its exit code and its message) lives in one place the selftest can call directly.
      --to) P_to="$2"; shift 2 ;;
      # --preprove: the same as LAND_PREPROVE=1, AS AN ARGUMENT, and it has to be one.
      #
      # scripts/land-remote.sh hands the box a FIXED environment — PATH, the cargo and sccache
      # variables, LAND_REMOTE_INNER, the oracle port base — and forwards the ARGV. So a
      # `LAND_PREPROVE=1` set on this side reached the local process and nothing else: the box ran
      # an ordinary landing, published its tip, and the transport fast-forwarded the caller's tree
      # to a landing they had asked NOT to take. A mode that is silently dropped by the transport
      # is worse than no mode. The argv is what travels, so the mode travels on the argv.
      --preprove) P_preprove=1; shift ;;
      *) break ;;
    esac
  done
  P_hashes="$*"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE FLOOR: which legs run when the caller named nothing.
#
# This is a function, not four `if`s inline, for one reason: it is the answer to "can a landing run
# no check and still print GREEN". prove_tree runs EXACTLY the tokens this returns and nothing else,
# so the selftest can ask the question directly — a union with no --tests and no --families must
# still come back with build, fmt, clippy and gates in the plan.
#
#   $1 = union tests   $2 = union gate rows   $3 = union families
# tokens: plugins  fmt  gatefiles  tests  clippy  workspace-clippy  kind-isolation  gate  oracle
# ──────────────────────────────────────────────────────────────────────────────────────────────────
land_floor_plan() {
  # $2 (the union's gate rows) is deliberately NOT read any more: it used to decide WHETHER the
  # construction gate ran, and it is now only the row filter the `gate` leg narrows with. The
  # argument stays in the signature because every caller passes it and the leg still wants it.
  local t="$1" f="$3" plan="plugins fmt gatefiles"
  if [ -n "$t" ]; then plan="$plan tests clippy"; fi
  # NOTHING WAS NAMED. The old script skipped the test and clippy legs when `$tests` was empty and
  # went on to print GREEN. A batch makes that worse, not better: one empty line in a union of six
  # would inherit five other lines' proof. When the union names no package and no family, the floor
  # is the whole workspace — expensive, and exactly what "prove it or do not call it landed" costs.
  if [ -z "$t" ] && [ -z "$f" ]; then plan="$plan workspace-clippy"; fi
  plan="$plan kind-isolation"
  # THE CONSTRUCTION GATE IS FLOOR, NOT OPT-IN. This read `[ -n "$g" ] && plan="$plan gate"`, so the
  # gate ran only when the caller passed `--gate` — and `--gate` is a caller-chosen regex over row
  # names, so even then the caller chose how much of it to run. A landing touching only `crates/**`
  # and naming no `--gate` had ZERO of the construction rows evaluated. The one gate a landing opts
  # into is the one gate that never runs. It is unconditional now, exactly like kind-isolation, and
  # the empty `--gate` means EVERY row (the leg substitutes `.`) rather than no rows.
  plan="$plan gate"
  [ -n "$f" ] && plan="$plan oracle"
  echo "$plan"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE CONSTRUCTION GATE'S STANDING REDS.
#
# The construction gate is RED BY DESIGN on HEAD while the work it measures is in flight, so a
# landing cannot simply require every row green. It can require that the red rows are EXACTLY these
# and no others — which is the whole value: a NEW red is a landing that broke something, and it is
# now indistinguishable from nothing.
#
# THIS LIST IS A RATCHET AND IT EXPIRES BY ITSELF. A name here that is no longer red is struck by
# the leg as STALE — red, not tolerated — the same transaction `[gate.ceiling_raises]` forces in
# qa/construction.toml. Otherwise the list would only ever grow, and a list that only grows is the
# report-only posture it exists to replace. Keep it in step with `REPORT_ONLY`'s construction entry
# in xtask/src/gates/mod.rs, which names the same rows for `gate --all`.
#
# `ceiling-rose` is deliberately NOT here: it is red only on the stale `[gate.ceiling_raises]`
# 26 -> 47 entry, which is being struck separately, and naming it would outlive that fix.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE CEILING RATCHET'S VERDICT OVER A CONSTRUCTION --report LOG.  $1 = log path.
#
# A function rather than four lines inline, for the same reason land_floor_plan is one: it is the
# answer to "can this leg report green having measured no ceiling", and the selftest can ask it
# directly instead of staging a whole landing.
#
# THE EMISSION CHECK IS THE POINT. This leg used to be a single grep for
# `^FAIL  (ceiling-rose|ceiling-slack)`, and a grep is satisfied by ABSENCE: rename the row, delete
# the rule, or have it throw before it emits, and the grep matches nothing, the result is empty, and
# the leg reports GREEN having compared no ceiling to anything. The `rows > 0` floor does not help —
# it counts ANY rows, not these two. Measured: renaming `ROW_ROSE` to `ceiling-rose2` passed the old
# leg with rows=112 while the gate itself printed `RED construction: ceiling-rose2: FAIL`.
# A filter that matches nothing is red.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
land_ceiling_verdict() {
  local clog="$1" missing="" bad
  grep -qE '^(PASS|FAIL)  ceiling-rose '  "$clog" || missing="$missing ceiling-rose"
  grep -qE '^(PASS|FAIL)  ceiling-slack ' "$clog" || missing="$missing ceiling-slack"
  if [ -n "$missing" ]; then
    echo "land.sh: RED — the construction gate emitted no row for:$missing — the ceiling ratchet was not measured at all (renamed or deleted rule?) (log: $clog)" >&2
    return 1
  fi
  bad="$(grep -E '^FAIL  (ceiling-rose|ceiling-slack) ' "$clog" || true)"
  if [ -n "$bad" ]; then
    printf '%s\n' "$bad" >&2
    echo "land.sh: RED — a ceiling rose, or a ceiling has slack under it (log: $clog)" >&2
    return 1
  fi
  return 0
}

# THE LIST BELOW IS A DEV-LINE CONVENIENCE, NOT A GRANT. It exists so that a landing on the
# integration branch is not held hostage by a red the team already knows about and has not gotten
# around to fixing — the dev line moves fast, and a fixed cost re-litigated on every single landing
# is a tax nobody would pay, so a handful of NAMED, DATED rows are allowed to stay red there. That
# reasoning does not survive contact with qa or main. A promotion is the one moment the tree is
# claimed clean enough to ship, and "clean enough to ship, except for the rows we have gotten used
# to ignoring" is not clean — it is the dev line's backlog laundered through a gate that was
# supposed to stop exactly that. So under `--to qa` or `--to main` this function hands back NOTHING:
# every construction FAIL row, including every row on the list below, aborts the gate leg. The
# operator is not left to guess what the dev line was carrying — the refusal message NAMES every
# row on the list, because a promotion that silently drops a waiver without saying so reads, from
# the log, exactly like a landing that never had one.
land_construction_standing_reds() {
  local reds
  reds="$(cat <<'EOF'
hold-discipline:cancellation-before-await
hold-escapes
kernel-seal-impls
one-pick-site
one-pricing-site:fee-fields
plane-no-money
ports-only-tests:busbar-llm
request-path-fn-size
terminal-doors-in-audit-step
EOF
)"
  case "${P_to:-}" in
    qa|main)
      echo "land.sh: the standing-red allowance is a DEV-LINE CONVENIENCE, not a grant this run" >&2
      echo "land.sh: inherits — a promotion to $P_to carries NONE of it, so every construction row" >&2
      echo "land.sh: must be green here, full stop. Rows that are standing red on the dev line (and" >&2
      echo "land.sh: therefore now BLOCK this $P_to promotion unless they have since gone green):" >&2
      printf '%s\n' "$reds" | sed 's/^/land.sh:   /' >&2
      return 0
      ;;
  esac
  printf '%s\n' "$reds"
}

# THE GATE LEG'S VERDICT, PULLED OUT OF THE prove_tree CASE ARM SO IT IS A FUNCTION THE SELFTEST CAN
# CALL ON A FIXTURE LOG. This is exactly the land_ceiling_verdict move above, for the same reason: a
# case arm buried inside prove_tree can only be exercised by staging a whole landing, and the one
# fact that matters here — does a standing-red row under `--to qa` still abort the leg — has to be
# provable without building the real xtask gate binary. The behaviour is byte-identical to what used
# to live inline; only the seam moved.
#   $1 = construction gate --report log     $2 = row regex (default: every row)
land_gate_verdict() {
  local glog="$1" grx="${2:-.}"
  # The gate's own exit status is not the verdict here (its verdict covers every rule); what this
  # leg proves is that the named rows were MEASURED and are not red. A gate that produced no rows at
  # all (an unreadable ceilings file, an unbuildable runner) is red, not green.
  local rows; rows="$(grep -cE '^(PASS|FAIL)  ' "$glog" || true)"
  [ "${rows:-0}" -gt 0 ] || { echo "land.sh: RED — construction gate produced no rows (log: $glog)" >&2; return 1; }
  local named; named="$(grep -E '^(PASS|FAIL)  ' "$glog" | awk '{print $2}' | grep -E "$grx" || true)"
  [ -n "$named" ] || { echo "land.sh: RED — no gate row matches '$grx' (renamed rule?)" >&2; return 1; }
  local red; red="$(grep -E '^FAIL  ' "$glog" | awk '{print $2}' | grep -E "$grx" || true)"
  # THE STANDING REDS ARE SUBTRACTED, AND THE LIST IS ITSELF RATCHETED. Anything red that the list
  # does not name is a NEW red — the landing broke it. Anything the list names that is no longer red
  # is a STALE entry, and a stale entry is red too: that is what stops this list becoming a
  # permanent, undated waiver that only ever grows. Under `--to qa`/`--to main`,
  # land_construction_standing_reds hands back nothing at all, so every row it would otherwise have
  # excused falls straight into "new red" here and aborts the leg — there is no second allowance to
  # thread past this check.
  local standing; standing="$(land_construction_standing_reds)"
  local scoped_standing; scoped_standing="$(printf '%s\n' "$standing" | grep -E "$grx" || true)"
  local newred; newred="$(comm -23 <(printf '%s\n' "$red" | grep -v '^$' | sort -u) <(printf '%s\n' "$standing" | grep -v '^$' | sort -u))"
  [ -z "$newred" ] || { printf 'land.sh: new construction red(s): %s\n' "$(echo $newred)" >&2
         echo "land.sh: RED — construction gate rows red that the standing list does not name (log: $glog)" >&2; return 1; }
  local stale; stale="$(comm -13 <(printf '%s\n' "$red" | grep -v '^$' | sort -u) <(printf '%s\n' "$scoped_standing" | grep -v '^$' | sort -u))"
  [ -z "$stale" ] || { printf 'land.sh: standing red(s) no longer red: %s\n' "$(echo $stale)" >&2
         echo "land.sh: RED — strike them from land_construction_standing_reds (and from REPORT_ONLY in xtask/src/gates/mod.rs)" >&2; return 1; }
  echo "land.sh: gate rows green apart from the standing reds: $grx"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --to: THE POSTURE, AND THE LAW THAT A RED CANNOT SURVIVE IT TO qa OR main.
#
# Everything above this comment already does the load-bearing work of PROVING green: build, tests,
# clippy, the construction gate, the oracle. What was missing was a way to say, from the runner
# itself, "this proof is for a promotion" — and to have that statement mean something stronger than
# a label. The three functions below are that meaning. `land_validate_to` refuses a `--to` value
# this script does not recognise. `land_refuse_red_overrides` refuses, before a single cherry-pick
# or a single leg runs, any environment variable that exists to let a red through, whenever the
# posture is qa or main. `land_print_posture` puts both facts in the run's own output, because a
# safety property nobody can see in the log is a safety property nobody can audit after the fact.
#
# THE REASONING, WRITTEN OUT, BECAUSE IT IS THE WHOLE POINT OF THIS SECTION: an override flag that
# still works in qa/main posture is not a smaller version of the gate — it is the ABSENCE of the
# gate wearing the gate's clothes. A gate that can be turned off by an environment variable set
# somewhere upstream (a CI job template, a shell profile on a landing box, a stale `export` from an
# earlier debugging session) protects nothing, because the property it is meant to guarantee —
# "nothing red reaches qa or main" — now depends on an operator remembering NOT to have set
# something, which is exactly the class of failure a gate exists to remove. So in this posture the
# checks below are not "an extra confirmation step"; refusing the override IS the gate.
# ──────────────────────────────────────────────────────────────────────────────────────────────────

# The full set of `--to` values this runner understands. `dev` and the empty string (no `--to` at
# all) are the SAME posture — today's unposture behaviour, byte-for-byte — named explicitly so an
# operator can write `--to dev` and mean it, without that spelling being treated as unrecognised.
land_validate_to() {  # $1 = the raw --to value (may be "")
  case "$1" in
    ""|dev|qa|main) return 0 ;;
    *)
      echo "land.sh: refused — '--to $1' is not a posture this runner knows. Accepted values are:" >&2
      echo "land.sh:   dev   (default; today's behaviour, standing reds allowed, overrides honoured)" >&2
      echo "land.sh:   qa    (promotion posture; standing-red allowance refused, overrides refused)" >&2
      echo "land.sh:   main  (promotion posture; standing-red allowance refused, overrides refused)" >&2
      return 1 ;;
  esac
}

# THE FIVE NAMES BELOW ARE EVERY ENVIRONMENT VARIABLE IN THIS SCRIPT WHOSE JOB IS TO LET SOMETHING
# RED THROUGH. A grep of the rest of land.sh at the time this was written turns up none of them
# already wired to anything — there is no pre-existing `LAND_PUSH_ANYWAY`, `LAND_CI_RED_OK`,
# `LAND_FORCE`, `LAND_SKIP_GATES` or `LAND_ALLOW_RED` reader in this file today. That is exactly WHY
# they are refused unconditionally here rather than "refused if set to override something": the law
# this function exists to enforce is that qa/main posture cannot be talked out of a red BY ANY NAME,
# including names nobody has gotten around to wiring an override to yet. Refusing the variable up
# front, before it has a job, is cheaper than discovering after the fact that someone gave it one.
land_refuse_red_overrides() {
  case "${P_to:-}" in
    qa|main) ;;
    *) return 0 ;;
  esac
  local v
  for v in LAND_PUSH_ANYWAY LAND_CI_RED_OK LAND_FORCE LAND_SKIP_GATES LAND_ALLOW_RED; do
    if [ -n "${!v:-}" ]; then
      echo "land.sh: REFUSED (posture-refuses-override) — $v is set and --to ${P_to} forbids any" >&2
      echo "land.sh: override that could let a red through. An override that still works in" >&2
      echo "land.sh: qa/main posture is not a smaller gate, it is no gate at all. Unset $v and" >&2
      echo "land.sh: re-run, or drop --to $P_to if this really is a dev-line landing." >&2
      return 1
    fi
  done
  return 0
}

# THE POSTURE HEADER. Printed on every run, not only qa/main, because "this is a dev-line landing
# and standing reds are allowed" is exactly as much a fact about the run as "this is a qa promotion
# and none are" — an operator scrolling a log should never have to infer which posture ran from the
# absence of a line.
land_print_posture() {
  local to="${1:-dev}"; [ -n "$to" ] || to=dev
  echo "land.sh: posture: --to $to"
  case "$to" in
    qa|main)
      echo "land.sh: qa/main posture — no standing-red allowance and no environment override can turn a red into a land here." ;;
  esac
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# WHICH TOUCHED FILES ARE THE GATES' OWN.
#
# Two sets, because they are proven two different ways, and both are functions so the selftest can
# assert the patterns directly rather than by reading the log of a landing.
#
#   land_gate_scripts  the runnable gates: parsed, and their own --selftest run.
#   land_gate_data     the gates' DATA and SOURCE: qa/*.toml and xtask/src/gates/**.
#
# The second set is the one that was missing, and the gap was measured: `gatefiles` matched only
# `^(scripts|testing|\.github)/.*\.(sh|py|mjs|yml|yaml)$`, so a landing whose only edit was
# `legacy-reach.ceiling: 92 -> 200` in qa/construction.toml selected NO cargo package, ran plugins,
# fmt, gatefiles (zero files), workspace-clippy and kind-isolation, and printed GREEN having
# executed nothing that reads a ceiling. Raising a ceiling was the cheapest unproven landing in the
# tree. The same held for the gate SOURCE: `xtask/src/gates/**` is where every ratchet, exemption
# table and waiver list lives, and none of it was a gate file either.
# ──────────────────────────────────────────────────────────────────────────────────────────────────

land_gate_scripts() {  # $1 = newline-separated touched paths
  printf '%s\n' "$1" | grep -E '^(scripts|testing|\.github)/.*\.(sh|py|mjs|yml|yaml)$' || true
}

land_gate_data() {  # $1 = newline-separated touched paths
  printf '%s\n' "$1" | grep -E '^(qa/.*\.toml|xtask/src/gates/.*\.rs)$' || true
}
# The gate RUNNER itself: any file under xtask/. A line that touches it re-proves every registered
# gate's self-test and the registry-vs-workflow equality (below); a line that does not, does not
# pay the ~50 minutes for evidence the previous landing already produced on an identical runner.
land_xtask_touched() {  # $1 = newline-separated touched paths
  printf '%s\n' "$1" | grep -E '^xtask/' || true
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# SHARDING THE ORACLE RECORDING.
#
# record.sh selects cells with bash's own `[[ "$id" =~ $FILTER ]]` (record.sh:958) — an UNANCHORED
# ERE over the cell id. Every function below therefore matches with `[[ =~ ]]` too, never with grep
# and never with python's `re`: a partition asserted with a different matcher than the recorder uses
# is not an assertion about what will be recorded.
#
# The shard unit is the FAMILY — the id's first `|`-field — because that is the unit the queue's own
# --families regexes are written in, and because a family-anchored shard filter is small enough to
# read in a log. A shard may record MORE than was requested (a filter that selects part of a family
# still drags the whole family into its shard); that is sound, because the ONE diff at the end is
# id-filtered by the caller's own regex. What would not be sound is a shard boundary that DROPS a
# requested cell or that records one cell twice, and both are refused below.
# ──────────────────────────────────────────────────────────────────────────────────────────────────

# All cell ids, one per line. Extraction only — the matching is bash's.
land_cell_ids() {
  python3 -c 'import json,sys,signal
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
d=json.load(open(sys.argv[1]))
for c in d["cells"]: print(c["id"])' "$here/testing/shadow-oracle/cells.json"
}
# id<TAB>1 when record.sh can produce a PASS row for it, id<TAB>0 when it cannot.
#
# record.sh:995-997 SKIPs the whole mcp and a2a planes unconditionally ("proven by its conformance
# rig, not recorded here"), and record.sh:1318-1320 exits 1 on "ZERO ROWS IS RED". Those two facts
# together are a sharding hazard that has nothing to do with the picked commits: pack the 912-cell
# mcp family into a shard of its own and that shard records 912 skips, counts zero, and exits 1 —
# a RED landing where the unsharded run was green. So the packer weights families by RECORDABLE
# cells and refuses to emit a shard that has none.
land_cell_recordable() {
  python3 -c 'import json,sys,signal
signal.signal(signal.SIGPIPE, signal.SIG_DFL)
d=json.load(open(sys.argv[1]))
for c in d["cells"]:
    print("%s\t%d" % (c["id"], 0 if c.get("plane") in ("mcp","a2a") else 1))' \
    "$here/testing/shadow-oracle/cells.json"
}

# ERE-escape a family token. The id charset is [A-Za-z0-9 ()+-./|_]; bracket classes are used rather
# than backslashes because `\|` and `\+` are not portable ERE.
land_ere_escape() {
  printf '%s' "$1" | sed -e 's/[.]/[.]/g' -e 's/|/[|]/g' -e 's/(/[(]/g' -e 's/)/[)]/g' -e 's/+/[+]/g'
}

# land_shard_plan <filter> <K>  -> prints one shard filter per line; non-zero and a reason on stderr
# when the requested set is empty (zero rows is red, never a fast green).
land_shard_plan() {
  local filter="$1" k="$2" id fam rec
  local all; all="$(land_cell_recordable)" || return 1
  [ -n "$all" ] || { echo "land.sh: RED — cells.json enumerated no cells" >&2; return 1; }
  # The requested set as `<family> <recordable>` rows.
  local req
  req="$(
    while IFS="$(printf '\t')" read -r id rec; do
      [ -n "$id" ] || continue
      if [[ "$id" =~ $filter ]]; then printf '%s %s\n' "${id%%|*}" "$rec"; fi
    done <<EOF
$all
EOF
  )"
  [ -n "$req" ] || {
    echo "land.sh: RED — the family filter selects ZERO cells: $filter" >&2
    echo "land.sh:       a recording of nothing diffs green against nothing. Name families that exist." >&2
    return 1
  }
  # Families that can produce a PASS row, heaviest first; then the inert ones (mcp/a2a), which cost
  # nothing to record and must never be alone in a shard.
  local live inert nf
  live="$(printf '%s\n' "$req" | awk '$2==1{c[$1]++} END{for (f in c) printf "%d %s\n", c[f], f}' | sort -rn | awk '{print $2}')"
  inert="$(printf '%s\n' "$req" | awk '$2==0{c[$1]++} END{for (f in c) printf "%d %s\n", c[f], f}' | sort -rn | awk '{print $2}')"
  [ -n "$live" ] || {
    echo "land.sh: RED — every cell the filter selects is on a plane record.sh never records" >&2
    echo "land.sh:       (mcp/a2a are proven by their conformance rigs). record.sh would exit on" >&2
    echo "land.sh:       ZERO ROWS IS RED whether this ran sharded or not: $filter" >&2
    return 1
  }
  nf="$(printf '%s\n' "$live" | grep -c .)"
  [ "$k" -ge 1 ] 2>/dev/null || k=1
  [ "$k" -le "$nf" ] || k="$nf"
  # Greedy largest-first bin packing: the point of sharding is wall clock, and wall clock is the
  # slowest shard, so the heaviest family must not share a shard with the second-heaviest while a
  # third shard records five cells.
  local i best bestload n
  local -a shardf shardload
  i=0; while [ "$i" -lt "$k" ]; do shardf[$i]=""; shardload[$i]=0; i=$((i + 1)); done
  # LIVE first (weighted, so every shard ends with at least one recordable family), then INERT.
  while IFS= read -r fam; do
    [ -n "$fam" ] || continue
    n="$(printf '%s\n' "$req" | awk -v f="$fam" '$1==f && $2==1' | grep -c .)"
    best=0; bestload="${shardload[0]}"; i=1
    while [ "$i" -lt "$k" ]; do
      if [ "${shardload[$i]}" -lt "$bestload" ]; then best="$i"; bestload="${shardload[$i]}"; fi
      i=$((i + 1))
    done
    if [ -z "${shardf[$best]}" ]; then shardf[$best]="$(land_ere_escape "$fam")"
    else shardf[$best]="${shardf[$best]}|$(land_ere_escape "$fam")"; fi
    shardload[$best]=$(( ${shardload[$best]} + n ))
  done <<EOF
$live
EOF
  local j=0
  while IFS= read -r fam; do
    [ -n "$fam" ] || continue
    best=$(( j % k )); j=$((j + 1))
    shardf[$best]="${shardf[$best]}|$(land_ere_escape "$fam")"
  done <<EOF
$inert
EOF
  i=0; while [ "$i" -lt "$k" ]; do
    [ -n "${shardf[$i]}" ] && printf '^(%s)[|]\n' "${shardf[$i]}"
    i=$((i + 1))
  done
  return 0
}

# land_shard_assert <filter> <shard-re>...  -> 0 when the shards are a partition that covers the
# requested set, non-zero (with the offending cell named) otherwise. This is the gate on the
# sharding, and it is deliberately callable on a plan this script did not produce so the selftest
# can hand it a KNOWN-BAD plan and watch it refuse.
land_shard_assert() {
  local filter="$1"; shift
  [ $# -gt 0 ] || { echo "land.sh: RED — no shards to assert" >&2; return 1; }
  local -a res; local i=0
  for r in "$@"; do res[$i]="$r"; i=$((i + 1)); done
  local n_shards=$i
  local all; all="$(land_cell_ids)"
  local id hits j req=0 covered=0 over=0
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    hits=0; j=0
    while [ "$j" -lt "$n_shards" ]; do
      if [[ "$id" =~ ${res[$j]} ]]; then hits=$((hits + 1)); fi
      j=$((j + 1))
    done
    if [ "$hits" -gt 1 ]; then
      echo "land.sh: RED — shards are not disjoint: cell '$id' is recorded by $hits shards" >&2
      return 1
    fi
    if [[ "$id" =~ $filter ]]; then
      req=$((req + 1))
      if [ "$hits" -eq 0 ]; then
        echo "land.sh: RED — shard union does not cover the requested set: '$id' is in no shard" >&2
        return 1
      fi
      covered=$((covered + 1))
    elif [ "$hits" -eq 1 ]; then over=$((over + 1)); fi
  done <<EOF
$all
EOF
  [ "$req" -gt 0 ] || { echo "land.sh: RED — the requested family set is empty" >&2; return 1; }
  echo "land.sh: shards: $n_shards, disjoint, covering all $req requested cell(s) (+$over recorded over)"
  return 0
}

# land_shards_collect <dir-prefix> <K>  -> 0 only when every shard exited 0 AND left a recording.
# A shard that died is a landing that is RED, never a landing that is green over the shards that
# happened to survive: the merged recording would simply be missing those cells and --strict would
# have nothing to complain about because it was never told they were owed by THIS run.
land_shards_collect() {
  local pre="$1" k="$2" i=0 bad=0
  while [ "$i" -lt "$k" ]; do
    local d="$pre$i" rc
    rc="$(cat "$d.rc" 2>/dev/null || echo missing)"
    if [ "$rc" != "0" ]; then
      echo "land.sh: RED — oracle shard $i exited '$rc' (see $d.log)" >&2; bad=1
    elif [ ! -d "$d" ] || [ -z "$(ls -A "$d" 2>/dev/null)" ]; then
      echo "land.sh: RED — oracle shard $i left no recording in $d" >&2; bad=1
    fi
    i=$((i + 1))
  done
  return "$bad"
}

# land_ledger_assert <filter> <dir-prefix> <K>  -> 0 when the parts' ledgers are disjoint and cover
# every requested cell. Callable on directories this script did not produce, so the selftest can
# hand it a ledger pair it knows is wrong and watch it refuse.
land_ledger_assert() {
  local filter="$1" pre="$2" k="$3" i=0 rows=0
  local tmp; tmp="$(mktemp -t land-ledger.XXXXXX)" || return 1
  : >"$tmp"
  while [ "$i" -lt "$k" ]; do
    [ -f "$pre$i/ledger.tsv" ] || {
      echo "land.sh: RED — oracle shard $i wrote no ledger; what it recorded is unmeasurable" >&2
      rm -f "$tmp"; return 1; }
    cut -f1 "$pre$i/ledger.tsv" >>"$tmp"
    i=$((i + 1))
  done
  rows="$(grep -c . "$tmp" || true)"
  [ "${rows:-0}" -gt 0 ] || {
    echo "land.sh: RED — the shard ledgers hold no rows at all. Zero rows is red." >&2
    rm -f "$tmp"; return 1; }
  local dup; dup="$(sort "$tmp" | uniq -d | head -3)"
  [ -z "$dup" ] || {
    echo "land.sh: RED — shards recorded the same cell twice: $(echo $dup)" >&2
    rm -f "$tmp"; return 1; }
  local recorded; recorded="$(sort -u "$tmp")"
  local id miss=0
  while IFS= read -r id; do
    [ -n "$id" ] || continue
    if [[ "$id" =~ $filter ]]; then
      printf '%s\n' "$recorded" | grep -qxF -- "$id" || {
        echo "land.sh: RED — requested cell '$id' was recorded by no shard" >&2; miss=$((miss + 1)); }
    fi
    [ "$miss" -lt 3 ] || break
  done <<EOF
$(land_cell_ids)
EOF
  rm -f "$tmp"
  [ "$miss" -eq 0 ] || return 1
  echo "land.sh: shard ledgers: $rows row(s), disjoint, covering every requested cell"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE TWO LONG SELF-TESTS, SPLIT OVER THE FLEET
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# `cargo xtask gate kind-isolation --selftest` is 1508 s on the laptop and 1642 s on a fleet box;
# `construction --selftest` is 370-420 s. Both run on EVERY landing by design, and both are ONE
# process on ONE box while seven boxes idle. `--shard k/n` partitions the case list by index (see
# `gates::Shard`), so the same battery runs on up to four boxes at once.
#
# THE SAME PROOF, NOT A SMALLER ONE. That is the whole claim, and it rests on three refusals:
#
#   * every shard must be GREEN. Nothing is inferred from a sibling's verdict.
#   * every shard must REPORT. A shard whose exit status never came back is RED — not skipped, not
#     "the box was busy". A box that does not vote is not a box that voted yes, and the reason this
#     is written down is that "the transport failed so we ran the other three" is exactly how a
#     four-box leg quietly becomes a three-quarter proof.
#   * the UNION must be the whole list. Every shard prints `shard k/n: X of TOTAL case(s)`; the
#     shards must agree about TOTAL (they ran the same tree) and their X must SUM to it. That is
#     what makes "no case was lost" a measurement rather than a hope, and it needs no unsharded run
#     to compare against — which is the run this exists to avoid taking.
#
# OFF BY DEFAULT. With `LAND_SELFTEST_SHARDS` unset, every landing runs exactly what it ran before.
#
# ── THE FAN-OUT IS ORCHESTRATED FROM THE LAPTOP, NOT FROM THE BOX ─────────────────────────────────
# A fleet box cannot reach a sibling: it has no ~/.busbar-fleet, no ~/.busbar-fleet-ssh, no aws on
# PATH, and box-to-box tcp/22 is CLOSED (probed 2026-09-09; the security group is egress-only, as
# scripts/ci-remote-lib.sh's header says). The laptop that launched the landing reaches every box.
# So the fan-out is a REQUEST/DELIVER protocol between this copy of land.sh on the primary box and
# scripts/land-remote.sh on the laptop, and it has to be a protocol rather than a one-shot launch
# because the tree a shard must prove is THIS box's cherry-picked tip — it exists nowhere else — and
# a red batch BISECTS, running these legs again per half at a tip that did not exist a minute ago.
#
#   * this box runs shard 1 itself, pushes its tree to its OWN bare repo under refs/heads/<req>, and
#     writes `<dir>/REQUEST` (`gate= n= sha= ref= ceil=`). Then it WAITS.
#   * the laptop polls the primary for REQUEST files (the same 60 s poll that streams the log),
#     fetches the sha from the primary's bare repo, pushes it to n-1 distinct least-loaded siblings,
#     runs `cargo xtask gate <g> --selftest --shard k/n` detached on each, and when a sibling's exit
#     status is on disk copies its log and then its .rc into `<dir>` here — log first, because the
#     .rc is the signal.
#   * this box's union check (land_shard_union, unchanged) reads what was delivered. A shard whose
#     .rc never arrived — the laptop went away, the sibling died, the deadline passed — is RED with
#     "never reported", exactly as before. THIS BOX NEVER FABRICATES A SIBLING'S VERDICT; it can only
#     read what the laptop put on its disk, and with `LAND_SHARD_FANOUT=laptop` set it cannot go
#     green on shard 1 alone, because the union is short by n-1 shards until they are delivered.
#   * the laptop keeps its own copy of every shard's log and .rc and re-runs the same union check
#     over them after this box reports; a green from here that the laptop's copies do not support
#     is refused there. The join therefore happens in two places that must agree, and the laptop's
#     is the authoritative one.
#
# `LAND_SHARD_FANOUT=laptop` is set by land-remote.sh's remote environment and by nothing else. On a
# box without it (an older transport that does not serve requests) the shards run SEQUENTIALLY here
# — the same proof, on one box. Set without LAND_REMOTE_INNER it is a refusal: nobody serves
# requests for a landing that was not launched through the transport.

# The shard count, validated. Empty or 1 is "do not shard"; anything above 4 or not a number is a
# REFUSAL rather than a silent fallback, because a caller who wrote `LAND_SELFTEST_SHARDS=eight`
# and got an unsharded run would believe eight boxes had proven it.
land_shard_count() {
  local n="${LAND_SELFTEST_SHARDS:-}"
  [ -n "$n" ] || { echo 0; return 0; }
  case "$n" in
    *[!0-9]*) echo "land.sh: RED — LAND_SELFTEST_SHARDS='$n' is not a number" >&2; return 1 ;;
  esac
  [ "$n" -le 4 ] || { echo "land.sh: RED — LAND_SELFTEST_SHARDS=$n: at most 4 boxes take a leg" >&2; return 1; }
  [ "$n" -ge 2 ] || { echo 0; return 0; }
  echo "$n"
}

# THE UNION CHECK, over the logs the shards left behind. See the three refusals above.
land_shard_union() { # $1 = gate  $2 = n  $3 = dir
  local g="$1" n="$2" dir="$3" k rc line owned total first="" sum=0
  k=1
  while [ "$k" -le "$n" ]; do
    rc="$(cat "$dir/shard-$k.rc" 2>/dev/null || true)"
    if [ -z "$rc" ]; then
      echo "land.sh: RED — $g self-test shard $k/$n never reported an exit status. A box that did not vote is not a box that voted yes (log: $dir/shard-$k.log)" >&2
      return 1
    fi
    if [ "$rc" != 0 ]; then
      grep -E 'FAILED|REFUSED|expected|infra|^  - ' "$dir/shard-$k.log" 2>/dev/null | head -12 >&2
      echo "land.sh: RED — $g self-test shard $k/$n exited $rc (log: $dir/shard-$k.log)" >&2
      return 1
    fi
    line="$(grep -E "^ *shard $k/$n: [0-9]+ of [0-9]+ case\(s\)$" "$dir/shard-$k.log" 2>/dev/null | tail -1)"
    if [ -z "$line" ]; then
      echo "land.sh: RED — $g self-test shard $k/$n exited 0 without printing its case count. A shard that does not say what it ran has not reported (log: $dir/shard-$k.log)" >&2
      return 1
    fi
    owned="$(printf '%s\n' "$line" | awk '{print $3}')"
    total="$(printf '%s\n' "$line" | awk '{print $5}')"
    [ -n "$first" ] || first="$total"
    if [ "$total" != "$first" ]; then
      echo "land.sh: RED — $g self-test shards disagree about the case list: shard $k/$n counted $total case(s), an earlier shard counted $first. They did not prove the same tree." >&2
      return 1
    fi
    sum=$((sum + owned))
    k=$((k + 1))
  done
  if [ "$sum" != "$first" ]; then
    echo "land.sh: RED — $g self-test: $n shard(s) own $sum of $first case(s). $((first - sum)) case(s) were proven by nobody, so this is a smaller proof, not a faster one." >&2
    return 1
  fi
  echo "land.sh: $g self-test: $n shard(s) green, $sum of $first case(s), union complete"
  return 0
}

# PUBLISH THE TREE FOR THE SIBLINGS. A function of its own so the self-test can stand in for the
# transport (there is no `prove` remote on a laptop) without standing in for anything else.
land_shard_publish() { # $1 = ref
  git -C "$here" push -q --force prove "HEAD:refs/heads/$1"
}

# THE REQUEST/WAIT ARM. Shard 1 here, in the background; the tree published; the request written
# atomically (a laptop that reads a half-written request would launch the wrong thing, so the file
# appears complete or not at all); then a wait on the siblings' .rc files bounded by the gate's own
# ceiling plus the transport's share (clone, xtask build, two copies) — LAND_SHARD_WAIT_SECS overrides
# for the self-test. The wait ENDS; it does not decide. land_shard_union decides, over whatever is
# on disk when it ends.
land_shard_request() { # $1 gate  $2 n  $3 dir  $4 CEIL=VALUE
  local g="$1" n="$2" dir="$3" ceil="$4" pid1 k ref sha t0 deadline all
  ( cd "$here" && env "$ceil" cargo xtask gate "$g" --selftest --shard "1/$n" >"$dir/shard-1.log" 2>&1 ) &
  pid1=$!
  ref="shardreq-$stamp-$LAND_SHARD_SEQ"
  sha="$(git -C "$here" rev-parse HEAD)"
  if ! land_shard_publish "$ref" >"$dir/publish.log" 2>&1; then
    # No tree for the siblings means no shards for the siblings: each is RED with the reason, and
    # the union will say so. Shard 1 still finishes, because it is a fact about the tree.
    k=2
    while [ "$k" -le "$n" ]; do
      { echo "land.sh: shard $k/$n: this box could not publish its tree for the fan-out (refs/heads/$ref); see publish.log"; cat "$dir/publish.log"; } >"$dir/shard-$k.log"
      echo 2 >"$dir/shard-$k.rc"; k=$((k + 1))
    done
    wait "$pid1"; echo $? >"$dir/shard-1.rc"; return 0
  fi
  printf 'gate=%s n=%s sha=%s ref=%s ceil=%s\n' "$g" "$n" "$sha" "$ref" "$ceil" >"$dir/REQUEST.tmp"
  mv "$dir/REQUEST.tmp" "$dir/REQUEST"
  echo "land.sh: $g self-test in $n shard(s): shard 1 here; shards 2..$n requested from the laptop ($dir/REQUEST, tree $(printf '%.9s' "$sha"))"
  deadline="${LAND_SHARD_WAIT_SECS:-$(( ${ceil#*=} + 900 ))}"
  t0="$(date +%s)"
  while :; do
    all=1; k=2
    # -s, not -f: a .rc that exists and is still empty is a delivery in progress, not a verdict.
    while [ "$k" -le "$n" ]; do [ -s "$dir/shard-$k.rc" ] || all=0; k=$((k + 1)); done
    [ "$all" = 1 ] && break
    [ $(( $(date +%s) - t0 )) -lt "$deadline" ] || {
      echo "land.sh: $g self-test: waited ${deadline}s for the siblings' verdicts; what arrived is what will be judged" >&2; break; }
    sleep "${LAND_SHARD_POLL_SECS:-20}"
  done
  wait "$pid1"; echo $? >"$dir/shard-1.rc"
  return 0
}

land_shard_local() { # $1 gate  $2 n  $3 dir  $4 CEIL=VALUE
  local g="$1" n="$2" dir="$3" ceil="$4" k=1
  while [ "$k" -le "$n" ]; do
    ( cd "$here" && env "$ceil" cargo xtask gate "$g" --selftest --shard "$k/$n" >"$dir/shard-$k.log" 2>&1 )
    echo $? >"$dir/shard-$k.rc"
    k=$((k + 1))
  done
  return 0
}

# ONE DIRECTORY PER LEG, NOT PER RUN. prove_tree is called once per batch and once per bisected
# half, and each call runs this leg again; a directory named by the run's stamp alone was the SAME
# directory for every round, so a second round's union check read the first round's `.rc` files —
# four green votes from a tree that is not the one being proven. The sequence number is the run's
# own, advanced on every leg, and the name carries the gate so two gates' legs never share one.
# It SETS a variable rather than printing: called as `$(...)` the increment would happen in a
# subshell and every leg would be handed the same "-1" directory — which is what the self-test's
# first run of this found.
LAND_SHARD_SEQ=0
land_shard_dir() { # $1 = gate; sets LAND_SHARD_DIR (does not create it)
  LAND_SHARD_SEQ=$((LAND_SHARD_SEQ + 1))
  LAND_SHARD_DIR="$here/target/land-shards-$1-$stamp-$LAND_SHARD_SEQ"
}

# THE LEG. Unsharded unless asked; sharded across the fleet when this copy is already ON a box
# (LAND_REMOTE_INNER), sharded SEQUENTIALLY when it is not — a laptop has one set of cores, and four
# shards racing on it is the same wall clock with four times the noise.
land_selftest_leg() { # $1 gate  $2 log  $3 CEIL=VALUE
  local g="$1" log="$2" ceil="$3" n dir
  n="$(land_shard_count)" || return 1
  if [ "$n" = 0 ]; then
    ( cd "$here" && env "$ceil" cargo xtask gate "$g" --selftest >"$log" 2>&1 )
    return $?
  fi
  land_shard_dir "$g"; dir="$LAND_SHARD_DIR"
  mkdir -p "$dir"
  if [ "${LAND_SHARD_FANOUT:-}" = laptop ] && [ -z "${LAND_REMOTE_INNER:-}" ]; then
    echo "land.sh: RED — LAND_SHARD_FANOUT=laptop outside a remote landing: nobody serves shard requests here" >&2
    return 1
  fi
  if [ -n "${LAND_REMOTE_INNER:-}" ] && [ "${LAND_SHARD_FANOUT:-}" = laptop ]; then
    land_shard_request "$g" "$n" "$dir" "$ceil"
  else
    echo "land.sh: $g self-test in $n shard(s), sequentially (no laptop serves a fan-out for this landing)"
    land_shard_local "$g" "$n" "$dir" "$ceil"
  fi
  # ONE LOG, so every reader below — and every operator — still has the gate's own words in the
  # place the unsharded leg left them.
  cat "$dir"/shard-*.log > "$log" 2>/dev/null || true
  land_shard_union "$g" "$n" "$dir" || return 1
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE PROOF. Every leg a landing has ever had, over a union of packages / rows / families, at
# whatever tip the tree is at. Called once per batch, and once per bisected half.
#
#   prove_tree <base-sha> <tests> <gate> <families> <label>
#
# It reads the tree; it does not move it. Resetting after a red is the caller's business, because
# only the caller knows whether a red is "leave it in place for the integrator" (a single landing)
# or "put it back and split" (a batch).
# ──────────────────────────────────────────────────────────────────────────────────────────────────
prove_tree() {
  local base="$1" tests="$2" gate="$3" families="$4" label="$5" features="${6:-}"
  PROVEN=""

  # THE SELFTEST'S PROVER. It is a function of the TREE, not of the line number — a poisoned file
  # is red wherever it is and however the batch was split — which is what makes the bisect below a
  # thing the selftest can actually catch getting wrong. Everything above and below this point (the
  # picking, the resetting, the halving, the outcome book-keeping) runs for real.
  if [ -n "${LAND_SELFTEST_ROOT:-}" ]; then
    if [ -e "$here/POISON" ]; then
      echo "land.sh: RED — [$label] selftest prover: POISON is on the tree" >&2; return 1
    fi
    PROVEN=" selftest prover;"; echo "land.sh: [$label] selftest prover: green"; return 0
  fi

  local plan; plan="$(land_floor_plan "$tests" "$gate" "$families")"
  echo "land.sh: [$label] plan: $plan"
  local touched; touched="$(git -C "$here" diff --name-only "$base" HEAD 2>/dev/null || true)"

  local leg
  for leg in $plan; do
    case "$leg" in

    plugins)
      # The plugin batteries refuse to skip when their cdylib is absent, so the example plugins are
      # built before any test leg; a green here must mean the ABI-crossing cells actually ran.
      local plog="$here/target/land-plugins-$stamp.log"
      if ! (cd "$here" && cargo build -p busbar-hook-test-plugin -p busbar-auth-static-plugin -p busbar-store-example-plugin -p busbar-export-example-plugin -p busbar-secret-example-plugin >"$plog" 2>&1); then
        grep -E '^error' "$plog" | head -5 >&2
        echo "land.sh: RED — example plugin cdylibs did not build (log: $plog)" >&2; return 1
      fi
      PROVEN="$PROVEN plugin cdylibs build;" ;;

    fmt)
      # RUSTFMT OVER THE FILES THE PICKS TOUCHED, not over the workspace. CI runs `cargo fmt --all
      # --check`, so a pick that lands unformatted Rust is a red CI run this script could have
      # caught in two seconds; but a workspace check would attribute the tree's PRE-EXISTING drift
      # to whoever landed next, and a gate that reds on somebody else's file is a gate people learn
      # to pass with --no-verify. Scoped to the diff, the verdict is the picks'.
      local rs; rs="$(printf '%s\n' "$touched" | grep -E '\.rs$' || true)"
      local nfmt=0
      if [ -n "$rs" ]; then
        local bad=""
        while IFS= read -r f; do
          [ -n "$f" ] && [ -f "$here/$f" ] || continue
          nfmt=$((nfmt + 1))
          (cd "$here" && rustfmt --check --quiet "$f" >/dev/null 2>&1) || bad="$bad $f"
        done <<EOF
$rs
EOF
        [ -z "$bad" ] || {
          echo "land.sh: RED — rustfmt --check on picked file(s):$bad" >&2; return 1; }
      fi
      PROVEN="$PROVEN rustfmt on $nfmt picked .rs file(s);" ;;

    gatefiles)
      # A landing whose picks touch only `scripts/`, `.github/` or `testing/` selects NO cargo
      # package — the crate-directory grep below matches nothing — so `$tests` is empty, the test and
      # clippy legs are skipped, and with no `--gate` and no `--families` this script used to reach
      # its final line having executed not one check. It then printed GREEN, which is the exact
      # sentence an integrator reads as "these commits were proven". Landing a change to the GATES
      # THEMSELVES was the one case with no proof at all, which is precisely backwards: a broken gate
      # script is invisible to every other leg here, because every other leg is about the crates.
      #
      # So every touched shell/python/workflow file is parsed, and every touched script that
      # advertises a `--selftest` runs it. These are cheap (seconds) and they catch the two failures
      # that actually happen to a picked gate script: it no longer parses, and its own self-test
      # cases no longer hold.
      local gate_files; gate_files="$(land_gate_scripts "$touched")"
      local n_parsed=0 n_selftests=0 f
      if [ -n "$gate_files" ]; then
        while IFS= read -r f; do
          [ -n "$f" ] && [ -f "$here/$f" ] || continue
          case "$f" in
            *.sh)
              bash -n "$here/$f" || { echo "land.sh: RED — $f does not parse (bash -n)" >&2; return 1; }
              n_parsed=$((n_parsed + 1)) ;;
            *.py)
              python3 -m py_compile "$here/$f" || { echo "land.sh: RED — $f does not compile (py_compile)" >&2; return 1; }
              n_parsed=$((n_parsed + 1)) ;;
            *.yml|*.yaml)
              case "$f" in
                .github/workflows/*)
                  if command -v actionlint >/dev/null 2>&1; then
                    (cd "$here" && actionlint "$f") || { echo "land.sh: RED — actionlint $f" >&2; return 1; }
                    n_parsed=$((n_parsed + 1))
                  else
                    python3 -c 'import sys,yaml; yaml.safe_load(open(sys.argv[1]))' "$here/$f" \
                      || { echo "land.sh: RED — $f is not valid YAML" >&2; return 1; }
                    n_parsed=$((n_parsed + 1))
                  fi ;;
              esac ;;
            *.mjs)
              if command -v node >/dev/null 2>&1; then
                node --check "$here/$f" || { echo "land.sh: RED — $f does not parse (node --check)" >&2; return 1; }
                n_parsed=$((n_parsed + 1))
              fi ;;
          esac
          # …and its own self-test, where it has one. A gate script that has stopped discriminating
          # is worse than one that fails to parse: it lands green and goes on reporting green.
          local slog="$here/target/land-selftest-$stamp.log"
          case "$f" in
            *.sh)
              # A script ADVERTISES a self-test when it handles the flag (a `case` arm or a quoted
              # comparison), not when its prose merely mentions one.
              if grep -qE -- "(--selftest\)|[\"']--selftest[\"'])" "$here/$f"; then
                if ! (cd "$here" && bash "$f" --selftest >"$slog" 2>&1); then
                  tail -20 "$slog" >&2
                  echo "land.sh: RED — $f --selftest failed (log: $slog)" >&2; return 1
                fi
                n_selftests=$((n_selftests + 1))
              fi ;;
            *.py)
              if grep -qE -- "[\"']--selftest[\"']" "$here/$f"; then
                if ! (cd "$here" && python3 "$f" --selftest >"$slog" 2>&1); then
                  tail -20 "$slog" >&2
                  echo "land.sh: RED — $f --selftest failed (log: $slog)" >&2; return 1
                fi
                n_selftests=$((n_selftests + 1))
              fi ;;
          esac
        done <<EOF
$gate_files
EOF
        PROVEN="$PROVEN $n_parsed gate file(s) parsed, $n_selftests self-test(s) green;"
      fi

      # …AND THE GATES' OWN DATA AND SOURCE. A landing that edits a ceiling, a waiver table or the
      # rule that reads one must run something that READS it; see land_gate_data's header for what
      # this used to cost. The construction gate is the reader for `qa/*.toml` — its `ceiling-rose`
      # row compares every integer in qa/construction.toml and qa/kind-isolation.toml against the
      # base, and its `ceiling-slack` row holds each ratcheted ceiling to its measurement — and its
      # self-test is what proves the gate that reads them can still fail. The gate is RED BY DESIGN
      # on HEAD, so its exit status is not the verdict here; the two ceiling rows are.
      local gate_data; gate_data="$(land_gate_data "$touched")"
      if [ -n "$gate_data" ]; then
        local ndata; ndata="$(printf '%s\n' "$gate_data" | grep -c . || true)"
        (cd "$here" && cargo build -q -p xtask --locked >/dev/null 2>&1) \
          || { echo "land.sh: RED — the gate runner will not build" >&2; return 1; }
        # Same reason as the kind-isolation leg above: 394s measured over thirty-two planted trees.
        land_selftest_leg construction "$here/target/land-cselftest-$stamp.log" XTASK_GATE_CEILING_SECS_CONSTRUCTION=3600 \
          || { tail -20 "$here/target/land-cselftest-$stamp.log" >&2
               echo "land.sh: RED — construction --selftest (the gate that reads these files can no longer prove itself)" >&2; return 1; }
        local clog="$here/target/land-ceilings-$stamp.log"
        ( cd "$here" && cargo xtask gate construction --report ) >"$clog" 2>&1 || true
        local crows; crows="$(grep -cE '^(PASS|FAIL)  ' "$clog" || true)"
        [ "${crows:-0}" -gt 0 ] || { echo "land.sh: RED — construction gate produced no rows (log: $clog)" >&2; return 1; }
        land_ceiling_verdict "$clog" || return 1
        PROVEN="$PROVEN $ndata gate data/source file(s): construction self-test + ceiling ratchets green;"
      fi
      # EVERY REGISTERED GATE'S SELF-TEST, ONCE, WHEN THE RUNNER CHANGED. xtask/tests/cli.rs carries
      # two cases that do exactly this (`xtask selftest` over every gate, then `full-gate --selftest`
      # for the registry-vs-ci.yml equality). They took 46 minutes of one landing's tests leg on a
      # line that did not touch xtask at all, beside a kind-isolation and a construction self-test
      # this script had already run. The tests leg skips those two cases by name; this is where
      # their evidence is produced instead — on the lines that can have changed it. CI runs
      # `full-gate --selftest` on every push regardless: the judge is unchanged.
      if [ -n "$(land_xtask_touched "$touched")" ]; then
        (cd "$here" && cargo build -q -p xtask --locked >/dev/null 2>&1) \
          || { echo "land.sh: RED — the gate runner will not build" >&2; return 1; }
        # THE SAME CEILING THE PER-GATE SELFTESTS GET. `xtask selftest` runs the kind-isolation
        # self-test inside it, measured at 1642 s on an otherwise idle fleet box and past 1800 s on a
        # box sharing its cores with CI; a hard-coded 1800 here turned every xtask-touching landing
        # red as "hung" while the two per-gate legs below already say 3600.
        local xlog="$here/target/land-xselftest-$stamp.log"
        (cd "$here" && XTASK_GATE_CEILING_SECS="${XTASK_GATE_CEILING_SECS:-3600}" cargo xtask selftest >"$xlog" 2>&1) \
          || { tail -20 "$xlog" >&2; echo "land.sh: RED — xtask selftest (a registered gate can no longer prove itself; log: $xlog)" >&2; return 1; }
        (cd "$here" && cargo xtask full-gate --selftest >>"$xlog" 2>&1) \
          || { tail -20 "$xlog" >&2; echo "land.sh: RED — full-gate --selftest (the registry and ci.yml no longer name the same gates; log: $xlog)" >&2; return 1; }
        PROVEN="$PROVEN xtask touched: every registered gate self-test + full-gate --selftest green;"
      fi ;;

    tests)
      local args=""; for p in $tests; do args="$args -p $p"; done
      [ -n "$features" ] && args="$args --features $features"
      # The two xtask/tests/cli.rs cases that re-run every gate's self-test are produced by the
      # gatefiles leg on the lines that touch xtask (see land_xtask_touched); here they are named
      # and skipped, never silently filtered.
      case " $tests " in *" xtask "*) args="$args -- --skip selftest_runs_every_registered_gates_red_proof --skip the_registry_and_the_workflow_still_name_the_same_gates" ;; esac
      echo "land.sh: cargo test $args"
      # cargo's own exit status is the verdict; the grep only names the red lines. A pipeline here
      # would let pipefail turn a failing cargo into a skipped check.
      local log="$here/target/land-$stamp.log"
      # shellcheck disable=SC2086
      if ! (cd "$here" && cargo test $args >"$log" 2>&1); then
        grep -E '^test result:.* [1-9][0-9]* failed|^error(\[|:)|^---- .* stdout ----|panicked at' "$log" | head -20 >&2
        echo "land.sh: RED — tests failed in: $tests (log: $log)" >&2; return 1
      fi
      PROVEN="$PROVEN cargo test ($tests);" ;;

    clippy)
      local args=""; for p in $tests; do args="$args -p $p"; done
      [ -n "$features" ] && args="$args --features $features"
      local log="$here/target/land-$stamp.log"
      # shellcheck disable=SC2086
      if ! (cd "$here" && cargo clippy $args --all-targets -- -D warnings >"$log" 2>&1); then
        grep -E '^(warning|error)' "$log" | head -5 >&2
        echo "land.sh: RED — clippy (log: $log)" >&2; return 1
      fi
      echo "land.sh: tests and clippy green for: $tests"
      PROVEN="$PROVEN cargo clippy ($tests);" ;;

    workspace-clippy)
      local log="$here/target/land-wsclippy-$stamp.log"
      echo "land.sh: nothing was named — falling back to the workspace floor (build + clippy)"
      if ! (cd "$here" && cargo clippy --workspace --all-targets -- -D warnings >"$log" 2>&1); then
        grep -E '^(warning|error)' "$log" | head -5 >&2
        echo "land.sh: RED — workspace clippy (log: $log)" >&2; return 1
      fi
      PROVEN="$PROVEN workspace build+clippy;" ;;

    kind-isolation)
      # THE KIND-ISOLATION GATE IS MEASURED ON EVERY LANDING, unconditionally — it is the owner's
      # ship criterion (2026-09-07), and a criterion only measured when somebody remembers to ask is
      # not one. It is an xtask-registry gate, not a construction row, so it runs through the
      # registry rather than being grepped out of the construction gate's log. Self-test FIRST.
      (cd "$here" && cargo build -q -p xtask --locked >/dev/null 2>&1) \
        || { echo "land.sh: RED — the gate runner will not build" >&2; return 1; }
      # THE HANG CEILING IS A CEILING, NOT A BUDGET. Measured 2026-09-09: 1508 s on the laptop, 1642 s
      # on a fleet box beside four CI runners — 91% of 1800, and the remote landing that hit it was
      # reported as "the gate can no longer prove itself" when nothing was wrong with the gate. 3600
      # is still a hang ceiling (the work-unit budget is the ratchet that notices growth). `gates::DEFAULT_GATE_CEILING` is 300s, which
      # is right for a gate RUN and wrong for a self-test that plants fifty-eight trees and runs
      # the whole gate over each (273s measured on a warm laptop; a loaded landing box is slower).
      # Raised for THIS GATE ONLY, so a hang anywhere else still costs five minutes and a red row —
      # and the cost itself is ratcheted by the gate's own work-unit budget, which is the
      # instrument that notices it growing.
      # THE SELF-TEST'S OWN WORDS ARE THE DIAGNOSIS. Sent to /dev/null, a red here said only "the
      # gate can no longer prove itself" and the operator re-ran fifteen minutes of proof to learn
      # which case — on a fleet box, from a session that had already ended.
      local kslog="$here/target/land-kselftest-$stamp.log"
      land_selftest_leg kind-isolation "$kslog" XTASK_GATE_CEILING_SECS_KIND_ISOLATION=3600 \
        || { grep -E 'FAILED|expected|infra' "$kslog" | head -12 >&2
             echo "land.sh: RED — kind-isolation self-test (the gate can no longer prove itself; log: $kslog)" >&2; return 1; }
      (cd "$here" && cargo xtask gate kind-isolation) \
        || { echo "land.sh: RED — kind-isolation (a plugin kind was fused; rows above)" >&2; return 1; }
      PROVEN="$PROVEN kind-isolation green;" ;;

    gate)
      # AN EMPTY --gate IS EVERY ROW, NOT NO ROWS. This leg is floor now (see land_floor_plan), so
      # the caller who named nothing gets the whole gate measured rather than a silent skip.
      local grx="${gate:-.}"
      local glog="$here/target/land-gate-$stamp.log"
      ( cd "$here" && cargo xtask gate construction --report ) >"$glog" 2>&1 || true
      land_gate_verdict "$glog" "$grx" || return 1
      PROVEN="$PROVEN construction rows ($grx, standing reds named);" ;;

    oracle)
      prove_oracle "$families" || return 1 ;;
    esac
  done
  [ -n "$PROVEN" ] || {
    echo "land.sh: RED — nothing was proven. The plan was empty, which land_floor_plan must never" >&2
    echo "land.sh:       return. A landing that ran no check is not a green landing." >&2
    return 1; }
  return 0
}

# ── THE ORACLE LEG, SHARDED ───────────────────────────────────────────────────────────────────────
# Recording is the slowest leg in a landing and it is embarrassingly parallel: every cell is an
# independent (request, response, effects) triple. What makes it NOT trivially parallel is that each
# recorder binds a listen/admin/mock triple and drives one busbar process, so two shards on one port
# triple would produce a red attributed to the picked commits. Each shard gets its own triple.
prove_oracle() {
  local families="$1"
  # cargo's exit status is the verdict (a pipe into grep would let pipefail invert it).
  local blog="$here/target/land-build-$stamp.log"
  if ! (cd "$here" && cargo build --release -p busbar >"$blog" 2>&1); then
    grep -E '^error' "$blog" | head -5 >&2
    echo "land.sh: RED — release build (log: $blog)" >&2; return 1
  fi
  local out="$here/target/oracle/recordings/land-$stamp"
  # record.sh only `mkdir -p`s its --out, so the directory is cleared HERE. A recording the differ
  # reads must contain this candidate's cells and nothing else.
  rm -rf "$out" "$out.report" "$out".shard*
  # …and the PARENT has to exist before the redirect below opens `$out.log` in it. record.sh makes
  # its own `--out`, but the shell opens the log first, so a worktree that has never recorded dies
  # on "No such file or directory" AFTER paying for the release build — and the message it dies with
  # names the ports, so a first run reads as a port collision that is not happening.
  mkdir -p "$(dirname "$out")"

  local plan; plan="$(land_shard_plan "$families" "$LAND_ORACLE_SHARDS")" || return 1
  local -a sre; local i=0
  while IFS= read -r r; do [ -n "$r" ] && { sre[$i]="$r"; i=$((i + 1)); }; done <<EOF
$plan
EOF
  local k=$i
  [ "$k" -ge 1 ] || { echo "land.sh: RED — the shard planner produced no shards" >&2; return 1; }
  # THE PARTITION IS ASSERTED BEFORE A SINGLE CELL IS RECORDED, with record.sh's own matcher.
  land_shard_assert "$families" "${sre[@]}" || return 1

  if [ "$k" -eq 1 ]; then
    # One shard is the old path, and it keeps the operator's ORACLE_*_PORT overrides exactly.
    i=0
  fi
  # K RECORDERS ON ONE HOST MAKE THE HOST K TIMES SLOWER, and two of record.sh's waits are
  # wall-clock bounds whose expiry is written into the CELL: ORACLE_BOOT_BOUND_SECS (record.sh:334,
  # :589-593 — "on a loaded machine a warning-boot cell whose golden is `exit 0` records `exit 124`
  # … the harness's stopwatch frozen into the cell as if it were the binary's answer") and
  # ORACLE_EGRESS_SETTLE_SECS (record.sh:670). Left at their single-recorder defaults, sharding would
  # manufacture divergences that are facts about this host's load and about nothing the picks did.
  # They scale with the fan-out, and only upward — an operator's own export still wins.
  local boot_secs egress_secs
  boot_secs="${ORACLE_BOOT_BOUND_SECS:-$(( 60 * k ))}"
  egress_secs="${ORACLE_EGRESS_SETTLE_SECS:-$(( 15 * k ))}"

  # The oracle plugin cache under $HOME is shared and deliberately concurrency-safe (fetch-plugin.sh
  # writes beside the target and renames), but K shards starting cold would each pay for the same
  # download. Warm it once, and do not let a warm-up failure be the verdict: the shards fetch it
  # themselves and their own failure is the one that counts.
  [ "$k" -gt 1 ] && "$here/bin/oracle" fetch-plugin webrequest-hook >/dev/null 2>&1

  local pids=""
  i=0
  while [ "$i" -lt "$k" ]; do
    # SIX PORTS PER SHARD, not three. Beyond the recording's own listen/admin/mock, record.sh:266-267
    # starts a SECOND busbar for `exec.mode: boot` cells, and record.sh:1037 gives script cells a
    # mock on ADMIN_PORT+1. Left derived, the boot pair defaults to LISTEN+10/ADMIN+10 and then walks
    # upward by two (record.sh:274-278) until it is clear of this run's own four — a walk that could
    # step out of this shard's block and into the next shard's. Pinning all six inside a 20-wide
    # block makes the blocks provably non-overlapping and the walk a no-op.
    #   shard 0: 49901 49902 49903 49911 49913 49914   (the queue's historical triple)
    #   shard 1: 49921 49922 49923 49931 49933 49934
    #   shard 2: 49941 49942 49943 49951 49953 49954
    # The 499xx band is above the 4xxxx range the agent worktrees bind.
    local lp ap mp blp bap
    if [ "$k" -eq 1 ]; then
      # One shard keeps the operator's ORACLE_*_PORT overrides exactly; absent those it is block 0
      # of LAND_ORACLE_PORT_BASE, the same block shard 0 of a fan-out would take. The boot pair is
      # pinned rather than derived so it cannot walk (record.sh:274-278) out of the block.
      lp="$ORACLE_LISTEN_PORT"; ap="$ORACLE_ADMIN_PORT"; mp="$ORACLE_MOCK_PORT"
      blp=$(( LAND_ORACLE_PORT_BASE + 13 )); bap=$(( LAND_ORACLE_PORT_BASE + 14 ))
      # …unless the operator moved the triple by hand, in which case the boot pair follows it.
      case "$lp" in "$((LAND_ORACLE_PORT_BASE + 1))") ;; *) blp=$(( lp + 10 )); bap=$(( ap + 10 )) ;; esac
    else
      local b=$(( LAND_ORACLE_PORT_BASE + 20 * i ))
      lp=$(( b + 1 )); ap=$(( b + 2 )); mp=$(( b + 11 )); blp=$(( b + 13 )); bap=$(( b + 14 ))
    fi
    echo "land.sh: oracle shard $i on $lp/$ap/$mp (boot $blp/$bap): ${sre[$i]}"
    (
      ORACLE_LISTEN_PORT="$lp" ORACLE_ADMIN_PORT="$ap" ORACLE_MOCK_PORT="$mp" \
      ORACLE_BOOT_LISTEN_PORT="$blp" ORACLE_BOOT_ADMIN_PORT="$bap" \
      ORACLE_BOOT_BOUND_SECS="$boot_secs" ORACLE_EGRESS_SETTLE_SECS="$egress_secs" \
        "$here/bin/oracle" record --plane all --bin "$here/target/release/busbar" \
        --filter "${sre[$i]}" --out "$out.shard$i" >"$out.shard$i.log" 2>&1
      echo $? >"$out.shard$i.rc"
    ) &
    pids="$pids $!"
    i=$((i + 1))
  done
  for p in $pids; do wait "$p" || true; done
  # A shard that failed to record is a RED landing, full stop. It is never "the shards that finished
  # were green": the missing cells would simply be absent from the merged recording, and a differ
  # asked about a set it was never handed has nothing to be strict about.
  land_shards_collect "$out.shard" "$k" || {
    echo "land.sh:       if another landing is recording on this host, set LAND_ORACLE_PORT_BASE and re-run" >&2
    return 1; }
  # THE PARTITION, ASSERTED AGAIN AGAINST WHAT WAS ACTUALLY RECORDED. The check before the fan-out
  # is a claim about regexes; this one is a claim about ledger rows, and it is the one that catches a
  # filter that was not as anchored as it read. record.sh writes one ledger row per SELECTED cell
  # (PASS, SKIP or FAIL alike), so the union of the parts' first columns is exactly the set of cells
  # this landing recorded.
  land_ledger_assert "$families" "$out.shard" "$k" || return 1

  # The same regex selects the cells on both sides (an ID filter, the domain record.sh --filter
  # uses), and --strict makes the differ's exit code carry the verdict for this subset: zero owed
  # cells, an unaccepted divergence, or an owed cell missing from the candidate is red.
  # THE SAME GOLDEN CI READS — the committed, signed-off recording, which is also why
  # `--allow-harness-skew` is not passed: a harness edit that moves the rev is a golden to re-stamp
  # or re-record, not a warning to pass over.
  local golden="$here/testing/shadow-oracle/golden/1.5.5"
  if [ "$LAND_ORACLE_DIFF" = merged ] && [ "$k" -gt 1 ]; then
    local parts=""; i=0
    while [ "$i" -lt "$k" ]; do parts="$parts $out.shard$i"; i=$((i + 1)); done
    # No --allow-*-skew: the shards ran in this same process, on this host, against this one binary,
    # under this one pinned harness. If merge refuses them, the thing it is refusing is REAL — the
    # shards did not record the same candidate — and that is a red landing, not a flag to add.
    # shellcheck disable=SC2086
    # --cells so the merged ledger is written in cells.json order (record.sh's own order) rather
    # than in part order: a merged part must be byte-comparable to a single-shot recording.
    "$here/bin/oracle" merge --out "$out" --cells "$here/testing/shadow-oracle/cells.json" $parts >"$out.merge.log" 2>&1 || {
      tail -20 "$out.merge.log" >&2
      echo "land.sh: RED — busbar-oracle merge refused the shards (see $out.merge.log)." >&2
      echo "land.sh:       Re-run with LAND_ORACLE_DIFF=per-shard to diff each shard on its own," >&2
      echo "land.sh:       or LAND_ORACLE_SHARDS=1 for one unsharded recording." >&2
      return 1; }
    "$here/bin/oracle" diff --golden "$golden" \
      --candidate "$out" --out "$out.report" --cells "$here/testing/shadow-oracle/cells.json" \
      --accepted "$here/testing/shadow-oracle/accepted-differences.json" \
      --id-filter "$families" --strict \
      || { echo "land.sh: RED — oracle families: $families (see $out.report)" >&2; return 1; }
    echo "land.sh: oracle green on: $families ($(grep -c . "$out.report/owed.txt" 2>/dev/null || echo '?') owed, $k merged shard(s))"
  else
    # PER-SHARD: each shard diffed against its own filter, red if ANY shard is red. Strictness is
    # asked of each subset rather than of the union, which is weaker in exactly one way — it cannot
    # see a cell owed by the requested set that landed in no shard — and that is the one thing
    # land_shard_assert already refused above.
    local red=0; i=0
    while [ "$i" -lt "$k" ]; do
      "$here/bin/oracle" diff --golden "$golden" \
        --candidate "$out.shard$i" --out "$out.shard$i.report" --cells "$here/testing/shadow-oracle/cells.json" \
        --accepted "$here/testing/shadow-oracle/accepted-differences.json" \
        --id-filter "${sre[$i]}" --strict \
        || { echo "land.sh: RED — oracle shard $i: ${sre[$i]} (see $out.shard$i.report)" >&2; red=1; }
      i=$((i + 1))
    done
    [ "$red" = 0 ] || return 1
    echo "land.sh: oracle green on: $families ($k shard(s), diffed per shard)"
  fi
  PROVEN="$PROVEN oracle families ($families);"
  return 0
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE BATCH ENGINE
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# BL_text/BL_tests/BL_fams/BL_gate/BL_hashes/BL_prove/BL_out, indexed by line number (0-based).

# ── THE LEDGER IS A MEASUREMENT, AND MEASUREMENTS ARE NOT MERGED ──────────────────────────────────
# qa/kind-isolation.toml and qa/construction.toml are EXACT ratchets: every pinned figure equals
# what the tree measures, in both directions. So every drain, move and face edit re-pins cells in
# those two files, and two hand-backs that drained different edges of the same cell carry the same
# textual edit to the same line. Cherry-picked in sequence, that is one of two failures, measured
# twice by two auditors on the live queue:
#
#   (a) the two pins DIFFER (98->97 and 98->96, say): a textual conflict on the ledger line, so the
#       second line is RED-CONFLICT, the batch bisects around it, and a line whose code was fine is
#       parked for a hand re-pick — of a NUMBER nobody should be typing by hand.
#   (b) the two pins AGREE (both 98->97, for disjoint drains): the picks land clean, the tree then
#       measures 96 against a pin of 97, and `ceiling-slack` reds the whole union.
#
# Both are the same mistake: treating the ledger as text to be merged, when it is a reading to be
# taken. So a conflict whose ONLY unmerged paths are the two ledgers is not a conflict at all — the
# tree's version is kept, the pick is completed, and the figures are RE-MEASURED before the proof
# (land_repin_ledger). A conflict on ANY other path is a RED-CONFLICT exactly as before.
land_ledger_paths() {
  printf 'qa/kind-isolation.toml\nqa/construction.toml\n'
}

# land_resolve_ledger_conflict <hash> -> 0 when the failed pick of <hash> was a ledger-only conflict
# and has been completed with the tree's ledgers; 1 otherwise (the sequencer state is left for the
# caller to abort, exactly as a failed pick is today).
land_resolve_ledger_conflict() {
  local h="$1" p
  local unmerged; unmerged="$(git -C "$here" diff --name-only --diff-filter=U 2>/dev/null || true)"
  # No unmerged path means the pick failed for a reason that is not a content conflict (a bad
  # hash, a pick that is already empty): that is today's path, untouched.
  [ -n "$unmerged" ] || return 1
  local other; other="$(printf '%s\n' "$unmerged" | grep -vxF -f <(land_ledger_paths) || true)"
  [ -z "$other" ] || return 1
  while IFS= read -r p; do
    [ -n "$p" ] || continue
    # `--ours` inside a cherry-pick is HEAD: the tree's ledger, which is at (or about to be re-pinned
    # to) the measurement. A path that cannot be resolved this way is a real conflict.
    git -C "$here" checkout --ours -- "$p" >/dev/null 2>&1 || return 1
    git -C "$here" add -- "$p" >/dev/null 2>&1 || return 1
  done <<EOF
$unmerged
EOF
  if git -C "$here" diff --cached --quiet; then
    # The pick was NOTHING BUT ledger lines. `cherry-pick --continue` refuses an empty result; the
    # commit is made anyway, with the source's message, author and the `-x` trailer, so the landed
    # tip still CONTAINS the line's pick — the invariant every GREEN below is stated against.
    git -C "$here" commit -q --allow-empty --no-verify \
      --author="$(git -C "$here" log -1 --format='%an <%ae>' "$h")" \
      -m "$(git -C "$here" log -1 --format=%B "$h")" \
      -m "(cherry picked from commit $(git -C "$here" rev-parse "$h"))" >/dev/null 2>&1 || return 1
  else
    git -C "$here" -c core.editor=true cherry-pick --continue >/dev/null 2>&1 || return 1
  fi
  echo "land.sh: pick $(git -C "$here" rev-parse --short "$h"): ledger conflict resolved by measurement ($(echo $unmerged)) — the tree's figures are kept and re-measured before the proof"
  LAND_LEDGER_RESOLVED="$LAND_LEDGER_RESOLVED $h"
  return 0
}

# ── THE RE-PIN: the ledgers are re-measured at landing, never merged ─────────────────────────────
# land_repin_available <gate> <tree> -> prints nothing when `cargo xtask gate <gate> --write` exists
# on <tree>; otherwise prints the reason the step is skipped. Read from the tree's own source, not
# from this script's knowledge: an older base has no `--write`, and on such a tree the behaviour is
# byte-identical to before this step existed. Under the selftest the "tree" is a scratch repo and
# the gate is scripted (LAND_SELFTEST_REPIN names the script); absent, the skip path is exercised.
land_repin_available() {
  local gate="$1" tree="$2"
  if [ -n "${LAND_SELFTEST_ROOT:-}" ]; then
    [ -n "${LAND_SELFTEST_REPIN:-}" ] || echo "selftest: no scripted --write (LAND_SELFTEST_REPIN unset)"
    return 0
  fi
  case "$gate" in
    kind-isolation)
      grep -q 'KindIsolationGate::write()' "$tree/xtask/src/cli.rs" 2>/dev/null \
        || echo "this tree's xtask has no \`gate kind-isolation --write\` (older base)" ;;
    construction)
      grep -q 'construction::ceilings::rewrite' "$tree/xtask/src/cli.rs" 2>/dev/null \
        || echo "this tree's xtask has no \`gate construction --write\` (older base)" ;;
    *) echo "no re-pin arm is known for gate '$gate'" ;;
  esac
}

# land_repin_run <gate> -> runs the gate's --write arm on $here; its exit status and its words.
land_repin_run() {
  local gate="$1"
  if [ -n "${LAND_SELFTEST_ROOT:-}" ]; then
    bash "$LAND_SELFTEST_REPIN" "$gate" "$here"; return $?
  fi
  (cd "$here" && cargo xtask gate "$gate" --write)
}

# land_repin_ledger <label> -> 0 when both ledgers are at the measurement (committing the DOWNWARD
# re-pins the picks earned, if any; LAND_REPIN_SHA names the commit or is empty), 1 when a --write
# refused. The refusal is the batch's RED, with the gate's own words quoted: `--write` never writes
# a RISE, and a landing whose picks grew a coupling is read by a person, never re-pinned by a tool.
# Runs after the picks of a batch (and again for each bisected half), BEFORE the proof, so the
# proof measures the tree the ledger now describes.
land_repin_ledger() {
  local label="$1" gate reason rlog
  LAND_REPIN_SHA=""
  local paths; paths="$(land_ledger_paths)"
  # Which arms this TREE has. None: the skip is printed and nothing else happens — the older base
  # lands byte-for-byte as it did before this step existed.
  local avail="" skipped=""
  for gate in kind-isolation construction; do
    reason="$(land_repin_available "$gate" "$here")"
    if [ -n "$reason" ]; then
      echo "land.sh: [$label] re-pin ($gate): skipped — $reason"; skipped="$skipped $gate"
    else avail="$avail $gate"; fi
  done
  [ -n "$avail" ] || { echo "land.sh: [$label] re-pin: no --write arm on this tree; the ledgers land as picked"; return 0; }
  # A tree that is already dirty cannot have its re-pin attributed to the picks.
  local dirty; dirty="$(git -C "$here" status --porcelain 2>/dev/null | grep -vE '^\?\?' || true)"
  [ -z "$dirty" ] || {
    printf '%s\n' "$dirty" | head -5 >&2
    echo "land.sh: RED — [$label] the tree is dirty before the ledger re-pin; a re-pin over uncommitted edits is a number nobody measured" >&2
    return 1; }
  if [ -z "${LAND_SELFTEST_ROOT:-}" ]; then
    (cd "$here" && cargo build -q -p xtask --locked >/dev/null 2>&1) \
      || { echo "land.sh: RED — [$label] the gate runner will not build, so the ledger cannot be re-measured" >&2; return 1; }
  fi
  for gate in $avail; do
    rlog="$here/target/land-repin-$gate-$stamp.log"
    mkdir -p "$(dirname "$rlog")" 2>/dev/null || true
    if ! land_repin_run "$gate" >"$rlog" 2>&1; then
      # THE GATE'S OWN WORDS ARE THE DIAGNOSIS: which row would rise, or which rule is red.
      sed 's/^/land.sh:   | /' "$rlog" | head -20 >&2
      echo "land.sh: RED — [$label] \`gate $gate --write\` refused to re-pin the ledger (a RISE, or a red gate; quoted above). A ledger that does not measure cannot land (log: $rlog)" >&2
      return 1
    fi
    # What moved, in the gate's words, in the landing log — not only in the commit body.
    grep -vE '^\s*$' "$rlog" | head -20 | sed 's/^/land.sh:   | /'
  done
  # WHAT --write TOUCHED. Only the two ledgers may have moved; anything else is a gate writing where
  # it has no business, and it is red rather than swept into a commit that says "ledger".
  local moved; moved="$(git -C "$here" status --porcelain 2>/dev/null | grep -vE '^\?\?' | awk '{print $2}' || true)"
  if [ -z "$moved" ]; then
    echo "land.sh: [$label] re-pin: the ledgers already equal the measurement; nothing to commit"
    return 0
  fi
  local stray; stray="$(printf '%s\n' "$moved" | grep -vxF -f <(printf '%s\n' "$paths") || true)"
  [ -z "$stray" ] || {
    echo "land.sh: RED — [$label] --write moved files outside the ledger: $(echo $stray)" >&2
    git -C "$here" checkout -q -- . 2>/dev/null || true
    return 1; }
  local body; body="$(cat "$here"/target/land-repin-*-"$stamp".log 2>/dev/null | grep -vE '^\s*$' | head -40)"
  # shellcheck disable=SC2086
  git -C "$here" add -- $moved >/dev/null 2>&1 || return 1
  git -C "$here" commit -q --no-verify -m "ledger: re-pinned by measurement at landing ($stamp)" -m "$body" >/dev/null 2>&1 \
    || { echo "land.sh: RED — [$label] the re-pin commit could not be made (git identity on this runner?)" >&2; return 1; }
  LAND_REPIN_SHA="$(git -C "$here" rev-parse --short HEAD)"
  echo "land.sh: [$label] ledger re-pinned by measurement: $LAND_REPIN_SHA ($(echo $moved))"
  return 0
}

land_pick_hashes() {  # $1 = space-separated hashes; 0 on success, 1 on conflict (tree restored)
  local base; base="$(git -C "$here" rev-parse HEAD)"
  local h
  LAND_LEDGER_RESOLVED=""
  # The lock file drifts between worktrees; a pick must never fail on it.
  git -C "$here" checkout -- Cargo.lock 2>/dev/null || true
  for h in $1; do
    if ! git -C "$here" cherry-pick -x "$h" >/dev/null 2>&1; then
      # A conflict confined to the two ledgers is resolved by measurement (above); anything else
      # is the RED-CONFLICT it always was.
      if ! land_resolve_ledger_conflict "$h"; then
        git -C "$here" cherry-pick --abort >/dev/null 2>&1
        git -C "$here" reset -q --hard "$base"
        LAND_CONFLICT_AT="$h"
        return 1
      fi
    fi
  done
  return 0
}

land_apply_line() {  # $1 = index; 0 when the line's picks are on the tree
  local i="$1"
  BL_out[$i]=PENDING
  local base; base="$(git -C "$here" rev-parse HEAD)"
  if [ -n "${BL_hashes[$i]}" ]; then
    if ! land_pick_hashes "${BL_hashes[$i]}"; then
      echo "land.sh: line $((i + 1)) RED-conflict at $LAND_CONFLICT_AT — its picks are backed out, the batch continues" >&2
      BL_out[$i]=RED-CONFLICT
      return 1
    fi
    # WHAT THE PICKS ACTUALLY TOUCHED, per line, so a line that named no --tests contributes the
    # same packages to the union that it would have tested on its own.
    if [ -z "${BL_tests[$i]}" ]; then
      BL_tests[$i]="$(git -C "$here" diff --name-only "$base" HEAD 2>/dev/null | grep -o '^crates/[^/]*' | sort -u \
        | while read -r d; do grep -m1 '^name = ' "$here/$d/Cargo.toml" 2>/dev/null | sed 's/name = "\(.*\)"/\1/'; done | tr '\n' ' ')"
    fi
  fi
  return 0
}

land_batch_range() {  # $@ = line indices; the tree is at their base on entry
  local -a idx; local i=0
  for a in "$@"; do idx[$i]="$a"; i=$((i + 1)); done
  local n=$i
  [ "$n" -gt 0 ] || return 0
  local base; base="$(git -C "$here" rev-parse HEAD)"
  local -a applied; local na=0
  i=0
  while [ "$i" -lt "$n" ]; do
    if land_apply_line "${idx[$i]}"; then applied[$na]="${idx[$i]}"; na=$((na + 1)); fi
    i=$((i + 1))
  done
  [ "$na" -gt 0 ] || return 0   # every line in this range conflicted; nothing to prove

  # THE UNION. Packages are a set; gate rows and family regexes are alternations.
  local u_tests="" u_feats="" u_gate="" u_fams="" lbl=""
  i=0
  while [ "$i" -lt "$na" ]; do
    local j="${applied[$i]}"
    u_tests="$u_tests ${BL_tests[$j]}"
    [ -n "${BL_feats[$j]}" ] && u_feats="$u_feats,${BL_feats[$j]}"
    [ -n "${BL_gate[$j]}" ] && u_gate="$u_gate|${BL_gate[$j]}"
    [ -n "${BL_fams[$j]}" ] && u_fams="$u_fams|(${BL_fams[$j]})"
    lbl="$lbl,$((j + 1))"
    i=$((i + 1))
  done
  # shellcheck disable=SC2086
  u_tests="$(printf '%s\n' $u_tests | sed '/^$/d' | sort -u | tr '\n' ' ')"
  u_feats="$(printf '%s\n' "$u_feats" | tr ',' '\n' | sed '/^$/d' | sort -u | paste -sd, -)"
  u_gate="${u_gate#|}"; u_fams="${u_fams#|}"; lbl="lines ${lbl#,}"

  # THE LEDGERS ARE RE-MEASURED BEFORE THE PROOF, at this union, so the proof runs on the tree the
  # ledger now describes. A refused write (a RISE) is a red for the union — and it bisects like any
  # other red, so the line that grew the coupling ends up alone in a half that is red for that.
  local repinned=1
  land_repin_ledger "$lbl" || repinned=0
  echo "land.sh: === proving $lbl at $(git -C "$here" rev-parse --short HEAD)"
  if [ "$repinned" = 1 ] && prove_tree "$base" "$u_tests" "$u_gate" "$u_fams" "$lbl" "$u_feats"; then
    i=0; while [ "$i" -lt "$na" ]; do BL_out[${applied[$i]}]=GREEN; BL_repin[${applied[$i]}]="${LAND_REPIN_SHA:-none}"; i=$((i + 1)); done
    echo "land.sh: === GREEN $lbl — proven by:$PROVEN"
    return 0
  fi

  git -C "$here" reset -q --hard "$base"
  if [ "$na" -eq 1 ]; then
    BL_out[${applied[0]}]=RED
    echo "land.sh: === RED line $(( ${applied[0]} + 1 )) — alone, proven red, backed out" >&2
    return 0
  fi
  # BISECT. The whole range is split — including the lines that conflicted, because a line can
  # conflict against a preceding line that is about to be found red and dropped, and it deserves the
  # second chance the serial queue would have given it.
  local half=$(( (n + 1) / 2 ))
  echo "land.sh: === RED over $lbl — bisecting into $half + $((n - half))" >&2
  land_batch_range "${idx[@]:0:$half}"
  land_batch_range "${idx[@]:$half}"
  return 0
}

# PRE-PROVE MODE. `--preprove` is what survives the trip to a fleet box; `LAND_PREPROVE=1` is what
# an operator types. MAIN folds the flag into the variable the moment the top-level argv is parsed,
# so there is ONE reader — and it has to be the variable rather than `P_preprove`, because
# land_parse_args is re-run over every batch LINE and would reset a flag read from it to 0.
land_preproving() {
  [ "${LAND_PREPROVE:-}" = 1 ]
}

land_run_batch() {  # $1 = batch file
  local bf="$1"
  [ -f "$bf" ] || { echo "land.sh: --batch: no such file: $bf" >&2; exit 2; }
  local n=0 line
  while IFS= read -r line || [ -n "$line" ]; do
    case "$line" in ''|'#'*) continue ;; esac
    BL_text[$n]="$line"
    eval "land_parse_args $line"
    BL_tests[$n]="$P_tests"; BL_feats[$n]="$P_features"; BL_fams[$n]="$P_families"; BL_gate[$n]="$P_gate"
    BL_hashes[$n]="$P_hashes"; BL_prove[$n]="$P_prove"; BL_out[$n]=PENDING; BL_repin[$n]=none
    if [ -z "$P_hashes" ] && [ "$P_prove" != 1 ]; then
      echo "land.sh: --batch line $((n + 1)) has no hashes and no --prove: $line" >&2; exit 2
    fi
    n=$((n + 1))
  done <"$bf"
  # AN EMPTY BATCH IS REFUSED. It is the one input that would otherwise walk the entire engine,
  # prove nothing at all, and exit 0 — the queue runner would read that as "those lines landed".
  [ "$n" -gt 0 ] || {
    echo "land.sh: RED — --batch $bf holds no landing lines. An empty batch proves nothing and is" >&2
    echo "land.sh:       not a green landing; it is a queue that popped nothing." >&2
    exit 2; }

  local -a all; local i=0
  while [ "$i" -lt "$n" ]; do all[$i]="$i"; i=$((i + 1)); done
  local base0; base0="$(git -C "$here" rev-parse HEAD)"
  echo "land.sh: batch $stamp: $n line(s) on $(git -C "$here" rev-parse --short HEAD)"
  land_batch_range "${all[@]}"

  # PER-LINE OUTCOMES, in the queue's own order, for the runner and for the record.
  local res="$bf.result"; : >"$res"
  local done_file="${LAND_DONE:-$here/target/gate/land-done.txt}"
  # ── LAND_PREPROVE=1: PROVE AND REPORT, PUBLISH NOTHING ─────────────────────────────────────────
  # A pre-proof runs the SAME batch through the SAME engine — the picks, the legs, the bisect — and
  # then puts the tree back. It exists so a box can answer "would this line be green on the current
  # tip?" ahead of the serial runner reaching it, and it is worth nothing unless it is impossible to
  # mistake for a landing. So:
  #   * its outcomes go to a scratch file, never to the land-done ledger. The ledger is the record
  #     of what LANDED, and a pre-proof landed nothing.
  #   * the tree is reset to the base it started from, which also makes the remote transport a
  #     no-op: scripts/land-remote.sh fast-forwards the local tree to the tip the box published,
  #     and a box that published its own base has nothing to fast-forward TO.
  # NOTHING LANDS ON A PRE-PROOF. The serial runner still runs the full proof over the union it
  # pops; a green here only chooses the ORDER of the queue, never its verdict.
  land_preproving && done_file="$here/target/land-preprove-$stamp.done"
  mkdir -p "$(dirname "$done_file")" 2>/dev/null || true
  local green=0 red=0 conflict=0
  i=0
  while [ "$i" -lt "$n" ]; do
    local st="${BL_out[$i]}"
    [ "$st" = PENDING ] && st=RED   # never left unstated: an unproven line is red
    printf '%s\t%s\n' "$st" "${BL_text[$i]}" >>"$res"
    # `repin=` names the ledger re-pin commit that is part of this line's landed tip (or `none`).
    printf '%s batch=%s log=%s repin=%s %s\n' "$st" "$stamp" "$here/target/land-$stamp.log" "${BL_repin[$i]:-none}" "${BL_text[$i]}" >>"$done_file"
    case "$st" in GREEN) green=$((green + 1)) ;; RED-CONFLICT) conflict=$((conflict + 1)) ;; *) red=$((red + 1)) ;; esac
    i=$((i + 1))
  done
  echo "land.sh: batch $stamp: $green green, $red red, $conflict red-conflict; base $(git -C "$here" rev-parse --short "$base0"), tip $(git -C "$here" rev-parse --short HEAD)"
  echo "land.sh: per-line outcomes: $res"
  if land_preproving; then
    git -C "$here" reset -q --hard "$base0"
    echo "land.sh: PRE-PROVE — published nothing; tree back at $(git -C "$here" rev-parse --short HEAD) (proven against $(git -C "$here" rev-parse --short "$base0"))"
  fi
  [ $((red + conflict)) -eq 0 ]
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest: the engine's own refusals, proven RED before anything is called green.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
land_selftest() {
  local root="$here/target/land-selftest-$stamp"
  local repo="$root/repo" fails=0 name
  rm -rf "$root"; mkdir -p "$repo"
  _st() { # $1 = name, $2 = expected rc (0|1|2), rest = command
    local nm="$1" want="$2"; shift 2
    ST_OUT="$root/$(printf '%s' "$nm" | tr -c 'A-Za-z0-9._-' '_').out"
    "$@" >"$ST_OUT" 2>&1; local got=$?
    if [ "$got" = "$want" ]; then printf '  ok   %-46s (rc %s)\n' "$nm" "$got"
    else printf '  FAIL %-46s (rc %s, wanted %s; %s)\n' "$nm" "$got" "$want" "$ST_OUT"; fails=$((fails + 1)); fi
  }
  _stgrep() { # $1 = name, $2 = file, $3 = regex that must match
    if grep -qE "$3" "$2" 2>/dev/null; then printf '  ok   %-46s\n' "$1"
    else printf '  FAIL %-46s (no /%s/ in %s)\n' "$1" "$3" "$2"; fails=$((fails + 1)); fi
  }
  _stno() { # $1 = name, $2 = file, $3 = regex that must NOT match
    if grep -qE "$3" "$2" 2>/dev/null; then printf '  FAIL %-46s (unwanted /%s/ in %s)\n' "$1" "$3" "$2"; fails=$((fails + 1))
    else printf '  ok   %-46s\n' "$1"; fi
  }

  echo "land.sh selftest: the floor plan (a landing that named nothing must still run legs)"
  land_floor_plan "" "" "" >"$root/plan-empty.txt"
  _stgrep "plan(empty) has the workspace build+clippy" "$root/plan-empty.txt" 'workspace-clippy'
  _stgrep "plan(empty) has fmt"                        "$root/plan-empty.txt" '(^| )fmt( |$)'
  _stgrep "plan(empty) has the gate-tree legs"         "$root/plan-empty.txt" 'gatefiles'
  _stgrep "plan(empty) has kind-isolation"             "$root/plan-empty.txt" 'kind-isolation'
  _stgrep "plan(empty) has the plugin cdylib build"    "$root/plan-empty.txt" 'plugins'
  # THE CONSTRUCTION GATE IS FLOOR. It used to be added only when the caller passed `--gate`, so a
  # landing that named nothing evaluated none of the 112 construction rows. This case is the one
  # that goes red if that `[ -n "$g" ]` ever comes back.
  _stgrep "plan(empty) has the construction gate"      "$root/plan-empty.txt" '(^| )gate( |$)'
  land_floor_plan "busbar" "loc-ceilings" "^x" >"$root/plan-full.txt"
  _stgrep "plan(named) has tests/clippy/gate/oracle"   "$root/plan-full.txt" 'tests clippy'
  _stgrep "plan(named) has the gate row leg"           "$root/plan-full.txt" '(^| )gate( |$)'
  _stgrep "plan(named) has the oracle leg"             "$root/plan-full.txt" 'oracle'
  _stno   "plan(named) does NOT fall back to workspace" "$root/plan-full.txt" 'workspace-clippy'

  echo "land.sh selftest: the ceiling ratchet's verdict (a filter that matches nothing is red)"
  # Both rows present and passing: the only shape that is green.
  printf 'PASS  ceiling-rose   x\nPASS  ceiling-slack  x\nPASS  other  x\n' >"$root/cl-ok.txt"
  _st "ceilings: both rows PASS is green"        0 land_ceiling_verdict "$root/cl-ok.txt"
  # A row that ran and failed. Must be red — this part always worked.
  printf 'FAIL  ceiling-rose   x\nPASS  ceiling-slack  x\n' >"$root/cl-fail.txt"
  _st "ceilings: a risen ceiling is red"         1 land_ceiling_verdict "$root/cl-fail.txt"
  # THE MISS. The rule was renamed, so neither the old FAIL grep nor the rows>0 floor sees anything
  # and the leg used to report green. 112 other rows are not a substitute for these two.
  printf 'FAIL  ceiling-rose2  x\nPASS  ceiling-slack  x\nPASS  other  x\n' >"$root/cl-renamed.txt"
  _st "ceilings: a RENAMED rose row is red"      1 land_ceiling_verdict "$root/cl-renamed.txt"
  _stgrep "ceilings: the rename names the row"   "$ST_OUT" 'emitted no row for: ceiling-rose'
  # The slack row deleted outright, with rose still present and green.
  printf 'PASS  ceiling-rose   x\nPASS  other  x\n' >"$root/cl-noslack.txt"
  _st "ceilings: a DELETED slack row is red"     1 land_ceiling_verdict "$root/cl-noslack.txt"
  _stgrep "ceilings: the deletion names the row" "$ST_OUT" 'emitted no row for: ceiling-slack'
  # A gate that produced nothing at all.
  : >"$root/cl-empty.txt"
  _st "ceilings: an empty report is red"         1 land_ceiling_verdict "$root/cl-empty.txt"

  # ── THE SHARDED SELF-TEST LEG ──────────────────────────────────────────────────────────────────
  # A leg split over four boxes is only the same proof if a box that does not answer is RED. These
  # cases are the ones that hold that: every way a shard can fail to report is exercised here
  # against fabricated shard directories, because the failure being guarded against is a TRANSPORT
  # failure and a transport that works is no test of what happens when it does not.
  echo "land.sh selftest: the shard count (a nonsense value is a refusal, not an unsharded run)"
  # `env` cannot call a shell function, and the thing under test IS one.
  _shcount() { LAND_SELFTEST_SHARDS="$1" land_shard_count; }
  _st "shards: unset is 'do not shard'"          0 _shcount ""
  _stgrep "shards: unset prints 0"                 "$ST_OUT" '^0$'
  _st "shards: 1 is 'do not shard'"              0 _shcount 1
  _stgrep "shards: 1 prints 0"                     "$ST_OUT" '^0$'
  _st "shards: 4 is four shards"                 0 _shcount 4
  _stgrep "shards: 4 prints 4"                     "$ST_OUT" '^4$'
  _st "shards: a word is REFUSED"                1 _shcount eight
  _st "shards: above four boxes is REFUSED"      1 _shcount 8

  echo "land.sh selftest: the shard directory (one per LEG, so a bisect round never reads the last round's votes)"
  local sd1 sd2; land_shard_dir kind-isolation; sd1="$LAND_SHARD_DIR"; land_shard_dir kind-isolation; sd2="$LAND_SHARD_DIR"
  [ "$sd1" != "$sd2" ] && printf '  ok   %-46s\n' "shards: two legs of one gate get two directories" \
    || { printf '  FAIL %-46s (%s twice)\n' "shards: two legs of one gate get two directories" "$sd1"; fails=$((fails + 1)); }
  case "$sd1" in "$here/target/land-shards-kind-isolation-$stamp-"*) printf '  ok   %-46s\n' "shards: the directory names the gate and the run" ;;
    *) printf '  FAIL %-46s (%s)\n' "shards: the directory names the gate and the run" "$sd1"; fails=$((fails + 1)) ;; esac

  echo "land.sh selftest: the shard union (a shard that does not report is RED, never skipped)"
  _mkshard() { # $1 = dir, $2 = k, $3 = n, $4 = rc, $5 = owned|'-' for no count line, $6 = total
    mkdir -p "$1"
    printf 'xtask selftest g --shard %s/%s\n' "$2" "$3" >"$1/shard-$2.log"
    [ "$5" = "-" ] || printf '  shard %s/%s: %s of %s case(s)\n' "$2" "$3" "$5" "$6" >>"$1/shard-$2.log"
    [ "$4" = "-" ] || printf '%s\n' "$4" >"$1/shard-$2.rc"
  }
  local sd="$root/shards"
  rm -rf "$sd/ok"; _mkshard "$sd/ok" 1 4 0 38 152; _mkshard "$sd/ok" 2 4 0 38 152
  _mkshard "$sd/ok" 3 4 0 38 152; _mkshard "$sd/ok" 4 4 0 38 152
  _st "union: four green shards summing to the total" 0 land_shard_union g 4 "$sd/ok"
  _stgrep "union: it says what it proved"             "$ST_OUT" '4 shard\(s\) green, 152 of 152 case\(s\), union complete'

  # THE CASE THIS WHOLE LEG EXISTS FOR. Three boxes answered; the fourth never did. Nothing about
  # the three is evidence about the fourth, and a leg that reported green here would be reporting a
  # proof three quarters of which was taken and one quarter of which was assumed.
  rm -rf "$sd/silent"; _mkshard "$sd/silent" 1 4 0 38 152; _mkshard "$sd/silent" 2 4 0 38 152
  _mkshard "$sd/silent" 3 4 0 38 152; _mkshard "$sd/silent" 4 4 - 38 152
  _st "union: a shard that never reported is RED"     1 land_shard_union g 4 "$sd/silent"
  _stgrep "union: the silent shard is NAMED"          "$ST_OUT" 'shard 4/4 never reported an exit status'

  rm -rf "$sd/red"; _mkshard "$sd/red" 1 4 0 38 152; _mkshard "$sd/red" 2 4 1 38 152
  _mkshard "$sd/red" 3 4 0 38 152; _mkshard "$sd/red" 4 4 0 38 152
  _st "union: a shard that went red is RED"           1 land_shard_union g 4 "$sd/red"
  _stgrep "union: the red shard is NAMED"             "$ST_OUT" 'shard 2/4 exited 1'

  # Exit 0 and no count line: the binary was replaced, the flag was ignored, the log was truncated.
  # An exit status alone is not a report.
  rm -rf "$sd/mute"; _mkshard "$sd/mute" 1 4 0 38 152; _mkshard "$sd/mute" 2 4 0 - 152
  _mkshard "$sd/mute" 3 4 0 38 152; _mkshard "$sd/mute" 4 4 0 38 152
  _st "union: exit 0 without a case count is RED"     1 land_shard_union g 4 "$sd/mute"
  _stgrep "union: the mute shard is NAMED"            "$ST_OUT" 'shard 2/4 exited 0 without printing its case count'

  # Two boxes that saw different case lists ran different trees. Their union is not a proof of
  # either of them.
  rm -rf "$sd/split"; _mkshard "$sd/split" 1 4 0 38 152; _mkshard "$sd/split" 2 4 0 37 148
  _mkshard "$sd/split" 3 4 0 38 152; _mkshard "$sd/split" 4 4 0 38 152
  _st "union: shards that disagree about the total are RED" 1 land_shard_union g 4 "$sd/split"
  _stgrep "union: the disagreement is NAMED"          "$ST_OUT" 'disagree about the case list'

  # Every shard green, every shard reporting, and the arithmetic still short: a case nobody ran.
  rm -rf "$sd/lost"; _mkshard "$sd/lost" 1 4 0 38 152; _mkshard "$sd/lost" 2 4 0 38 152
  _mkshard "$sd/lost" 3 4 0 38 152; _mkshard "$sd/lost" 4 4 0 30 152
  _st "union: a case owned by no shard is RED"        1 land_shard_union g 4 "$sd/lost"
  _stgrep "union: the lost cases are COUNTED"         "$ST_OUT" 'own 144 of 152 case\(s\). 8 case\(s\) were proven by nobody'

  # THE REQUEST/WAIT ARM. The transport is the laptop's; what is proven here is everything this side
  # owns: the refusal, the request's shape, that nothing delivered is RED, and that what the laptop
  # delivers is what the union reads. `cargo xtask` is stood in for by a stub on PATH so shard 1 is
  # instant, and the publish step by a function that succeeds or fails on demand.
  echo "land.sh selftest: the request/wait arm (the box asks, waits, and judges only what arrived)"
  local stubbin="$root/stubbin"; mkdir -p "$stubbin"
  # argv: xtask gate <g> --selftest --shard k/n — the stub owns 38 of 152, like the union cases above.
  printf '#!/bin/sh\necho "stub xtask $*"\nn=${6#*/}\necho "  shard $6: $((152 / n)) of 152 case(s)"\nexit 0\n' >"$stubbin/cargo"; chmod +x "$stubbin/cargo"
  _req() { # $1 = shards, $2 = fanout, $3 = inner, $4 = deliver (0|1), $5 = publish rc
    local out="$root/req-$1-$2-$3-$4-$5"; mkdir -p "$out"
    # THE ENVIRONMENT IS THE CASE'S, NOT THE CALLER'S. On a fleet box this self-test runs INSIDE a
    # landing, whose environment carries LAND_REMOTE_INNER=1; inherited, it turned "FANOUT without
    # INNER is refused" into a request arm that timed out — found by the box, not by the laptop.
    ( unset LAND_REMOTE_INNER LAND_SHARD_FANOUT
      export PATH="$stubbin:$PATH" LAND_SELFTEST_SHARDS="$1" LAND_SHARD_WAIT_SECS=4 LAND_SHARD_POLL_SECS=1
      [ -n "$2" ] && export LAND_SHARD_FANOUT="$2"; [ -n "$3" ] && export LAND_REMOTE_INNER=1
      eval "land_shard_publish() { return $5; }"
      # The leg names its own directory (land_shard_dir, sequence 1 of this subshell); the stand-in
      # laptop delivers there, log first and then .rc, as the real one does.
      LAND_SHARD_SEQ=0
      local legdir="$here/target/land-shards-kind-isolation-$stamp-1"
      if [ "$4" = 1 ]; then
        # As the real laptop does it, with the race the first landing hit: the .rc EXISTS empty for a
        # second before its verdict is in it. The wait must not end on the empty file.
        ( sleep 1; k=2; while [ "$k" -le "$1" ]; do printf '  shard %s/%s: %s of 152 case(s)\n' "$k" "$1" "$((152 / $1))" >"$legdir/shard-$k.log"; : >"$legdir/shard-$k.rc"; k=$((k + 1)); done
          sleep 1; k=2; while [ "$k" -le "$1" ]; do echo 0 >"$legdir/shard-$k.rc"; k=$((k + 1)); done ) &
      fi
      land_selftest_leg kind-isolation "$out/leg.log" XTASK_GATE_CEILING_SECS_KIND_ISOLATION=3600 )
  }
  _st "req: FANOUT=laptop without INNER is REFUSED" 1 _req 4 laptop "" 0 0
  _stgrep "req: the refusal says why"                "$ST_OUT" 'nobody serves shard requests here'
  _st "req: nothing delivered is RED"                1 _req 4 laptop 1 0 0
  _stgrep "req: the silent shards are NAMED"         "$ST_OUT" 'shard 2/4 never reported'
  _stgrep "req: the request was written, complete" "$here/target/land-shards-kind-isolation-$stamp-1/REQUEST" 'gate=kind-isolation n=4 sha=[0-9a-f]{40} ref=shardreq-.* ceil=XTASK_GATE_CEILING_SECS_KIND_ISOLATION=3600'
  rm -rf "$here"/target/land-shards-kind-isolation-*
  _st "req: what the laptop delivers is what is judged" 0 _req 4 laptop 1 1 0
  _stgrep "req: ...four shards, union complete"      "$ST_OUT" '4 shard\(s\) green, 152 of 152 case\(s\), union complete'
  rm -rf "$here"/target/land-shards-kind-isolation-*
  _st "req: a tree that cannot be published is RED"  1 _req 4 laptop 1 0 1
  _stgrep "req: ...and each sibling shard says so"   "$ST_OUT" 'shard 2/4 exited 2'
  rm -rf "$here"/target/land-shards-kind-isolation-*
  _st "req: sequential when no laptop serves (INNER, no FANOUT)" 0 _req 2 "" 1 0 0
  _stgrep "req: ...and says it ran sequentially"     "$ST_OUT" 'sequentially'
  rm -rf "$here"/target/land-shards-kind-isolation-*

  echo "land.sh selftest: the integration base (the box judges against the sha the laptop resolved)"
  local brepo="$root/base-repo"; mkdir -p "$brepo" "$root/nohooks"; git -C "$brepo" init -q; git -C "$brepo" config commit.gpgsign false
  git -C "$brepo" config core.hooksPath "$root/nohooks"
  git -C "$brepo" config user.email s@t; git -C "$brepo" config user.name s; git -C "$brepo" commit -q --allow-empty -m one
  local bsha; bsha="$(git -C "$brepo" rev-parse HEAD)"
  git -C "$brepo" update-ref refs/remotes/origin/integration/oracle-phase0 "$bsha"
  _bc() { ( here="$brepo"; export LAND_BASE_SHA="$1"; land_base_check ); }
  _st "base: the laptop's sha, as the box holds it, is green" 0 _bc "$bsha"
  _st "base: a box holding another sha is RED"               1 _bc "$(printf '%040d' 1)"
  _stgrep "base: ...and names both"                         "$ST_OUT" 'refusing to judge the ceilings against a tree nobody chose'
  _st "base: no LAND_BASE_SHA (off the box) checks nothing"  0 bash -c 'unset LAND_BASE_SHA; LAND_LIB_ONLY=1 . "$1"; land_base_check' _ "$0"
  git -C "$brepo" update-ref -d refs/remotes/origin/integration/oracle-phase0
  _st "base: a ref that does not resolve is RED"             1 _bc "$bsha"

  echo "land.sh selftest: only the runner lands while landq4.sh holds its lock"
  local lk="$root/landq4.lock"
  _held() { ( export LANDQ_LOCK="$lk"; unset LANDQ_RUNNER_PID; [ -n "${1:-}" ] && export LANDQ_RUNNER_PID="$1"; land_runner_holds_lock ); }
  printf '%s\n' "$$" >"$lk"
  _st "lock: a live holder is a holder"            0 _held
  _stgrep "lock: ...and is named"                  "$ST_OUT" "^$$\$"
  _st "lock: the runner itself is exempt"          1 _held "$$"
  printf '%s\n' 999999999 >"$lk"
  _st "lock: a dead pid holds nobody"              1 _held
  rm -f "$lk"
  _st "lock: no lock file holds nobody"            1 _held
  printf '%s\n' "$$" >"$lk"
  _st "lock: --remote <sha> while held is REFUSED (rc 2)" 2 env LANDQ_LOCK="$lk" LAND_SELFTEST_ROOT="$repo" bash "$0" --remote box-x deadbeefcafe
  _stgrep "lock: ...and says who holds it"          "$ST_OUT" "landq4.sh \(pid $$\) holds the landing lock"
  rm -f "$lk"

  # THE LEG ITSELF, ON A REAL GATE. Everything above tests the arithmetic over fabricated logs; this
  # runs `cargo xtask gate <g> --selftest --shard k/n` for real and asserts the leg's own verdict,
  # so a `--shard` flag that stopped being accepted, a summary line that changed shape, or a union
  # check wired to nothing would be caught here rather than on a landing. `segregation` is the
  # cheapest gate in the registry (about 6 s whole); the built runner is required, not built here,
  # because a self-test that compiles the workspace is one nobody runs.
  if [ -x "$here/target/debug/xtask" ]; then
    echo "land.sh selftest: the sharded leg, on a real gate"
    local lg="$root/leg.log"
    # `env` cannot call a shell function; a subshell keeps the variable out of the cases below.
    _leg() { local nn="$1"; shift; ( LAND_SELFTEST_SHARDS="$nn"; land_selftest_leg "$@" ); }
    _st "leg: unsharded is the whole list"  0 _leg "" \
        segregation "$lg" XTASK_GATE_CEILING_SECS_SEGREGATION=3600
    _stgrep "leg: unsharded prints no shard line" "$lg" '[0-9]+ case\(s\), 0 skipped'
    _stno   "leg: unsharded says nothing about shards" "$lg" '^ *shard [0-9]+/'
    _st "leg: three shards, union complete"  0 _leg 3 \
        segregation "$lg" XTASK_GATE_CEILING_SECS_SEGREGATION=3600
    _stgrep "leg: it names the union it proved" "$ST_OUT" '3 shard\(s\) green, [0-9]+ of [0-9]+ case\(s\), union complete'
    _stgrep "leg: every shard's own count is in the log" "$lg" '^ *shard 3/3: [0-9]+ of [0-9]+ case\(s\)'
    # A SHARD COUNT THIS SCRIPT REFUSES stops the leg before a single case runs.
    _st "leg: a nonsense shard count is RED"  1 _leg eleven \
        segregation "$lg" XTASK_GATE_CEILING_SECS_SEGREGATION=3600
  else
    printf '  SKIP %-46s (no target/debug/xtask in this tree)\n' "the sharded leg on a real gate"
  fi

  echo "land.sh selftest: the construction gate's standing reds"
  _stgrep "standing reds: the list is not empty" <(land_construction_standing_reds) '[^[:space:]]'
  _stno   "standing reds: ceiling-rose is NOT excused" <(land_construction_standing_reds) '^ceiling-rose$'

  echo "land.sh selftest: --to posture and the standing-red allowance"
  # `P_to=X land_construction_standing_reds` is a plain simple command: a one-word variable
  # assignment sitting in front of a function call. Bash applies a temporary-environment assignment
  # to a shell function exactly as it does to an external command, so this drives the SAME function
  # the gate leg calls, under the SAME posture switch, rather than a copy or a description of it.
  _land_reds_at() { P_to="$1" land_construction_standing_reds; }
  # Each of these three is its OWN case: proving "qa empties the list" says nothing about "main"
  # or "dev leaves it alone", and a single combined assertion here would pass even if two of the
  # three postures were wired wrong.
  _stno   "--to qa empties the standing-red list"                 <(_land_reds_at qa)   '[^[:space:]]'
  _stno   "--to main empties the standing-red list"                <(_land_reds_at main) '[^[:space:]]'
  _stgrep "--to dev leaves the standing-red list intact"           <(_land_reds_at dev)  '^plane-no-money$'
  _stgrep "no --to at all leaves the list intact (default is dev)" <(_land_reds_at "")   '^plane-no-money$'
  # And the refusal is not silent: it says WHY (a dev-line convenience, not inherited) and it NAMES
  # the rows an operator would otherwise not know were blocking the promotion.
  _land_reds_at qa >/dev/null 2>"$root/reds-to-qa.err"
  _stgrep "--to qa's message explains the standing-red list is a dev-line convenience" \
    "$root/reds-to-qa.err" 'DEV-LINE CONVENIENCE'
  _stgrep "--to qa's message names a standing-red row (plane-no-money)" \
    "$root/reds-to-qa.err" 'plane-no-money'

  echo "land.sh selftest: --to qa/main refuses every red-through override, one variable at a time"
  # FIVE separate cases, not a loop with one shared assertion: proving "some override got refused"
  # would still pass with four of the five silently unwired to the check. Each spawns the real
  # script — not an in-process call of land_refuse_red_overrides — so what is proven is the exit
  # code a live invocation actually gives an operator.
  _st "--to qa refuses LAND_PUSH_ANYWAY (rc 2)" 2 env LAND_PUSH_ANYWAY=1 bash "$0" --to qa
  _stgrep "...and NAMES LAND_PUSH_ANYWAY"       "$ST_OUT" 'LAND_PUSH_ANYWAY'
  _st "--to qa refuses LAND_CI_RED_OK (rc 2)"   2 env LAND_CI_RED_OK=1 bash "$0" --to qa
  _stgrep "...and NAMES LAND_CI_RED_OK"         "$ST_OUT" 'LAND_CI_RED_OK'
  _st "--to qa refuses LAND_FORCE (rc 2)"       2 env LAND_FORCE=1 bash "$0" --to qa
  _stgrep "...and NAMES LAND_FORCE"             "$ST_OUT" 'LAND_FORCE'
  _st "--to qa refuses LAND_SKIP_GATES (rc 2)"  2 env LAND_SKIP_GATES=1 bash "$0" --to qa
  _stgrep "...and NAMES LAND_SKIP_GATES"        "$ST_OUT" 'LAND_SKIP_GATES'
  _st "--to qa refuses LAND_ALLOW_RED (rc 2)"   2 env LAND_ALLOW_RED=1 bash "$0" --to qa
  _stgrep "...and NAMES LAND_ALLOW_RED"         "$ST_OUT" 'LAND_ALLOW_RED'
  _st "--to main also refuses LAND_FORCE (rc 2)" 2 env LAND_FORCE=1 bash "$0" --to main
  _stgrep "...and NAMES LAND_FORCE under --to main" "$ST_OUT" 'LAND_FORCE'

  echo "land.sh selftest: with NO --to, the override variables keep today's behaviour"
  # Same variable, no posture: the run still exits 2 (there are no hashes and no --prove), but for
  # the ORDINARY reason, not the posture refusal — the posture check must not fire at all here.
  _st "no --to: LAND_FORCE set still exits 2, but not from the posture check" 2 \
    env LAND_FORCE=1 bash "$0"
  _stno "no --to: the exit is NOT the posture refusal" "$ST_OUT" 'posture-refuses-override'

  echo "land.sh selftest: an unrecognised --to is refused and names itself plus the three it accepts"
  _st "an unrecognised --to zz is refused (rc 2)" 2 bash "$0" --to zz
  _stgrep "...names the bad value 'zz'" "$ST_OUT" "\\-\\-to zz"
  _stgrep "...names dev as accepted"    "$ST_OUT" '\bdev\b'
  _stgrep "...names qa as accepted"     "$ST_OUT" '\bqa\b'
  _stgrep "...names main as accepted"   "$ST_OUT" '\bmain\b'

  echo "land.sh selftest: a standing-red construction row still aborts the gate leg under --to qa"
  # Drives land_gate_verdict directly on a fixture report — the exact code path prove_tree's `gate)`
  # arm calls — rather than building and running the real xtask construction gate.
  # Row-filtered to `plane-no-money` alone (rather than the default "every row"): the standing-red
  # list names EIGHT other rows land_gate_verdict has never seen a PASS or FAIL for in this fixture,
  # and the leg treats a standing entry with no matching row in the log as STALE — a different red,
  # for a different reason, that this case is not testing. Scoping the regex is what isolates the
  # one fact under test: this ONE standing-red row, present and still FAIL, is excused on dev and
  # not excused under --to qa.
  printf 'FAIL  plane-no-money  x\nPASS  other  x\n' >"$root/gate-standing.txt"
  _land_gate_verdict_to() { P_to="$1" land_gate_verdict "$2" 'plane-no-money'; }
  _st "gate leg: a standing red is excused on the dev line"  0 _land_gate_verdict_to dev "$root/gate-standing.txt"
  _st "gate leg: the SAME standing red aborts under --to qa" 1 _land_gate_verdict_to qa  "$root/gate-standing.txt"
  _stgrep "gate leg: the abort names the row that is blocking" "$ST_OUT" 'plane-no-money'

  echo "land.sh selftest: the gate-file patterns (a ceiling edit is not an unproven landing)"
  land_gate_data "qa/construction.toml" >"$root/gd-ceiling.txt"
  _stgrep "a qa ceilings edit is a gate file"      "$root/gd-ceiling.txt" '^qa/construction\.toml$'
  land_gate_data "qa/kind-isolation.toml" >"$root/gd-kis.txt"
  _stgrep "the kind allowance is a gate file"      "$root/gd-kis.txt" '^qa/kind-isolation\.toml$'
  land_gate_data "xtask/src/gates/construction/ceilings.rs" >"$root/gd-src.txt"
  _stgrep "a gate SOURCE edit is a gate file"      "$root/gd-src.txt" 'gates/construction/ceilings\.rs'
  land_gate_data "crates/busbar/src/main.rs" >"$root/gd-crate.txt"
  _stno   "an ordinary crate edit is not one"      "$root/gd-crate.txt" '[^[:space:]]'
  land_gate_scripts "scripts/land.sh" >"$root/gs-sh.txt"
  _stgrep "a shell gate script is still one"       "$root/gs-sh.txt" '^scripts/land\.sh$'
  land_gate_scripts "qa/construction.toml" >"$root/gs-toml.txt"
  _stno   "the two sets do not overlap"            "$root/gs-toml.txt" '[^[:space:]]'

  echo "land.sh selftest: the shard partition (record.sh's own matcher)"
  if [ -f "$here/testing/shadow-oracle/cells.json" ]; then
    local sp; sp="$(land_shard_plan '^(billing|ledger)[|.]' 3)"
    printf '%s\n' "$sp" >"$root/shards.txt"
    local -a sr; local i=0
    while IFS= read -r r; do [ -n "$r" ] && { sr[$i]="$r"; i=$((i + 1)); }; done <<EOF
$sp
EOF
    _st "shard plan for two families is a partition" 0 land_shard_assert '^(billing|ledger)[|.]' "${sr[@]}"
    # RED-ABILITY 1: overlapping shards must be refused. Two shards that both claim `billing`.
    _st "overlapping shards are REFUSED"            1 land_shard_assert '^(billing|ledger)[|.]' '^(billing)[|]' '^(billing|ledger)[|]'
    # RED-ABILITY 2: a shard set that drops a requested family must be refused.
    _st "a shard set that drops a family is REFUSED" 1 land_shard_assert '^(billing|ledger)[|.]' '^(billing)[|]'
    # RED-ABILITY 3: a filter that selects nothing is refused, never recorded-and-green.
    _st "a zero-cell family filter is REFUSED"      1 land_shard_plan '^no-such-family-at-all[|]' 3
    # …and the planner never emits more shards than there are families.
    _stgrep "K is clamped to the family count"      "$root/shards.txt" '^\^\('
    [ "$(grep -c . "$root/shards.txt")" = 2 ] && printf '  ok   %-46s\n' "two families -> two shards" \
      || { printf '  FAIL %-46s\n' "two families -> two shards"; fails=$((fails + 1)); }
  else
    printf '  SKIP %-46s (no cells.json in this tree)\n' "shard partition"
  fi

  echo "land.sh selftest: a shard that fails to record is a RED landing"
  mkdir -p "$root/rec0" "$root/rec1"; : >"$root/rec0/meta.json"; : >"$root/rec1/meta.json"
  echo 0 >"$root/rec0.rc"; echo 0 >"$root/rec1.rc"
  _st "all shards recorded -> collect green"    0 land_shards_collect "$root/rec" 2
  echo 1 >"$root/rec1.rc"
  _st "one shard exited non-zero -> RED"        1 land_shards_collect "$root/rec" 2
  echo 0 >"$root/rec1.rc"; rm -f "$root/rec1/meta.json"
  _st "one shard left an EMPTY recording -> RED" 1 land_shards_collect "$root/rec" 2
  rm -f "$root/rec1.rc"
  _st "one shard never reported at all -> RED"  1 land_shards_collect "$root/rec" 2

  echo "land.sh selftest: the ledger union (what was RECORDED, not what was requested)"
  if [ -f "$here/testing/shadow-oracle/cells.json" ]; then
    local b1 b2 l1 l2
    b1="$(land_cell_ids | grep -m1 '^billing|')"; b2="$(land_cell_ids | grep '^billing|' | sed -n 2p)"
    l1="$(land_cell_ids | grep -m1 '^ledger|')"
    mkdir -p "$root/led0" "$root/led1"
    # Complete and disjoint over a filter that selects exactly those three cells.
    local f3; f3="$(printf '^(%s|%s|%s)$' "$(land_ere_escape "$b1")" "$(land_ere_escape "$b2")" "$(land_ere_escape "$l1")")"
    printf '%s\tPASS\tt\td\n%s\tPASS\tt\td\n' "$b1" "$b2" >"$root/led0/ledger.tsv"
    printf '%s\tPASS\tt\td\n' "$l1" >"$root/led1/ledger.tsv"
    _st "complete, disjoint ledgers -> green"   0 land_ledger_assert "$f3" "$root/led" 2
    # RED-ABILITY: the same cell in two ledgers.
    printf '%s\tPASS\tt\td\n%s\tPASS\tt\td\n' "$l1" "$b1" >"$root/led1/ledger.tsv"
    _st "a cell in two shard ledgers -> RED"    1 land_ledger_assert "$f3" "$root/led" 2
    # RED-ABILITY: a requested cell nobody recorded.
    printf '%s\tPASS\tt\td\n' "$l1" >"$root/led1/ledger.tsv"
    printf '%s\tPASS\tt\td\n' "$b1" >"$root/led0/ledger.tsv"
    _st "a requested cell in no ledger -> RED"  1 land_ledger_assert "$f3" "$root/led" 2
    # RED-ABILITY: no ledger at all is unmeasurable, therefore red.
    rm -f "$root/led1/ledger.tsv"
    _st "a shard with no ledger -> RED"         1 land_ledger_assert "$f3" "$root/led" 2
    : >"$root/led1/ledger.tsv"; : >"$root/led0/ledger.tsv"
    _st "empty ledgers (zero rows) -> RED"      1 land_ledger_assert "$f3" "$root/led" 2
  else
    printf '  SKIP %-46s (no cells.json in this tree)\n' "ledger union"
  fi

  # ── THE BATCH ENGINE, on a real repository ─────────────────────────────────────────────────────
  # Real commits, real cherry-picks, a real conflict, real resets. Only the PROOF is scripted, and
  # it is scripted as a function of the tree (a file named POISON), never of the line number — so a
  # bisect that reset the wrong way, kept a red line's picks, or dropped a green line's picks gives
  # the wrong answer here and the case fails.
  echo "land.sh selftest: the batch engine (real picks, scripted prover)"
  git -C "$repo" init -q
  git -C "$repo" config user.email land@selftest; git -C "$repo" config user.name land
  git -C "$repo" config commit.gpgsign false
  # A THROWAWAY REPOSITORY, NOT THIS DEVELOPER'S. The host's global core.hooksPath (identity checks,
  # signing policy, whatever an operator has installed) would otherwise decide whether this script's
  # own self-test can commit — a self-test whose verdict depends on the machine is not a self-test.
  mkdir -p "$root/nohooks"; git -C "$repo" config core.hooksPath "$root/nohooks"
  printf 'base\n' >"$repo/f.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm base
  local base; base="$(git -C "$repo" rev-parse HEAD)"
  # A source branch of hand-backs, exactly as an agent worktree would leave them.
  git -C "$repo" checkout -q -b src
  printf '1\n' >"$repo/a.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm c1
  local c1; c1="$(git -C "$repo" rev-parse HEAD)"
  : >"$repo/POISON"; git -C "$repo" add -A; git -C "$repo" commit -qm c2-poison
  local c2; c2="$(git -C "$repo" rev-parse HEAD)"
  printf '3\n' >"$repo/b.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm c3
  local c3; c3="$(git -C "$repo" rev-parse HEAD)"
  printf '4\n' >"$repo/c.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm c4
  local c4; c4="$(git -C "$repo" rev-parse HEAD)"
  # A commit that cannot be picked onto the integration line: it rewrites f.txt from a different base.
  git -C "$repo" checkout -q -b conflicting "$base"
  printf 'theirs\n' >"$repo/f.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm conflict-side
  local cx; cx="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q -b integ "$base"
  printf 'ours\n' >"$repo/f.txt"; git -C "$repo" add -A; git -C "$repo" commit -qm ours
  local integ; integ="$(git -C "$repo" rev-parse HEAD)"

  # CASE A — one poisoned line in four: that line alone is RED, the other three are GREEN and are
  # on the tree; the poisoned line's commit is not.
  local ba="$root/batchA.txt"
  { echo "--prove $c1"; echo "--prove $c2"; echo "--prove $c3"; echo "--prove $c4"; } >"$ba"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  _st "batch A runs (red batch exits 1)" 1 env LAND_SELFTEST_ROOT="$repo" LAND_DONE="$root/done.txt" \
      bash "$0" --batch "$ba"
  _stgrep "A: line 1 GREEN"  "$ba.result" "^GREEN.*$c1"
  _stgrep "A: line 2 RED"    "$ba.result" "^RED.*$c2"
  _stgrep "A: line 3 GREEN"  "$ba.result" "^GREEN.*$c3"
  _stgrep "A: line 4 GREEN"  "$ba.result" "^GREEN.*$c4"
  for f in a.txt b.txt c.txt; do
    [ -f "$repo/$f" ] && printf '  ok   %-46s\n' "A: $f landed" \
      || { printf '  FAIL %-46s\n' "A: $f landed"; fails=$((fails + 1)); }
  done
  [ -e "$repo/POISON" ] && { printf '  FAIL %-46s\n' "A: POISON backed out"; fails=$((fails + 1)); } \
    || printf '  ok   %-46s\n' "A: POISON backed out"
  # The batch id is the CHILD's stamp, not this selftest's: the shape is what is asserted.
  _stgrep "A: land-done.txt names outcome+batch+log" "$root/done.txt" \
    "^GREEN batch=[0-9]{8}-[0-9]{6}-[0-9]+ log=.*land-[0-9]{8}-[0-9]{6}-[0-9]+\.log .*$c1"
  _stgrep "A: land-done.txt records the RED line too" "$root/done.txt" "^RED batch=.* log=.*$c2"

  # CASE B — a conflicting line in the middle: RED-CONFLICT for that line alone, and the other three
  # are proven and landed. (No poison here: a conflict must not contaminate the rest.)
  local bb="$root/batchB.txt"
  { echo "--prove $c1"; echo "--prove $cx"; echo "--prove $c3"; echo "--prove $c4"; } >"$bb"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  _st "batch B runs (red-conflict batch exits 1)" 1 env LAND_SELFTEST_ROOT="$repo" LAND_DONE="$root/done.txt" \
      bash "$0" --batch "$bb"
  _stgrep "B: the conflicting line is RED-CONFLICT" "$bb.result" "^RED-CONFLICT.*$cx"
  _stgrep "B: line 1 GREEN" "$bb.result" "^GREEN.*$c1"
  _stgrep "B: line 3 GREEN" "$bb.result" "^GREEN.*$c3"
  _stgrep "B: line 4 GREEN" "$bb.result" "^GREEN.*$c4"
  _stgrep "B: ours survived the conflict"  "$repo/f.txt" '^ours$'

  # CASE C — all green: one proof, no bisect, every line GREEN, exit 0.
  local bc="$root/batchC.txt"
  { echo "--prove $c1"; echo "--prove $c3"; echo "--prove $c4"; } >"$bc"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  _st "batch C (all green) exits 0" 0 env LAND_SELFTEST_ROOT="$repo" LAND_DONE="$root/done.txt" \
      bash "$0" --batch "$bc"
  [ "$(grep -c '^GREEN' "$bc.result")" = 3 ] && printf '  ok   %-46s\n' "C: three GREEN lines" \
    || { printf '  FAIL %-46s\n' "C: three GREEN lines"; fails=$((fails + 1)); }
  _stgrep "C: proved ONCE, over all three lines" "$ST_OUT" 'proving lines 1,2,3'
  _stno   "C: no bisection happened"             "$ST_OUT" 'bisecting'

  # CASE C-PRE — THE SAME BATCH AS A PRE-PROOF. Same verdict, same result file, and the tree is
  # exactly where it was: a pre-proof that moved the tree would be a landing nobody asked for, and
  # the serial runner would then be popping lines onto a tip it never proved.
  local bcp="$root/batchCpre.txt"
  cp "$bc" "$bcp"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  local pre_before; pre_before="$(git -C "$repo" rev-parse HEAD)"
  _st "pre-prove of an all-green batch exits 0" 0 env LAND_SELFTEST_ROOT="$repo" LAND_PREPROVE=1 \
      LAND_DONE="$root/done-pre.txt" bash "$0" --batch "$bcp"
  [ "$(grep -c '^GREEN' "$bcp.result")" = 3 ] && printf '  ok   %-46s\n' "pre: three GREEN lines reported" \
    || { printf '  FAIL %-46s\n' "pre: three GREEN lines reported"; fails=$((fails + 1)); }
  [ "$(git -C "$repo" rev-parse HEAD)" = "$pre_before" ] \
    && printf '  ok   %-46s\n' "pre: the tree did NOT move" \
    || { printf '  FAIL %-46s (tree moved to %s)\n' "pre: the tree did NOT move" "$(git -C "$repo" rev-parse --short HEAD)"; fails=$((fails + 1)); }
  for f in a.txt b.txt c.txt; do
    [ -f "$repo/$f" ] && { printf '  FAIL %-46s\n' "pre: $f did NOT land"; fails=$((fails + 1)); } \
      || printf '  ok   %-46s\n' "pre: $f did NOT land"
  done
  [ -s "$root/done-pre.txt" ] && { printf '  FAIL %-46s\n' "pre: nothing written to land-done"; fails=$((fails + 1)); } \
    || printf '  ok   %-46s\n' "pre: nothing written to land-done"
  _stgrep "pre: it says it published nothing"    "$ST_OUT" 'PRE-PROVE — published nothing'
  # A RED PRE-PROOF IS STILL RED, and still moves nothing.
  local bfp="$root/batchFpre.txt"
  { echo "--prove $c2"; } >"$bfp"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  _st "pre-prove of a poisoned batch is RED" 1 env LAND_SELFTEST_ROOT="$repo" LAND_PREPROVE=1 \
      LAND_DONE="$root/done-pre.txt" bash "$0" --batch "$bfp"
  [ "$(git -C "$repo" rev-parse HEAD)" = "$pre_before" ] \
    && printf '  ok   %-46s\n' "pre(red): the tree did NOT move" \
    || { printf '  FAIL %-46s\n' "pre(red): the tree did NOT move"; fails=$((fails + 1)); }

  # THE FLAG FORM, which is the one that survives the trip to a fleet box. `LAND_PREPROVE=1` in the
  # environment reaches the local process and NOTHING ELSE: scripts/land-remote.sh hands the box a
  # fixed environment and forwards the argv, so the mode has to be an argument or the box takes an
  # ordinary landing and the transport fast-forwards this tree onto it.
  local bcf="$root/batchCflag.txt"
  cp "$bc" "$bcf"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  _st "--preprove (the flag) exits 0" 0 env LAND_SELFTEST_ROOT="$repo" \
      LAND_DONE="$root/done-pre.txt" bash "$0" --preprove --batch "$bcf"
  _stgrep "flag: it says it published nothing"  "$ST_OUT" 'PRE-PROVE — published nothing'
  [ "$(git -C "$repo" rev-parse HEAD)" = "$pre_before" ] \
    && printf '  ok   %-46s\n' "flag: the tree did NOT move" \
    || { printf '  FAIL %-46s\n' "flag: the tree did NOT move"; fails=$((fails + 1)); }
  # AND IT SURVIVES BEING RE-PARSED PER LINE. land_parse_args runs again for every batch line and
  # resets its own P_ variables; a mode read from those would be lost between the argv and the run.
  [ "$(grep -c '^GREEN' "$bcf.result")" = 3 ] && printf '  ok   %-46s\n' "flag: three GREEN lines reported" \
    || { printf '  FAIL %-46s\n' "flag: three GREEN lines reported"; fails=$((fails + 1)); }
  # A `--prove <sha> --preprove` argv must not read `--preprove` as a commit-ish, which is why the
  # delegation PREPENDS it. Here the same shape is parsed directly.
  printf -- '--prove %s\n' "$c1" >"$root/batchG.txt"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  _st "--preprove before the hashes parses" 0 env LAND_SELFTEST_ROOT="$repo" \
      LAND_DONE="$root/done-pre.txt" bash "$0" --preprove --batch "$root/batchG.txt"
  _stgrep "flag: one line, published nothing" "$ST_OUT" 'PRE-PROVE — published nothing'

  # CASE D — an empty batch is refused, not silently green.
  : >"$root/batchD.txt"
  _st "an empty batch is REFUSED (rc 2)" 2 env LAND_SELFTEST_ROOT="$repo" bash "$0" --batch "$root/batchD.txt"
  printf '# only a comment\n\n' >"$root/batchD.txt"
  _st "a comments-only batch is REFUSED"  2 env LAND_SELFTEST_ROOT="$repo" bash "$0" --batch "$root/batchD.txt"
  _st "a missing batch file is REFUSED"   2 env LAND_SELFTEST_ROOT="$repo" bash "$0" --batch "$root/nope.txt"
  printf -- "--tests busbar\n" >"$root/batchE.txt"
  _st "a line with no hashes and no --prove is REFUSED" 2 env LAND_SELFTEST_ROOT="$repo" bash "$0" --batch "$root/batchE.txt"

  # CASE F — every line red: nothing is left on the tree, and the batch is red.
  local bf2="$root/batchF.txt"
  { echo "--prove $c2"; } >"$bf2"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  _st "a one-line poisoned batch is RED" 1 env LAND_SELFTEST_ROOT="$repo" LAND_DONE="$root/done.txt" \
      bash "$0" --batch "$bf2"
  [ "$(git -C "$repo" rev-parse HEAD)" = "$integ" ] && printf '  ok   %-46s\n' "F: tree reset to the batch base" \
    || { printf '  FAIL %-46s\n' "F: tree reset to the batch base"; fails=$((fails + 1)); }

  # ── THE LEDGER IS RE-PINNED BY MEASUREMENT, NEVER MERGED ───────────────────────────────────────
  # A scratch model of the exact ratchet: `edges.txt` is the tree (one line per plane edge) and
  # `qa/kind-isolation.toml` pins its line count. The scripted `--write` (repin.sh) lowers the pin
  # to the count, refuses with the gate's own sentence when the count would RISE, and writes
  # nothing when they agree — the three answers the real arm gives. Every pick below is real.
  echo "land.sh selftest: the ledger by measurement (ledger conflicts resolve; re-pins are committed; a RISE is red)"
  local repin="$root/repin.sh"
  cat >"$repin" <<'EOF'
#!/usr/bin/env bash
# $1 = gate, $2 = tree. kind-isolation: re-pin `count` in qa/kind-isolation.toml DOWN to the line
# count of edges.txt; refuse a rise. construction: nothing to write.
gate="$1"; tree="$2"
[ "$gate" = kind-isolation ] || { echo "$gate: every ratcheted ceiling already equals what it measures"; exit 0; }
now="$(grep -c . "$tree/edges.txt")"; was="$(sed -n 's/^count = //p' "$tree/qa/kind-isolation.toml")"
if [ "$now" -gt "$was" ]; then
  echo "FAIL  kind-isolation:write  --write refuses: a count would RISE, and this flag only ever lowers one  (edges $was -> $now; NOTHING was written)"; exit 1
elif [ "$now" -lt "$was" ]; then
  printf 'count = %s\n' "$now" >"$tree/qa/kind-isolation.toml"; echo "PASS  kind-isolation:write  re-pinned edges $was -> $now"; exit 0
fi
echo "PASS  kind-isolation:write  every count already equals the measurement, so --write writes nothing"; exit 0
EOF
  # The ledger model goes onto the integration line's base, as a landing of its own.
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$integ"
  mkdir -p "$repo/qa"; seq -f 'edge %g' 1 98 >"$repo/edges.txt"
  printf 'count = 98\n' >"$repo/qa/kind-isolation.toml"; printf 'legacy-reach = 1\n' >"$repo/qa/construction.toml"
  git -C "$repo" add -A; git -C "$repo" commit -qm ledger-base
  local lbase; lbase="$(git -C "$repo" rev-parse HEAD)"
  # M2': drains edge 1 and pins 98 -> 97.  M3: drains edge 50 and pins 98 -> 97 — the SAME textual
  # edit to the ledger line for a DISJOINT drain. Both are honest hand-backs; together they are 96.
  git -C "$repo" checkout -q -b m2 "$lbase"
  sed -i.bak '/^edge 1$/d' "$repo/edges.txt"; rm -f "$repo/edges.txt.bak"; printf 'count = 97\n' >"$repo/qa/kind-isolation.toml"
  git -C "$repo" commit -qam "m2: drain edge 1"; local cm2; cm2="$(git -C "$repo" rev-parse HEAD)"
  git -C "$repo" checkout -q -b m3 "$lbase"
  sed -i.bak '/^edge 50$/d' "$repo/edges.txt"; rm -f "$repo/edges.txt.bak"; printf 'count = 97\n' >"$repo/qa/kind-isolation.toml"
  git -C "$repo" commit -qam "m3: drain edge 50"; local cm3; cm3="$(git -C "$repo" rev-parse HEAD)"
  # L1: drains edge 90 and pins to a DIFFERENT number (a hand-typed 50): after M2' the ledger line
  # conflicts textually, and nothing else does.
  git -C "$repo" checkout -q -b l1 "$lbase"
  sed -i.bak '/^edge 90$/d' "$repo/edges.txt"; rm -f "$repo/edges.txt.bak"; printf 'count = 50\n' >"$repo/qa/kind-isolation.toml"
  git -C "$repo" commit -qam "l1: drain edge 90, mistyped pin"; local cl1; cl1="$(git -C "$repo" rev-parse HEAD)"
  # L0: NOTHING but a ledger edit (98 -> 60). Resolved by measurement it is an empty pick, and the
  # tip must still contain it.
  git -C "$repo" checkout -q -b l0 "$lbase"
  printf 'count = 60\n' >"$repo/qa/kind-isolation.toml"; git -C "$repo" commit -qam "l0: ledger only"
  local cl0; cl0="$(git -C "$repo" rev-parse HEAD)"
  # X2: a ledger edit AND a code conflict (f.txt from the other base). Still a RED-CONFLICT.
  git -C "$repo" checkout -q -b x2 "$base"
  mkdir -p "$repo/qa"; printf 'count = 77\n' >"$repo/qa/kind-isolation.toml"; printf 'theirs2\n' >"$repo/f.txt"
  git -C "$repo" add -A; git -C "$repo" commit -qm "x2: ledger + code conflict"; local cx2; cx2="$(git -C "$repo" rev-parse HEAD)"
  # R1: ADDS an edge without touching the pin — the tree would measure 99 against 98.
  git -C "$repo" checkout -q -b r1 "$lbase"
  printf 'edge 99\n' >>"$repo/edges.txt"; git -C "$repo" commit -qam "r1: grow a coupling"; local cr1; cr1="$(git -C "$repo" rev-parse HEAD)"

  # CASE G — two lines pinning one cell to the same number for disjoint drains: both GREEN, the tree
  # measures 96, and the re-pin commit is on the tip and named in the land-done row.
  local bg="$root/batchG.txt"
  { echo "--prove $cm2"; echo "--prove $cm3"; } >"$bg"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$lbase"
  _st "G: disjoint drains, same pin -> batch exits 0" 0 env LAND_SELFTEST_ROOT="$repo" LAND_SELFTEST_REPIN="$repin" LAND_DONE="$root/done-ledger.txt" \
      bash "$0" --batch "$bg"
  _stgrep "G: M2' GREEN" "$bg.result" "^GREEN.*$cm2"
  _stgrep "G: M3 GREEN"  "$bg.result" "^GREEN.*$cm3"
  _stgrep "G: the ledger was re-pinned 97 -> 96" "$ST_OUT" 're-pinned edges 97 -> 96'
  _stgrep "G: the pin equals the measurement"     "$repo/qa/kind-isolation.toml" '^count = 96$'
  _stgrep "G: the re-pin commit is the tip"       <(git -C "$repo" log -1 --format=%s) '^ledger: re-pinned by measurement at landing \([0-9]{8}-[0-9]{6}-[0-9]+\)$'
  _stgrep "G: the re-pin commit carries the gate's words" <(git -C "$repo" log -1 --format=%b) 're-pinned edges 97 -> 96'
  _stgrep "G: both picks are under the re-pin"    <(git -C "$repo" log --format=%s -3) 'm3: drain edge 50'
  _stgrep "G: land-done names the re-pin commit"  "$root/done-ledger.txt" "^GREEN batch=.* repin=$(git -C "$repo" rev-parse --short HEAD) .*$cm3"
  _stno   "G: the tree is clean after the landing" <(git -C "$repo" status --porcelain | grep -v '^??') '[^[:space:]]'

  # CASE H — a ledger-only conflict resolves and the line is GREEN. M2' pins 97; L1 pins 50 on the
  # same line (conflict) and drains edge 90 (no conflict). The tree keeps 97, then measures 96.
  local bh="$root/batchH.txt"
  { echo "--prove $cm2"; echo "--prove $cl1"; echo "--prove $cl0"; } >"$bh"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$lbase"
  _st "H: ledger-only conflicts -> batch exits 0" 0 env LAND_SELFTEST_ROOT="$repo" LAND_SELFTEST_REPIN="$repin" LAND_DONE="$root/done-ledger.txt" \
      bash "$0" --batch "$bh"
  _stgrep "H: L1 (ledger conflict + code) GREEN"  "$bh.result" "^GREEN.*$cl1"
  _stgrep "H: L0 (ledger-only pick) GREEN"        "$bh.result" "^GREEN.*$cl0"
  _stno   "H: nothing was RED-CONFLICT"           "$bh.result" '^RED-CONFLICT'
  _stgrep "H: the resolution is recorded"         "$ST_OUT" "pick $(git -C "$repo" rev-parse --short "$cl1"): ledger conflict resolved by measurement \(qa/kind-isolation.toml\)"
  _stgrep "H: the tree measures 96 and is pinned 96" "$repo/qa/kind-isolation.toml" '^count = 96$'
  _stgrep "H: L1's drain landed"                  <(grep -c '^edge 90$' "$repo/edges.txt") '^0$'
  _stgrep "H: the empty pick is on the tip with its trailer" <(git -C "$repo" log --format=%B -4) "cherry picked from commit $cl0"
  _stno   "H: no sequencer state left behind"     <(ls "$repo/.git") 'CHERRY_PICK_HEAD|sequencer'

  # CASE I — a ledger + code conflict is RED-CONFLICT exactly as before; ours survives, nothing of
  # the pick is left on the tree.
  local bi="$root/batchI.txt"
  { echo "--prove $cm2"; echo "--prove $cx2"; } >"$bi"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$lbase"
  _st "I: ledger + code conflict -> batch exits 1" 1 env LAND_SELFTEST_ROOT="$repo" LAND_SELFTEST_REPIN="$repin" LAND_DONE="$root/done-ledger.txt" \
      bash "$0" --batch "$bi"
  _stgrep "I: X2 is RED-CONFLICT"                 "$bi.result" "^RED-CONFLICT.*$cx2"
  _stgrep "I: M2' still GREEN"                    "$bi.result" "^GREEN.*$cm2"
  _stno   "I: a code conflict is never 'resolved by measurement'" "$ST_OUT" 'resolved by measurement'
  _stgrep "I: ours survived"                      "$repo/f.txt" '^ours$'
  _stno   "I: X2's pin is not on the tree"        "$repo/qa/kind-isolation.toml" '^count = 77$'

  # CASE J — a pick that would need a RISE is RED, with the gate's message quoted; bisected off
  # the line beside it, which lands.
  local bj="$root/batchJ.txt"
  { echo "--prove $cm2"; echo "--prove $cr1"; } >"$bj"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$lbase"
  _st "J: a RISE -> batch exits 1"                1 env LAND_SELFTEST_ROOT="$repo" LAND_SELFTEST_REPIN="$repin" LAND_DONE="$root/done-ledger.txt" \
      bash "$0" --batch "$bj"
  _stgrep "J: R1 is RED"                          "$bj.result" "^RED.*$cr1"
  _stgrep "J: M2' is GREEN"                       "$bj.result" "^GREEN.*$cm2"
  _stgrep "J: the gate's refusal is quoted"       "$ST_OUT" 'land.sh:   [|] .*--write refuses: a count would RISE'
  _stgrep "J: the refusal is the RED's reason"    "$ST_OUT" 'RED — .*`gate kind-isolation --write` refused'
  _stgrep "J: R1's edge is not on the tree"       <(grep -c '^edge 99$' "$repo/edges.txt") '^0$'
  _stgrep "J: the pin is at the measurement (97)" "$repo/qa/kind-isolation.toml" '^count = 97$'
  _stno   "J: a refused write commits nothing"    <(git -C "$repo" log --format=%s -3) '^ledger: re-pinned'

  # CASE K — the skip path: a tree without `--write` (no scripted gate) lands exactly as before:
  # the picks and nothing else, the reason printed, the pin left where the picks put it.
  local bk="$root/batchK.txt"
  { echo "--prove $cm2"; } >"$bk"
  git -C "$repo" checkout -q integ; git -C "$repo" reset -q --hard "$lbase"
  _st "K: no --write on the tree -> batch exits 0" 0 env LAND_SELFTEST_ROOT="$repo" LAND_DONE="$root/done-ledger.txt" \
      bash "$0" --batch "$bk"
  _stgrep "K: the skip names its reason"          "$ST_OUT" 're-pin \(kind-isolation\): skipped — '
  _stgrep "K: …for both gates"                    "$ST_OUT" 're-pin \(construction\): skipped — '
  _stgrep "K: the tip is the pick itself"         <(git -C "$repo" log -1 --format=%s) '^m2: drain edge 1$'
  _stgrep "K: land-done says repin=none"          "$root/done-ledger.txt" "^GREEN batch=.* repin=none .*$cm2"
  # …and the real detector reads the TREE, not this script: a cli.rs without the arms is skipped.
  mkdir -p "$root/oldtree/xtask/src"; : >"$root/oldtree/xtask/src/cli.rs"
  _stgrep "K: an older xtask has no kind-isolation --write" <(LAND_SELFTEST_ROOT='' land_repin_available kind-isolation "$root/oldtree") 'older base'
  _stgrep "K: an older xtask has no construction --write"   <(LAND_SELFTEST_ROOT='' land_repin_available construction "$root/oldtree") 'older base'
  printf 'KindIsolationGate::write()\nconstruction::ceilings::rewrite(&cx)\n' >"$root/oldtree/xtask/src/cli.rs"
  _stno   "K: a tree with both arms is not skipped" <(LAND_SELFTEST_ROOT='' land_repin_available kind-isolation "$root/oldtree"; LAND_SELFTEST_ROOT='' land_repin_available construction "$root/oldtree") '[^[:space:]]'

  if [ "$fails" = 0 ]; then
    printf '\nland.sh selftest: GREEN (floor plan, shard partition, shard collection, batch bisect,\n'
    printf '                  conflict isolation, empty-batch refusal, ledger by measurement — each refuses its own planted counter-case)\n'
    rm -rf "$root"
    return 0
  fi
  printf '\nland.sh selftest: RED (%s failure(s); artifacts under %s)\n' "$fails" "$root"
  return 1
}

# THE INTEGRATION BASE, CHECKED. Under LAND_BASE_SHA (set by land-remote.sh on the box) the ref the
# construction gate reads — LAND_BASE_REF, default the origin name of the integration branch — must
# resolve to exactly that sha. Off the box (no LAND_BASE_SHA) there is nothing to check: the laptop's
# own ref is the laptop's own business.
land_base_check() {
  [ -n "${LAND_BASE_SHA:-}" ] || return 0
  local ref="${LAND_BASE_REF:-refs/remotes/origin/integration/oracle-phase0}" have
  have="$(git -C "$here" rev-parse --verify --quiet "$ref")" || {
    echo "land.sh: RED — the integration base $ref does not resolve here; the ceilings would be judged against HEAD~1" >&2; return 1; }
  [ "$have" = "$LAND_BASE_SHA" ] || {
    echo "land.sh: RED — the integration base $ref is $(printf '%.9s' "$have") here and $(printf '%.9s' "$LAND_BASE_SHA") on the laptop; refusing to judge the ceilings against a tree nobody chose" >&2; return 1; }
  echo "land.sh: integration base $ref = $(printf '%.9s' "$have"), as the laptop resolved it"
  return 0
}

# ONLY THE RUNNER LANDS. While scripts/landq4.sh holds its lock — a host-wide file naming its pid —
# a `--remote` landing that is not a pre-proof is refused: two engines landing on one fleet from one
# host is two tips racing for one integration branch. A slot proves its own branch with --preprove,
# which publishes nothing. The runner is exempt by its own pid (LANDQ_RUNNER_PID, exported by
# landq4.sh into everything it launches); a lock whose pid is dead is stale and holds nobody.
land_runner_holds_lock() { # prints the holder's pid on yes
  local lock="${LANDQ_LOCK:-$HOME/.busbar-landq4.lock}" pid
  [ -f "$lock" ] || return 1
  pid="$(head -n1 "$lock" 2>/dev/null | tr -d '[:space:]')"
  case "$pid" in ''|*[!0-9]*) return 1 ;; esac
  kill -0 "$pid" 2>/dev/null || return 1
  [ "$pid" != "${LANDQ_RUNNER_PID:-}" ] || return 1
  printf '%s\n' "$pid"
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# MAIN
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# LIBRARY MODE. scripts/land-remote.sh sources this file with LAND_LIB_ONLY=1 to run land_shard_union
# over its own copies of the shards' logs — the same five refusals, one implementation, rather than
# a second one that could drift. Nothing below this line runs when sourced that way.
if [ "${LAND_LIB_ONLY:-}" = 1 ]; then return 0 2>/dev/null || exit 0; fi
land_parse_args "$@"
export P_to

# ── --to: VALIDATE AND REFUSE, BEFORE ANY WORK ────────────────────────────────────────────────────
# This runs before the --remote delegation below (which would otherwise hand the whole job to
# another box before an unrecognised posture or a live override was ever noticed), before --batch,
# before --selftest, before a single cherry-pick. "Before any work" is not a nicety here — it is the
# difference between an override refusal and an override refusal that happened to arrive after the
# tree was already dirtied.
land_validate_to "$P_to" || exit 2
land_refuse_red_overrides || exit 2
land_print_posture "$P_to"

# ── --remote: THE SAME LANDING, ON A FLEET BOX ────────────────────────────────────────────────────
# The owner's ruling during dev churn is that GitHub Actions judges integration/qa/main and nothing
# else; a landing is proven on the EC2 fleet, directly. That is a transport decision, not a proof
# decision, so it is delegated here and NOTHING below this block changes: scripts/land-remote.sh
# pushes this tree and the batch's picks to a box, runs THIS script there with the same arguments
# minus --remote, streams the log back, copies <batch>.result back to the path the local runner
# reads, and exits with the REMOTE's status.
#
# LAND_REMOTE_INNER is what stops the delegation from being infinite: the copy running on the box
# has it set, sees it, and falls through to the ordinary engine.
[ -n "${LAND_REMOTE:-}" ] && [ -z "$P_remote" ] && P_remote="$LAND_REMOTE"
# THE FLAG BECOMES THE VARIABLE, HERE AND ONLY HERE. Every batch line is parsed by the same
# land_parse_args, which would reset `P_preprove` to 0; the mode is a property of the RUN.
[ "$P_preprove" = 1 ] && LAND_PREPROVE=1
if [ -n "$P_remote" ] && [ -z "${LAND_REMOTE_INNER:-}" ] && [ "$P_selftest" != 1 ]; then
  if [ "${LAND_PREPROVE:-}" != 1 ] && holder="$(land_runner_holds_lock)"; then
    echo "land.sh: REFUSED — landq4.sh (pid $holder) holds the landing lock; only the runner lands. Prove this branch with --preprove, which publishes nothing." >&2
    exit 2
  fi
  # THE PRE-PROVE MODE TRAVELS ON THE ARGV, because the environment does not travel at all: see
  # `--preprove` in land_parse_args. `LAND_PREPROVE=1 land.sh --remote <host>` used to prove on the
  # box in ORDINARY mode and fast-forward this tree onto the result.
  if [ "${LAND_PREPROVE:-}" = 1 ] && [ "$P_preprove" != 1 ]; then
    # PREPENDED, never appended: land_parse_args stops at the first non-flag and treats the rest as
    # hashes, so `--prove <sha> --preprove` would have made `--preprove` a commit-ish.
    exec "$(cd "$(dirname "$0")" && pwd)/land-remote.sh" --host "$P_remote" --preprove "$@"
  fi
  exec "$(cd "$(dirname "$0")" && pwd)/land-remote.sh" --host "$P_remote" "$@"
fi

if [ "$P_selftest" = 1 ]; then land_selftest; exit $?; fi

# THE BASE THE CEILINGS ARE JUDGED AGAINST IS THE ONE THE LAPTOP RESOLVED. scripts/land-remote.sh
# pushes the integration branch as this repository holds it and tells this copy the sha; a box
# whose ref says otherwise judges against a tree nobody chose. Checked here as well as by the
# transport, because this is the process that runs the gate.
land_base_check || exit 2

if [ -n "$P_batch" ]; then
  land_run_batch "$P_batch"
  exit $?
fi

# ── SINGLE LANDING ────────────────────────────────────────────────────────────────────────────────
# Unchanged in every observable way: the picks stay on the tree after a red so the integrator can
# look, and a conflict stops at the conflicting hash.
set -- $P_hashes
[ $# -gt 0 ] || [ "$P_prove" = 1 ] || { echo "land.sh: no hashes" >&2; exit 2; }
base="$(git -C "$here" rev-parse HEAD)"
git -C "$here" checkout -- Cargo.lock 2>/dev/null || true
LAND_LEDGER_RESOLVED=""
for h in "$@"; do
  git -C "$here" cherry-pick -x "$h" >/dev/null || land_resolve_ledger_conflict "$h" || {
    echo "land.sh: RED — cherry-pick $h conflicted; resolve, then re-run with the remaining hashes" >&2
    git -C "$here" status --short | head -20 >&2
    exit 1
  }
done
echo "land.sh: picked $# commit(s); tip $(git -C "$here" rev-parse --short HEAD)"
# The same re-measurement a batch gets, before the proof; a refused write leaves the picks in place
# for the integrator, like any other red on a single landing.
land_repin_ledger landing || exit 1
if [ -z "$P_tests" ] && [ $# -gt 0 ]; then
  P_tests="$(git -C "$here" diff --name-only "$base" HEAD 2>/dev/null | grep -o '^crates/[^/]*' | sort -u \
    | while read -r d; do grep -m1 '^name = ' "$here/$d/Cargo.toml" 2>/dev/null | sed 's/name = "\(.*\)"/\1/'; done | tr '\n' ' ')"
fi
prove_tree "$base" "$P_tests" "$P_gate" "$P_families" "landing" "$P_features" || exit 1
# ── THE GREEN LINE NAMES ITS SCOPE ────────────────────────────────────────────────────────────────
# It used to read "GREEN — landed N commit(s)" whatever had run, including nothing. A verdict that
# does not say what it measured is read as having measured everything.
echo "land.sh: GREEN — landed $# commit(s) at $(git -C "$here" rev-parse --short HEAD)"
echo "land.sh: proven by:$PROVEN and nothing else. A green here is exactly that list."
