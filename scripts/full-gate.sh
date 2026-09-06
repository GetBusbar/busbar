#!/usr/bin/env bash
# full-gate.sh -- run LOCALLY what CI runs, so "green" has one meaning.
#
#   scripts/full-gate.sh              # every locally-runnable gate
#   scripts/full-gate.sh --selftest   # prove this script's own discovery and floors
#   scripts/full-gate.sh --list       # what it would run, and what it deliberately skips
#
# WHY THIS EXISTS, and it is not convenience.
#
# `ci.yml` invokes twenty distinct gate scripts across thirteen jobs. There was no single command
# that ran them, so everybody -- people and agents alike -- ran `cargo test`, maybe clippy, and
# reported "green". That is not a hypothetical: during the 1.5.5 build two branches were reported
# green on `cargo test` alone and BOTH were failing gates that had never been run. One was
# `structure-lint` (a file 46 lines over the size cap); the other was `public-hygiene` (a comment
# that pointed a reader at something they had no way to open). Neither was a hard problem. Both
# were invisible because the person checking chose the subset.
#
# That second one is also why this header had to be edited: the sentence describing the hit
# reproduced the hit. A gate that its own explanation fails is a gate people learn to skip.
#
# A subset that the checker chooses is not a gate. It is a preference. This script removes the
# choice.
#
# HOW THE LIST IS BUILT, and why not by hand. The gates are DISCOVERED from `.github/workflows/ci.yml`
# by reading its `run:` lines, not from a list maintained here. A hand-written list is exactly the
# drift this file exists to stop, one level up: it would agree with CI on the day it was written and
# quietly disagree forever after. Add a gate to `ci.yml` and it appears here on the next run.
#
# CLASSIFICATION IS EXPLICIT AND FAILS CLOSED. Some CI gates cannot run on a laptop -- they need a
# tagged release, published artifacts, or a full qa fleet. Those are named in SKIP_REASON below WITH
# the reason. Anything discovered that is in NEITHER list is a HARD FAILURE, not a silent skip: a new
# gate in `ci.yml` breaks this script until somebody decides which it is. That is the same
# make-omission-impossible shape `config_validate::secret_refs` uses on the config surface, and it is
# here for the same reason -- the failure mode is a gate that silently stops being run.
#
# FLOORS. A discovery step that finds nothing passes everything. This one refuses to run if it finds
# fewer than MIN_GATES, and refuses if `ci.yml` is unreadable. Unknown is not green.
#
# `ci.yml` IS NOT THE WHOLE OF WHAT A PUSH IS JUDGED BY, and this script behaved as though it were.
# A push to `qa` also spends `qa-gate.yml`, whose `umbrella` is the second required check. Every one
# of its tiers is invoked as `./scripts/qa-gate-run.sh <verb>`, so discovery collapsed all of them
# into one bare script name that SKIP_REASON already excused -- a new tier of the qa gate was
# therefore neither run here nor named, which is the "absent from both lists" hole, one file over.
# qa-gate.yml is now discovered PER VERB into QA_ACCOUNTED, with the same fails-closed rule, and
# `--selftest` additionally refuses a tree whose qa-gate umbrella has lost the `done-oracle` job
# (proven by planting that exact mutation and requiring `ci-umbrella-lint.py` to go red on it).
#
# THE CARGO INVOCATIONS ARE DISCOVERED AND CLASSIFIED THE SAME WAY, and that is a repair, not a
# feature. This script used to hard-code three cargo lines -- fmt, clippy, test, all on the DEFAULT
# feature set, on this host. CI runs eleven, across FOUR build configurations, and the three that
# were missing are the three that have now taken the 1.6.0 build down in a row: a stale committed
# `openapi.json` (`--features openapi-schema`), a hook-resolution defect that only surfaced under
# `--no-default-features`, and an mTLS test reading a client-side error string that Windows words
# differently. Every one of them was reported 33/33 green here on the exact commit CI rejected.
#
# A local green that does not cover the configuration CI runs is not the same claim as a CI green,
# and it was being read as one. So the cargo lines are now read out of `ci.yml` like everything
# else, each is classified LOCAL or CI-only WITH A REASON, and an unclassified one is a hard
# failure -- the same fails-closed shape the script's rule already had. Windows genuinely cannot run
# here; that is named as such, and the final line says so rather than letting "all pass" imply it.
set -uo pipefail
export RUSTFLAGS="-D warnings"   # same as CI env; --selftest asserts ci.yml's workflow-level RUSTFLAGS matches this

CI_YML=".github/workflows/ci.yml"

# `--dump-cargo [FILE]` prints, one per line, the cargo invocations discovery finds in FILE (default:
# CI's own workflow) and exits before any classification. It exists so the selftest can point discovery
# at a fixture and assert on what it found. It runs NO gate and relaxes NO floor: the floors below still
# apply, which is why the fixture carries eight script invocations of its own.
[ "${1:-}" = "--dump-cargo" ] && [ -n "${2:-}" ] && CI_YML="$2"

# `--dump-gates [FILE]` is the script half's twin of `--dump-cargo`: it prints the SCRIPT invocations
# discovery finds in FILE and exits before classification, so the selftest can point discovery at a
# fixture and assert on what it found rather than on what it hopes it found.
[ "${1:-}" = "--dump-gates" ] && [ -n "${2:-}" ] && CI_YML="$2"

# Gates that genuinely cannot run locally. Each entry carries WHY, because a skip without a reason
# becomes permanent.
declare -a SKIP_REASON=(
  "scripts/release-check.sh|consumer-side verification of a PUBLISHED release: downloads tagged artifacts from GitHub Releases and Docker Hub. There is nothing to verify before a tag exists."
  "scripts/verify-artifact.py|per-artifact contract against BUILT release binaries. Needs the release matrix's outputs, which only the release workflow produces."
  "scripts/qa-gate-run.sh|the full qa fleet: ten plugin repos, service containers, a real Postgres/Valkey/MySQL. Runs on promotion, not on a laptop."
  "scripts/qa-segments.sh|drives the qa fleet segmentation; same fleet dependency as qa-gate-run.sh."
  "scripts/plugin-registry-check.sh|reads the published plugin registry over the network; a local run measures the network, not the tree."
  "scripts/loom.sh|exhaustive interleaving model, minutes of CPU per run. Deliberately out of the default loop; run it directly when touching the config swap."
  "scripts/txn-fence.sh|compiles a module that MUST FAIL to type-check, in its own target dir. Correct, but it inverts the exit code and confuses a batch runner; run it directly."
  "scripts/build-provenance-gate.sh|asserts the provenance stamp of a BUILT release binary ('… target/release/busbar release false'). Needs the release artifact the release build produces, exactly as verify-artifact.py does; a bare local run has no binary to inspect. The --selftest form runs here — it is the local mirror that proves the stamp discriminates."
  "scripts/proof-manifest.py|the Build-Proof-Dashboard collator, run ONLY on the dev/qa/main promotion branches (it needs --version/--out and re-emits docs/proof/<branch>.json). By its own contract it CHANGES NO GATE — it re-runs the cheap grep gates and records their verdicts — so there is nothing to prove locally on an integration branch."
  "scripts/release-order-lint.py|release-graph shape; included via its own entries below, see RELEASE_ORDER."
  # ── THE `testing/` HARNESS GATES ────────────────────────────────────────────────────────────────
  # Newly VISIBLE, not newly skipped: discovery could not see a `testing/` path at all until now, so
  # these were neither run nor named. Four of the eleven invocations DO run here and are absent from
  # this list on purpose — testing/shadow-oracle/enumerate-cells.py --check,
  # testing/shadow-oracle/harness-rev.sh, testing/shadow-oracle/replay-selftest.sh and
  # testing/llm-conformance/selftest.sh are hermetic and each takes seconds.
  "testing/shadow-oracle/fetch-golden.sh|downloads the PUBLISHED 1.5.5 release tarball from GitHub Releases and verifies it against golden-digests.tsv. It measures the network and a published artifact, not this tree."
  "testing/shadow-oracle/fetch-plugin.sh|same: fetches each published plugin artifact by digest over the network, one per plugin named in plugin-digests.tsv."
  "testing/shadow-oracle/selftest.sh|takes TWO built binaries as positional arguments (the release build and the cached 1.5.5 golden). Neither exists on a laptop until fetch-golden.sh has run and a release profile has been built; a bare invocation has nothing to compare."
  "testing/shadow-oracle/record.sh|drives a built binary through every recorded cell and writes a recording tree. Needs the release build and the fetched golden binary, exactly as selftest.sh does — CI runs it twice, once per side."
  "testing/shadow-oracle/replay.sh|compares the two recording trees record.sh produces. With no recordings there is nothing to replay; the harness's own logic IS proven here by testing/shadow-oracle/replay-selftest.sh, which runs."
  "testing/llm-conformance/run.sh|replays the candidate recording against the vendor specs pinned in spec-digests.tsv, which are fetched over the network and are not in the repository. Its harness logic is proven here by testing/llm-conformance/selftest.sh, which runs."
  "scripts/construction-gate.sh|RED BY DESIGN on HEAD (three rows over their qa/construction.toml ceilings) while the construction work it measures is in flight; ci.yml runs its --check report-only (continue-on-error, verdict printed by the umbrella, not counted). Running it here would red the whole local gate on a fact CI does not score. Its --selftest DOES run here (the rule above). Run 'scripts/construction-gate.sh --check' directly for the report; DELETE this entry when the CI job is flipped to blocking."
)

# `release-order-lint.py` IS locally runnable and IS included -- named here only so the skip loop
# above does not swallow it by prefix.
RELEASE_ORDER=1

MIN_GATES=8

# ── THE qa-gate SIDE OF CI, DISCOVERED THE SAME WAY ───────────────────────────────────────────────
# `ci.yml` is not the whole of what a push is judged by. Pushing to `qa` also spends `qa-gate.yml`,
# whose umbrella is the second required check, and this script could not see a single one of its
# gates: every one is invoked as `./scripts/qa-gate-run.sh <verb>`, and discovery collapsed all of
# them into the bare script name that SKIP_REASON already covered. So a new verb -- a new tier of the
# qa gate -- was neither run here nor named as CI-only, which is the exact "absent from both lists"
# hole the extension and directory sets were widened to close, one file over.
#
# It matters now because `done-oracle` is that new tier: `scripts/verify-1.6.0-done.sh` in FULL,
# including the release build, both `--plane all` recordings and the replay against the pinned 1.5.5
# golden. It is the longest job in either workflow. It is CI-only for two independent reasons and
# both are written down below, and it is discovered per-VERB rather than per-script so that adding a
# verb to the qa gate breaks this script until somebody classifies it.
QA_YML=".github/workflows/qa-gate.yml"
MIN_QA_GATES=6

declare -a QA_ACCOUNTED=(
  "scripts/qa-gate-run.sh matrix|converts qa/segments.toml into a strategy.matrix JSON on \$GITHUB_OUTPUT. Outside a runner it has no job output to write and no matrix to drive."
  "scripts/qa-gate-run.sh fast|the fast tier plus the reserved-slot report, and it runs the fleet's segments. Same fleet dependency as qa-segments.sh above."
  "scripts/qa-gate-run.sh build|builds the whole workspace and packs target/ into a tarball for the fan-out. Locally that is just a slow rebuild of what is already here, for an artifact nothing consumes."
  "scripts/qa-gate-run.sh hydrate|restores that tarball over a fresh checkout and rewrites mtimes. There is no build-once artifact on a laptop, and running it over a real tree is a way to lose one."
  "scripts/qa-gate-run.sh siblings|clones ten plugin repos plus busbar-admin with a runner token. It measures the network and the org's permissions, not this tree."
  "scripts/qa-gate-run.sh segment|one live-mock leg: real Postgres/Valkey/MySQL/Vault containers and the published plugin set. Runs on promotion, not on a laptop."
  "scripts/qa-gate-run.sh loader|the loader-mechanism tests against the SIBLING-built store-sqlite cdylib, which only exists after the sibling checkouts above."
  "testing/shadow-oracle/harness-rev.sh|NOT a gate here: qa-gate.yml runs it to COMPUTE the golden cache key (it must be the same key ci.yml computes, from the same shared function, or the two jobs restore different goldens). It is hermetic and already runs locally, discovered from ci.yml, in the RUN list above."
  "scripts/qa-gate-run.sh done-oracle|LONG, and CI-only for two independent reasons. (1) It runs scripts/verify-1.6.0-done.sh in FULL, whose BUILD group is THIS SCRIPT -- running it here is unbounded recursion, not a gate. (2) Its PARITY group needs the published 1.5.5 binary and the pinned plugin set fetched over the network, then a release build and two full --plane all recordings; measured wall clock is ~100-140 min with a warm golden cache. The parts of it that CAN run on a laptop already do, individually, as the gates ci.yml invokes directly. Run 'scripts/verify-1.6.0-done.sh' yourself when you want the whole verdict, and give it two hours."
)

# ── THE CARGO GATES ───────────────────────────────────────────────────────────────────────────────
# CI's cargo invocations, normalised (spaces collapsed, `--verbose` dropped -- it changes output, not
# what is proven). LOCAL ones run here, in this order. CI-only ones carry their reason.
#
# Normalisation is what makes the two `--workspace` pairs distinguishable: the Linux job passes
# `--locked` and the Windows job does not, so "same command, different platform" does not collapse
# into one entry.
declare -a CARGO_LOCAL=(
  "cargo fmt --all -- --check"
  "cargo clippy --workspace --all-targets --locked -- -D warnings"
  "cargo build --workspace --locked"
  "cargo test --workspace --locked"
  "cargo clippy --no-default-features --locked -- -D warnings"
  "cargo build --no-default-features --locked"
  "cargo test --no-default-features --locked"
  "cargo clippy -p busbar -p busbar-core --all-targets --features openapi-schema --locked -- -D warnings"
  "cargo test -p busbar -p busbar-core --features openapi-schema --locked openapi -- --nocapture"
  "cargo build --locked --bin busbar"
  "cargo test -p busbar --test migration_corpus --locked -- --nocapture"
  "cargo test -p busbar-voice --features runtime,test-support -p busbar-voice-codec --features runtime --locked"
  "cargo test -p busbar-llm --features teller-waist --locked --lib unit::"
  "cargo test -p busbar-timing --features timing --locked"
)

declare -a CARGO_CI_ONLY=(
  "cargo build --workspace|the WINDOWS job's build. There is no Windows host here, and the failures it catches are precisely the ones that do not reproduce on this one -- path separators, socket error wording, line endings. Nothing local substitutes for it."
  "cargo test --workspace|the WINDOWS job's test run; same reason. This is the one gap a local run genuinely cannot close: read a green here as 'green on this platform'."
  "cargo clippy --workspace --all-targets -- -D warnings|the WINDOWS job's clippy. It exists to catch the platform-gated code no local run compiles at all -- a #[cfg(unix)] item whose #[cfg(windows)] twin was never written is a warning THERE and nowhere here. A macOS/Linux clippy cannot substitute: it takes the other arm of every cfg. Approximated locally with 'cargo xwin clippy --target x86_64-pc-windows-msvc', which type-checks the Windows arms without a Windows host but still executes nothing."
  "cargo test --release --locked timing_gate -- --ignored|a RELEASE-profile wall-clock gate on a dedicated runner. A debug tree with a compiler and a browser competing for the CPU measures the laptop, not the engine; run it directly when touching the timing path."
  "cargo build -p busbar --release --locked|the RELEASE-profile build that feeds build-provenance-gate.sh (it asserts the shipped binary's optimized posture). The local build mirror is the debug 'cargo build --locked --bin busbar' above; a release build here would re-measure the laptop, not prove anything the debug build does not."
  "cargo build -p busbar-core -p busbar-substrate -p busbar-api --no-default-features --features \"\$FEATS\" --locked|the plane-DELETION matrix build. \$FEATS is '\${{ matrix.features }}', which expands per kept-plane combination -- a CI matrix construct with no single local form, and the literal string is not a runnable command. It is mirrored locally by the delete-test gate (PLANE-DELETE group), which compiles the neutral crates with a plane removed."
  "cargo build -p busbar-core -p busbar-substrate -p busbar-api --no-default-features --locked|the same plane-DELETION matrix build's EMPTY-features arm (every plane removed). Same matrix job, same local mirror in the delete-test gate; listed separately because the step branches on \$FEATS and both arms are real invocations."
  "cargo test -p busbar-llm --lib alloc_gate -- --nocapture|the deterministic alloc-count perf gate, invoked BY NAME so a regression reds this one line rather than a 400-test workspace run. The same tests are also executed by 'cargo test --workspace --locked' above, which DOES run locally. (It read '-p busbar-core' here for as long as ci.yml did, matching zero tests in both places — a libtest filter that selects nothing exits 0.)"
)

# Normalise a cargo invocation for comparison: drop the shell plumbing CI wraps it in (`2>&1`, a
# trailing `\` line-continuation, a stdout redirect WITH its target file, and a trailing `&` that
# backgrounds it), drop `--verbose` (it changes output, not what is proven), collapse whitespace. So
# the COMMAND, not the log file it writes or the job control around it, is what gets classified.
#
# The redirect used to fall off for the wrong reason — capture stopped at the `"` that opened the log
# file's name. Capture now keeps quoted arguments (the plane-deletion build passes `--features
# "$FEATS"`, and cutting there left a dangling `--features`), so the redirect is stripped HERE, by
# name, instead of by accident.
cargo_norm() {
  printf '%s\n' "$1" | sed -e 's/2>&1//g' -e 's/--verbose//g' -e 's/[[:space:]]*\\$//' \
    -e 's/[0-9]*>>\{0,1\}.*$//' -e 's/[[:space:]]*&[[:space:]]*$//' \
    -e 's/[[:space:]]\{1,\}/ /g' -e 's/^ //' -e 's/ $//'
}

cargo_ci_only_reason() {
  local cmd="$1" entry
  for entry in "${CARGO_CI_ONLY[@]}"; do
    [ "${entry%%|*}" = "$cmd" ] && { printf '%s' "${entry#*|}"; return 0; }
  done
  return 1
}

die() { printf 'full-gate: %s\n' "$*" >&2; exit 2; }

[ -f "$CI_YML" ] || die "no $CI_YML -- run this from the repository root. A gate runner that cannot find CI is not a gate runner."

# ── ci.yml AS LOGICAL LINES ───────────────────────────────────────────────────────────────────────
# A COMMAND CI WRAPS OVER SEVERAL LINES IS ONE COMMAND, and discovery used to read `ci.yml` a physical
# line at a time. The voice-runtime step wraps its `cargo test` over three backslash-continued lines,
# so the runner saw the first fragment — `cargo test -p busbar-voice --features runtime,test-support`,
# a TRUNCATION that names neither the second crate nor `--locked`. It matched no list, the fails-closed
# rule fired, and `--list` and `--selftest` both aborted: the gate runner was unusable, on a defect in
# its own reader rather than anything in the tree. Pasting the truncation into a list would have been
# worse than the abort — it records a command CI does not run.
#
# So the file is folded into LOGICAL lines here, once, before anything matches against it:
#
#   * inside a `run:` block scalar only, a line ending in `\` is joined to the next one. Outside a
#     `run:` step nothing is joined; `run: cargo fmt --all -- --check` on one line stays one line.
#   * `>` folded scalars are folded the way YAML folds them (every line of the block is one command),
#     `|` literal scalars keep their line structure except for the `\` joins.
#   * a joined statement that begins `echo ` is DROPPED. This is the half a first attempt got wrong:
#     joining without it welds a step's surrounding `echo` lines onto its command and invents
#     fragments CI never runs. An `echo` that quotes a cargo command is a step printing a message, the
#     same category as a `#` comment or a step `name:`, and none of the three is a gate.
#
# Shell comment lines inside a step are dropped here; the `#`/`name:` stripping downstream handles the
# YAML level. `scripts/fixtures/full-gate/continuation-ci.yml` holds all four shapes and the selftest
# asserts on what discovery makes of them.
ci_logical_lines() {
  awk '
    function emit(s) {
      sub(/^[ \t]+/, "", s)
      if (s ~ /^echo[ \t]/) return
      if (s ~ /^#/) return
      print s
    }
    function flush(  s) { if (pending != "") { s = pending; pending = ""; emit(s) } }
    {
      line = $0
      if (in_run) {
        if (line ~ /^[ \t]*$/) { flush(); next }
        indent = match(line, /[^ \t]/) - 1
        if (indent <= run_indent) { flush(); in_run = 0 }
      }
      if (!in_run) {
        if (line ~ /^[ \t]*-?[ \t]*run:[ \t]*[|>]/) {
          run_indent = match(line, /[^ \t]/) - 1
          fold = (line ~ /run:[ \t]*>/)
          in_run = 1; pending = ""
          next
        }
        print line
        next
      }
      body = line
      sub(/^[ \t]+/, "", body)
      if (body ~ /^#/) next
      if (fold || body ~ /\\[ \t]*$/) {
        sub(/\\[ \t]*$/, "", body)
        pending = pending body " "
        next
      }
      pending = pending body
      flush()
    }
    END { flush() }
  ' "$CI_YML"
}

# ── DISCOVERY ─────────────────────────────────────────────────────────────────────────────────────
# Every `scripts/...` invocation CI makes, with its arguments, deduplicated and in a stable order.
# COMMENT LINES AND STEP `name:` LABELS ARE STRIPPED FIRST, exactly as the cargo discovery below does:
# a `#` comment that MENTIONS a script by name (e.g. "scripts/plane-delete-test.sh PHYSICALLY REMOVES
# ...") is documentation, not an invocation, and running that bare mention as if it were a gate prints
# a usage line and a false red. Only real `run:` lines survive.
#
# This half reads PHYSICAL lines deliberately, where the cargo half below reads logical ones. A gate
# script's continuation lines are ARGUMENTS, and the head line already names the gate; splicing the
# rest in would hand a gate a half-captured argument list (the capture stops at the first quote), which
# is the false red this file exists to prevent.
#
# THE EXTENSION SET IS NOT `sh|py`, and it was, which is how a gate went unrun AND unlisted. `ci.yml`
# runs `node scripts/check-proof-manifest-public.mjs` — the fail-closed public-safety guard on the
# proof manifest, the one thing standing between the private source tree and a manifest the
# marketing site renders publicly. Discovery could not see a `.mjs` file or a `node ` prefix, so it
# appeared in neither list: not run here, and not named as CI-only either. That is worse than a
# skip. The whole classification below fails CLOSED on a gate it can SEE; a gate it cannot see is
# not classified at all, and the "N gates, M skipped with reason" line at the end counts confidently
# past it. The extension set and the interpreter prefixes are therefore both widened beyond what the
# tree happens to contain today, because the next gate written in a new language should break this
# script rather than disappear from it.
#
# THE DIRECTORY SET IS NOT `scripts/`, AND IT WAS — the same shape of hole as the extension set, one
# axis over. `ci.yml` makes ELEVEN gate invocations under `testing/`: the whole shadow-oracle harness
# (`replay-selftest.sh`, `selftest.sh`, `fetch-golden.sh`, `record.sh`, `replay.sh`,
# `enumerate-cells.py`, `harness-rev.sh`) and the llm-conformance suite (`selftest.sh`, `run.sh`).
# Those are gates by every definition this file uses — CI reds when they red — and discovery could
# not see any of them because the pattern began with the literal `scripts/`. Four of the eleven run
# perfectly well on a laptop and were simply never run; the other seven need a golden binary, a
# recording or the network, and were not NAMED as such either. Both halves are now visible: run, or
# skipped with a reason, and never absent.
#
# The path pattern also allows nested directories (`testing/shadow-oracle/replay.sh`), which the
# flat `scripts/` shape never needed.
GATE_EXT='(sh|py|mjs|js|ts|rb)'
# The trailing `\b` is load-bearing now that `testing/` is in the set: `spec-digests.tsv`,
# `golden-digests.tsv` and `plugin-digests.tsv` are DATA files ci.yml reads with `cut`/`awk`, and
# without a word boundary the `ts` alternative matches their first two extension characters and
# discovery invents three gates named `…-digests.ts` that do not exist. A discovery that invents
# gates is the mirror of one that loses them, and it fails just as closed: those three would land in
# neither list and abort the runner.
GATE_PATH="(scripts|testing)/([a-z0-9-]+/)*[a-z0-9-]+\.${GATE_EXT}\b"
mapfile -t DISCOVERED < <(
  sed -e 's/^[[:space:]]*#.*$//' -e 's/^[[:space:]]*-\{0,1\}[[:space:]]*name:.*$//' "$CI_YML" \
    | grep -oE "(python3 |bash |node |npx )?${GATE_PATH}( --[a-z-]+( [^ \"'|]+)?)*" \
    | sed 's/^ *//' | sort -u
)

[ "${#DISCOVERED[@]}" -ge "$MIN_GATES" ] || die "discovered only ${#DISCOVERED[@]} gate invocation(s) in $CI_YML (floor $MIN_GATES). The parser is broken, and a broken discovery reports a clean tree."

# qa-gate's gates, discovered PER VERB. Only when CI_YML is the real ci.yml -- `--dump-cargo` /
# `--dump-gates` point discovery at a fixture and must not silently pull a second real file in
# beside it. The capture allows one bare word after the script name, which is what makes
# `qa-gate-run.sh done-oracle` a distinct invocation from `qa-gate-run.sh loader` instead of both
# collapsing into the script name SKIP_REASON already excuses.
QA_DISCOVERED=(); QA_UNCLASSIFIED=()
if [ "$CI_YML" = ".github/workflows/ci.yml" ] && [ -f "$QA_YML" ]; then
  mapfile -t QA_DISCOVERED < <(
    sed -e 's/^[[:space:]]*#.*$//' -e 's/^[[:space:]]*-\{0,1\}[[:space:]]*name:.*$//' "$QA_YML" \
      | grep -oE "${GATE_PATH}( [a-z][a-z-]*)?" | sort -u
  )
  [ "${#QA_DISCOVERED[@]}" -ge "$MIN_QA_GATES" ] || die "discovered only ${#QA_DISCOVERED[@]} gate invocation(s) in $QA_YML (floor $MIN_QA_GATES). qa-gate's umbrella is a required check; a discovery that cannot see its tiers cannot classify them."

  # FAILS CLOSED, exactly as the ci.yml halves do: a qa-gate verb in neither list breaks this script
  # until somebody decides which it is. Every one is CI-only today, and each says why in writing.
  for inv in "${QA_DISCOVERED[@]}"; do
    known=0
    for entry in "${QA_ACCOUNTED[@]}"; do [ "${entry%%|*}" = "$inv" ] && { known=1; break; }; done
    [ "$known" = 1 ] || QA_UNCLASSIFIED+=("$inv")
  done
  if [ "${#QA_UNCLASSIFIED[@]}" -gt 0 ] && [ "${1:-}" != "--selftest" ]; then
    printf 'full-gate: %s\n' "$QA_YML runs gate invocation(s) this script neither runs nor names as CI-only:" >&2
    printf '  %s\n' "${QA_UNCLASSIFIED[@]}" >&2
    die "add each to QA_ACCOUNTED with a reason. A tier of the qa gate that is in neither list is a tier nobody is accounting for."
  fi
fi

# After the floor, deliberately: `--dump-gates` relaxes nothing.
if [ "${1:-}" = "--dump-gates" ]; then
  printf '%s\n' "${DISCOVERED[@]}"
  exit 0
fi

# Every cargo invocation CI makes, normalised. COMMENT LINES AND STEP `name:` LABELS ARE STRIPPED
# FIRST: `ci.yml` documents the openapi refresh command in a comment, and a step's `name:` field is a
# human label that quotes commands in prose (e.g. "the suite `cargo test --workspace` never runs") —
# a documented or quoted command is not a gate. A `>` redirect is likewise excluded at capture, so the
# COMMAND, not the log file it writes, is what gets classified.
mapfile -t CARGO_DISCOVERED < <(
  ci_logical_lines \
    | sed -e 's/^[[:space:]]*#.*$//' -e 's/^[[:space:]]*-\{0,1\}[[:space:]]*name:.*$//' \
    | grep -v "^[[:space:]]*echo " \
    | grep -oE 'cargo (fmt|clippy|build|test|run)[^|)]*' \
    | while IFS= read -r c; do cargo_norm "$c"; done \
    | grep -v '^$' | sort -u
)

if [ "${1:-}" = "--dump-cargo" ]; then
  printf '%s\n' "${CARGO_DISCOVERED[@]}"
  exit 0
fi

# FAILS CLOSED, exactly as the script's rule does: a cargo invocation in `ci.yml` that is in NEITHER
# list breaks this script until somebody decides which it is. Silence here is how the openapi and
# no-default-features configurations went unrun for three releases.
CARGO_UNCLASSIFIED=()
for cmd in "${CARGO_DISCOVERED[@]}"; do
  known=0
  for l in "${CARGO_LOCAL[@]}"; do [ "$l" = "$cmd" ] && { known=1; break; }; done
  [ "$known" = 1 ] && continue
  cargo_ci_only_reason "$cmd" >/dev/null && continue
  CARGO_UNCLASSIFIED+=("$cmd")
done
if [ "${#CARGO_UNCLASSIFIED[@]}" -gt 0 ] && [ "${1:-}" != "--selftest" ]; then
  printf 'full-gate: %s\n' "$CI_YML runs cargo invocation(s) this script neither runs nor names as CI-only:" >&2
  printf '  %s\n' "${CARGO_UNCLASSIFIED[@]}" >&2
  die "add each to CARGO_LOCAL (it runs here) or CARGO_CI_ONLY with a reason (it cannot). An unrun configuration is how a local green stops meaning a CI green."
fi

skip_reason_for() {
  local script="$1" entry
  for entry in "${SKIP_REASON[@]}"; do
    [ "${entry%%|*}" = "$script" ] && { printf '%s' "${entry#*|}"; return 0; }
  done
  return 1
}

RUN=(); SKIP=()
for inv in "${DISCOVERED[@]}"; do
  script="$(printf '%s' "$inv" | grep -oE "$GATE_PATH")"
  # A `--selftest` ALWAYS runs, whatever its script's classification. A self-test plants its own
  # fixtures by definition -- that is what makes it a self-test rather than a run -- so it needs no
  # release artifact, no fleet and no network. Skipping one because its sibling REAL run needs a
  # tagged build would drop exactly the check that proves the gate still works, which is the check
  # most worth having locally: `verify-artifact.py --selftest` proves the artifact contract
  # discriminates without a single artifact existing.
  case "$inv" in *--selftest*) RUN+=("$inv"); continue ;; esac
  # `release-order-lint.py` is runnable; everything else in SKIP_REASON is not.
  if [ "$script" = "scripts/release-order-lint.py" ]; then RUN+=("$inv"); continue; fi
  if skip_reason_for "$script" >/dev/null; then SKIP+=("$inv"); else RUN+=("$inv"); fi
done

# ── --list ────────────────────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--list" ]; then
  printf '== CARGO GATES, WILL RUN (%d) ==\n' "${#CARGO_LOCAL[@]}"
  printf '  %s\n' "${CARGO_LOCAL[@]}"
  printf '\n== CARGO GATES, CI-ONLY WITH REASON (%d) ==\n' "${#CARGO_CI_ONLY[@]}"
  for entry in "${CARGO_CI_ONLY[@]}"; do printf '  %-46s %s\n' "${entry%%|*}" "${entry#*|}"; done
  printf '\n== WILL RUN (%d) ==\n' "${#RUN[@]}"
  printf '  %s\n' "${RUN[@]}"
  printf '\n== SKIPPED, WITH REASON (%d) ==\n' "${#SKIP[@]}"
  for inv in "${SKIP[@]}"; do
    s="$(printf '%s' "$inv" | grep -oE "$GATE_PATH")"
    printf '  %-44s %s\n' "$inv" "$(skip_reason_for "$s")"
  done
  printf '\n== qa-gate.yml TIERS, ACCOUNTED FOR WITH REASON (%d discovered) ==\n' "${#QA_DISCOVERED[@]}"
  for inv in "${QA_DISCOVERED[@]}"; do
    for entry in "${QA_ACCOUNTED[@]}"; do
      [ "${entry%%|*}" = "$inv" ] && printf '  %-40s %s\n' "$inv" "${entry#*|}"
    done
  done
  exit 0
fi

# ── --selftest ────────────────────────────────────────────────────────────────────────────────────
# Asserts DISCOVERY works and the floors bite. Without this, a parser that silently matched nothing
# would report a perfectly clean tree, which is the failure this whole file is about.
if [ "${1:-}" = "--selftest" ]; then
  bad=0
  n=${#DISCOVERED[@]}
  [ "$n" -ge "$MIN_GATES" ] && printf '  [ok]     discovery found %d invocations (floor %d)\n' "$n" "$MIN_GATES" \
    || { printf '  [FAILED] discovery found only %d\n' "$n"; bad=1; }

  # The last of these is a `.mjs` run through `node`, and it is in this list BECAUSE it was the one
  # discovery silently dropped: a gate in a language the parser did not know about is not skipped
  # with a reason, it is absent from both lists and from the counts. Keeping a non-shell,
  # non-python gate named here is what stops the extension set narrowing back.
  for must in scripts/structure-lint.sh scripts/public-hygiene-lint.py scripts/workspace-deps-lint.py \
              scripts/check-proof-manifest-public.mjs; do
    if printf '%s\n' "${DISCOVERED[@]}" | grep -q "$must"; then
      printf '  [ok]     %s is discovered\n' "$must"
    else
      printf '  [FAILED] %s is in ci.yml but was NOT discovered -- the parser missed a real gate\n' "$must"; bad=1
    fi
  done

  # THE `testing/` HALF, planted rather than hoped for. Discovery hard-coded `scripts/` and was blind
  # to every gate under `testing/`; a gate a discovery cannot SEE is not skipped with a reason, it is
  # absent from both lists while the final "N gates, M skipped" line counts confidently past it. The
  # fixture carries one planted `testing/planted/gate.sh` invocation, and this is the red-before-green:
  # against the old pattern `--dump-gates` on that fixture returns it nowhere.
  PLANTED_FIXTURE="scripts/fixtures/full-gate/continuation-ci.yml"
  if [ ! -f "$PLANTED_FIXTURE" ]; then
    printf '  [FAILED] the discovery fixture %s is missing\n' "$PLANTED_FIXTURE"; bad=1
  elif bash "$0" --dump-gates "$PLANTED_FIXTURE" 2>/dev/null | grep -q '^bash testing/planted/gate.sh'; then
    printf '  [ok]     a planted testing/planted/gate.sh invocation IS discovered (nested dirs included)\n'
  else
    printf '  [FAILED] a planted testing/ gate invocation was NOT discovered -- gates outside scripts/ are invisible\n'; bad=1
  fi

  # And the real ones: the shadow-oracle harness and the llm-conformance suite, by name, so the
  # directory set cannot narrow back to `scripts/` without this going red.
  for must in testing/shadow-oracle/replay-selftest.sh testing/shadow-oracle/record.sh \
              testing/shadow-oracle/enumerate-cells.py testing/llm-conformance/run.sh; do
    if printf '%s\n' "${DISCOVERED[@]}" | grep -q "$must"; then
      printf '  [ok]     %s is discovered\n' "$must"
    else
      printf '  [FAILED] %s is invoked by ci.yml but was NOT discovered\n' "$must"; bad=1
    fi
  done

  # ── THE qa-gate HALF ──────────────────────────────────────────────────────────────────────────
  # Discovery must SEE the new tier by name. A `qa-gate-run.sh` invocation that collapses into the
  # bare script name is the "absent from both lists" hole all over again: the counts below would
  # walk confidently past a two-hour job nobody had accounted for.
  n=${#QA_DISCOVERED[@]}
  [ "$n" -ge "$MIN_QA_GATES" ] && printf '  [ok]     qa-gate discovery found %d tier(s) (floor %d)\n' "$n" "$MIN_QA_GATES" \
    || { printf '  [FAILED] qa-gate discovery found only %d tier(s)\n' "$n"; bad=1; }

  if printf '%s\n' "${QA_DISCOVERED[@]}" | grep -qx 'scripts/qa-gate-run.sh done-oracle'; then
    printf '  [ok]     the qa-gate done-oracle tier is discovered as its own invocation\n'
  else
    printf '  [FAILED] `scripts/qa-gate-run.sh done-oracle` is in qa-gate.yml but was NOT discovered as a distinct tier\n'; bad=1
  fi
  if [ "${#QA_UNCLASSIFIED[@]}" -eq 0 ]; then
    printf '  [ok]     every qa-gate tier is accounted for with a written reason\n'
  else
    printf '  [FAILED] unclassified qa-gate tier(s):\n'
    printf '           %s\n' "${QA_UNCLASSIFIED[@]}"; bad=1
  fi
  # The done-oracle entry must say BOTH why it cannot run here and that it is long -- a reason that
  # omits the recursion invites somebody to "just run it locally" and hang their terminal.
  qa_done_reason=""
  for entry in "${QA_ACCOUNTED[@]}"; do
    [ "${entry%%|*}" = "scripts/qa-gate-run.sh done-oracle" ] && qa_done_reason="${entry#*|}"
  done
  if printf '%s' "$qa_done_reason" | grep -qi 'recursion' && printf '%s' "$qa_done_reason" | grep -qi 'LONG'; then
    printf '  [ok]     the done-oracle tier is classified CI-only AND long, in writing\n'
  else
    printf '  [FAILED] the done-oracle CI-only reason does not name both facts (it is long; it re-enters this script)\n'; bad=1
  fi

  # ── FAIL CLOSED IF qa-gate LOSES done-oracle FROM ITS UMBRELLA ────────────────────────────────
  # The classification above accounts for the job; this asserts the job still GATES. Two independent
  # checks, because they fail in different directions: a direct assertion on this tree's needs list
  # (which is what a reader of this script wants to know), and the umbrella lint driven over a
  # MUTATED copy, which proves the enforcement still discriminates rather than merely agreeing.
  if grep -qE '^\s*needs: \[.*\bdone-oracle\b.*\]' "$QA_YML"; then
    printf '  [ok]     qa-gate.yml`s umbrella still lists done-oracle in its needs\n'
  else
    printf '  [FAILED] qa-gate.yml`s umbrella does NOT list done-oracle in needs -- the FULL done-oracle would not gate qa->main\n'; bad=1
  fi
  QA_MUT="target/full-gate/qa-mutation"
  rm -rf "$QA_MUT"; mkdir -p "$QA_MUT/.github/workflows"
  sed 's/needs: \[build, fast, slow, loader, done-oracle\]/needs: [build, fast, slow, loader]/' \
    "$QA_YML" >"$QA_MUT/$QA_YML"
  if cmp -s "$QA_YML" "$QA_MUT/$QA_YML"; then
    printf '  [FAILED] could not plant the mutation: qa-gate.yml`s umbrella needs list is not the expected shape\n'; bad=1
  elif python3 scripts/ci-umbrella-lint.py --root "$QA_MUT" --workflow qa-gate >/dev/null 2>&1; then
    printf '  [FAILED] removing done-oracle from qa-gate`s umbrella needs was ACCEPTED by ci-umbrella-lint\n'; bad=1
  else
    printf '  [ok]     qa-gate.yml with done-oracle removed from the umbrella needs is REFUSED\n'
  fi
  if python3 scripts/ci-umbrella-lint.py --workflow qa-gate >/dev/null 2>&1; then
    printf '  [ok]     the tree`s own qa-gate umbrella passes ci-umbrella-lint\n'
  else
    printf '  [FAILED] ci-umbrella-lint refuses this tree`s qa-gate.yml:\n'
    python3 scripts/ci-umbrella-lint.py --workflow qa-gate 2>&1 | sed 's/^/           /'; bad=1
  fi
  rm -rf "$QA_MUT"

  # The floor must BITE, not merely exist.
  if (cd "$(mktemp -d)" && mkdir -p .github/workflows && : > .github/workflows/ci.yml \
        && bash "$OLDPWD/scripts/full-gate.sh" --list >/dev/null 2>&1); then
    printf '  [FAILED] an EMPTY ci.yml was accepted -- the floor does not bite, so a broken parser reads as clean\n'; bad=1
  else
    printf '  [ok]     an empty ci.yml is REFUSED (exit 2), so a broken parser cannot report a clean tree\n'
  fi

  # Every skip carries a reason, or it becomes permanent by accident.
  for entry in "${SKIP_REASON[@]}"; do
    [ -n "${entry#*|}" ] && [ "${entry#*|}" != "$entry" ] || { printf '  [FAILED] a skip entry carries no reason: %s\n' "$entry"; bad=1; }
  done
  printf '  [ok]     all %d skip entries carry a written reason\n' "${#SKIP_REASON[@]}"
  for entry in "${CARGO_CI_ONLY[@]}"; do
    [ -n "${entry#*|}" ] && [ "${entry#*|}" != "$entry" ] || { printf '  [FAILED] a CI-only cargo entry carries no reason: %s\n' "$entry"; bad=1; }
  done
  printf '  [ok]     all %d CI-only cargo entries carry a written reason\n' "${#CARGO_CI_ONLY[@]}"

  # THE CARGO HALF: discovery finds them, every one is classified, and the configurations that have
  # actually broken CI are among the ones that RUN here.
  n=${#CARGO_DISCOVERED[@]}
  [ "$n" -ge 10 ] && printf '  [ok]     cargo discovery found %d invocations (floor 10)\n' "$n" \
    || { printf '  [FAILED] cargo discovery found only %d -- the parser missed CI build configurations\n' "$n"; bad=1; }

  if [ "${#CARGO_UNCLASSIFIED[@]}" -eq 0 ]; then
    printf '  [ok]     every cargo invocation in ci.yml is classified LOCAL or CI-only\n'
  else
    printf '  [FAILED] unclassified cargo invocation(s) -- the script must refuse to run:\n'
    printf '           %s\n' "${CARGO_UNCLASSIFIED[@]}"; bad=1
  fi

  # A COMMAND CI WRAPS OVER SEVERAL LINES IS ONE COMMAND. Discovery used to read `ci.yml` line-wise,
  # so a `cargo test` continued over three lines was discovered as its own first fragment — a
  # TRUNCATION of the real invocation, matching neither list, which (correctly, and uselessly) refused
  # to run the whole gate. The fixture holds that exact shape, together with the `echo` lines, the `#`
  # comment and the step `name:` that each quote a DIFFERENT cargo command: joining that welds an echo
  # onto a command is the other way to get this wrong, and it invents fragments CI never runs.
  CONT_FIXTURE="scripts/fixtures/full-gate/continuation-ci.yml"
  if [ ! -f "$CONT_FIXTURE" ]; then
    printf '  [FAILED] the continuation fixture %s is missing -- the multi-line shape is unproven\n' "$CONT_FIXTURE"; bad=1
  else
    cont_found="$(bash "$0" --dump-cargo "$CONT_FIXTURE" 2>/dev/null)"
    cont_want="cargo test -p busbar-voice --features runtime,test-support -p busbar-voice-codec --features runtime --locked"
    if printf '%s\n' "$cont_found" | grep -qxF "$cont_want"; then
      printf '  [ok]     a cargo invocation continued over three lines is discovered WHOLE\n'
    else
      printf '  [FAILED] a three-line continued cargo invocation was not joined; discovery saw:\n'
      printf '           %s\n' "$cont_found"; bad=1
    fi
    if printf '%s\n' "$cont_found" | grep -q -- '--workspace'; then
      printf '  [FAILED] discovery invented an invocation from an echo/comment/name: line:\n'
      printf '           %s\n' "$(printf '%s\n' "$cont_found" | grep -- '--workspace')"; bad=1
    else
      printf '  [ok]     the echo, comment and name: lines quoting cargo commands are NOT discovered\n'
    fi
    cont_n="$(printf '%s\n' "$cont_found" | grep -c .)"
    if [ "$cont_n" = 2 ]; then
      printf '  [ok]     the fixture yields exactly its 2 real invocations, no fragments\n'
    else
      printf '  [FAILED] the fixture yields %s invocations, expected 2 -- joining produced fragments:\n' "$cont_n"
      printf '           %s\n' "$cont_found"; bad=1
    fi
  fi

  for must in "--no-default-features" "--features openapi-schema"; do
    if printf '%s\n' "${CARGO_LOCAL[@]}" | grep -q -- "$must"; then
      printf '  [ok]     the %s configuration is RUN locally\n' "$must"
    else
      printf '  [FAILED] %s is a CI build configuration that this script does not run -- a local green would not mean a CI green\n' "$must"; bad=1
    fi
  done

  # The equality-ledger printer this script calls in its result section must itself discriminate:
  # its own selftest proves a broken ledger is REFUSED rather than printed as a clean line.
  if python3 scripts/capability-equality-summary.py --selftest >/dev/null 2>&1; then
    printf '  [ok]     the equality-ledger printer refuses a broken ledger (its selftest holds)\n'
  else
    printf '  [FAILED] scripts/capability-equality-summary.py --selftest failed -- the ledger line this script prints could lie\n'; bad=1
  fi

  # THIS SCRIPT'S OWN RUSTFLAGS MUST MATCH CI'S, or a local green is a green on a laxer flag set than
  # the one CI actually enforces. Read straight from the real ci.yml (not whatever --dump-* pointed
  # CI_YML at), so drift between the two `RUSTFLAGS: "..."` lines fails closed instead of quietly
  # diverging.
  ci_rustflags="$(grep -m1 '^[[:space:]]*RUSTFLAGS:' .github/workflows/ci.yml | sed -E 's/^[[:space:]]*RUSTFLAGS:[[:space:]]*"([^"]*)".*/\1/')"
  if [ -z "$ci_rustflags" ]; then
    printf '  [FAILED] could not find a workflow-level RUSTFLAGS in .github/workflows/ci.yml\n'; bad=1
  elif [ "$ci_rustflags" = "$RUSTFLAGS" ]; then
    printf '  [ok]     ci.yml RUSTFLAGS (%s) matches this script'"'"'s exported RUSTFLAGS\n' "$ci_rustflags"
  else
    printf '  [FAILED] ci.yml RUSTFLAGS is "%s" but this script exports "%s" -- a local green would not enforce what CI enforces\n' "$ci_rustflags" "$RUSTFLAGS"; bad=1
  fi

  [ "$bad" = 0 ] && { printf '\nfull-gate selftest: discovery, floors and skip-reasons all hold\n'; exit 0; }
  printf '\nSELFTEST FAILED\n'; exit 1
fi

# ── RUN ───────────────────────────────────────────────────────────────────────────────────────────
printf '== full gate: %d cargo gate(s) + %d script gate(s), %d + %d skipped with reason ==\n\n' \
  "${#CARGO_LOCAL[@]}" "${#RUN[@]}" "${#CARGO_CI_ONLY[@]}" "${#SKIP[@]}"

# ── THE SCRATCH FILE, AND WHY IT IS CHECKED RATHER THAN ASSUMED ───────────────────────────────────
# `if "$@" >FILE` makes the shell open FILE *before* running the command. If that open fails the
# command never runs, the `if` takes its else branch, and this script printed FAILED and blamed the
# gate. On 2026-08-16 a full disk turned that into a report of "8 passed, 35 FAILED" in which every
# one of the 35 was `No space left on device` on this file, and three gate runs were spent before
# anyone doubted the number. A gate runner that cannot tell "the gate failed" from "I could not
# write my own temp file" produces exactly the wrong conclusion under exactly the conditions where
# a correct one matters most: a red gate is believed, and the believer starts debugging the code.
#
# Two changes. The scratch file moves under the repo's own `target/` rather than `/tmp` (one
# writability domain to reason about instead of two, and it dies with the tree), and an unwritable
# scratch file is now an INFRASTRUCTURE abort with a distinct exit code, not a gate failure. It
# aborts rather than continuing because once the disk is full every remaining gate is meaningless
# too, and 40 more lines of false red is worse than one honest line of stop.
GATE_TMPDIR="${GATE_TMPDIR:-target/full-gate}"
mkdir -p "$GATE_TMPDIR" 2>/dev/null || true
GATE_OUT="$GATE_TMPDIR/out.$$"

gate_scratch_or_die() {
  # Prove writability by writing, not by testing a permission bit: ENOSPC and a read-only mount both
  # pass `[ -w ]` on a directory that cannot actually take a byte.
  if ! : > "$GATE_OUT" 2>/dev/null; then
    printf '\n'
    printf 'INFRASTRUCTURE FAILURE, NOT A GATE FAILURE.\n'
    printf 'Could not write the scratch file: %s\n' "$GATE_OUT"
    printf 'Nothing below this line was measured. Do not read this run as a red gate.\n'
    printf 'Most likely the disk is full. Free space:\n'
    df -h . 2>/dev/null | sed 's/^/  /'
    printf 'On macOS a local Time Machine snapshot can pin blocks you have already deleted:\n'
    printf '  tmutil listlocalsnapshots /\n'
    printf '  tmutil thinlocalsnapshots / 500000000000 4\n'
    exit 3
  fi
}
gate_scratch_or_die

FAILED=(); PASSED=0
run_one() {
  local label="$1"; shift
  printf '  %-58s ' "$label"
  # Re-prove writability each time: the disk can fill *during* a run, and it did.
  if ! : > "$GATE_OUT" 2>/dev/null; then
    printf 'ABORT\n'
    gate_scratch_or_die
  fi
  if "$@" >"$GATE_OUT" 2>&1; then printf 'ok\n'; PASSED=$((PASSED+1));
  else printf 'FAILED\n'; FAILED+=("$label"); sed 's/^/        /' "$GATE_OUT" | tail -15; fi
  rm -f "$GATE_OUT"
}

# The Rust gates first: they are the slowest and the most likely to fail, so failing early is kinder.
# ALL FOUR locally-runnable build configurations, not just the default one -- see the header.
for cmd in "${CARGO_LOCAL[@]}"; do
  # shellcheck disable=SC2086
  run_one "$cmd" ${cmd}
done

for inv in "${RUN[@]}"; do
  # shellcheck disable=SC2086
  run_one "$inv" ${inv}
done

# ── THE EQUALITY LEDGER ───────────────────────────────────────────────────────────────────────────
# Owner: "LLM == MCP == A2A -- just different protocols not different pathway through engine at
# all." The RED enforcement is `crates/busbar/tests/capability_equality.rs` (already run by the
# cargo gates above); THIS line exists because a cargo test's output is swallowed on green, and the
# doctrine's gap must be NAMED on every umbrella run, green or red -- the honest-ledger pattern.
# A ledger that cannot be read is a failure, not a silence: a gap that can no longer be named is a
# gap on its way to being forgotten.
printf '\n== equality ledger ==\n'
if ! python3 scripts/capability-equality-summary.py; then
  FAILED+=("scripts/capability-equality-summary.py (qa/capability-equality.json is unreadable or does not tile -- the gap can no longer be named)")
fi

printf '\n== result ==\n'
if [ "${#FAILED[@]}" -eq 0 ]; then
  printf '  %d gates ran, all pass -- across %d build configurations, not just the default one.\n' \
    "$PASSED" "${#CARGO_LOCAL[@]}"
  printf '  NOT covered by this green (%d script gate(s) needing a release or the fleet, and):\n' "${#SKIP[@]}"
  for entry in "${CARGO_CI_ONLY[@]}"; do printf '    %s\n' "${entry%%|*}"; done
  printf '  Windows is the real gap: it runs the same tests on a platform this host cannot be.\n'
  exit 0
fi
printf '  %d passed, %d FAILED:\n' "$PASSED" "${#FAILED[@]}"
printf '    %s\n' "${FAILED[@]}"
exit 1
