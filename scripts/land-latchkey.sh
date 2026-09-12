#!/usr/bin/env bash
# The LANDING half of the Latchkey migration: scripts/land-remote.sh's contract, over `latchkey run`.
#
#   BUSBAR_LAND_BACKEND=latchkey scripts/land.sh --batch target/gate/batch-17.txt
#   scripts/land-latchkey.sh --prove-tree --base <sha> --tests 'xtask' --families '^(llm)([|.]|$)'
#   scripts/land-latchkey.sh --base-replay --families '^(llm)([|.]|$)'
#   scripts/land-latchkey.sh --selftest
#
# ── WHAT MOVES, AND WHAT DELIBERATELY DOES NOT ──────────────────────────────────────────────────
# land-remote.sh ships the WHOLE batch to one fleet box: the box picks, the box proves, the box
# bisects, the box publishes a tip and the laptop fast-forwards onto it. That shape cannot shard.
# A Latchkey job is a packed directory and one bash line; the picks are a property of the TREE, so
# the tree is what travels — and once the tree travels, the laptop is the box:
#
#   * scripts/land.sh runs HERE, in W, exactly as it runs on a fleet box. It applies the picks, it
#     halves the batch on red, it writes `<batch>.result`, it fast-forwards nothing because the
#     tree it proved is already HEAD, and the laptop pushes as it always did.
#   * prove_tree is the ONLY thing that leaves. Each call becomes a fan of jobs over the tree as it
#     stands at that moment, which is why the BISECT WORKS UNCHANGED: land.sh resets to a smaller
#     pick set and calls the prover again, and the prover packs whatever it is given.
#
# THE COST OF THAT IS ONE COLD BUILD PER JOB, and it is paid on purpose. `latchkey run` exposes no
# cache (LK-5 measured Fast Cache as a WORKFLOW feature only), so a shard is 168 s of cold
# `cargo build --workspace --all-targets` before it measures anything. Four shards pay it four
# times; four shards also turn a 2.2 h serial oracle into four jobs of well under the 7200 s cap,
# which is the difference between a landing that can run here at all and one that cannot.
#
# ── THE SHARD PLAN, AND WHY THE CAP IS THE REASON FOR IT ────────────────────────────────────────
# MEASURED: the gate-only union was 908 s on 32 cores (LK-2's xlarge run, cold); a full oracle run
# over every family took up to 2.2 h SERIAL on a fleet box. Latchkey's per-job ceiling is 7200 s and
# it is not negotiable — a job that hits it is `expired`, which is not a verdict.
#
#   job "union"   plugins, fmt, gatefiles, tests, clippy, kind-isolation, gate   (the oracle subtracted)
#   job "fam-k"   the oracle, over bucket k of the union's family alternation    (k = 1..N, default N=4)
#   job "base"    the oracle at the BASE tip with NO picks, run alongside        (what makes a red readable)
#
# EACH SHARD BINDS ITS OWN MOCK UPSTREAM ON ITS OWN RUNNER, so there is no port-block registry to
# keep: land.sh's land_claim_port_block exists because a fleet box runs several proofs at once, and
# a fresh Latchkey runner runs exactly one. LAND_ORACLE_PORT_CLAIM is left off and the fixed block
# is used, which is the same reasoning prove-latchkey.sh's runner environment already carries.
#
# ── THE FAMILIES ARE SPLIT BY land.sh's OWN BRANCH READER, NEVER BY `tr | \n` ────────────────────
# Every family expression in this tree ends `[|]` — a BRACKETED literal pipe separating a cell id's
# family from its case — so splitting an alternation on the character `|` makes one family into two
# nonsense ones, and a shard that records a nonsense family records nothing and says GREEN.
# land_families_branches already walks brackets, parens and escapes for the inheritance rule; it is
# read out of land.sh and used here, so there is one answer in this engine to "what are the
# branches of this expression".
#
# ── A REFUSED SUBMISSION IS NOT A RED, AND IT IS NOT A WAIT EITHER ──────────────────────────────
# The workspace's concurrent-runner cap is 20, shared with CI (40 requested). `latchkey run` answers
# `Job creation blocked: concurrency_limit` when it is full, and NOTHING HAS BEEN LEARNED about the
# picks when that happens. This script retries the submission on a backoff — 30, 60, 120, 240, 300 s
# — because a landing that gives up on the first refusal loses the line to the back of the queue for
# a reason that had nothing to do with it; and then it exits 75, which landq4.sh reads as
# NONE:harness and re-takes next loop. It never BLOCKS on the cap: a landing holding the engine
# open for an hour waiting for a slot is the same outage as a landing that failed, taken slowly.
#
# ── SELF-HEALING IS VERIFIED OFF AT THE WORKSPACE, AND IS STILL DETECTED HERE ───────────────────
# The owner turned the sidecar off, so a failing job now stays failed with its own exit code and the
# sidecar only posts a diagnosis. That is a SETTING, and a setting can be changed by somebody who is
# not reading this file. lk_job_verdict's healed-retry rule is unchanged and still runs on every
# job's log: a zero with the wrapper's fingerprint in it is NONE:healed, which is not a verdict.
#
# THE EXIT CODE IS THE PROOF'S. 0 green, 1 red, 75 "nothing was learned, ask again", 70 the
# harness's own failure. Never "the transport worked, so the landing is green".
set -uo pipefail
LKL_HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO="$(cd "$LKL_HERE/.." && pwd)"
LKL_REPO="$REPO"

# ── THE PACKER IS prove-latchkey.sh's, SOURCED, NEVER COPIED ────────────────────────────────────
# The staged copy first (target/gate/prove-latchkey.run.sh, whose REPO the engine home rewrote to
# the runner's tree), then the sibling in scripts/. A home that carries neither has no transport at
# all, and that is exit 70 — the harness's own failure — never a red about somebody's picks.
LKL_LIB=""
for _c in "$LKL_HERE/prove-latchkey.run.sh" "$LKL_HERE/prove-latchkey.sh"; do
  [ -f "$_c" ] && { LKL_LIB="$_c"; break; }
done
[ -n "$LKL_LIB" ] || { echo "land-latchkey: no prove-latchkey transport beside $LKL_HERE — nothing was proven" >&2; exit 70; }
# shellcheck source=scripts/prove-latchkey.sh
LK_LIB_ONLY=1 . "$LKL_LIB" || { echo "land-latchkey: could not source the packer ($LKL_LIB)" >&2; exit 70; }
# The library derives REPO from ITS OWN path; this script's is the authority (the two differ the
# moment the engine stages one of them and not the other).
REPO="$LKL_REPO"

LKL_SHARDS="${LAND_LATCHKEY_SHARDS:-4}"
LKL_BASE_REPLAY="${LAND_LATCHKEY_BASE_REPLAY:-1}"
# THE SUBMISSION BACKOFF, in seconds, one per attempt. Spelled as a list rather than computed so
# that the selftest can read the same list this script retries on.
LKL_RETRY_WAITS="${LAND_LATCHKEY_RETRY_WAITS:-30 60 120 240 300}"

lllog() { printf '[land-latchkey %s] %s\n' "$(date -u +%H:%M:%S)" "$*" >&2; }

# ── THE FAMILY BUCKETS ──────────────────────────────────────────────────────────────────────────
# land.sh's own branch reader over the union's alternation, dealt round-robin into N buckets and
# re-joined with `|`. Round-robin rather than contiguous because the branches are not equal-cost and
# the expensive ones cluster (a union is built member by member, and one member's families are
# adjacent); dealing them spreads a heavy member across shards instead of loading one.
#
# FEWER BRANCHES THAN SHARDS IS FEWER SHARDS, never an empty job: a job whose filter matches no cell
# records nothing and would be reported green.
ll_family_buckets() { # $1 = the union's families, $2 = N; prints one bucket per line
  local fams="${1:-}" n="${2:-4}" i=0 b
  [ -n "$fams" ] || return 0
  case "$n" in ''|*[!0-9]*) n=4 ;; esac
  [ "$n" -ge 1 ] || n=1
  local -a bucket=() count=()
  while [ "$i" -lt "$n" ]; do bucket[$i]=""; count[$i]=0; i=$((i + 1)); done
  i=0
  while IFS= read -r b; do
    [ -n "$b" ] || continue
    local k=$(( i % n ))
    # RE-WRAPPED, BECAUSE THE READER UNWRAPPED. land_families_strip removes the one paren layer
    # land.sh's union builder added, so a bucket of two branches re-joined bare would be `a|b` where
    # the engine everywhere else writes `(a)|(b)` — and land_families_covers, which decides what a
    # pre-proof may be inherited from, compares those strings. A bucket of ONE keeps its branch
    # verbatim: that is the common case (a queue line names one family), and a wrapped copy of it
    # would make this backend's `--families` textually different from the fleet backend's for the
    # same line, which is the one thing the two-way landing must not be.
    if [ "${count[$k]}" = 0 ]; then bucket[$k]="$b"
    elif [ "${count[$k]}" = 1 ]; then bucket[$k]="(${bucket[$k]})|($b)"
    else bucket[$k]="${bucket[$k]}|($b)"
    fi
    count[$k]=$(( count[$k] + 1 ))
    i=$((i + 1))
  done <<EOF
$(ll_families_branches "$fams")
EOF
  i=0
  while [ "$i" -lt "$n" ]; do
    [ -n "${bucket[$i]}" ] && printf '%s\n' "${bucket[$i]}"
    i=$((i + 1))
  done
}

# land.sh's land_families_branches, read OUT OF land.sh and eval'd — the same discipline
# prove-latchkey.sh's runner uses for land.sh's verdict functions, and for the same reason: a second
# implementation of "what are the branches of this expression" is a second answer, and the two would
# disagree exactly on the bracketed pipe every family in this tree ends with.
ll_load_families_reader() {
  declare -F ll_families_branches >/dev/null && return 0
  local src lsh=""
  for src in "$LKL_HERE/land.run.sh" "$LKL_HERE/land.sh" "$REPO/scripts/land.sh"; do
    [ -f "$src" ] && { lsh="$src"; break; }
  done
  [ -n "$lsh" ] || return 1
  local fsrc
  fsrc="$(sed -n '/^land_families_branches() {/,/^}/p;/^land_families_strip() {/,/^}/p' "$lsh")"
  case "$fsrc" in *"land_families_branches()"*) ;; *) return 1 ;; esac
  eval "$fsrc" || return 1
  ll_families_branches() { land_families_branches "$@"; }
  return 0
}

# ── THE RUNNER SCRIPT ───────────────────────────────────────────────────────────────────────────
# Emitted from ONE function so --selftest drives the real text. Its whole job is: the shared
# preamble (put the history back — lk_onbox_preamble, prove-latchkey.sh's, not a copy), then ONE
# call into the tree's own scripts/land.sh with the leg subset this shard owns. The legs, their
# order and their verdicts are land.sh's, which is the entire contract: this file decides WHICH
# legs run WHERE and nothing whatever about what a leg means.
ll_onbox_script() {
  cat <<'ONBOX'
#!/usr/bin/env bash
# Generated by scripts/land-latchkey.sh — runs on a Latchkey runner, never on a fleet box.
set -uo pipefail
SHARD="$1"; BR="$2"; TIP="$3"; BASE="$4"; LEGS="$5"; TESTS="${6:-}"; GATE="${7:-}"; FAMILIES="${8:-}"; FEATURES="${9:-}"
ONBOX
  lk_onbox_preamble
  cat <<'ONBOX'

# ── THE LEG SUBSET THIS SHARD OWNS ──────────────────────────────────────────────────────────────
# LAND_LEGS_ONLY only ever SUBTRACTS from land.sh's plan (see land_floor_plan): the plan is the
# authority on what this union owes, and a shard that could ADD a leg would be a shard deciding
# what a proof is. An empty intersection is refused by land.sh, loudly, rather than run as nothing.
export LAND_LEGS_ONLY="$LEGS"
# THE LOOP-BREAKER, BOTH WAYS. LAND_REMOTE_INNER stops the tree's land.sh delegating to a fleet box;
# LAND_LATCHKEY_INNER stops it delegating back to this transport, which would be a runner renting a
# runner. Neither variable travels by itself — a Latchkey job's environment is whatever the command
# line sets — so both are set here, where the command line is.
export LAND_REMOTE_INNER=1 LAND_LATCHKEY_INNER=1
export LAND_BASE_REF=origin/integration/oracle-phase0
export LAND_BASE_SHA="$BASE"
export BUSBAR_GATE_BASE_REF="$BASE" GATE_MUTANTS_BASE="$BASE"
# NO PORT-BLOCK REGISTRY ON A FRESH RUNNER. land_claim_port_block exists because a fleet box runs
# several proofs at once; this runner runs exactly one job and gives the machine back afterwards,
# so the fixed block is the whole truth and a claim would only be a file nobody reads.
export LAND_ORACLE_PORT_CLAIM=0
export LAND_ORACLE_PORT_BASE="${LAND_ORACLE_PORT_BASE:-40000}"
export CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-$(nproc)}"
export XTASK_GATE_CEILING_SECS="${XTASK_GATE_CEILING_SECS:-3600}"

say "shard $SHARD: land.sh over legs [$LEGS]"
set -- --prove
[ -n "$TESTS" ]    && set -- "$@" --tests "$TESTS"
[ -n "$GATE" ]     && set -- "$@" --gate "$GATE"
[ -n "$FAMILIES" ] && set -- "$@" --families "$FAMILIES"
[ -n "$FEATURES" ] && set -- "$@" --features "$FEATURES"
echo "   argv: $*"
bash scripts/land.sh "$@"; RC=$?
echo
echo "land-latchkey: shard $SHARD exit $RC"
exit $RC
ONBOX
}

# ── SUBMISSION, WITH THE CAP RETRIED AND NEVER WAITED ON ────────────────────────────────────────
# `lk_submit` prints a job id or nothing; nothing means the account was full. Each refusal is
# retried after the next wait in the list, and a submission that is still refused after the last one
# returns empty — which the caller turns into 75, not into a red.
ll_submit_retry() { # $1 = the bash line; prints the job id, or nothing
  local line="$1" id w
  id="$(lk_submit "$line")"
  case "$id" in cli-*) printf '%s\n' "$id"; return 0 ;; esac
  for w in $LKL_RETRY_WAITS; do
    lllog "submission refused (the workspace's 20-runner cap is shared with CI) — retrying in ${w}s"
    sleep "$w"
    id="$(lk_submit "$line")"
    case "$id" in cli-*) printf '%s\n' "$id"; return 0 ;; esac
  done
  lllog "the cap refused this submission on $(( $(printf '%s\n' $LKL_RETRY_WAITS | grep -c .) + 1 )) attempts — exit 75, nothing was proven, the batch is re-taken"
  return 1
}

# ── ONE JOB'S OUTCOME ───────────────────────────────────────────────────────────────────────────
# Polled, its log fetched, its log KEPT past Latchkey's 24 h beside the state repository, and its
# verdict taken by prove-latchkey.sh's rule (a healed zero is never GREEN). Prints
# "<verdict> <rc> <runner-secs> <log>" so the merge below reads one shape whatever happened.
ll_collect() { # $1 = shard name, $2 = job id
  local name="$1" id="$2" state rc log verdict secs
  log="$REPO/target/land-latchkey-$LKL_REF-$name.log"
  state="$(lk_poll "$id")" || { lllog "$name: gave up waiting on $id after ${LK_POLL_MAX}s"; "$LK_BIN" cancel "$id" >/dev/null 2>&1 || true; printf 'NONE:no-verdict 75 0 %s\n' "$log"; return 0; }
  "$LK_BIN" logs "$id" >"$log" 2>&1 || true
  mkdir -p "$LK_LOGDIR" 2>/dev/null && cp "$log" "$LK_LOGDIR/$id.log" 2>/dev/null \
    || lllog "WARNING: could not keep $name's log under $LK_LOGDIR — Latchkey drops it in 24 h"
  rc=1
  case "$state" in
    succeeded) rc="$(lk_exit_code "$id")"; [ -n "$rc" ] || rc=0 ;;
    failed)    rc="$(lk_exit_code "$id")"; [ -n "$rc" ] || rc=1 ;;
    cancelled) rc=130 ;;
    expired)   rc=124 ;;
  esac
  verdict="$(lk_job_verdict "$log" "$rc")"
  secs="$(lk_runner_secs "$id")"
  printf '%s %s %s %s\n' "$verdict" "$rc" "${secs:-0}" "$log"
}

# ── WHAT A JOB'S RED IS ABOUT ───────────────────────────────────────────────────────────────────
# 126/127/70 are the harness's own codes and can never be reached BY a proof (landq4's
# lq_rc_is_harness has the list); 124 is Latchkey's own timeout, which is a statement about the
# 7200 s cap and this script's shard plan, not about anyone's picks; 130 is a cancel. None of them
# is a verdict, and every one of them used to be indistinguishable from RED.
ll_rc_is_harness() { # $1 = rc
  case "${1:-}" in 126|127|70|124|130) return 0 ;; esac
  return 1
}

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --selftest — what this file can prove of itself with no account and no runner.
# ──────────────────────────────────────────────────────────────────────────────────────────────────
if [ "${1:-}" = "--selftest" ]; then
  fails=0
  _ok() { printf '  ok   %s\n' "$1"; }
  _fail() { printf '  FAIL %s\n' "$1"; fails=$((fails + 1)); }
  _eq() { # $1 = what, $2 = want, $3 = got
    [ "$2" = "$3" ] && _ok "$1" || _fail "$1 (want '$2', got '$3')"; }
  root="$(mktemp -d "$LAND_TMP/land-latchkey-selftest.XXXXXX")" || exit 2
  trap 'rm -rf "$root"' EXIT

  echo "== land-latchkey selftest: this file, and the packer it refuses to copy =="
  bash -n "${BASH_SOURCE[0]}" && _ok "parses (bash -n)" || _fail "parses (bash -n)"
  # ONE PACKER IN THIS ENGINE. The whole `.latchkey/git` design is one paragraph of reasoning about
  # shallow clones and atomic pushes; a second copy of it drifts silently because both look right.
  _eq "the packer is sourced, never re-implemented here" 0 \
    "$(grep -c '^lk_stage_repo() {' "${BASH_SOURCE[0]}")"
  grep -qF 'LK_LIB_ONLY=1 . "$LKL_LIB"' "${BASH_SOURCE[0]}" \
    && _ok "  ...it comes from prove-latchkey.sh's library mode" || _fail "the packer is not sourced"
  declare -F lk_stage_repo >/dev/null && _ok "  ...and it really is defined here" || _fail "lk_stage_repo is not defined"
  declare -F lk_job_verdict >/dev/null && _ok "  ...with the healed-retry rule that goes with it" || _fail "lk_job_verdict is not defined"
  # A HOME WITH NO TRANSPORT IS 70, NOT 127 AND NOT A RED. 127 is what the first live latchkey sweep
  # recorded as a pre-proof RED on every line it touched.
  grep -qF 'exit 70' "${BASH_SOURCE[0]}" \
    && _ok "a home carrying no packer exits 70 (the harness's own code), never a red" \
    || _fail "a missing packer is not exit 70"

  echo "== land-latchkey selftest: the family buckets (land.sh's branch reader, never \`tr | \\n\`) =="
  ll_load_families_reader && _ok "land.sh's land_families_branches is read out of land.sh" \
    || _fail "land.sh's branch reader could not be read"
  if declare -F ll_families_branches >/dev/null; then
    # THE BRACKETED PIPE. Every family expression in this tree ends `[|]`; a split on the character
    # would make one family into two nonsense ones, and a shard filtered by a nonsense family
    # records nothing and reports green.
    _eq "a bracketed pipe is not a branch separator" 1 \
      "$(ll_family_buckets '^(llm)([|.]|$)' 4 | grep -c .)"
    _eq "  ...and the one bucket is the whole expression" '^(llm)([|.]|$)' \
      "$(ll_family_buckets '^(llm)([|.]|$)' 4)"
    _eq "four branches over four shards is four buckets" 4 \
      "$(ll_family_buckets '(a)|(b)|(c)|(d)' 4 | grep -c .)"
    _eq "  ...and every branch appears exactly once" 'a b c d' \
      "$(ll_family_buckets '(a)|(b)|(c)|(d)' 4 | tr '\n' ' ' | sed 's/ $//')"
    # FEWER BRANCHES THAN SHARDS IS FEWER JOBS, never an empty one: a job whose filter matches no
    # cell records nothing at all and would be reported green.
    _eq "two branches over four shards is two buckets, not two and two empties" 2 \
      "$(ll_family_buckets '(a)|(b)' 4 | grep -c .)"
    _eq "six branches over four shards deal round-robin" '(a)|(e) (b)|(f) c d' \
      "$(ll_family_buckets '(a)|(b)|(c)|(d)|(e)|(f)' 4 | tr '\n' ' ' | sed 's/ $//')"
    _eq "  ...and no branch is lost or duplicated" 6 \
      "$(ll_family_buckets '(a)|(b)|(c)|(d)|(e)|(f)' 4 | tr '|' '\n' | tr -d '()' | sort -u | grep -c .)"
    _eq "one shard is one bucket carrying the whole union" '(a)|(b)|(c)' \
      "$(ll_family_buckets '(a)|(b)|(c)' 1)"
    _eq "no families at all is no oracle job" 0 "$(ll_family_buckets '' 4 | grep -c .)"
  else
    _fail "the branch reader is not available; the bucket cases could not run"
  fi

  echo "== land-latchkey selftest: the runner script (the legs are land.sh's, the subset is ours) =="
  emit="$(ll_onbox_script)"
  case "$emit" in
    *'mv "$STAGE/git" .git'*) _ok "the runner reconstitutes the history from the shipped bare repo" ;;
    *) _fail "the runner does not put the history back" ;;
  esac
  case "$emit" in
    *"$(lk_onbox_preamble)"*) _ok "  ...using prove-latchkey.sh's preamble character for character" ;;
    *) _fail "the runner carries a COPY of the reconstitution, not the shared preamble" ;;
  esac
  case "$emit" in
    *'refusing to judge'*) _ok "  ...and refuses to judge when the runner's base is not the laptop's" ;;
    *) _fail "a differing base is not refused on the runner" ;;
  esac
  case "$emit" in
    *'bash scripts/land.sh "$@"'*) _ok "the legs are run by the TREE's own land.sh, not by this file" ;;
    *) _fail "this file runs legs of its own" ;;
  esac
  case "$emit" in
    *'export LAND_REMOTE_INNER=1 LAND_LATCHKEY_INNER=1'*) _ok "  ...with BOTH loop-breakers set (a runner must not rent a runner)" ;;
    *) _fail "the runner can delegate again" ;;
  esac
  case "$emit" in
    *'export LAND_LEGS_ONLY="$LEGS"'*) _ok "  ...and the shard's leg subset travels as LAND_LEGS_ONLY" ;;
    *) _fail "the leg subset does not travel" ;;
  esac
  case "$emit" in
    *'LAND_ORACLE_PORT_CLAIM=0'*) _ok "  ...and claims no port block: a fresh runner runs one job" ;;
    *) _fail "the runner still claims a port block" ;;
  esac
  case "$emit" in
    *'unset RUSTC_WRAPPER'*) _ok "  ...with no sccache (measured unreliable from these runners)" ;;
    *) _fail "the runner reaches for sccache" ;;
  esac

  echo "== land-latchkey selftest: a refused submission is retried, then 75 — never a red, never a wait =="
  # DRIVEN OVER A STUBBED `lk_submit`, with the real ll_submit_retry and a zero-length backoff: the
  # question is how many attempts it makes and what it returns, not how long it sleeps.
  # THE COUNTER IS A FILE, NOT A VARIABLE. `id="$(lk_submit …)"` is a command SUBSTITUTION, so a
  # variable the stub increments is incremented in a subshell and is 0 again by the time the case
  # reads it — this case scored 0 attempts against a retry loop that really made six.
  _ctr="$root/attempts"
  lk_submit() {
    local n; n=$(( $(cat "$_ctr" 2>/dev/null || echo 0) + 1 )); echo "$n" >"$_ctr"
    [ "$n" -ge "$(cat "$root/ok_at")" ] && printf 'cli-0000%s\n' "$n"
    return 0
  }
  sleep() { :; }
  echo 1 >"$root/ok_at"; : >"$_ctr"
  _eq "a submission the cap accepts is one attempt" "cli-00001" "$(ll_submit_retry x 2>/dev/null)"
  echo 3 >"$root/ok_at"; : >"$_ctr"
  out="$(ll_submit_retry x 2>/dev/null)"
  case "$out" in cli-*) _ok "  ...and a refusal that clears on the third attempt still gets its job" ;;
    *) _fail "a refusal that clears was not retried (got '$out')" ;; esac
  _eq "  ...in exactly three attempts" 3 "$(cat "$_ctr")"
  echo 99 >"$root/ok_at"; : >"$_ctr"
  out="$(ll_submit_retry x 2>/dev/null)"; rc=$?
  [ -z "$out" ] && [ "$rc" != 0 ] \
    && _ok "  ...and a cap that never clears returns nothing, for the caller to make 75 of" \
    || _fail "an unrelenting cap did not give up (out '$out', rc $rc)"
  # THE FIRST SUBMISSION PLUS ONE PER WAIT IN THE LIST, and not one more: the difference between a
  # bounded retry and holding the engine open until a slot appears.
  _eq "  ...after the first attempt plus one per wait in the backoff list, and no more" \
    "$(( $(printf '%s\n' $LKL_RETRY_WAITS | grep -c .) + 1 ))" "$(cat "$_ctr")"
  unset -f lk_submit sleep
  # THE LANDING NEVER BLOCKS ON THE CAP. A bounded list of waits is the whole difference between
  # "retry with backoff" and "hold the engine open until a slot appears".
  grep -qF 'LKL_RETRY_WAITS="${LAND_LATCHKEY_RETRY_WAITS:-30 60 120 240 300}"' "${BASH_SOURCE[0]}" \
    && _ok "the backoff is a bounded list, declared once, and the retry loop reads it" \
    || _fail "the backoff is not a bounded declared list"

  echo "== land-latchkey selftest: what is a verdict and what is only an exit code =="
  for c in 126 127 70 124 130; do
    ll_rc_is_harness "$c" && _ok "rc $c is the harness's, never the tree's" || _fail "rc $c was read as a verdict"
  done
  for c in 0 1 2; do
    ll_rc_is_harness "$c" && _fail "rc $c was excused as a harness failure" || _ok "  ...and rc $c is the engine's own answer"
  done
  # A HEALED ZERO IS NEVER GREEN, even with the workspace switch off: the switch is a setting, and a
  # setting can be changed by somebody who is not reading this file.
  printf 'boom\n%s BEGIN sidecar POST\n' "$LK_HEAL_MARK" >"$root/healed.log"
  _eq "a sidecar-healed zero is NONE:healed even now the switch is off" "NONE:healed" \
    "$(lk_job_verdict "$root/healed.log" 0)"

  echo "== land-latchkey selftest: scratch is never /tmp; the logs outlive Latchkey's 24 h =="
  _eq "the scratch root is LAND_TMP, and it is the library's one declaration" 0 \
    "$(grep -c '^LAND_TMP=' "${BASH_SOURCE[0]}")"
  _eq "  ...and nothing here names the wiped directory" 0 \
    "$(grep -vE '^[[:space:]]*#' "${BASH_SOURCE[0]}" | grep -cE 'mktemp[^|]*\B/tmp/' || true)"
  grep -qF 'cp "$log" "$LK_LOGDIR/$id.log"' "${BASH_SOURCE[0]}" \
    && _ok "every job's log is kept under the state repository's latchkey-logs" \
    || _fail "a job's log is not kept past Latchkey's retention"

  if [ "$fails" = 0 ]; then echo "land-latchkey selftest: GREEN"; exit 0; fi
  echo "land-latchkey selftest: RED ($fails failure(s))" >&2; exit 1
fi

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# THE ARGUMENTS
# ──────────────────────────────────────────────────────────────────────────────────────────────────
MODE=""; BASE=""; TESTS=""; GATE=""; FAMILIES=""; FEATURES=""; LABEL="landing"; IGNORED_HOST=""
while [ $# -gt 0 ]; do
  case "$1" in
    --prove-tree)  MODE=prove-tree; shift ;;
    --base-replay) MODE=base-replay; shift ;;
    --base)      BASE="${2:-}"; shift 2 ;;
    --tests)     TESTS="${2:-}"; shift 2 ;;
    --gate)      GATE="${2:-}"; shift 2 ;;
    --families)  FAMILIES="${2:-}"; shift 2 ;;
    --features)  FEATURES="${2:-}"; shift 2 ;;
    --label)     LABEL="${2:-}"; shift 2 ;;
    # ACCEPTED AND IGNORED, exactly as prove-latchkey.sh accepts them: the caller must not have to
    # know which backend it got, which is the coupling BUSBAR_LAND_BACKEND exists to remove.
    --host|--remote) IGNORED_HOST="${2:-}"; shift 2 ;;
    --setup) echo "land-latchkey: --setup is a no-op — a Latchkey runner is fresh per job."; exit 0 ;;
    -h|--help) sed -n '2,8p' "$0"; exit 0 ;;
    *) lllog "unknown argument '$1' — ignored"; shift ;;
  esac
done
[ -n "$MODE" ] || { echo "land-latchkey: one of --prove-tree or --base-replay is required" >&2; exit 2; }

command -v "$LK_BIN" >/dev/null 2>&1 || { echo "land-latchkey: no \`$LK_BIN\` on PATH" >&2; exit 70; }
lk_load_token || { echo "land-latchkey: no LATCHKEY_TOKEN in the environment and none readable in $LK_ENVFILE" >&2; exit 70; }
ll_load_families_reader || { echo "land-latchkey: land.sh's family branch reader is not readable — refusing to split an alternation by hand" >&2; exit 70; }

LKL_REF="land-lk-$(date -u +%Y%m%d-%H%M%S)-$$"
TIP="$(git -C "$REPO" rev-parse HEAD)" || { echo "land-latchkey: $REPO has no HEAD" >&2; exit 70; }
[ -n "$BASE" ] || BASE="$(lk_base_sha "$REPO")"
[ -n "$BASE" ] || { echo "land-latchkey: no integration base to judge the ceilings against" >&2; exit 70; }
BRANCH_NAME="$(git -C "$REPO" rev-parse --abbrev-ref HEAD 2>/dev/null)"
case "$BRANCH_NAME" in HEAD|"") BRANCH_NAME="$LKL_REF" ;; esac
[ -n "$IGNORED_HOST" ] && lllog "note: --host/--remote '$IGNORED_HOST' is accepted and ignored; this backend rents runners"

# ──────────────────────────────────────────────────────────────────────────────────────────────────
# --base-replay: THE TIP ITSELF, NO PICKS, AS ITS OWN JOB
# ──────────────────────────────────────────────────────────────────────────────────────────────────
# What makes every other verdict in a landing readable. An oracle row that is red at the BASE is red
# for a reason no pick in this batch can have caused, and a batch judged without that measurement
# parks real work over the tree's own standing state (landq4's lq_red_is_unmeasured_oracle is the
# rule this feeds). It packs the base's tree, not W's, so it needs a directory of its own — W is
# carrying the picks at this moment and must not be disturbed by a measurement.
#
# THE BASE OF THE BASE IS THE BASE. Every gate that reads history is subtracted from this job: it
# runs the ORACLE and nothing else, so no ceiling is compared against anything and the degenerate
# base-equals-tip that would silently pass a ceiling row can never be reached from here.
ll_base_tree() { # prints a directory holding the base's tree, packed and ready
  local d
  d="$(lk_pack_dir "$REPO" "$BASE" "$LKL_REF-base")" || return 1
  lk_stage_repo "$REPO" "$d/.latchkey" "$BASE" "$BASE" || return 1
  ll_onbox_script >"$d/.lk-land.sh"
  printf '%s\n' "$d"
}

# ── THE JOBS ────────────────────────────────────────────────────────────────────────────────────
# Submitted first, ALL of them, and polled afterwards: a script that polled each job before
# submitting the next would serialise exactly the fan-out that exists to fit under the 7200 s cap.
JOB_NAMES=(); JOB_IDS=(); JOB_DIRS=()
ll_launch() { # $1 = shard name, $2 = directory to pack, $3.. = the runner's positionals
  local name="$1" dir="$2"; shift 2
  local q="" a id
  for a in "$@"; do q="$q '$(printf '%s' "$a" | sed "s/'/'\\\\''/g")'"; done
  id="$( cd "$dir" && ll_submit_retry "bash .lk-land.sh$q" )" || return 1
  JOB_NAMES+=("$name"); JOB_IDS+=("$id"); JOB_DIRS+=("$dir")
  lllog "job $id  = shard $name"
  return 0
}

# ── THE DIRECTORY THAT IS PACKED IS NEVER W ─────────────────────────────────────────────────────
# lk_pack_dir's header has the measurement: `latchkey run` packs the CURRENT DIRECTORY, and staging
# into the landing tree writes the very tree the engine refuses to find unsettled — while N of these
# running at once would share one constant path and `rm -rf` each other's staging. Every proof
# exports the tree it is about into a directory of its own, named by a ref that carries the
# timestamp and this process's pid.
#
# THE UNION AND ITS ORACLE SHARDS SHARE ONE EXPORT, and only that one: they prove the SAME tree, so
# re-exporting it per shard would be four copies of 3,580 files to say the same thing. The base
# replay is a different tree and gets its own.
PACKDIR=""; BASEDIR=""
cleanup() { [ -n "$PACKDIR" ] && rm -rf "$PACKDIR"; [ -n "$BASEDIR" ] && rm -rf "$BASEDIR"; }
trap cleanup EXIT INT TERM

if [ "$MODE" = base-replay ]; then
  [ -n "$FAMILIES" ] || { lllog "no families to measure at the base — nothing to replay"; exit 0; }
  BASEDIR="$(ll_base_tree)" || { echo "land-latchkey: could not stage the base's tree" >&2; exit 70; }
  lllog "base replay at $(printf '%.9s' "$BASE") (no picks), families $FAMILIES"
  ll_launch base "$BASEDIR" base "$BRANCH_NAME" "$BASE" "$BASE" oracle "" "" "$FAMILIES" "" \
    || { echo "land-latchkey: concurrency_limit — no job was created for the base replay; nothing was measured" >&2; exit 75; }
else
  # ── THE UNION'S TREE, PACKED ONCE, SUBMITTED N+1 TIMES ────────────────────────────────────────
  # Every job proves the SAME tree — W as land.sh has just picked it — so the history is staged once
  # and each submission packs the same directory with a different argv. The picks travel as the
  # tip's own objects; there is nothing to cherry-pick on a runner, which is the whole shape change
  # from land-remote.sh.
  PACKDIR="$(lk_pack_dir "$REPO" "$TIP" "$LKL_REF")" \
    || { echo "land-latchkey: could not export $(git -C "$REPO" rev-parse --short "$TIP") into $LAND_TMP — nothing was packed" >&2; exit 70; }
  lk_stage_repo "$REPO" "$PACKDIR/.latchkey" "$TIP" "$BASE" \
    || { echo "land-latchkey: could not stage the history into $PACKDIR/.latchkey" >&2; exit 70; }
  ll_onbox_script >"$PACKDIR/.lk-land.sh"
  lllog "[$LABEL] tip $(git -C "$REPO" rev-parse --short "$TIP")  base $(printf '%.9s' "$BASE")  packed from $PACKDIR, history $(du -sh "$PACKDIR/.latchkey/git" 2>/dev/null | cut -f1)"

  # THE UNION JOB: land.sh's whole plan with the oracle subtracted. The subtraction is named, not
  # implied — `workspace-clippy` is in the list because a union that named no package and no family
  # falls back to it, and a shard list that forgot it would silently drop the only leg such a union
  # has.
  ll_launch union "$PACKDIR" union "$BRANCH_NAME" "$TIP" "$BASE" \
    "plugins fmt gatefiles tests clippy workspace-clippy kind-isolation gate" \
    "$TESTS" "$GATE" "" "$FEATURES" \
    || { echo "land-latchkey: concurrency_limit — no job was created for the union; nothing was proven" >&2; exit 75; }

  # THE ORACLE, ONE JOB PER FAMILY BUCKET. Each runner binds its own mock upstream on its own
  # machine, so the buckets are independent in the only way that ever mattered.
  if [ -n "$FAMILIES" ]; then
    k=0
    while IFS= read -r bucket; do
      [ -n "$bucket" ] || continue
      k=$((k + 1))
      ll_launch "fam-$k" "$PACKDIR" "fam-$k" "$BRANCH_NAME" "$TIP" "$BASE" oracle "" "" "$bucket" "$FEATURES" \
        || { echo "land-latchkey: concurrency_limit — no job was created for oracle shard $k; nothing was proven" >&2; exit 75; }
    done <<EOF
$(ll_family_buckets "$FAMILIES" "$LKL_SHARDS")
EOF
    lllog "[$LABEL] oracle: $k shard(s) over $FAMILIES"
    # ── THE BASE REPLAY, ALONGSIDE ──────────────────────────────────────────────────────────────
    # Not after: it is the same families on a machine of its own and it costs nothing in wall time
    # to run it beside the shards. A base replay that could not be created is NOT a failure of this
    # landing — the batch is judged without it, exactly as the fleet path is when no box was free —
    # so its launch is best-effort and its absence is said out loud.
    if [ "$LKL_BASE_REPLAY" = 1 ]; then
      if BASEDIR="$(ll_base_tree)"; then
        ll_launch base "$BASEDIR" base "$BRANCH_NAME" "$BASE" "$BASE" oracle "" "" "$FAMILIES" "" \
          || lllog "[$LABEL] the base replay got no job (the cap); the tip stays unmeasured and an oracle red is NONE, never a park"
      else
        lllog "[$LABEL] could not stage the base's tree; the tip stays unmeasured"
      fi
    fi
  fi
fi

# ── COLLECTING ──────────────────────────────────────────────────────────────────────────────────
lllog "[$LABEL] ${#JOB_IDS[@]} job(s) in flight; polling every ${LK_POLL_SECS}s (cap ${LK_TIMEOUT}s per job)"
RC=0; HARNESS=0; NOVERDICT=0; BASE_RED=0; ORACLE_RED=""
i=0
while [ "$i" -lt "${#JOB_IDS[@]}" ]; do
  name="${JOB_NAMES[$i]}"; id="${JOB_IDS[$i]}"
  read -r verdict jrc jsecs jlog <<EOF
$(ll_collect "$name" "$id")
EOF
  lllog "[$LABEL] shard $name  job $id  verdict $verdict  exit $jrc  runner ${jsecs}s (~$(( (jsecs + 59) / 60 )) billed minute(s))  log $jlog"
  case "$name" in
    # THE BASE REPLAY IS A MEASUREMENT, NOT A VOTE. Its red is the tree's standing state and can
    # never be a verdict on picks that are not in it.
    base) [ "$verdict" = GREEN ] || BASE_RED=1 ;;
    *)
      case "$verdict" in
        GREEN) ;;
        NONE:healed|NONE:no-verdict) NOVERDICT=1 ;;
        *) if ll_rc_is_harness "$jrc"; then HARNESS=1
           else
             RC=1
             case "$name" in fam-*) ORACLE_RED="${ORACLE_RED:+$ORACLE_RED }$name" ;; esac
             # THE RED'S OWN WORDS, out of the shard's log, so the operator reads a diagnosis here
             # and not only a job id. land.sh's sentences are the ones the ledgers already carry.
             grep -E '^land\.sh: RED —' "$jlog" 2>/dev/null | head -5 >&2
           fi ;;
      esac ;;
  esac
  i=$((i + 1))
done

# ── THE MERGED VERDICT ──────────────────────────────────────────────────────────────────────────
# A no-verdict outranks a red: a shard that was healed, expired or never polled has measured nothing
# about the tree, and a union called red on the strength of the shards that DID report is a union
# judged on a subset nobody chose.
if [ "$NOVERDICT" = 1 ]; then
  echo "land-latchkey: NO VERDICT — a shard came back healed or unpolled; nothing about these picks was learned (exit 75)" >&2
  exit 75
fi
if [ "$HARNESS" = 1 ]; then
  echo "land-latchkey: NO VERDICT — a shard failed as a harness (timeout, cancel or a code no proof can reach); exit 70" >&2
  exit 70
fi
if [ "$RC" = 0 ]; then
  echo "land-latchkey: GREEN — ${#JOB_IDS[@]} job(s), tip $(git -C "$REPO" rev-parse --short "$TIP")${ORACLE_RED:+ }"
  exit 0
fi
# ── AN ORACLE RED THE BASE ALSO HAS IS THE BASE'S ───────────────────────────────────────────────
# Said in land.sh's own words ("at the base"), because landq4.sh's lq_base_state_red already reads
# that sentence and scores it NONE:base — requeued live, never parked. A second vocabulary for the
# same fact would be a second thing to keep in step.
if [ -n "$ORACLE_RED" ] && [ "$BASE_RED" = 1 ]; then
  echo "land.sh: RED — oracle: the same rows are red at the base (shard(s) $ORACLE_RED); this is the tip's standing state, not these picks'" >&2
  exit 1
fi
echo "land-latchkey: RED — shard(s) ${ORACLE_RED:-union} (see the logs above and $LK_LOGDIR)" >&2
exit 1
