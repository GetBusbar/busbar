#!/usr/bin/env bash
#
# ci-branch-protection.sh — branch protection as code for GetBusbar/busbar.
#
# WHY THIS EXISTS
# ----------------
# Branch protection settings live only in GitHub's UI/API state, not in this
# repo. That means every rule (required checks, no force-push, admins can't
# bypass, ...) is one accidental click away from silently disappearing, and
# nobody would notice until a broken commit landed on qa or main. This script
# makes those settings reproducible and auditable: run it and the protection
# on qa/main is guaranteed to match what's declared here, regardless of what
# drifted in the UI.
#
# THE CORE CORRECTNESS RULE: READ-MODIFY-WRITE, NOT WRITE
# ---------------------------------------------------------
# GitHub's branch protection endpoint is a single PUT that REPLACES the whole
# protection object. There is no "patch just this field" API. That means if
# this script (or anyone) ever does a blind PUT with only the fields it cares
# about, every field it didn't think to include gets reset to its default —
# often "off". A required-reviewers policy someone set up by hand, or a
# required_conversation_resolution flag, would vanish with no error and no
# log line, because from GitHub's point of view that's just what was asked
# for. So every code path that writes protection first performs a GET of the
# CURRENT protection, and builds the new PUT body by taking the current
# object's fields as the baseline and only overriding the specific fields
# this script has an opinion about. Fields we have no opinion about (see
# required_linear_history / required_conversation_resolution / block_creations
# / lock_branch / allow_fork_syncing below) are carried through unchanged
# from whatever they currently are, so running this script can never regress
# a protection setting that was configured through some other means.
#
# THE FOUR REQUIRED STATUS CHECKS
# --------------------------------
# The contexts below are matched by GitHub against the `name:` of the GitHub
# Actions job that reports the check, not the workflow file name and not the
# step name. Three of the four ("ci umbrella", "structure lint",
# "construction gate (how the tree is built vs ARCHITECTURE.md — BLOCKING, on
# its posture)") were verified against .github/workflows/ci.yml at the time
# this script was written — they are the literal `name:` fields of jobs in
# that file.
#
# "gate-mutants" (the mutation-strength gate, from .github/workflows/gate-mutants.yml)
# was a fifth required check. Per owner ruling (DECISIONS #78) it is now
# MANUAL-ONLY and OPTIONAL — it tests the tests, it does not gate a release —
# so it is NO LONGER a required status check and is absent from
# REQUIRED_CONTEXTS_JSON below. The workflow may still be run manually, but
# qa/main no longer require it.
#
# ABSENT FROM THE REQUIRED LIST IS NOT THE SAME AS REMOVED FROM PROTECTION.
# `build_body` unions `required` with whatever contexts the branch ALREADY
# has (see that function's own comment for why the union must never become a
# blind replacement) — and a union can only ever ADD, never drop, a context.
# Simply leaving "gate-mutants" out of REQUIRED_CONTEXTS_JSON would therefore
# never actually strip it from a branch that already requires it, which is
# exactly the state qa/main were found in: "gate-mutants" was still present
# in both branches' live protection long after this comment started claiming
# it had been removed. So RETIRED_CONTEXTS_JSON exists as a second, narrow
# list: contexts named here are filtered OUT of the final contexts sent in
# the PUT body, even if they came from the branch's own pre-existing state.
# It is deliberately not "whatever required doesn't mention" (that would
# silently delete every hand-added context, the exact hazard the union
# exists to avoid) — it is an explicit, reviewed list of contexts this
# script actively retires.
#
# A REQUIRED CONTEXT MUST BE ABLE TO REPORT, OR WRITING IT IS A WEDGE (item 488).
# "ship-ready" and "construction gate (...)" exist as job names in `ci.yml` on `predev`, but not on
# `dev`, `qa` or `main`. promote.sh reads the TARGET branch's required contexts and resolves each
# against the check-runs of the SOURCE sha, refusing on any that never reported ("a missing context
# is a refusal too"). So writing a context onto qa that dev's workflows cannot produce makes
# `promote.sh dev --to qa` impossible, and the promotion that would land the job is the very thing
# it blocks. Every write path therefore PREFLIGHTS first: each context in REQUIRED_CONTEXTS_JSON must
# be a job `name:` (or, for a job with no name, its id) in `.github/workflows/*.yml` at
# `origin/<feeder>` — the branch whose shas are checked when the protected branch is advanced
# (qa is fed by dev, main by qa; CI_PROTECTION_FEEDERS overrides). A context that cannot report
# is REFUSED before any PUT, naming the context and the ref; nothing is written for that branch.
# Fetch the feeder first (`git fetch origin dev qa`) — an absent ref is a refusal too.
#
# WHY strict=false
# -----------------
# `strict: true` means "the PR branch must be up to date with the base branch
# before a merge is allowed" (GitHub re-requires the checks after every base
# branch update). This repo lands changes by cherry-pick rather than by
# merging a branch that tracks the base, so a PR's notion of "up to date"
# with qa/main is not meaningful the way GitHub assumes — turning strict on
# would force pointless rebases/re-runs and can wedge the merge queue when
# multiple cherry-picks land back to back, each invalidating the others'
# "up to date" status. So strict is explicitly false.
#
# WHY enforce_admins=true
# ------------------------
# Without this, repo admins (which in practice is most of the people who'd be
# in a hurry) can merge past a red or missing required check with no audit
# trail beyond "an admin did it". The whole point of wiring these checks up
# is that a red gate blocks the merge for everyone, no exceptions — so
# enforce_admins is on unconditionally.
#
# WHY required_pull_request_reviews is left alone
# --------------------------------------------------
# This script's mandate is CI status checks and force-push/deletion
# protection, not review policy. Inventing a review requirement here (e.g.
# "require 1 approval") would be a policy decision nobody asked this script
# to make. So: if the branch already has a required_pull_request_reviews
# object configured (by a human, through the UI), it is carried through
# unchanged by the read-modify-write merge. If it is unset, this script
# explicitly sends null rather than fabricating a policy.
#
# restrictions is explicitly null (nobody is restricted from pushing to these
# branches beyond what required checks + enforce_admins already enforce).
set -euo pipefail

REPO="${CI_PROTECTION_REPO:-GetBusbar/busbar}"
BRANCHES="${CI_PROTECTION_BRANCHES:-qa main}"
# protected=feeder pairs: whose shas get checked when the protected branch is advanced.
FEEDERS="${CI_PROTECTION_FEEDERS:-qa=dev main=qa}"
# The git checkout whose origin/* refs the preflight reads (the one this script lives in).
PROTECTION_GIT_DIR="${CI_PROTECTION_GIT_DIR:-$(cd "$(dirname "$0")/.." && pwd)}"

# These four strings are GitHub Actions job `name:` values, matched verbatim
# by the status-checks API. See the block comment above for provenance /
# verification notes on each one.
REQUIRED_CONTEXTS_JSON='[
  "ci umbrella",
  "structure lint",
  "construction gate (how the tree is built vs ARCHITECTURE.md — BLOCKING, on its posture)",
  "ship-ready"
]'

# Contexts this script ACTIVELY STRIPS from a branch's required-status-checks,
# even though `build_body`'s contexts merge is otherwise a union (existing +
# required) that never removes anything on its own. See the "ABSENT FROM THE
# REQUIRED LIST IS NOT THE SAME AS REMOVED" comment above for why this list
# has to exist separately from simply not naming a context in
# REQUIRED_CONTEXTS_JSON. Every entry here must cite the ruling that retired
# it — this is a deliberate removal path, not a place to quietly prune
# something.
#
# "gate-mutants" — a test-effectiveness check, not a release-breaking one;
# workflow_dispatch-only and disabled_manually on GitHub.
RETIRED_CONTEXTS_JSON='[
  "gate-mutants"
]'

feeder_of() {
  local branch="$1" pair
  for pair in $FEEDERS; do
    if [ "${pair%%=*}" = "$branch" ]; then printf '%s' "${pair#*=}"; return 0; fi
  done
  printf '%s' "$branch"
}

# missing_contexts <required-json>  (stdin: the concatenated workflow YAML at one ref)
# Prints every required context that no job in that text can report as, one per line. A job
# reports as its `name:` (4-space indent under `jobs:`) or, when it has none, as its id.
missing_contexts() {
  python3 -c "
import json, re, sys
required = json.loads(sys.argv[1])
names = set()
for doc in sys.stdin.read().split('\x00'):
    in_jobs, job, job_named = False, None, False
    def close():
        if job is not None and not job_named:
            names.add(job)
    for line in doc.splitlines():
        if re.match(r'^jobs:\s*$', line):
            in_jobs = True; continue
        if in_jobs and re.match(r'^[^\s#]', line):  # a column-0 comment does not end jobs:
            close(); in_jobs, job = False, None; continue
        if not in_jobs:
            continue
        m = re.match(r'^  ([A-Za-z0-9_-]+):\s*$', line)
        if m:
            close(); job, job_named = m.group(1), False; continue
        m = re.match(r'^    name:\s*(.+?)\s*$', line)
        if m and job is not None:
            v = m.group(1)
            if len(v) >= 2 and v[0] == v[-1] and v[0] in '\'\"':
                v = v[1:-1]
            names.add(v); job_named = True
    close()
for c in required:
    if c not in names:
        print(c)
" "$1"
}

# workflows_at <ref> — every workflow file at <ref>, NUL-separated, on stdout. Fails if the ref
# does not resolve or carries no workflow file.
workflows_at() {
  local ref="$1" f n=0
  git -C "$PROTECTION_GIT_DIR" rev-parse --verify -q "$ref^{commit}" >/dev/null || return 1
  for f in $(git -C "$PROTECTION_GIT_DIR" ls-tree --name-only "$ref" .github/workflows/ 2>/dev/null); do
    case "$f" in *.yml|*.yaml) ;; *) continue ;; esac
    git -C "$PROTECTION_GIT_DIR" show "$ref:$f" || return 1
    printf '\0'; n=$((n + 1))
  done
  [ "$n" -gt 0 ]
}

# preflight_branch <branch> — refuse (return 1) unless every required context can report on the
# shas that advance <branch>. See "A REQUIRED CONTEXT MUST BE ABLE TO REPORT" above.
preflight_branch() {
  local branch="$1" feeder ref missing
  feeder="$(feeder_of "$branch")"; ref="refs/remotes/origin/$feeder"
  # Piped, never captured: the NUL file separators do not survive a $(...).
  if ! missing="$(set -o pipefail; workflows_at "$ref" | missing_contexts "$REQUIRED_CONTEXTS_JSON")"; then
    echo "REFUSED ${branch}: cannot read .github/workflows at origin/${feeder} (fetch it first) — the"
    echo "  required contexts cannot be shown to report, so none are written"
    return 1
  fi
  if [ -n "$missing" ]; then
    echo "REFUSED ${branch}: required context(s) that no job at origin/${feeder} can report:"
    printf '%s\n' "$missing" | sed 's/^/    /'
    echo "  promote.sh resolves ${branch}'s required contexts against origin/${feeder}'s shas and refuses"
    echo "  on any that never reported, so writing these would wedge the promotion that lands them."
    return 1
  fi
  echo "preflight ${branch}: all required contexts are job names at origin/${feeder}"
  return 0
}

# Fetch the CURRENT protection object for a branch. On a branch that has no
# protection configured yet, GitHub's API returns 404; we treat that as "the
# current state is the empty object" rather than erroring, so this script
# can also be used to protect a branch for the very first time.
fetch_current_protection() {
  local branch="$1"
  local out
  if out=$(gh api "repos/${REPO}/branches/${branch}/protection" 2>/dev/null); then
    printf '%s' "$out"
  else
    printf '{}'
  fi
}

# Build the PUT body for branches/{branch}/protection from a CURRENT
# protection JSON object (GET-shaped: booleans arrive nested as
# {"enabled": true/false}) and the desired contexts list. This is the one
# place that performs the "modify" step of read-modify-write: every field in
# the output is either an explicit policy decision documented above, or is
# carried through from `current` untouched.
#
# CONTEXTS ARE A UNION, NEVER A REPLACEMENT — WITH ONE NAMED EXCEPTION: this
# script's job is to guarantee a FLOOR of four required checks on qa/main,
# not to be the sole authority over the complete list of required contexts.
# main, for example, already requires "qa-gate umbrella" and "record the
# staged digest (the promote's only input)" in addition to the shared ones —
# those were added by hand for reasons specific to how release promotion
# works, and this script has no opinion about them and no business deleting
# them. If this script set `contexts` to exactly its four required strings,
# every hand-added context on every branch would become a casualty of the
# next run — the exact silent-loss-of-protection hazard the rest of this
# script is built around avoiding for every other field. So the contexts we
# send are (current contexts) UNION (required contexts): anything already
# required keeps being required, and the four required contexts are added
# if they're missing.
#
# Removing a context from protection is, in general, a deliberate action for
# a human via `gh api` or the UI — not something this script does on its
# own. RETIRED_CONTEXTS_JSON is the one exception, and it is exactly that
# deliberate human action, just captured here instead of run by hand once: a
# short, reviewed, cited list (see its own comment) of contexts this script
# actively subtracts from the union's result, even when the branch's own
# current state still carries them. A union alone can never do this — it can
# only add — which is why "gate-mutants" being absent from
# REQUIRED_CONTEXTS_JSON was not enough to ever get it off a branch that
# already required it; see case (g) in `cmd_selftest` for the proof.
#
# Usage: build_body <<<"$current_json"
build_body() {
  python3 -c "
import json, sys

current = json.load(sys.stdin)
required = json.loads('''${REQUIRED_CONTEXTS_JSON}''')
retired = set(json.loads('''${RETIRED_CONTEXTS_JSON}'''))
existing_rsc = current.get('required_status_checks') or {}
existing_contexts = existing_rsc.get('contexts') or []
# Union, preserving order: required contexts first (so the floor is always
# legible at the top of the list), then any pre-existing context not
# already in the required set, in its original order.
contexts = list(required) + [c for c in existing_contexts if c not in required]
# Then subtract the retired set explicitly — the one place this script
# removes a context rather than merely declining to add it. Applied AFTER
# the union, and against both halves of it, so a retired context can never
# survive by riding in on 'existing_contexts' (the whole reason the union
# alone could not do this) nor by someone accidentally leaving it in
# REQUIRED_CONTEXTS_JSON too.
contexts = [c for c in contexts if c not in retired]

def flag(key, default=False):
    v = current.get(key)
    if isinstance(v, dict) and 'enabled' in v:
        return bool(v['enabled'])
    if isinstance(v, bool):
        return v
    return default

body = {
    # Opinionated fields — this script's actual policy.
    'required_status_checks': {
        'strict': False,
        'contexts': contexts,
    },
    'enforce_admins': True,
    'allow_force_pushes': False,
    'allow_deletions': False,
    'restrictions': None,
    # required_pull_request_reviews: leave as-is if already configured,
    # otherwise explicitly null rather than inventing a review policy.
    'required_pull_request_reviews': current.get('required_pull_request_reviews') or None,
    # Untouched fields — carried through from whatever the branch already
    # has, so this script can never silently regress a setting it has no
    # opinion about.
    'required_linear_history': flag('required_linear_history'),
    'required_conversation_resolution': flag('required_conversation_resolution'),
    'block_creations': flag('block_creations'),
    'lock_branch': flag('lock_branch'),
    'allow_fork_syncing': flag('allow_fork_syncing'),
}
print(json.dumps(body, indent=2, ensure_ascii=False))
"
}

# Human-readable compliance summary for one branch's CURRENT protection JSON.
# Used by --show, and by the --selftest compliance-detection case.
summarize_protection() {
  local branch="$1"
  python3 -c "
import json, sys

branch = sys.argv[1]
current = json.load(sys.stdin)
required = json.loads('''${REQUIRED_CONTEXTS_JSON}''')
retired = json.loads('''${RETIRED_CONTEXTS_JSON}''')

if not current:
    print(f'{branch}: UNPROTECTED (no branch protection configured)')
    sys.exit(0)

rsc = current.get('required_status_checks') or {}
contexts = set(rsc.get('contexts') or [])
strict = bool(rsc.get('strict'))
enforce_admins = bool((current.get('enforce_admins') or {}).get('enabled')) if isinstance(current.get('enforce_admins'), dict) else bool(current.get('enforce_admins'))
force_push = bool((current.get('allow_force_pushes') or {}).get('enabled')) if isinstance(current.get('allow_force_pushes'), dict) else bool(current.get('allow_force_pushes'))
deletions = bool((current.get('allow_deletions') or {}).get('enabled')) if isinstance(current.get('allow_deletions'), dict) else bool(current.get('allow_deletions'))

missing = [c for c in required if c not in contexts]
stale = [c for c in retired if c in contexts]
problems = []
if missing:
    problems.append(f'missing contexts: {missing}')
if stale:
    problems.append(f'retired contexts still required (run this script, or gh api, to drop them): {stale}')
if strict:
    problems.append('strict is true (should be false for cherry-pick workflow)')
if not enforce_admins:
    problems.append('enforce_admins is false')
if force_push:
    problems.append('allow_force_pushes is true')
if deletions:
    problems.append('allow_deletions is true')

print(f'{branch}: contexts={sorted(contexts)} strict={strict} enforce_admins={enforce_admins} allow_force_pushes={force_push} allow_deletions={deletions}')
if problems:
    print(f'{branch}: NOT COMPLIANT — ' + '; '.join(problems))
else:
    print(f'{branch}: COMPLIANT')
" "$branch"
}

cmd_show() {
  for branch in $BRANCHES; do
    fetch_current_protection "$branch" | summarize_protection "$branch"
  done
}

cmd_dry_run() {
  local rc=0
  for branch in $BRANCHES; do
    echo "# ${REPO} : ${branch}"
    preflight_branch "$branch" || rc=1
    fetch_current_protection "$branch" | build_body
    echo
  done
  return "$rc"
}

cmd_apply() {
  local branch
  # Preflight EVERY branch before writing ANY, so a refusal never leaves one branch re-protected
  # and the other not.
  for branch in $BRANCHES; do
    preflight_branch "$branch" || { echo "nothing applied." >&2; return 1; }
  done
  for branch in $BRANCHES; do
    local body
    body=$(fetch_current_protection "$branch" | build_body)
    echo "Applying branch protection to ${REPO}:${branch} ..."
    printf '%s' "$body" | gh api \
      --method PUT \
      -H "Accept: application/vnd.github+json" \
      "repos/${REPO}/branches/${branch}/protection" \
      --input - >/dev/null
    echo "Applied. Current state:"
    fetch_current_protection "$branch" | summarize_protection "$branch"
    echo
  done
}

# ---------------------------------------------------------------------------
# --selftest: proves the body-building and summarising logic against fixture
# JSON, with NO network access. Every case prints ok/FAIL; any FAIL makes the
# whole script exit non-zero.
# ---------------------------------------------------------------------------
cmd_selftest() {
  local failures=0

  # Fixture: a realistic "current protection" object for an already-protected
  # branch. It deliberately: (1) is missing required contexts (e.g. the
  # "construction gate ..." check and "ship-ready") from its contexts, so the
  # compliance check must catch that; (2) has strict=true, which this
  # script must flip to false; (3) carries an unrelated, unrequested setting
  # (required_conversation_resolution.enabled = true) that must survive the
  # merge untouched, proving read-modify-write actually preserves state
  # instead of dropping it; (4) carries a pre-existing, hand-added context
  # ("qa-gate umbrella", modelled on main's real protection) that is not one
  # of the four required contexts and must survive the merge too, proving
  # contexts are unioned rather than replaced; (5) carries "gate-mutants" —
  # modelled on qa/main's REAL protection at the time this fixture was last
  # updated, where it was still required despite the header above already
  # claiming it had been removed — so the retired-context removal path has a
  # non-synthetic case to prove itself against.
  local fixture_current='{
    "required_status_checks": {
      "strict": true,
      "contexts": ["ci umbrella", "structure lint", "qa-gate umbrella", "gate-mutants"]
    },
    "enforce_admins": {"enabled": false},
    "allow_force_pushes": {"enabled": true},
    "allow_deletions": {"enabled": true},
    "required_conversation_resolution": {"enabled": true},
    "required_linear_history": {"enabled": true}
  }'

  local body
  body=$(printf '%s' "$fixture_current" | build_body)

  # (a) all four desired contexts present in the built body.
  local a_result
  a_result=$(python3 -c "
import json, sys
body = json.loads(sys.argv[1])
required = json.loads(sys.argv[2])
contexts = body['required_status_checks']['contexts']
print('ok' if all(c in contexts for c in required) else 'FAIL')
" "$body" "$REQUIRED_CONTEXTS_JSON")
  echo "selftest (a) four contexts present after build: ${a_result}"
  [ "$a_result" = "ok" ] || failures=$((failures + 1))

  # (b) the unrelated fixture setting (required_conversation_resolution) is
  # preserved by the merge rather than reset to a default.
  local b_result
  b_result=$(python3 -c "
import json, sys
body = json.loads(sys.argv[1])
print('ok' if body.get('required_conversation_resolution') is True else 'FAIL')
" "$body")
  echo "selftest (b) unrelated setting survives merge: ${b_result}"
  [ "$b_result" = "ok" ] || failures=$((failures + 1))

  # (c) force-push/deletions come out false, enforce_admins true, regardless
  # of what the fixture had (fixture had all three the wrong way around).
  local c_result
  c_result=$(python3 -c "
import json, sys
body = json.loads(sys.argv[1])
ok = (body['allow_force_pushes'] is False
      and body['allow_deletions'] is False
      and body['enforce_admins'] is True
      and body['required_status_checks']['strict'] is False)
print('ok' if ok else 'FAIL')
" "$body")
  echo "selftest (c) force-push/deletions false, enforce_admins true, strict false: ${c_result}"
  [ "$c_result" = "ok" ] || failures=$((failures + 1))

  # (d) a missing/404 current-protection (empty object) still produces a
  # valid, complete body instead of erroring.
  local d_body
  local d_result="FAIL"
  if d_body=$(printf '{}' | build_body 2>/dev/null); then
    d_result=$(python3 -c "
import json, sys
body = json.loads(sys.argv[1])
required_keys = {'required_status_checks','enforce_admins','allow_force_pushes',
                  'allow_deletions','restrictions','required_pull_request_reviews',
                  'required_linear_history','required_conversation_resolution',
                  'block_creations','lock_branch','allow_fork_syncing'}
print('ok' if required_keys.issubset(body.keys()) else 'FAIL')
" "$d_body")
  fi
  echo "selftest (d) unprotected (404-shaped empty) input still builds a valid body: ${d_result}"
  [ "$d_result" = "ok" ] || failures=$((failures + 1))

  # (e) removing a context from the desired list is detected: a branch whose
  # current contexts are missing one of the four must be reported as NOT
  # COMPLIANT by the summariser (using the original fixture, which is
  # missing "construction gate ..." and "ship-ready").
  local e_summary e_result
  e_summary=$(printf '%s' "$fixture_current" | summarize_protection "fixture-branch")
  if echo "$e_summary" | grep -q "NOT COMPLIANT"; then
    e_result="ok"
  else
    e_result="FAIL"
  fi
  echo "selftest (e) missing-context branch reported NOT COMPLIANT: ${e_result}"
  [ "$e_result" = "ok" ] || failures=$((failures + 1))

  # (f) contexts are a UNION, never a replacement: the fixture's pre-existing,
  # unrelated context ("qa-gate umbrella", not one of the four required
  # strings) must still be present in the built body. This case must fail
  # if someone reverts build_body to set contexts = required verbatim
  # instead of required UNION existing.
  local f_result
  f_result=$(python3 -c "
import json, sys
body = json.loads(sys.argv[1])
contexts = body['required_status_checks']['contexts']
print('ok' if 'qa-gate umbrella' in contexts else 'FAIL')
" "$body")
  echo "selftest (f) pre-existing unrelated context survives union merge: ${f_result}"
  [ "$f_result" = "ok" ] || failures=$((failures + 1))

  # (g) THE REMOVAL PATH ITSELF: "gate-mutants" is in the fixture's current
  # contexts (see the fixture comment above — this models qa/main's real,
  # observed state) and MUST NOT survive into the built body, even though the
  # union step alone would have carried it through exactly like "qa-gate
  # umbrella" did in case (f). This is the case that fails if someone reverts
  # the union to a plain union with no retired-context subtraction — the
  # exact bug this defect was filed against: REQUIRED_CONTEXTS_JSON not
  # naming a context was assumed to be enough to drop it, and it never was.
  local g_result
  g_result=$(python3 -c "
import json, sys
body = json.loads(sys.argv[1])
contexts = body['required_status_checks']['contexts']
print('ok' if 'gate-mutants' not in contexts else 'FAIL')
" "$body")
  echo "selftest (g) retired context (gate-mutants) does NOT survive the merge: ${g_result}"
  [ "$g_result" = "ok" ] || failures=$((failures + 1))

  # (h) the summariser SURFACES a stale retired context as NOT COMPLIANT too
  # (not just missing-required contexts), so `--show` on a branch nobody has
  # re-applied this script to still tells a human the drift is there.
  local h_summary h_result
  h_summary=$(printf '%s' "$fixture_current" | summarize_protection "fixture-branch")
  if echo "$h_summary" | grep -q "NOT COMPLIANT" && echo "$h_summary" | grep -q "retired contexts still required" && echo "$h_summary" | grep -q "gate-mutants"; then
    h_result="ok"
  else
    h_result="FAIL"
  fi
  echo "selftest (h) a branch still requiring a retired context is reported NOT COMPLIANT, by name: ${h_result}"
  [ "$h_result" = "ok" ] || failures=$((failures + 1))

  # (i) item 488 — a required context the feeder's workflows cannot report is REFUSED before any
  # PUT; the same preflight over workflows that do carry all four jobs passes. Built in a scratch
  # git repo so the refs are real and nothing touches the network.
  local st_repo i_result="FAIL" j_result="FAIL" k_result="FAIL"
  st_repo="$(mktemp -d)"
  (
    set -e
    cd "$st_repo"; git init -q; git config user.email selftest@example.invalid; git config user.name selftest
    git config core.hooksPath /dev/null   # a host's global commit hooks must not decide a fixture
    mkdir -p .github/workflows
    printf 'on: push\njobs:\n  umbrella:\n    name: ci umbrella\n    runs-on: x\n# a column-0 comment inside jobs: must not end the job list\n  lint:\n    name: "structure lint"\n    runs-on: x\n  construction-gate:\n    name: construction gate (how the tree is built vs ARCHITECTURE.md — BLOCKING, on its posture)\n    runs-on: x\n' > .github/workflows/ci.yml
    git add -A; git commit -q --no-verify -m stale; git update-ref refs/remotes/origin/dev HEAD
    printf '  ship-ready:\n    runs-on: x\n' >> .github/workflows/ci.yml
    git commit -q --no-verify -am fresh; git update-ref refs/remotes/origin/qa HEAD
  ) >/dev/null 2>&1 || true
  local i_out i_rc=0
  i_out="$(FEEDERS="qa=dev main=qa" PROTECTION_GIT_DIR="$st_repo" preflight_branch qa 2>&1)" || i_rc=$?
  if [ "$i_rc" -ne 0 ] && printf '%s' "$i_out" | grep -q '^    ship-ready$' && ! printf '%s' "$i_out" | grep -q '^    ci umbrella$'; then i_result="ok"; fi
  echo "selftest (i) a required context the feeder cannot report (ship-ready at origin/dev) is REFUSED, by name: ${i_result}"
  [ "$i_result" = "ok" ] || failures=$((failures + 1))
  if FEEDERS="qa=dev main=qa" PROTECTION_GIT_DIR="$st_repo" preflight_branch main >/dev/null 2>&1; then j_result="ok"; fi
  echo "selftest (j) all four contexts reportable at the feeder (ship-ready by job id) passes preflight: ${j_result}"
  [ "$j_result" = "ok" ] || failures=$((failures + 1))
  if ! FEEDERS="qa=nosuchbranch" PROTECTION_GIT_DIR="$st_repo" preflight_branch qa >/dev/null 2>&1; then k_result="ok"; fi
  echo "selftest (k) an unreadable feeder ref is REFUSED, not waved through: ${k_result}"
  [ "$k_result" = "ok" ] || failures=$((failures + 1))
  rm -rf "$st_repo"

  if [ "$failures" -eq 0 ]; then
    echo "selftest: ALL OK"
    return 0
  else
    echo "selftest: ${failures} FAILURE(S)"
    return 1
  fi
}

usage() {
  cat <<EOF
usage: $0 [--dry-run|--show|--selftest]

  (no args)   apply branch protection to \$CI_PROTECTION_BRANCHES on \$CI_PROTECTION_REPO, then print a summary
  --dry-run   print the JSON body that would be PUT for each branch; change nothing
  --show      print the current protection summary for each branch; change nothing
  --selftest  prove the body-building and summarising logic against fixtures; no network access

Env vars:
  CI_PROTECTION_REPO      (default: GetBusbar/busbar)
  CI_PROTECTION_BRANCHES  (default: "qa main")
EOF
}

main() {
  case "${1:-}" in
    --dry-run) cmd_dry_run ;;
    --show) cmd_show ;;
    --selftest) cmd_selftest ;;
    -h|--help) usage ;;
    "") cmd_apply ;;
    *)
      echo "unknown argument: $1" >&2
      usage >&2
      exit 2
      ;;
  esac
}

main "$@"
