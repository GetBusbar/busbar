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
# THE FIVE REQUIRED STATUS CHECKS
# --------------------------------
# The contexts below are matched by GitHub against the `name:` of the GitHub
# Actions job that reports the check, not the workflow file name and not the
# step name. Three of the five ("ci umbrella", "structure lint",
# "construction gate (how the tree is built vs ARCHITECTURE.md — BLOCKING, on
# its posture)") were verified against .github/workflows/ci.yml at the time
# this script was written — they are the literal `name:` fields of jobs in
# that file. "gate-mutants" was verified against
# .github/workflows/gate-mutants.yml (the final aggregator job in that
# workflow is literally named `gate-mutants`). "ship-ready" was NOT found
# anywhere in .github/workflows/*.yml at the time this script was written —
# it does not exist yet as a job name in this repo. It is included here
# because it was specified as a requirement, but until a job named exactly
# "ship-ready" exists and reports a check with that name, GitHub will never
# see that context satisfied and PRs targeting qa/main will be permanently
# blocked. Whoever adds that gate must use this exact job name, or this
# script's REQUIRED_CONTEXTS list must be updated to match whatever name is
# actually used.
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

# These five strings are GitHub Actions job `name:` values, matched verbatim
# by the status-checks API. See the block comment above for provenance /
# verification notes on each one.
REQUIRED_CONTEXTS_JSON='[
  "ci umbrella",
  "structure lint",
  "construction gate (how the tree is built vs ARCHITECTURE.md — BLOCKING, on its posture)",
  "gate-mutants",
  "ship-ready"
]'

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
# CONTEXTS ARE A UNION, NEVER A REPLACEMENT: this script's job is to
# guarantee a FLOOR of five required checks on qa/main, not to be the sole
# authority over the complete list of required contexts. main, for example,
# already requires "qa-gate umbrella" and "record the staged digest (the
# promote's only input)" in addition to the shared ones — those were added
# by hand for reasons specific to how release promotion works, and this
# script has no opinion about them and no business deleting them. If this
# script set `contexts` to exactly its five required strings, every
# hand-added context on every branch would become a casualty of the next
# run — the exact silent-loss-of-protection hazard the rest of this script
# is built around avoiding for every other field. So the contexts we send
# are (current contexts) UNION (required contexts): anything already
# required keeps being required, and the five required contexts are added
# if they're missing. Removing a context from protection, if that's ever
# genuinely wanted, is a deliberate action for a human via `gh api` or the
# UI — not something this script will ever do on its own.
#
# Usage: build_body <<<"$current_json"
build_body() {
  python3 -c "
import json, sys

current = json.load(sys.stdin)
required = json.loads('''${REQUIRED_CONTEXTS_JSON}''')
existing_rsc = current.get('required_status_checks') or {}
existing_contexts = existing_rsc.get('contexts') or []
# Union, preserving order: required contexts first (so the floor is always
# legible at the top of the list), then any pre-existing context not
# already in the required set, in its original order.
contexts = list(required) + [c for c in existing_contexts if c not in required]

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
problems = []
if missing:
    problems.append(f'missing contexts: {missing}')
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
  for branch in $BRANCHES; do
    echo "# ${REPO} : ${branch}"
    fetch_current_protection "$branch" | build_body
    echo
  done
}

cmd_apply() {
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
  # branch. It deliberately: (1) is missing "gate-mutants" from its contexts,
  # so the compliance check must catch that; (2) has strict=true, which this
  # script must flip to false; (3) carries an unrelated, unrequested setting
  # (required_conversation_resolution.enabled = true) that must survive the
  # merge untouched, proving read-modify-write actually preserves state
  # instead of dropping it; (4) carries a pre-existing, hand-added context
  # ("qa-gate umbrella", modelled on main's real protection) that is not one
  # of the five required contexts and must survive the merge too, proving
  # contexts are unioned rather than replaced.
  local fixture_current='{
    "required_status_checks": {
      "strict": true,
      "contexts": ["ci umbrella", "structure lint", "qa-gate umbrella"]
    },
    "enforce_admins": {"enabled": false},
    "allow_force_pushes": {"enabled": true},
    "allow_deletions": {"enabled": true},
    "required_conversation_resolution": {"enabled": true},
    "required_linear_history": {"enabled": true}
  }'

  local body
  body=$(printf '%s' "$fixture_current" | build_body)

  # (a) all five desired contexts present in the built body.
  local a_result
  a_result=$(python3 -c "
import json, sys
body = json.loads(sys.argv[1])
required = json.loads(sys.argv[2])
contexts = body['required_status_checks']['contexts']
print('ok' if all(c in contexts for c in required) else 'FAIL')
" "$body" "$REQUIRED_CONTEXTS_JSON")
  echo "selftest (a) five contexts present after build: ${a_result}"
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
  # current contexts are missing one of the five must be reported as NOT
  # COMPLIANT by the summariser (using the original fixture, which is
  # missing "construction gate ..." and "gate-mutants" and "ship-ready").
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
  # unrelated context ("qa-gate umbrella", not one of the five required
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
