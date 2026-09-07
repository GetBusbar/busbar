#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# LANDING IN THE PR ERA: CI IS THE JUDGE, THIS SCRIPT IS ONLY THE COURIER.
#
# scripts/land.sh cherry-picked onto the integration branch and then ran a hand-picked subset of the
# gate locally, and the operator read its GREEN as the verdict. That is the defect this script
# exists to remove. A local green is a claim about one machine's toolchain, one machine's services,
# one machine's cache; the required checks on the pull request are the claim the branch protection
# actually reads. So this script picks, pushes, opens the PR, and hands the verdict to CI. It never
# renders a verdict of its own, and it never merges by hand: auto-merge is armed and GitHub merges
# when — and only when — the required contexts are green.
#
#   scripts/pr-land.sh <hash>... [--title T] [--base dev] [--wait] [--dry-run]
#
# --title     the PR title (default: the first picked commit's subject, plus a count).
# --base      the branch the PR targets and the branch the picks are taken onto (default: dev).
# --wait      poll the required checks until they settle, then print the verdict with run URLs.
#             Without it the script returns as soon as the PR is open and auto-merge is armed.
# --dry-run   print every command this would run; run none of them, touch no branch, open no PR.
#
# THE REBASE STRATEGY IS NOT A PREFERENCE. Each picked commit is a reviewed unit with its own
# message and its own `(cherry picked from commit …)` trailer; a squash would fuse N of those into
# one synthetic commit and throw the trailers away, which is exactly the provenance the promote path
# later reads back. So: --rebase, never --squash, never --merge.
#
# FAIL CLOSED. Unauthenticated `gh`, a repository whose auto-merge is disabled, a conflicting pick —
# each is an exit, never a fallback. A courier that guesses is worse than no courier.
set -uo pipefail

# The required contexts this script waits on. Overridable so a fork or a rehearsal repo can name its
# own; the default is the four the protections on dev/qa/main actually list.
#
#   ci umbrella                 .github/workflows/ci.yml — the single umbrella over every CI job,
#                               so protection never drifts when a job is renamed.
#   {A2A,MCP,Voice} conformance verdict
#                               the three protocol conformance workflows' terminal `verdict` jobs.
PR_LAND_CHECKS="${PR_LAND_CHECKS:-ci umbrella
A2A conformance verdict
MCP conformance verdict
Voice conformance verdict}"

# How long --wait will poll before it gives up and says so (it says "unsettled", never "green").
PR_LAND_POLL_SECONDS="${PR_LAND_POLL_SECONDS:-20}"
PR_LAND_WAIT_LIMIT="${PR_LAND_WAIT_LIMIT:-7200}"

usage() {
  sed -n '2,32p' "$0" | sed 's/^# \{0,1\}//'
}

base="dev"; title=""; wait_checks=0; dry=0; hashes=""
while [ $# -gt 0 ]; do
  case "$1" in
    --title) title="${2:-}"; shift 2 ;;
    --base) base="${2:-}"; shift 2 ;;
    --wait) wait_checks=1; shift ;;
    --dry-run) dry=1; shift ;;
    --selftest) exec bash "$(cd "$(dirname "$0")" && pwd)/pr-land-selftest.sh" ;;
    --help|-h) usage; exit 0 ;;
    -*) echo "pr-land.sh: unknown flag $1" >&2; exit 2 ;;
    *) hashes="$hashes $1"; shift ;;
  esac
done
# shellcheck disable=SC2086  # deliberate: $hashes is a whitespace-separated list of revisions
set -- $hashes
[ $# -gt 0 ] || { echo "pr-land.sh: no hashes" >&2; usage >&2; exit 2; }

repo_dir="$(git rev-parse --show-toplevel 2>/dev/null)" || {
  echo "pr-land.sh: not inside a git work tree" >&2; exit 2; }
G="git -C $repo_dir"

# `run` is the ONLY way this script mutates anything, so --dry-run is total by construction rather
# than by remembering to guard each call site.
run() {
  echo "+ $*"
  [ "$dry" = 1 ] && return 0
  "$@"
}

# ── FAIL CLOSED ON THE TOOL BEFORE TOUCHING THE TREE ──────────────────────────────────────────────
# A refusal here is REPORTED under --dry-run rather than exited on, because the point of a dry run is
# to read the whole plan — including "and then it would refuse, here, for this reason". The exit code
# still carries the refusal at the bottom, so a dry run that would refuse is never mistaken for a
# rehearsal that would work.
preflight_red=""
refuse() {
  echo "pr-land.sh: RED — $1" >&2
  [ -n "${2:-}" ] && echo "pr-land.sh:       $2" >&2
  if [ "$dry" = 1 ]; then preflight_red="yes"; return 0; fi
  exit 1
}
command -v gh >/dev/null 2>&1 || refuse "gh is required"
gh auth status >/dev/null 2>&1 \
  || refuse "gh is not authenticated (gh auth login)" "refusing to pick a thing"
slug="$(gh repo view --json nameWithOwner -q .nameWithOwner 2>/dev/null || true)"
[ -n "$slug" ] || { slug="<unresolved>"; refuse "cannot resolve the repository from gh"; }

# Auto-merge is a repository SETTING; if it is off, `gh pr merge --auto` fails after the PR is
# already open, and the operator walks away from a PR that will never merge itself. Ask first.
automerge="$(gh api "repos/$slug" --jq '.allow_auto_merge' 2>/dev/null || echo "unknown")"
[ "$automerge" = "true" ] \
  || refuse "auto-merge is not available on $slug (allow_auto_merge=$automerge)" \
            "Enable it in repository settings; this script will not merge by hand."

# ── THE BRANCH ────────────────────────────────────────────────────────────────────────────────────
run $G fetch origin "$base" || { echo "pr-land.sh: RED — cannot fetch origin/$base" >&2; exit 1; }
first_short="$($G rev-parse --short=8 "$1" 2>/dev/null || echo "$1")"
branch="land/$(date +%Y%m%d)-$first_short"
run $G switch -c "$branch" "origin/$base" || {
  echo "pr-land.sh: RED — cannot create $branch from origin/$base" >&2; exit 1; }

# ── THE PICKS ─────────────────────────────────────────────────────────────────────────────────────
# -x so every landed commit carries `(cherry picked from commit <sha>)`. That trailer is the only
# durable link between what an agent wrote on its worktree and what CI judged, and the PR body
# below reprints it so the link is legible without cloning.
#
# A CONFLICT IS AN ABORT, NEVER A RESOLUTION. Resolving here would put bytes into the PR that no
# commit message describes and no reviewer asked for, and CI would then judge a merge nobody wrote.
picked=""
for h in "$@"; do
  echo "+ $G cherry-pick -x $h"
  if [ "$dry" = 1 ]; then picked="$picked $h"; continue; fi
  if ! $G cherry-pick -x "$h" >/dev/null 2>&1; then
    conflicted="$($G diff --name-only --diff-filter=U | tr '\n' ' ')"
    $G cherry-pick --abort >/dev/null 2>&1 || true
    $G switch - >/dev/null 2>&1 || true
    $G branch -D "$branch" >/dev/null 2>&1 || true
    echo "pr-land.sh: RED — cherry-pick $h conflicted on: ${conflicted:-<unknown>}" >&2
    echo "pr-land.sh:       aborted and deleted $branch; nothing was pushed and no PR was opened." >&2
    echo "pr-land.sh:       Rebase the source commit onto origin/$base and hand back a clean hash." >&2
    exit 1
  fi
  picked="$picked $h"
done

# ── THE BODY: EVERY PICK, AND ITS TRAILER ─────────────────────────────────────────────────────────
body_file="$repo_dir/.fix/pr-land-body-$$.md"
mkdir -p "$repo_dir/.fix"
{
  echo "Landed by \`scripts/pr-land.sh\` onto \`$base\`. CI is the judge: this PR merges when the"
  echo "required contexts are green, and not before. Nothing here was proven on a laptop."
  echo
  echo "## Picked commits ($#)"
  echo
  n=0
  for h in $picked; do
    n=$((n + 1))
    full="$($G rev-parse "$h" 2>/dev/null || echo "$h")"
    subj="$($G log -1 --format=%s "$h" 2>/dev/null || echo '(unresolved)')"
    echo "$n. \`$full\` — $subj"
    if [ "$dry" = 1 ]; then
      echo "   - trailer: \`(cherry picked from commit $full)\`"
    else
      # The trailer as it actually exists on the landed commit, read back rather than assumed.
      landed="$($G log --format='%H %b' "origin/$base..HEAD" | grep -m1 "cherry picked from commit $full" || true)"
      echo "   - trailer: \`$(printf '%s' "${landed#* }" | sed -n 's/.*\((cherry picked from commit [0-9a-f]*)\).*/\1/p')\`"
    fi
  done
  echo
  echo "## Required contexts"
  echo
  printf '%s\n' "$PR_LAND_CHECKS" | while IFS= read -r c; do [ -n "$c" ] && echo "- \`$c\`"; done
} >"$body_file"

if [ -z "$title" ]; then
  title="$($G log -1 --format=%s "$1" 2>/dev/null || echo "land $first_short")"
  [ $# -gt 1 ] && title="$title (+$(($# - 1)) more)"
fi

run $G push -u origin "$branch" || {
  echo "pr-land.sh: RED — push of $branch failed; no PR opened" >&2; exit 1; }

run gh pr create --repo "$slug" --base "$base" --head "$branch" --title "$title" --body-file "$body_file" || {
  echo "pr-land.sh: RED — gh pr create failed; the branch is pushed, the PR is not open" >&2; exit 1; }

# --rebase: the N reviewed commits arrive on $base as N commits, trailers intact. Never --squash.
run gh pr merge --repo "$slug" "$branch" --auto --rebase || {
  echo "pr-land.sh: RED — could not arm auto-merge on $branch; the PR is OPEN and unmerged" >&2; exit 1; }

if [ "$dry" = 1 ]; then
  echo "pr-land.sh: dry-run — nothing above was executed. PR body that would be posted:"
  sed 's/^/  | /' "$body_file"
  rm -f "$body_file"
  [ -n "$preflight_red" ] || exit 0
  echo "pr-land.sh: dry-run RED — a real run would have REFUSED at the preflight above." >&2
  exit 1
fi
url="$(gh pr view --repo "$slug" "$branch" --json url -q .url 2>/dev/null || echo "(unknown)")"
echo "pr-land.sh: PR open with auto-merge (rebase) armed: $url"
rm -f "$body_file"

[ "$wait_checks" = 1 ] || {
  echo "pr-land.sh: not waiting (--wait to poll). CI's verdict on $url is the verdict."
  exit 0
}

# ── --wait: READ CI'S VERDICT, DO NOT FORM ONE ────────────────────────────────────────────────────
# Every required context must be present AND successful. A context that never reported is not a
# pass — the `windows build · test` trap (a required name nothing could report) is exactly the
# failure a "not red" test would wave through.
waited=0
while :; do
  checks="$(gh pr checks "$branch" --repo "$slug" --json name,state,link 2>/dev/null || echo '[]')"
  pending=0; failed=""
  while IFS= read -r c; do
    [ -n "$c" ] || continue
    st="$(printf '%s' "$checks" | jq -r --arg n "$c" '[.[]|select(.name==$n)]|last|.state // "MISSING"')"
    case "$st" in
      SUCCESS) ;;
      PENDING|QUEUED|IN_PROGRESS|EXPECTED|MISSING) pending=1 ;;
      *) failed="$failed$c
" ;;
    esac
  done <<EOF
$PR_LAND_CHECKS
EOF
  if [ -n "$failed" ]; then
    echo "pr-land.sh: RED — required checks failed on $url (the PR is left OPEN):" >&2
    printf '%s' "$failed" | while IFS= read -r c; do
      [ -n "$c" ] || continue
      link="$(printf '%s' "$checks" | jq -r --arg n "$c" '[.[]|select(.name==$n)]|last|.link // ""')"
      echo "  - $c  $link" >&2
      rid="$(printf '%s' "$link" | sed -n 's#.*/actions/runs/\([0-9]*\).*#\1#p')"
      if [ -n "$rid" ]; then
        gh run view "$rid" --repo "$slug" --log-failed 2>/dev/null | grep -m1 . | sed 's/^/      /' >&2
      fi
    done
    echo "pr-land.sh:       auto-merge stays armed; push a fix to $branch and CI re-judges." >&2
    exit 1
  fi
  [ "$pending" = 1 ] || break
  waited=$((waited + PR_LAND_POLL_SECONDS))
  if [ "$waited" -ge "$PR_LAND_WAIT_LIMIT" ]; then
    echo "pr-land.sh: RED — required checks unsettled after ${waited}s on $url" >&2
    exit 1
  fi
  sleep "$PR_LAND_POLL_SECONDS"
done

echo "pr-land.sh: GREEN — every required context succeeded on $url"
printf '%s\n' "$PR_LAND_CHECKS" | while IFS= read -r c; do
  [ -n "$c" ] || continue
  link="$(printf '%s' "$checks" | jq -r --arg n "$c" '[.[]|select(.name==$n)]|last|.link // ""')"
  echo "  - $c  $link"
done
echo "pr-land.sh: auto-merge will rebase $# commit(s) onto $base. That merge, not this line, is the landing."
