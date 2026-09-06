#!/usr/bin/env bash
# Promote a green SHA by fast-forwarding it onto the next branch in the
# dev -> qa -> main chain. This never rebuilds anything: it pushes the exact
# SHA that already carries the required checks for the destination branch,
# so the SHA that lands on qa is the same SHA that later lands on main.
set -euo pipefail

REPO="GetBusbar/busbar"

usage() {
  cat <<'EOF'
Usage: scripts/promote.sh <from> <to> [--dry-run]
       scripts/promote.sh --help

Promote <from> to <to> with a fast-forward push (git push origin <from>:<to>).
Only two promotions are allowed:

  dev qa      promote dev to qa
  qa  main    promote qa to main

Before pushing, this script:
  1. Refuses if the local <from> branch is not identical to origin/<from>.
  2. Refuses unless origin/<to> is an ancestor of <from> (fast-forward only).
  3. Reads the required status check names for <to> from GitHub branch
     protection (never hardcoded) and refuses unless every one of them has
     a "success" conclusion on <from>'s current SHA.
  4. Prints the SHA and the checks it saw.

Only then does it run: git push origin <from>:<to>   (no --force, ever)

Options:
  --dry-run   Print what would happen; do not push.
  --help      Show this help.
EOF
}

DRY_RUN=0
FROM=""
TO=""

for arg in "$@"; do
  case "$arg" in
    --help)
      usage
      exit 0
      ;;
    --dry-run)
      DRY_RUN=1
      ;;
    *)
      if [[ -z "$FROM" ]]; then
        FROM="$arg"
      elif [[ -z "$TO" ]]; then
        TO="$arg"
      else
        echo "error: unexpected argument: $arg" >&2
        usage >&2
        exit 1
      fi
      ;;
  esac
done

if [[ -z "$FROM" || -z "$TO" ]]; then
  usage >&2
  exit 1
fi

if [[ "$FROM" == "dev" && "$TO" == "qa" ]]; then
  :
elif [[ "$FROM" == "qa" && "$TO" == "main" ]]; then
  :
else
  echo "error: only 'dev qa' or 'qa main' are allowed promotions (got '$FROM' '$TO')" >&2
  exit 1
fi

command -v gh >/dev/null 2>&1 || { echo "error: gh is required" >&2; exit 1; }
command -v git >/dev/null 2>&1 || { echo "error: git is required" >&2; exit 1; }
command -v jq >/dev/null 2>&1 || { echo "error: jq is required" >&2; exit 1; }

git fetch origin "$FROM" "$TO" >&2

LOCAL_FROM_SHA="$(git rev-parse "$FROM")"
ORIGIN_FROM_SHA="$(git rev-parse "origin/$FROM")"

if [[ "$LOCAL_FROM_SHA" != "$ORIGIN_FROM_SHA" ]]; then
  echo "error: local '$FROM' ($LOCAL_FROM_SHA) is not identical to origin/$FROM ($ORIGIN_FROM_SHA)" >&2
  exit 1
fi

SHA="$LOCAL_FROM_SHA"

ORIGIN_TO_SHA="$(git rev-parse "origin/$TO")"

if ! git merge-base --is-ancestor "$ORIGIN_TO_SHA" "$SHA"; then
  echo "error: origin/$TO ($ORIGIN_TO_SHA) is not an ancestor of $FROM ($SHA); this would not be a fast-forward" >&2
  exit 1
fi

REQUIRED_CHECKS_JSON="$(gh api "repos/${REPO}/branches/${TO}/protection/required_status_checks" --jq '.contexts')"
mapfile -t REQUIRED_CHECKS < <(echo "$REQUIRED_CHECKS_JSON" | jq -r '.[]')

if [[ "${#REQUIRED_CHECKS[@]}" -eq 0 ]]; then
  echo "error: no required status checks found for '$TO'; refusing to promote blind" >&2
  exit 1
fi

CHECK_RUNS_JSON="$(gh api "repos/${REPO}/commits/${SHA}/check-runs" --paginate --jq '.check_runs')"

echo "SHA: $SHA"
echo "Required checks for '$TO':"

MISSING=0
for check in "${REQUIRED_CHECKS[@]}"; do
  CONCLUSION="$(echo "$CHECK_RUNS_JSON" | jq -r --arg name "$check" '[.[] | select(.name == $name)] | sort_by(.started_at) | last | .conclusion // "missing"')"
  echo "  - $check: $CONCLUSION"
  if [[ "$CONCLUSION" != "success" ]]; then
    MISSING=1
  fi
done

if [[ "$MISSING" -ne 0 ]]; then
  echo "error: not all required checks for '$TO' are successful on $SHA" >&2
  exit 1
fi

echo "All required checks green on $SHA."

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] would run: git push origin ${FROM}:${TO}"
  exit 0
fi

git push origin "${FROM}:${TO}"
