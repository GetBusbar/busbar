#!/usr/bin/env bash
# Promote a green SHA by fast-forwarding it onto the next branch in the
# dev -> qa -> main chain. This never rebuilds anything: it pushes the exact
# SHA that already carries the required checks for the destination branch,
# so the SHA that lands on qa is the same SHA that later lands on main.
#
# THE PUSH NAMES THE SHA, NOT THE BRANCH. `git push origin dev:qa` resolves `dev` at push time,
# which is a different read of the world than the read every check above it performed. Between the
# check-run query and the push, someone else's push to dev would silently widen the promotion to
# commits nothing in this script ever looked at. So the refspec is the resolved SHA:
# `git push origin <sha>:refs/heads/<to>`. Same fast-forward, no second read.
set -euo pipefail

# The repository is a variable so the self-test can point the whole thing at a stub; every real run
# uses the default.
REPO="${PROMOTE_REPO:-GetBusbar/busbar}"

usage() {
  cat <<'EOF'
Usage: scripts/promote.sh <from> <to> [--dry-run]
       scripts/promote.sh <from> --to <to> [--dry-run]
       scripts/promote.sh --help

Promote <from> to <to> with a fast-forward push of the exact SHA.
Only two promotions are allowed:

  dev qa      promote dev to qa      (--to qa)
  qa  main    promote qa to main     (--to main)

Before pushing, this script:
  1. Refuses if the local <from> branch is not identical to origin/<from>.
  2. Refuses unless origin/<to> is an ancestor of <from> (fast-forward only).
  3. Reads the required status check CONTEXTS FOR <to> BY NAME from GitHub branch
     protection (never a hardcoded list) and refuses unless every one of them has
     a "success" conclusion on <from>'s current SHA. A context that never reported
     is a refusal, exactly like a red one: an unreportable required name is the
     failure mode branch protection exists to catch, not a pass.
  4. Prints the SHA and the checks it saw.

Only then does it run: git push origin <sha>:refs/heads/<to>   (no --force, ever)

Options:
  --to <branch>  Name the destination as a flag instead of a positional.
  --dry-run      Print what would happen; do not push.
  --selftest     Run the self-test (throwaway repo, stubbed gh) and exit.
  --help         Show this help.
EOF
}

DRY_RUN=0
FROM=""
TO=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --help)
      usage
      exit 0
      ;;
    --selftest)
      exec bash "$(cd "$(dirname "$0")" && pwd)/promote-selftest.sh"
      ;;
    --dry-run)
      DRY_RUN=1
      shift
      ;;
    --to)
      if [[ -n "$TO" ]]; then
        echo "error: --to given twice (or after a positional destination)" >&2
        exit 1
      fi
      TO="${2:-}"
      if [[ -z "$TO" ]]; then
        echo "error: --to wants a branch name" >&2
        exit 1
      fi
      shift 2
      ;;
    -*)
      echo "error: unknown option: $1" >&2
      usage >&2
      exit 1
      ;;
    *)
      if [[ -z "$FROM" ]]; then
        FROM="$1"
      elif [[ -z "$TO" ]]; then
        TO="$1"
      else
        echo "error: unexpected argument: $1" >&2
        usage >&2
        exit 1
      fi
      shift
      ;;
  esac
done

if [[ -z "$FROM" || -z "$TO" ]]; then
  usage >&2
  exit 1
fi

# THE TWO GUARDS. `--to qa` and `--to main` are the only destinations, and each one pins its source:
# a promotion to main that started anywhere but qa would put a SHA on main that qa never staged, and
# the release path's `resolve-staged` would refuse it several irreversible steps later. Refusing it
# here costs nothing.
case "$FROM $TO" in
  "dev qa") ;;
  "qa main") ;;
  *)
    echo "error: only 'dev --to qa' or 'qa --to main' are allowed promotions (got '$FROM' -> '$TO')" >&2
    exit 1
    ;;
esac

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

# THE REQUIRED CONTEXTS ARE READ FROM THE BRANCH, BY NAME, EVERY TIME.
# Not a constant in this file, not a list in a doc: the thing branch protection will actually
# enforce on the push. If protection is renamed, tightened or loosened, this follows it in the same
# breath — and if it cannot be read at all, that is a refusal, never an empty loop that passes.
#
# The `while read` append below is deliberate and must stay: `mapfile`/`readarray` is bash 4, and
# macOS ships bash 3.2.57 as /bin/bash, which `/usr/bin/env bash` finds first on a stock Mac. On 3.2
# `mapfile` is "command not found", `set -e` aborts, and the promote dies before it has said
# anything about the SHA -- and an UNSET array under `set -u` would make the "no required checks"
# refusal below unprintable too. `while read` into an append and `< <(...)` are both bash 3.2.
if ! REQUIRED_CHECKS_JSON="$(gh api "repos/${REPO}/branches/${TO}/protection/required_status_checks" --jq '.contexts' 2>/dev/null)"; then
  echo "error: cannot read branch protection for '$TO' on $REPO; refusing to promote blind" >&2
  exit 1
fi

REQUIRED_CHECKS=()
while IFS= read -r c; do
  [[ -n "$c" ]] && REQUIRED_CHECKS+=("$c")
done < <(echo "$REQUIRED_CHECKS_JSON" | jq -r '.[]? // empty')

if [[ "${#REQUIRED_CHECKS[@]}" -eq 0 ]]; then
  echo "error: no required status checks found for '$TO'; refusing to promote blind" >&2
  exit 1
fi

CHECK_RUNS_JSON="$(gh api "repos/${REPO}/commits/${SHA}/check-runs" --paginate --jq '.check_runs')"

echo "SHA: $SHA"
echo "Required checks for '$TO' (read from branch protection, not from this script):"

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
  echo "       a 'missing' context is a refusal too: a required name that never reported is the" >&2
  echo "       exact gap branch protection exists to close." >&2
  exit 1
fi

echo "All required checks green on $SHA."

if [[ "$DRY_RUN" -eq 1 ]]; then
  echo "[dry-run] would run: git push origin ${SHA}:refs/heads/${TO}"
  exit 0
fi

git push origin "${SHA}:refs/heads/${TO}"
