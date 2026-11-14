#!/usr/bin/env bash
# promote.sh -- move a promotion branch forward by fast-forward, safely and repeatably.
#
#   scripts/promote.sh dev qa      # promote dev to qa
#   scripts/promote.sh qa main     # promote qa to main (this is what cuts the release)
#   scripts/promote.sh --selftest  # prove this script's RED and GREEN paths before trusting it
#
# WHAT IT REFUSES ON (each refusal is loud, names what it checked, and touches NOTHING):
#   (a) the required UMBRELLA check-runs are not green on the exact SHA being promoted. Required by
#       destination: qa needs `ci umbrella`; main needs `ci umbrella` AND `qa-gate umbrella` (which
#       only a qa-promoted SHA can carry). A MISSING umbrella is unverified, and unverified is red.
#       Queried via `gh api repos/{owner}/{repo}/commits/<sha>/check-runs`, not a branch name.
#   (b) the fast-forward is not possible (history rewrite or genuine divergence).
#   (c) qa->main only: the squash rule has not been applied — more than
#       PROMOTE_MAX_NONMERGE_COMMITS (default 20) NON-MERGE commits since the last tag boundary.
#
# TAGGING POLICY. This script NEVER pushes a git tag, and there is no longer a tag-on-main.yml
# (deleted): nothing is tagged automatically on push. A version tag is minted in exactly ONE place
# — release.yml's `promote-release` job — and only at the END of the staged release graph
# (draft -> build -> per-target contract -> set-equality -> staged consumer verify -> promote
# image by digest -> flip draft), after a final re-check that the SHA is still green. So a tag can
# appear only AFTER main is green and only as the OUTPUT of a verified release, never before it.
# Making this script tag would re-introduce publish-before-verify; it deliberately does not.
#
# WHY THIS IS A SCRIPT AND NOT THREE COMMANDS TYPED AT RELEASE TIME.
#
# During the 1.5.3 promotion, `git push origin qa:main` was REJECTED as non-fast-forward while
# `main` was verifiably a strict ancestor of `qa` with ZERO divergent commits. A retry seconds later
# succeeded with nothing having changed in between. So the guard in use at the time --
# `git merge-base --is-ancestor origin/main origin/qa` followed immediately by the push -- is not
# sufficient on its own, for a reason worth writing down:
#
#   `origin/main` is a LOCAL remote-tracking ref. It is a photograph of the remote taken at fetch
#   time. `git push` does not consult it; the SERVER re-checks fast-forwardness against whatever
#   that particular backend replica currently believes. Between the fetch and the push those two can
#   disagree, and the push loses. Nothing local is wrong, nothing has diverged, and the identical
#   command works moments later. Checking harder locally cannot fix this, because the check and the
#   thing being checked are on different machines.
#
# So this script does four things the ad-hoc commands did not:
#   1. Verifies STRICT ANCESTRY, and refuses loudly (never force-pushes) when it genuinely fails.
#   2. Verifies CI is green ON THE EXACT SHA being promoted, not on the branch NAME. A branch name
#      resolves to whatever it points at now; a release is cut from a commit. Those differ precisely
#      when someone pushed while you were reading the checks.
#   3. RETRIES a non-fast-forward rejection, re-fetching and RE-VERIFYING ancestry each time, so a
#      transient replica disagreement is absorbed while a real divergence still stops the promotion.
#   4. VERIFIES THE REMOTE ACTUALLY MOVED afterwards, by reading it back with `git ls-remote`,
#      rather than trusting the push's exit code. A zero exit is a claim; the remote ref is the fact.
#
# Idempotent: promoting a branch that is already at the target SHA is a no-op that exits 0.
set -euo pipefail

REMOTE="${PROMOTE_REMOTE:-origin}"
PUSH_ATTEMPTS="${PROMOTE_PUSH_ATTEMPTS:-5}"
VERIFY_ATTEMPTS="${PROMOTE_VERIFY_ATTEMPTS:-5}"
BACKOFF="${PROMOTE_BACKOFF:-3}"
CHECK_CI=1
DRY_RUN=0

die() { echo "promote: $*" >&2; exit 1; }
note() { echo "promote: $*"; }

# --- umbrella check-run verdict for an exact SHA ---------------------------------------------
# Branch names are not commits. Asking "is CI green on qa" answers a question about a name; asking
# "is the `ci umbrella` check green on 8f80889" answers the question a release actually depends on.
#
# We gate on the UMBRELLA check-runs, not on "every workflow run is green". The umbrella jobs
# (ci.yml's `ci umbrella`, qa-gate.yml's `qa-gate umbrella`) already assert internally that every
# tier they cover ran and passed — a skipped or vacuous tier turns the umbrella red. So requiring
# the umbrella by NAME on the exact SHA is the same contract branch protection enforces, verified
# from the operator's side before the push. A missing umbrella (the workflow never ran on this
# commit) is UNVERIFIED, and unverified is red — never promoted.
#
# `check_runs_verdict` is a PURE function: it reads the check-runs as NDJSON on stdin and the
# required context names as arguments, and renders the verdict. It carries no network, so the
# selftest drives it with canned data to prove RED and GREEN before any real promotion trusts it.
check_runs_verdict() {
  # Capture the NDJSON from stdin to a temp file FIRST: the python program is delivered on stdin
  # via the heredoc below, so the data cannot also come from stdin. It is read from argv instead.
  local tmp status
  tmp="$(mktemp)"
  cat > "$tmp"
  REQUIRED_NL="$(printf '%s\n' "$@")" python3 - "$tmp" <<'PY'
import json, os, sys
required = [c for c in os.environ.get("REQUIRED_NL", "").splitlines() if c]
runs = []
with open(sys.argv[1]) as fh:
    for line in fh:
        line = line.strip()
        if line:
            runs.append(json.loads(line))
fails = 0
for ctx in required:
    matching = [r for r in runs if r.get("name") == ctx]
    if not matching:
        print("promote:   %-20s MISSING (this umbrella never ran on the SHA — UNVERIFIED)" % ctx,
              file=sys.stderr)
        fails += 1
        continue
    pending = [r for r in matching if r.get("status") != "completed"]
    if pending:
        print("promote:   %-20s STILL RUNNING (%s) — wait, do not promote on a guess"
              % (ctx, pending[0].get("status")), file=sys.stderr)
        fails += 1
        continue
    # A re-run mints a new check-run with the same name; branch protection honours the newest.
    latest = max(matching, key=lambda r: ((r.get("started_at") or ""), (r.get("id") or 0)))
    concl = latest.get("conclusion")
    if concl == "success":
        print("promote:   %-20s success" % ctx)
    else:
        print("promote:   %-20s RED (%s)" % (ctx, concl), file=sys.stderr)
        fails += 1
if fails:
    print("promote: %d required umbrella check(s) are not green on this SHA." % fails, file=sys.stderr)
    sys.exit(1)
print("promote: every required umbrella check is green on this SHA.")
PY
  status=$?
  rm -f "$tmp"
  return "$status"
}

# The required umbrella contexts for a promotion, keyed by DESTINATION. These are exactly the
# branch-protection contexts in the audit: qa requires `ci umbrella`; main requires it plus
# `qa-gate umbrella` (which only a qa-promoted SHA can carry). Keeping this here means the script
# and the protection config agree by construction.
required_umbrellas_for_dest() {
  case "$1" in
    qa)   printf '%s\n' "ci umbrella" ;;
    main) printf '%s\n' "ci umbrella" "qa-gate umbrella" ;;
    *)    printf '%s\n' "ci umbrella" ;;
  esac
}

umbrella_is_green_for_sha() {
  local sha="$1"; shift
  local ndjson
  command -v gh >/dev/null 2>&1 || { echo "promote: gh not installed" >&2; return 2; }
  # --paginate + --jq emits one check-run object per line (NDJSON) across every page, so a commit
  # with >100 check-runs is handled without hand-rolling pagination.
  ndjson="$(gh api --paginate "repos/{owner}/{repo}/commits/${sha}/check-runs" \
            --jq '.check_runs[]' 2>/dev/null)" || {
    echo "promote: could not read check-runs for ${sha} from the API. Unknown is not green." >&2
    return 2
  }
  printf '%s\n' "$ndjson" | check_runs_verdict "$@"
}

# --- squash rule (qa -> main only) -----------------------------------------------------------
# The qa->main hop cuts a release, and a release commit on main must be a SQUASHED release
# changeset (CONTRIBUTING.md: "squash noisy WIP commits before opening the PR"), not the raw WIP
# history of a whole development cycle fast-forwarded wholesale. We detect a violation the only way
# that survives the merge-commit flow: count NON-MERGE commits since the last tag boundary. Merge
# commits are excluded on purpose — the feature-into-dev merges are expected; it is the unsquashed
# WIP leaf commits that the rule is about. Above the threshold, refuse with remediation.
check_squash_rule() {
  local src_sha="$1" max="${PROMOTE_MAX_NONMERGE_COMMITS:-20}" base n
  if base="$(git describe --tags --abbrev=0 "$src_sha" 2>/dev/null)"; then
    n="$(git rev-list --no-merges --count "${base}..${src_sha}")"
    note "squash rule: last tag boundary is ${base}; ${n} non-merge commit(s) since (threshold ${max})."
  else
    base=""
    n="$(git rev-list --no-merges --count "$src_sha")"
    note "squash rule: no tag boundary before ${src_sha}; ${n} non-merge commit(s) total (threshold ${max})."
  fi
  if [ "$n" -gt "$max" ]; then
    echo "promote: REFUSING qa->main. ${n} non-merge commits since ${base:-<root>} exceed the squash" >&2
    echo "promote: threshold of ${max}. A qa->main promotion must carry a SQUASHED release changeset," >&2
    echo "promote: not a whole cycle of unsquashed WIP. Squash the release changeset on dev, re-promote" >&2
    echo "promote: dev->qa, then re-run. If this count is genuinely legitimate, override deliberately" >&2
    echo "promote: with PROMOTE_MAX_NONMERGE_COMMITS=<n>." >&2
    return 1
  fi
  note "squash rule OK."
}

# --- ancestry --------------------------------------------------------------------------------
assert_strict_ancestor() {
  local dst_sha="$1" src_sha="$2" dst="$3" src="$4"
  if git merge-base --is-ancestor "$dst_sha" "$src_sha"; then
    return 0
  fi
  echo "promote: REFUSING. ${dst} (${dst_sha}) is NOT an ancestor of ${src} (${src_sha})." >&2
  echo "promote: these branches have genuinely diverged, so a fast-forward is not possible and" >&2
  echo "promote: this script will not force anything. Commits on ${dst} that are not on ${src}:" >&2
  git --no-pager log --oneline "${src_sha}..${dst_sha}" | sed 's/^/promote:   /' >&2 || true
  echo "promote: resolve the divergence (merge or rebase ${dst} into ${src}), then re-run." >&2
  return 1
}

remote_sha() { git ls-remote "$REMOTE" "refs/heads/$1" | awk '{print $1}'; }

promote() {
  local src="$1" dst="$2" i src_sha dst_sha pushed=0

  note "fetching ${REMOTE}"
  git fetch "$REMOTE" --prune --quiet
  # Best-effort tag refresh so the squash-rule boundary is current. A rejected/clobbering tag must
  # NOT abort a promotion — the operator's local tags may legitimately differ from origin's, and the
  # squash check falls back to whatever tags are already local.
  git fetch "$REMOTE" --tags --quiet 2>/dev/null \
    || note "note: tag refresh skipped (local tags differ from ${REMOTE}); squash rule uses local tags."

  src_sha="$(remote_sha "$src")"
  [ -n "$src_sha" ] || die "${REMOTE}/${src} does not exist"
  dst_sha="$(remote_sha "$dst")"
  [ -n "$dst_sha" ] || die "${REMOTE}/${dst} does not exist"

  note "${src} = ${src_sha}"
  note "${dst} = ${dst_sha}"

  if [ "$src_sha" = "$dst_sha" ]; then
    note "${dst} is already at ${src_sha}; nothing to promote (idempotent no-op)."
    return 0
  fi

  assert_strict_ancestor "$dst_sha" "$src_sha" "$dst" "$src" || return 1
  note "ancestry OK: ${dst} is a strict ancestor of ${src}, so this is a fast-forward."
  note "commits this promotion moves onto ${dst}:"
  git --no-pager log --oneline "${dst_sha}..${src_sha}" | sed 's/^/promote:   /'

  if [ "$CHECK_CI" = 1 ]; then
    # The squash rule is a qa->main concern only, and it is checked BEFORE the umbrella query so a
    # violation is reported even when the umbrellas are green.
    if [ "$dst" = "main" ]; then
      check_squash_rule "$src_sha" || die "squash rule violated for qa->main; refusing to promote."
    fi
    local required=()
    while IFS= read -r ctx; do [ -n "$ctx" ] && required+=("$ctx"); done < <(required_umbrellas_for_dest "$dst")
    note "verifying umbrella checks on the exact SHA being promoted (${src_sha}):"
    note "  required for ${dst}: ${required[*]}"
    umbrella_is_green_for_sha "$src_sha" "${required[@]}" \
      || die "required umbrella checks are not green on ${src_sha}; refusing to promote."
  else
    echo "promote: WARNING: --no-ci-check given. Promoting ${src_sha} to ${dst} WITHOUT" >&2
    echo "promote: verifying any umbrella check or the squash rule. Use this only when you" >&2
    echo "promote: already know why." >&2
  fi

  if [ "${DRY_RUN:-0}" = 1 ]; then
    note "DRY RUN: every check passed and the fast-forward is legal; would push ${src_sha} -> ${REMOTE}/${dst}."
    note "DRY RUN: nothing was pushed."
    return 0
  fi

  for (( i = 1; i <= PUSH_ATTEMPTS; i++ )); do
    note "push attempt ${i}/${PUSH_ATTEMPTS}: ${src_sha} -> ${REMOTE}/${dst}"
    if git push "$REMOTE" "${src_sha}:refs/heads/${dst}"; then
      pushed=1
      break
    fi
    if [ "$i" -eq "$PUSH_ATTEMPTS" ]; then break; fi
    # A rejection is only ever retried after RE-ESTABLISHING that the fast-forward is still legal.
    # If someone really did push to the destination in the meantime, ancestry now fails and we
    # refuse instead of hammering. This is the difference between absorbing a replica disagreement
    # and papering over a divergence.
    note "rejected; re-fetching and re-verifying before retrying in ${BACKOFF}s"
    sleep "$BACKOFF"
    git fetch "$REMOTE" --prune --quiet
    dst_sha="$(remote_sha "$dst")"
    if [ "$dst_sha" = "$src_sha" ]; then
      note "${dst} is now already at ${src_sha}: a concurrent promoter won the race. Nothing to do."
      pushed=1
      break
    fi
    assert_strict_ancestor "$dst_sha" "$src_sha" "$dst" "$src" || return 1
  done
  [ "$pushed" = 1 ] || die "push to ${dst} still rejected after ${PUSH_ATTEMPTS} attempts."

  # THE PUSH'S EXIT CODE IS A CLAIM. The remote ref is the fact. Read it back.
  for (( i = 1; i <= VERIFY_ATTEMPTS; i++ )); do
    dst_sha="$(remote_sha "$dst")"
    if [ "$dst_sha" = "$src_sha" ]; then
      note "VERIFIED: ${REMOTE}/${dst} now reads ${dst_sha}."
      note "promoted ${src} -> ${dst}."
      return 0
    fi
    note "post-push read-back ${i}/${VERIFY_ATTEMPTS}: ${dst} reads ${dst_sha:-<none>}, want ${src_sha}"
    [ "$i" -lt "$VERIFY_ATTEMPTS" ] && sleep "$BACKOFF"
  done
  echo "promote: PUSH REPORTED SUCCESS BUT ${REMOTE}/${dst} DID NOT MOVE." >&2
  echo "promote: wanted ${src_sha}, remote still reads ${dst_sha:-<none>}. Do NOT assume the" >&2
  echo "promote: promotion happened: check the remote by hand before doing anything else." >&2
  return 1
}

# --- selftest --------------------------------------------------------------------------------
# A promotion gate nobody has watched REFUSE is a promotion gate nobody should trust with a release.
# This builds throwaway local repos and drives every path: the fast-forward, the idempotent no-op,
# the divergence refusal, the transient-rejection retry (the exact 1.5.3 symptom), and the
# read-back verification that catches a push which did not land.
selftest() {
  local root rc=0
  root="$(mktemp -d)"
  trap 'rm -rf "$root"' RETURN
  export GIT_AUTHOR_NAME=selftest GIT_AUTHOR_EMAIL=selftest@example.com
  export GIT_COMMITTER_NAME=selftest GIT_COMMITTER_EMAIL=selftest@example.com

  fresh() {
    rm -rf "$root/bare" "$root/work"
    git init --quiet --bare "$root/bare"
    git init --quiet "$root/work"
    (
      cd "$root/work"
      git remote add origin "$root/bare"
      echo a > f; git add f; git commit --quiet -m base
      git branch -M dev
      git push --quiet origin dev:refs/heads/dev dev:refs/heads/qa
      echo b > f; git commit --quiet -am second
      git push --quiet origin dev:refs/heads/dev
    )
  }

  check() { # check <label> <expect-pass|expect-fail> <command...>
    local label="$1" expect="$2"; shift 2
    local out status
    out="$("$@" 2>&1)" && status=0 || status=$?
    if { [ "$expect" = expect-pass ] && [ "$status" -eq 0 ]; } ||
       { [ "$expect" = expect-fail ] && [ "$status" -ne 0 ]; }; then
      echo "  PASS  ${label}"
    else
      echo "  FAIL  ${label} (expected ${expect}, exit ${status})"
      echo "$out" | sed 's/^/        /'
      rc=1
    fi
  }

  local SELF; SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"
  run_promote() { ( cd "$root/work" && PROMOTE_BACKOFF=0 "$SELF" --no-ci-check "$@" ); }

  echo "== promote.sh selftest =="

  echo "-- a legal fast-forward is performed and read back --"
  fresh
  check "fast-forward promotes" expect-pass run_promote dev qa
  local qa dev
  qa="$(git --git-dir="$root/bare" rev-parse qa)"
  dev="$(git --git-dir="$root/bare" rev-parse dev)"
  if [ "$qa" = "$dev" ]; then echo "  PASS  remote qa actually moved to dev"; else
    echo "  FAIL  remote qa did not move ($qa != $dev)"; rc=1; fi

  echo "-- re-running is an idempotent no-op --"
  check "second run no-ops" expect-pass run_promote dev qa

  echo "-- genuine divergence is REFUSED, and the remote is left untouched --"
  fresh
  ( cd "$root/work"
    git checkout --quiet -B side origin/qa
    echo divergent > g; git add g; git commit --quiet -m "on qa only"
    git push --quiet origin side:refs/heads/qa ) >/dev/null 2>&1
  local before; before="$(git --git-dir="$root/bare" rev-parse qa)"
  check "divergence refused" expect-fail run_promote dev qa
  if [ "$(git --git-dir="$root/bare" rev-parse qa)" = "$before" ]; then
    echo "  PASS  remote qa untouched by the refusal"; else
    echo "  FAIL  remote qa was modified despite the refusal"; rc=1; fi

  echo "-- a TRANSIENT non-fast-forward rejection is retried and succeeds (the 1.5.3 symptom) --"
  fresh
  cat > "$root/bare/hooks/update" <<EOF
#!/bin/sh
n=\$(cat "$root/attempts" 2>/dev/null || echo 0); n=\$((n+1)); echo \$n > "$root/attempts"
[ "\$n" -lt 3 ] && { echo "simulated transient non-fast-forward" >&2; exit 1; }
exit 0
EOF
  chmod +x "$root/bare/hooks/update"; rm -f "$root/attempts"
  check "transient rejection retried to success" expect-pass run_promote dev qa
  if [ "$(git --git-dir="$root/bare" rev-parse qa)" = "$(git --git-dir="$root/bare" rev-parse dev)" ]; then
    echo "  PASS  remote qa reached dev after the retries"; else
    echo "  FAIL  remote qa did not reach dev"; rc=1; fi

  echo "-- a PERMANENT rejection is not retried forever, and fails loudly --"
  fresh
  printf '#!/bin/sh\necho "simulated permanent rejection" >&2\nexit 1\n' > "$root/bare/hooks/update"
  chmod +x "$root/bare/hooks/update"
  check "permanent rejection fails" expect-fail env PROMOTE_PUSH_ATTEMPTS=2 bash -c \
    "cd '$root/work' && PROMOTE_BACKOFF=0 '$SELF' --no-ci-check dev qa"

  echo "-- a push that reports success but does NOT move the remote is CAUGHT by read-back --"
  fresh
  # The client sees a clean push (exit 0, "9d350f9..52e29a3  -> qa"), and then the ref is put back.
  # That is the shape the read-back exists for: trusting the push's exit code alone would call this
  # a successful promotion and the release would be cut from a branch that never moved.
  cat > "$root/bare/hooks/post-receive" <<'EOF'
#!/bin/sh
while read -r old new ref; do git update-ref "$ref" "$old"; done
exit 0
EOF
  chmod +x "$root/bare/hooks/post-receive"
  check "silent no-op push is caught" expect-fail env PROMOTE_VERIFY_ATTEMPTS=2 bash -c \
    "cd '$root/work' && PROMOTE_BACKOFF=0 '$SELF' --no-ci-check dev qa"

  # --- umbrella check-run verdict (the pure gate that decides green-on-SHA), driven offline -----
  # A gate nobody has watched REFUSE is a gate nobody should trust. These feed canned check-runs
  # NDJSON to the SAME code path the real promotion uses, and prove every verdict.
  echo "-- umbrella verdict: all required umbrellas green is GREEN --"
  # shellcheck disable=SC2329  # invoked indirectly through check "$@", below
  verdict() { printf '%s\n' "$1" | env -u REQUIRED_NL "$SELF" --check-runs-verdict "${@:2}"; }
  ci_ok='{"name":"ci umbrella","status":"completed","conclusion":"success","id":2}'
  qg_ok='{"name":"qa-gate umbrella","status":"completed","conclusion":"success","id":3}'
  ci_bad='{"name":"ci umbrella","status":"completed","conclusion":"failure","id":4}'
  ci_run='{"name":"ci umbrella","status":"in_progress","conclusion":null,"id":5}'
  ci_old='{"name":"ci umbrella","status":"completed","conclusion":"failure","id":1}'
  check "all required umbrellas green passes" expect-pass \
    verdict "$ci_ok
$qg_ok" "ci umbrella" "qa-gate umbrella"
  echo "-- umbrella verdict: a MISSING required umbrella is RED (unverified) --"
  check "missing umbrella refused" expect-fail \
    verdict "$ci_ok" "ci umbrella" "qa-gate umbrella"
  echo "-- umbrella verdict: a FAILED umbrella is RED --"
  check "failed umbrella refused" expect-fail \
    verdict "$ci_bad" "ci umbrella"
  echo "-- umbrella verdict: a STILL-RUNNING umbrella is RED (do not promote on a guess) --"
  check "running umbrella refused" expect-fail \
    verdict "$ci_run" "ci umbrella"
  echo "-- umbrella verdict: the NEWEST re-run wins (green id>failed id) --"
  check "newest green re-run passes" expect-pass \
    verdict "$ci_old
$ci_ok" "ci umbrella"

  # --- squash rule (qa->main), driven against a real throwaway repo -----------------------------
  echo "-- squash rule: at/under the threshold PASSES, over it is REFUSED --"
  sq_root="$(mktemp -d)"
  (
    cd "$sq_root"
    git init --quiet; git config user.email s@e.x; git config user.name s
    echo a > f; git add f; git commit --quiet -m base
    git tag v0.0.0
    for i in 1 2 3; do echo "$i" > f; git commit --quiet -am "wip $i"; done
  )
  check "3 non-merge commits under threshold 5 passes" expect-pass bash -c \
    "cd '$sq_root' && PROMOTE_MAX_NONMERGE_COMMITS=5 '$SELF' --squash-check \$(git rev-parse HEAD)"
  check "3 non-merge commits over threshold 2 refused" expect-fail bash -c \
    "cd '$sq_root' && PROMOTE_MAX_NONMERGE_COMMITS=2 '$SELF' --squash-check \$(git rev-parse HEAD)"
  rm -rf "$sq_root"

  echo
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST PASSED: promotes, no-ops, refuses divergence, absorbs a transient rejection,"
    echo "gives up on a permanent one, catches a push that did not land, holds the umbrella verdict"
    echo "to green-on-SHA, and enforces the qa->main squash rule."
  else
    echo "SELFTEST FAILED"
  fi
  return "$rc"
}

main() {
  local args=()
  while [ "$#" -gt 0 ]; do
    case "$1" in
      --selftest) selftest; exit $? ;;
      # Internal: render the umbrella verdict from NDJSON check-runs on stdin + contexts as args.
      # Exposed only so the selftest can drive the pure verdict logic offline. Not for operators.
      --check-runs-verdict) shift; check_runs_verdict "$@"; exit $? ;;
      # Internal: run the squash rule against a SHA. Exposed only for the selftest.
      --squash-check) shift; check_squash_rule "$1"; exit $? ;;
      # Run every check and prove the fast-forward is legal, but stop BEFORE pushing anything.
      --dry-run) DRY_RUN=1; shift ;;
      --no-ci-check) CHECK_CI=0; shift ;;
      -h|--help) sed -n '2,30p' "${BASH_SOURCE[0]}"; exit 0 ;;
      -*) die "unknown option $1" ;;
      *) args+=("$1"); shift ;;
    esac
  done
  [ "${#args[@]}" -eq 2 ] || die "usage: $0 <source-branch> <dest-branch> | $0 --selftest"
  promote "${args[0]}" "${args[1]}"
}

main "$@"
