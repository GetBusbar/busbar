#!/usr/bin/env bash
# promote.sh -- move a promotion branch forward by fast-forward, safely and repeatably.
#
#   scripts/promote.sh dev qa      # promote dev to qa
#   scripts/promote.sh qa main     # promote qa to main (this is what cuts the release)
#   scripts/promote.sh --selftest  # prove this script's RED and GREEN paths before trusting it
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

die() { echo "promote: $*" >&2; exit 1; }
note() { echo "promote: $*"; }

# --- CI verdict for an exact SHA -------------------------------------------------------------
# Branch names are not commits. Asking "is CI green on qa" answers a question about a name; asking
# "is CI green on 8f80889" answers the question a release actually depends on.
ci_is_green_for_sha() {
  local sha="$1" json fails
  command -v gh >/dev/null 2>&1 || { echo "promote: gh not installed" >&2; return 2; }
  json="$(gh run list --commit "$sha" --json workflowName,status,conclusion --limit 100 2>/dev/null)" || return 2
  python3 - "$sha" <<'PY' <<<"$json"
import json, sys
runs = json.load(sys.stdin)
sha = sys.argv[1]
if not runs:
    print("promote: NO workflow runs at all for %s." % sha, file=sys.stderr)
    print("promote: an unverified commit must not be promoted. If CI genuinely did not run for this",
          file=sys.stderr)
    print("promote: commit, push it to a branch and let CI run, or re-run CI on it explicitly.",
          file=sys.stderr)
    sys.exit(1)
bad = [r for r in runs if r["status"] != "completed"
       or r["conclusion"] not in ("success", "skipped", "neutral")]
running = [r for r in bad if r["status"] != "completed"]
failed = [r for r in bad if r["status"] == "completed"]
for r in sorted(runs, key=lambda r: r["workflowName"]):
    print("promote:   %-24s %s/%s" % (r["workflowName"], r["status"], r["conclusion"]))
if running:
    print("promote: STILL RUNNING on %s: %s" % (sha, ", ".join(r["workflowName"] for r in running)),
          file=sys.stderr)
    print("promote: wait for it. Promoting on a run that has not finished is promoting on a guess.",
          file=sys.stderr)
    sys.exit(1)
if failed:
    print("promote: FAILED on %s: %s" % (sha, ", ".join(r["workflowName"] for r in failed)),
          file=sys.stderr)
    sys.exit(1)
print("promote: every workflow run for %s is green (%d run(s))." % (sha, len(runs)))
PY
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
    note "checking CI on the exact SHA being promoted (${src_sha})"
    ci_is_green_for_sha "$src_sha" || die "CI is not green on ${src_sha}; refusing to promote."
  else
    echo "promote: WARNING: --no-ci-check given. Promoting ${src_sha} to ${dst} WITHOUT" >&2
    echo "promote: verifying any workflow result. Use this only when you already know why." >&2
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

  echo
  if [ "$rc" -eq 0 ]; then
    echo "SELFTEST PASSED: promotes, no-ops, refuses divergence, absorbs a transient rejection,"
    echo "gives up on a permanent one, and catches a push that did not actually land."
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
