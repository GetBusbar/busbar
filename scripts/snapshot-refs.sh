#!/usr/bin/env bash
# SNAPSHOT BEFORE YOU DELETE. Run this before ANY branch deletion, rename, gc,
# prune, reflog expire, or force-push — in either repo.
#
# WHY A BUNDLE AND NOT A PUSH: a bundle is a single file holding every object
# reachable from every ref, restorable with `git clone <bundle>` on a machine
# with no network and no remote. It survives the remote being wrong, the remote
# being gone, and the operator being asleep.
#
# WHAT IT DOES NOT CAPTURE: uncommitted working-tree changes. Those are NOT in
# any ref, so no bundle holds them. For those use `git stash create` (which
# mints a commit object WITHOUT touching the worktree or the stash stack) and
# tag the result — see SNAPSHOT_UNCOMMITTED below.
set -uo pipefail

OUT="${SNAPSHOT_DIR:-$HOME/Downloads}"
STAMP="$(date +%Y-%m-%d-%H%M)"
REPOS=(
  "/Users/matthew/Developer/GetBusbar/busbar:busbar"
  "/Users/matthew/Developer/GetBusbar/busbar-release:busbar-release"
)

# Refuse to write a snapshot we cannot finish. A truncated bundle that LOOKS
# present is worse than no bundle — it is the "a gap and a success must never
# be the same output" rule applied to our own safety net.
FREE_MB=$(df -m "$OUT" | awk 'NR==2 {print $4}')
if [ "$FREE_MB" -lt 300 ]; then
  echo "REFUSING: only ${FREE_MB}MB free at $OUT; a bundle needs headroom." >&2
  echo "Free space first. A half-written bundle is not a backup." >&2
  exit 1
fi

rc=0
for entry in "${REPOS[@]}"; do
  repo="${entry%%:*}"; name="${entry##*:}"
  [ -d "$repo/.git" ] || { echo "SKIP $name (not a git repo at $repo)"; continue; }

  bundle="$OUT/$name-all-refs-$STAMP.bundle"
  git -C "$repo" bundle create "$bundle" --all >/dev/null 2>&1

  # VERIFY, ALWAYS. An unverified bundle is a guess.
  if git -C "$repo" bundle verify "$bundle" >/dev/null 2>&1; then
    git -C "$repo" for-each-ref \
      --format='%(refname) %(objectname) %(committerdate:iso)' \
      > "$OUT/$name-refs-$STAMP.txt"
    n=$(wc -l < "$OUT/$name-refs-$STAMP.txt" | tr -d ' ')
    sz=$(ls -la "$bundle" | awk '{print $5}')
    echo "OK   $name  $n refs  $sz bytes  -> $(basename "$bundle")"
  else
    echo "FAILED $name — bundle did not verify; treat as NO BACKUP" >&2
    rc=1
  fi

  # SNAPSHOT_UNCOMMITTED: `stash create` writes a commit object and returns its
  # SHA without modifying the working tree, the index, or the stash stack. Tag
  # it so gc cannot reap it. This is how uncommitted work survives a checkout.
  if [ -n "$(git -C "$repo" status --porcelain 2>/dev/null)" ]; then
    snap=$(git -C "$repo" stash create "snapshot $STAMP" 2>/dev/null)
    if [ -n "$snap" ]; then
      git -C "$repo" tag -f "snapshot/uncommitted-$STAMP" "$snap" >/dev/null 2>&1
      echo "     + uncommitted work preserved as tag snapshot/uncommitted-$STAMP ($snap)"
    fi
  fi
done

echo
echo "RESTORE:  git clone $OUT/<name>-all-refs-<stamp>.bundle <dir>"
echo "ONE REF:  git fetch $OUT/<name>-all-refs-<stamp>.bundle 'refs/*:refs/restored/*'"
exit $rc
