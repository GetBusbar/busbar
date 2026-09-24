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
#
# WHICH REPOS. The checkout this script lives in, and its `busbar-release` sibling when one exists
# beside it. SNAPSHOT_REPOS="<path>:<name> ..." overrides both. No developer's home directory is
# written into this file (item 527): a hard-coded path snapshots whatever happens to sit there
# rather than the checkout being worked on, and it fails the public-hygiene gate over scripts/.
#
#   scripts/snapshot-refs.sh --selftest   # scratch repos only; proves the tag failure is RED
set -uo pipefail

SELF_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HERE_REPO="$(cd "$SELF_DIR/.." && pwd)"

# default_repos -> "<path>:<name>" lines: this checkout, plus ../busbar-release if it is a repo.
default_repos() {
  printf '%s:%s\n' "$HERE_REPO" "$(basename "$HERE_REPO")"
  local rel; rel="$(cd "$HERE_REPO/.." && pwd)/busbar-release"
  [ -d "$rel/.git" ] && printf '%s:%s\n' "$rel" "busbar-release"
  return 0
}

# preserve_uncommitted <repo> <stamp> — SNAPSHOT_UNCOMMITTED: `stash create` writes a commit object
# and returns its SHA without modifying the working tree, the index, or the stash stack. The TAG is
# the only thing keeping that commit alive against gc, so the tag's status IS the backup's status
# (item 528): it is checked, and the tag is read back and compared to the stash commit, before the
# success line is printed. A tag that could not be written (e.g. an existing `snapshot` tag makes
# refs/tags/snapshot/... a file/directory conflict) is FAILED, never "preserved". Returns 0/1.
preserve_uncommitted() {
  local repo="$1" stamp="$2" snap tag err
  [ -n "$(git -C "$repo" status --porcelain 2>/dev/null)" ] || return 0
  tag="snapshot/uncommitted-$stamp"
  snap=$(git -C "$repo" stash create "snapshot $stamp" 2>/dev/null)
  if [ -z "$snap" ]; then
    echo "FAILED $(basename "$repo") — uncommitted changes present but \`git stash create\` made no commit; treat them as NOT BACKED UP" >&2
    return 1
  fi
  if ! err="$(git -C "$repo" tag -f "$tag" "$snap" 2>&1 >/dev/null)" \
     || [ "$(git -C "$repo" rev-parse -q --verify "refs/tags/$tag^{commit}" 2>/dev/null)" != "$snap" ]; then
    echo "FAILED $(basename "$repo") — could not anchor uncommitted work ($snap) as tag $tag: ${err:-tag does not resolve to it}" >&2
    echo "       the stash commit is UNREFERENCED and gc can reap it; treat uncommitted work as NOT BACKED UP" >&2
    return 1
  fi
  echo "     + uncommitted work preserved as tag $tag ($snap)"
  return 0
}

selftest() {
  local tmp fail=0 out r
  tmp="$(mktemp -d)"
  r="$tmp/repo"
  git init -q "$r"
  git -C "$r" config user.email selftest@example.invalid; git -C "$r" config user.name selftest
  git -C "$r" config core.hooksPath /dev/null
  echo a >"$r/a"; git -C "$r" add a; git -C "$r" commit -q --no-verify -m one
  echo b >>"$r/a"
  if out="$(preserve_uncommitted "$r" 2000-01-01-0000 2>&1)" \
     && [ "$(git -C "$r" rev-parse -q --verify refs/tags/snapshot/uncommitted-2000-01-01-0000)" != "" ]; then
    echo "ok: dirty tree -> anchored tag, reported preserved"
  else fail=1; echo "FAIL: clean anchor not made: $out"; fi
  r="$tmp/repo2"
  git init -q "$r"
  git -C "$r" config user.email selftest@example.invalid; git -C "$r" config user.name selftest
  git -C "$r" config core.hooksPath /dev/null
  echo a >"$r/a"; git -C "$r" add a; git -C "$r" commit -q --no-verify -m one
  echo b >>"$r/a"
  git -C "$r" tag snapshot HEAD   # makes refs/tags/snapshot/... impossible to create
  if out="$(preserve_uncommitted "$r" 2000-01-01-0001 2>&1)"; then
    fail=1; echo "FAIL: tag conflict reported success: $out"
  elif printf '%s' "$out" | grep -q 'preserved as tag'; then
    fail=1; echo "FAIL: tag conflict printed a 'preserved' line: $out"
  else echo "ok: an anchor tag that cannot be written is FAILED, not 'preserved'"; fi
  local first; first="$(default_repos)"; first="${first%%$'\n'*}"
  if [ "$first" = "$HERE_REPO:$(basename "$HERE_REPO")" ]; then
    echo "ok: the default subject is this checkout ($HERE_REPO)"
  else fail=1; echo "FAIL: default subject is not this checkout: $first"; fi
  rm -rf "$tmp"
  if [ "$fail" = 0 ]; then echo "snapshot-refs selftest: PASS"; else echo "snapshot-refs selftest: FAIL"; fi
  return "$fail"
}
if [ "${1:-}" = "--selftest" ]; then selftest; exit $?; fi

OUT="${SNAPSHOT_DIR:-$HOME/Downloads}"
STAMP="$(date +%Y-%m-%d-%H%M)"
REPOS=()
if [ -n "${SNAPSHOT_REPOS:-}" ]; then
  # shellcheck disable=SC2206  # whitespace-separated "<path>:<name>" words, by contract
  REPOS=($SNAPSHOT_REPOS)
else
  while IFS= read -r e; do [ -n "$e" ] && REPOS+=("$e"); done < <(default_repos)
fi

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

  # SNAPSHOT_UNCOMMITTED — see preserve_uncommitted.
  preserve_uncommitted "$repo" "$STAMP" || rc=1
done

echo
echo "RESTORE:  git clone $OUT/<name>-all-refs-<stamp>.bundle <dir>"
echo "ONE REF:  git fetch $OUT/<name>-all-refs-<stamp>.bundle 'refs/*:refs/restored/*'"
exit $rc
