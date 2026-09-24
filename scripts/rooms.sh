#!/usr/bin/env bash
# ROOMS — the denominator of the sweep, computed, not asserted.
#
# WHY THIS IS A SCRIPT AND NOT A PARAGRAPH
# Four independent passes at the prose definition of "a room" returned 20,771 / 14,141 /
# 14,604 / 14,645. None was careless; each walked real git plumbing. The spread is the
# proof: a denominator stated in English is re-derived differently by every reader, which
# is exactly the property a denominator may not have. The number this script prints could
# have come out differently only if the repository were different — never if the reader
# were different. That is the whole point of it existing.
#
# THE KEY IS (path, blob). ONE ROOM = ONE REVIEW.
# A room is a unit of work someone must look at and rule on. The same bytes at the same
# path on five refs is ONE thing to look at, not five. Keying on (ref,path) instead yields
# 3,163,581 rooms and — under one-row-one-file — 3.16 million files, which is not a sweep,
# it is a denial of service against the sweep. Keying on content also survives ref churn:
# branches get deleted, blobs do not.
#
# The cost of this key, stated plainly: it cannot answer "did branch X contribute anything
# unique?" That is a per-BRANCH question and it already has its own instrument —
# ~/Downloads/busbar-branch-harvest-ledger-*.tsv, 83 branches the owner already ruled on.
# Do not bend ROOMS to answer it; cross-check ROOMS against it instead (see --controls).
#
# B IS OVER COMMITS, NOT REF TIPS.
# Sampling only the 903 ref tips misses every (path,blob) that lived on an intermediate
# off-trunk commit and was changed again before the tip — measured at 9,496 rooms, 65%
# more than tip-sampled B itself. A branch that built something in commit 3 and refactored
# it in commit 7 has its commit-3 work erased from a tip-sampled denominator. That is the
# defect class this whole sweep exists to catch, reproduced in the instrument meant to
# catch it.
set -euo pipefail

die() { printf 'rooms: %s\n' "$*" >&2; exit 2; }

# THE SUBJECT REPOSITORY IS THE CHECKOUT THIS SCRIPT LIVES IN (item 525). The default used to be a
# hard-coded absolute path inside one developer's home directory, so running this from any other
# checkout silently computed the denominator of a DIFFERENT tree — the one number this script exists
# to make reader-independent. `REPO` still overrides; unset, it resolves from the script's own path,
# and a script that is not inside a git work tree with no REPO set is refused, never guessed.
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -z "${REPO:-}" ]; then
  REPO="$(git -C "$SCRIPT_DIR" rev-parse --show-toplevel 2>/dev/null)" \
    || die "REPO is unset and $SCRIPT_DIR is not inside a git work tree — set REPO to the subject repository"
fi

# ── SELF-TEST — the subject repository is the one the script sits in, not a fixed path. ─────────────
# Builds a throwaway repo holding a COPY of this script, runs that copy with REPO unset, and asserts
# the denominator it computed is the throwaway repo's (its trunk sha, its one file). Control: the same
# copy placed OUTSIDE any repo honours an explicit REPO, and with REPO unset it is refused.
if [ "${1:-}" = "--selftest" ]; then
  st="$(mktemp -d)"; trap 'rm -rf "$st"' EXIT
  fails=0
  mkdir -p "$st/repo/scripts" "$st/loose"
  cp "${BASH_SOURCE[0]}" "$st/repo/scripts/rooms.sh"
  cp "${BASH_SOURCE[0]}" "$st/loose/rooms.sh"
  printf 'room-selftest-marker\n' >"$st/repo/marker.txt"
  git -C "$st/repo" init -q
  git -C "$st/repo" -c user.name=selftest -c user.email=selftest@invalid add -A
  git -C "$st/repo" -c user.name=selftest -c user.email=selftest@invalid -c core.hooksPath=/dev/null commit -q --no-verify -m fixture
  sha="$(git -C "$st/repo" rev-parse HEAD)"

  if env -u REPO OUT="$st/out1" bash "$st/repo/scripts/rooms.sh" "$sha" >/dev/null 2>"$st/err1" \
     && grep -q "\"trunk\": \"$sha\"" "$st/out1/ROOMS.json" \
     && grep -q $'\tmarker.txt$' "$st/out1/A.tsv"; then
    echo "  PASS  REPO unset: the denominator is the checkout the script lives in"
  else
    echo "  FAIL  REPO unset: the script measured some other repository ($(tail -1 "$st/err1" 2>/dev/null))"
    fails=$((fails+1))
  fi
  if REPO="$st/repo" OUT="$st/out2" bash "$st/loose/rooms.sh" "$sha" >/dev/null 2>&1 \
     && grep -q $'\tmarker.txt$' "$st/out2/A.tsv"; then
    echo "  PASS  control: an explicit REPO is honoured from outside any checkout"
  else
    echo "  FAIL  control: an explicit REPO was not honoured"
    fails=$((fails+1))
  fi
  if (cd "$st/loose" && env -u REPO OUT="$st/out3" GIT_CEILING_DIRECTORIES="$st" bash "$st/loose/rooms.sh" "$sha") >/dev/null 2>&1; then
    echo "  FAIL  REPO unset outside any checkout was NOT refused — the subject was guessed"
    fails=$((fails+1))
  else
    echo "  PASS  REPO unset outside any checkout is refused, never guessed"
  fi
  if [ "$fails" -eq 0 ]; then echo "rooms self-test: ALL GREEN"; exit 0; fi
  echo "rooms self-test: $fails FAILED"; exit 1
fi

OUT="${OUT:-/tmp/rooms}"
TRUNK="${1:-}"
[ -n "$TRUNK" ] || die "usage: rooms.sh <trunk-sha> — the pin is an argument, never a default"

# Resolve the pin to a full sha and FAIL if it is not a commit. A pin that silently
# resolves to something else is how `git ls-files <rev>` returned 0 for a week.
TRUNK_FULL=$(git -C "$REPO" rev-parse --verify "${TRUNK}^{commit}") || die "not a commit: $TRUNK"
mkdir -p "$OUT"

# ── pair extraction ────────────────────────────────────────────────────────────────────
# `git log --raw` emits ":<srcmode> <dstmode> <srcsha> <dstsha> <status>\t<path>". We take
# the DESTINATION blob: the content as it existed after that commit. --no-renames keeps a
# rename as delete+add so both paths are rooms (a file moved to a new home is a new room at
# the new path). -m expands merges so a merge's own resolution is not invisible. --root
# includes the initial commit, whose pairs are otherwise silently dropped.
#
# Filters: dstsha of all-zeros is a DELETION (no content to review — tracked separately by
# --deletions, never folded into ROOMS). Mode 160000 is a SUBMODULE gitlink, not a blob.
pairs_of() {
  git -C "$REPO" log --raw -m --no-renames --no-abbrev --root --format='' "$@" \
  | awk '$0 ~ /^:/ {
      dstmode = substr($2, 1, 6); dstsha = $4;
      if (dstsha ~ /^0+$/) next;          # deletion
      if (dstmode == "160000") next;      # submodule gitlink
      tab = index($0, "\t"); if (tab == 0) next;
      print dstsha "\t" substr($0, tab + 1);
    }'
}

echo "rooms: trunk pinned at $TRUNK_FULL" >&2

# TRUNK HISTORY — every (path,blob) that has EVER been on trunk. Not the tip: a room the
# trunk already absorbed and then edited is still swept, and must not reappear as new work.
echo "rooms: walking trunk history ($(git -C "$REPO" rev-list --count "$TRUNK_FULL") commits)..." >&2
pairs_of "$TRUNK_FULL" | sort -u > "$OUT/trunk_history.tsv"

# A — the shipping surface. The tip. v1 and v2 both scored this ZERO and called it done;
# including it is the single correction that made the money path visible.
git -C "$REPO" ls-tree -r --full-tree "$TRUNK_FULL" \
  | awk '$2 == "blob" { tab = index($0,"\t"); print $3 "\t" substr($0, tab+1) }' \
  | sort -u > "$OUT/A.tsv"

# EVERYTHING — all refs except notes/stash (mechanical bookkeeping, not authored work),
# plus unreachable commits, which hold real authored content that no ref points at and
# which `git gc` will eventually destroy.
git -C "$REPO" for-each-ref --format='%(objectname)' \
  | grep -vE '^$' | sort -u > "$OUT/reftips.txt"
git -C "$REPO" for-each-ref --format='%(refname)' | grep -cE '^refs/(notes|stash)' \
  > "$OUT/skipped_refs.count" || true
git -C "$REPO" fsck --unreachable --no-progress 2>/dev/null \
  | awk '$2 == "commit" { print $3 }' | sort -u > "$OUT/unreachable.txt" || true

echo "rooms: walking all history ($(git -C "$REPO" rev-list --count --all) reachable commits + $(wc -l < "$OUT/unreachable.txt" | tr -d ' ') unreachable)..." >&2
{ pairs_of --all; [ -s "$OUT/unreachable.txt" ] && pairs_of --stdin < "$OUT/unreachable.txt" || true; } \
  | sort -u > "$OUT/all_pairs.tsv"

# B = everything ever authored anywhere, minus everything trunk has ever held.
comm -23 "$OUT/all_pairs.tsv" "$OUT/trunk_history.tsv" > "$OUT/B.tsv"

# ROOMS = A ∪ B. A∩B is empty by construction (A ⊂ trunk history), so this is a concatenation,
# but it is written as a union so that a future change to A cannot silently double-count.
sort -u "$OUT/A.tsv" "$OUT/B.tsv" > "$OUT/ROOMS.tsv"

HASH=$(sha256sum < "$OUT/ROOMS.tsv" 2>/dev/null || shasum -a 256 < "$OUT/ROOMS.tsv")
HASH=${HASH%% *}

cat > "$OUT/ROOMS.json" <<JSON
{
  "trunk": "$TRUNK_FULL",
  "computed_at": "$(date -u +%Y-%m-%dT%H:%M:%SZ)",
  "key": "(path, blob)",
  "A": $(wc -l < "$OUT/A.tsv" | tr -d ' '),
  "B": $(wc -l < "$OUT/B.tsv" | tr -d ' '),
  "ROOMS": $(wc -l < "$OUT/ROOMS.tsv" | tr -d ' '),
  "trunk_history_pairs": $(wc -l < "$OUT/trunk_history.tsv" | tr -d ' '),
  "all_pairs": $(wc -l < "$OUT/all_pairs.tsv" | tr -d ' '),
  "unreachable_commits": $(wc -l < "$OUT/unreachable.txt" | tr -d ' '),
  "rooms_sha256": "$HASH"
}
JSON
cat "$OUT/ROOMS.json"
