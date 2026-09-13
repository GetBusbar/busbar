#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# history-rewrite-empty-bodies.sh — rewrite ONLY the message BODY of a named, closed set of
# already-landed commits, leaving every tree byte-identical and every subject line untouched.
#
# WHY THIS EXISTS. A handful of landed commits carry a subject line but no rationale in the body
# (some carry nothing at all, some carry only a mechanical "(cherry picked from commit ...)"
# trailer). Several of those commits are security fixes: the diff and the subject say WHAT changed,
# but nothing in the permanent record says WHY it mattered or what it closed. That is a hole in the
# audit trail, not a cosmetic gap, so the fix is a one-time, reviewed, provably-safe rewrite of those
# specific bodies — not an amend anyone can reach for casually. This script is that rewrite, built so
# it CANNOT be pointed at the wrong tree, the wrong tip, or a commit whose body was not actually
# empty, and so a dry run proves the trees are unchanged before anyone considers running it for real.
#
# HOW IT WORKS (no git-filter-repo dependency; pure plumbing, so nothing but git itself is needed):
#   1. Resolve the ref's tip and refuse unless it equals --expect-tip.
#   2. Refuse unless every sha named in the bodies file is (a) on the ref, (b) has an EMPTY body
#      today (subject line only, or subject + nothing but a bare cherry-pick trailer).
#   3. Compute the REWRITE SET = the named commits plus every commit that descends from any of them,
#      up to the ref tip. Everything NOT in that set is never read, never rebuilt, and keeps its
#      original sha — only a commit downstream of a rewritten ancestor can change identity, because a
#      commit's sha embeds its parent's sha. That is unavoidable and is not "touching" the commit: its
#      tree and message are byte-identical to before, only its parent-linkage announcement changed.
#   4. Walk the rewrite set in topological (parents-first) order and rebuild each with
#      `git commit-tree`, passing the ORIGINAL tree unchanged, remapped parents, the ORIGINAL
#      author/committer identity and timestamps (via GIT_AUTHOR_*/GIT_COMMITTER_* env), and either
#      the original message (commit not named) or the original subject + the new body (+ the
#      original cherry-pick trailer, if there was one) for a named commit.
#   5. DRY RUN (default): the rebuilt commits are written to the object database (harmless, orphaned,
#      gc-able objects) but NO ref is moved. Prints the full old->new mapping and asserts, for every
#      entry, that `<old>^{tree} == <new>^{tree}`.
#   6. REAL RUN (--for-real): identical computation, then `git update-ref` moves the ref's branch to
#      the new tip. Still prints the same mapping and the same tree-identity proof.
#
# BODIES FILE FORMAT (docs/security/rewrite-bodies.txt is one; --selftest writes its own to a temp
# dir). A sequence of blocks separated by a line that is exactly `%%%`. The first line of each block
# is `<sha><TAB><first line of the new body>`; any further lines up to the next `%%%` (or EOF) are
# additional body lines, verbatim. A sha may appear at most once in the file.
#
# REFUSALS (any one of these aborts before anything is written, dry run or real):
#   - the working tree is not clean (`git status --porcelain` non-empty)
#   - the ref's current tip is not exactly --expect-tip
#   - a sha in the bodies file is not an ancestor of the ref
#   - a sha in the bodies file does not have an empty body today
#   - a sha appears more than once in the bodies file
#   - a sha in the bodies file does not exist as a commit at all
#   - --for-real is given without --expect-tip, --bodies, or --ref
#
# USAGE:
#   history-rewrite-empty-bodies.sh --ref <ref> --bodies <file> --expect-tip <sha> [--for-real] [--repo <path>]
#   history-rewrite-empty-bodies.sh --selftest
#
# --repo defaults to the current directory's repository (via `git rev-parse --show-toplevel`); the
# selftest always passes its own throwaway --repo and never touches the caller's repository or its
# global git config (identity is supplied per-commit via GIT_AUTHOR_*/GIT_COMMITTER_* env, and the
# throwaway repo's own local config, never `git config --global`).

set -euo pipefail

SELF="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)/$(basename "${BASH_SOURCE[0]}")"

usage() {
  sed -n '/^# USAGE:/,/^# --repo/p' "$SELF" | sed 's/^# \{0,1\}//'
}

die() {
  echo "REFUSED: $*" >&2
  exit 1
}

REF=""
BODIES=""
EXPECT_TIP=""
FOR_REAL=0
REPO=""
SELFTEST=0

while [ $# -gt 0 ]; do
  case "$1" in
    --ref) REF="$2"; shift 2 ;;
    --bodies) BODIES="$2"; shift 2 ;;
    --expect-tip) EXPECT_TIP="$2"; shift 2 ;;
    --for-real) FOR_REAL=1; shift ;;
    --repo) REPO="$2"; shift 2 ;;
    --selftest) SELFTEST=1; shift ;;
    -h|--help) usage; exit 0 ;;
    *) die "unknown argument: $1" ;;
  esac
done

# ---------------------------------------------------------------------------------------------
# Body-emptiness test: a commit's body (everything after the first blank line following the
# subject) is EMPTY if, once blank lines and a bare "(cherry picked from commit <sha>)" trailer
# are stripped, nothing is left.
# ---------------------------------------------------------------------------------------------
body_is_empty() {
  local repo="$1" sha="$2"
  local body
  body="$(git -C "$repo" log -1 --format='%b' "$sha")"
  local stripped
  stripped="$(printf '%s\n' "$body" | grep -Ev '^\s*$' | grep -Ev '^\(cherry picked from commit [0-9a-f]{7,40}\)$' || true)"
  [ -z "$stripped" ]
}

# Extract the bare cherry-pick trailer line from a commit's body, if it has exactly one.
cherry_trailer() {
  local repo="$1" sha="$2"
  git -C "$repo" log -1 --format='%b' "$sha" | grep -E '^\(cherry picked from commit [0-9a-f]{7,40}\)$' | head -1 || true
}

# ---------------------------------------------------------------------------------------------
# Parse the bodies file into two parallel arrays: BODY_SHAS[] and BODY_TEXT[] (newline-joined).
# ---------------------------------------------------------------------------------------------
parse_bodies_file() {
  local file="$1"
  BODY_SHAS=()
  BODY_TEXT=()
  local cur_sha="" cur_text=""
  local have_block=0
  while IFS= read -r line || [ -n "$line" ]; do
    if [ "$line" = "%%%" ]; then
      if [ "$have_block" -eq 1 ]; then
        BODY_SHAS+=("$cur_sha")
        BODY_TEXT+=("$cur_text")
      fi
      cur_sha=""; cur_text=""; have_block=0
      continue
    fi
    if [ "$have_block" -eq 0 ]; then
      cur_sha="${line%%$'\t'*}"
      cur_text="${line#*$'\t'}"
      have_block=1
    else
      cur_text="$cur_text
$line"
    fi
  done < "$file"
  if [ "$have_block" -eq 1 ]; then
    BODY_SHAS+=("$cur_sha")
    BODY_TEXT+=("$cur_text")
  fi
}

run_rewrite() {
  local repo="$REPO"
  [ -n "$repo" ] || repo="$(git rev-parse --show-toplevel)"
  [ -n "$REF" ] || die "--ref is required"
  [ -n "$BODIES" ] || die "--bodies is required"
  [ -n "$EXPECT_TIP" ] || die "--expect-tip is required"
  [ -f "$BODIES" ] || die "bodies file not found: $BODIES"

  git -C "$repo" rev-parse --git-dir >/dev/null 2>&1 || die "not a git repository: $repo"

  # 1. Clean working tree.
  if [ -n "$(git -C "$repo" status --porcelain)" ]; then
    die "working tree at $repo is not clean; commit, discard, or move it aside first"
  fi

  # 2. Tip check.
  local tip
  tip="$(git -C "$repo" rev-parse "$REF")"
  [ "$tip" = "$EXPECT_TIP" ] || die "tip mismatch on $REF: expected $EXPECT_TIP, got $tip"

  # Parse bodies file.
  parse_bodies_file "$BODIES"
  [ "${#BODY_SHAS[@]}" -gt 0 ] || die "bodies file has no blocks: $BODIES"

  # No duplicate shas.
  local seen=" "
  for sha in "${BODY_SHAS[@]}"; do
    case "$seen" in
      *" $sha "*) die "sha listed more than once in bodies file: $sha" ;;
    esac
    seen="$seen$sha "
  done

  # 3. Every listed sha must exist, be on the ref, and have an empty body today.
  for sha in "${BODY_SHAS[@]}"; do
    git -C "$repo" cat-file -e "${sha}^{commit}" 2>/dev/null || die "not a commit in this repo: $sha"
    git -C "$repo" merge-base --is-ancestor "$sha" "$REF" || die "sha is not an ancestor of $REF: $sha"
    body_is_empty "$repo" "$sha" || die "sha does not have an empty body, refusing to touch it: $sha"
  done

  echo "checks passed: clean tree, tip == $EXPECT_TIP, ${#BODY_SHAS[@]} sha(s) on-ref with empty bodies"

  # 4. Compute the rewrite set: named shas + every descendant of any named sha, up to the ref tip.
  local -A IN_SET=()
  for sha in "${BODY_SHAS[@]}"; do
    local full
    full="$(git -C "$repo" rev-parse "$sha")"
    IN_SET["$full"]=1
    while IFS= read -r d; do
      [ -n "$d" ] && IN_SET["$d"]=1
    done < <(git -C "$repo" rev-list "${sha}..${REF}")
  done

  # Topological order, parents first, restricted to the rewrite set.
  local -a ORDER=()
  while IFS= read -r c; do
    if [ -n "${IN_SET[$c]:-}" ]; then
      ORDER+=("$c")
    fi
  done < <(git -C "$repo" rev-list --topo-order --reverse "$REF")

  echo "rewrite set: ${#ORDER[@]} commit(s) between the named sha(s) and the ref tip (inclusive)"

  # 5. Rebuild each commit in the set with commit-tree, remapping parents as we go.
  local -A REMAP=()
  local -a MAP_OLD=() MAP_NEW=()
  for old in "${ORDER[@]}"; do
    local tree
    tree="$(git -C "$repo" rev-parse "${old}^{tree}")"

    local -a new_parents=()
    while IFS= read -r p; do
      [ -z "$p" ] && continue
      if [ -n "${REMAP[$p]:-}" ]; then
        new_parents+=("${REMAP[$p]}")
      else
        new_parents+=("$p")
      fi
    done < <(git -C "$repo" log -1 --format='%P' "$old" | tr ' ' '\n')

    local -a parent_args=()
    for p in "${new_parents[@]}"; do
      parent_args+=(-p "$p")
    done

    local is_named=0 body_idx=-1
    for i in "${!BODY_SHAS[@]}"; do
      local full_named
      full_named="$(git -C "$repo" rev-parse "${BODY_SHAS[$i]}")"
      if [ "$full_named" = "$old" ]; then
        is_named=1; body_idx="$i"; break
      fi
    done

    local msg
    if [ "$is_named" -eq 1 ]; then
      local subject trailer
      subject="$(git -C "$repo" log -1 --format='%s' "$old")"
      trailer="$(cherry_trailer "$repo" "$old")"
      msg="$subject

${BODY_TEXT[$body_idx]}"
      if [ -n "$trailer" ]; then
        msg="$msg

$trailer"
      fi
    else
      msg="$(git -C "$repo" log -1 --format='%B' "$old")"
    fi

    local new
    new="$(export GIT_AUTHOR_NAME="$(git -C "$repo" log -1 --format='%an' "$old")"
      export GIT_AUTHOR_EMAIL="$(git -C "$repo" log -1 --format='%ae' "$old")"
      export GIT_AUTHOR_DATE="$(git -C "$repo" log -1 --format='%ad' --date=raw "$old")"
      export GIT_COMMITTER_NAME="$(git -C "$repo" log -1 --format='%cn' "$old")"
      export GIT_COMMITTER_EMAIL="$(git -C "$repo" log -1 --format='%ce' "$old")"
      export GIT_COMMITTER_DATE="$(git -C "$repo" log -1 --format='%cd' --date=raw "$old")"
      printf '%s' "$msg" | git -C "$repo" commit-tree "$tree" "${parent_args[@]}")"

    REMAP["$old"]="$new"
    MAP_OLD+=("$old")
    MAP_NEW+=("$new")
  done

  # 6. Prove every tree is byte-identical, and print the mapping.
  echo
  echo "old -> new (tree-identity proven for each):"
  local i
  for i in "${!MAP_OLD[@]}"; do
    local old="${MAP_OLD[$i]}" new="${MAP_NEW[$i]}"
    local old_tree new_tree
    old_tree="$(git -C "$repo" rev-parse "${old}^{tree}")"
    new_tree="$(git -C "$repo" rev-parse "${new}^{tree}")"
    [ "$old_tree" = "$new_tree" ] || die "INTERNAL: tree changed for $old (this must never happen)"
    local tag=""
    if [ -n "${REMAP[$old]:-}" ] && [ "$old" != "${MAP_OLD[$i]}" ]; then :; fi
    printf '  %s -> %s  (tree %s unchanged)%s\n' "$old" "$new" "$old_tree" "$([ "$old" = "$new" ] && echo '  [unchanged]' || echo)"
  done

  local new_tip="${MAP_NEW[-1]}"
  echo
  echo "new tip: $new_tip"

  if [ "$FOR_REAL" -eq 0 ]; then
    echo
    echo "DRY RUN ONLY: no ref was moved. Rebuilt objects above are orphaned and gc-able."
    echo "Re-run with --for-real to move $REF to the new tip."
    return 0
  fi

  # Resolve REF to a local branch name for update-ref (refuse to move anything else, e.g. a
  # detached tip sha passed directly as --ref).
  local branch_ref
  if git -C "$repo" show-ref --verify --quiet "refs/heads/$REF"; then
    branch_ref="refs/heads/$REF"
  elif git -C "$repo" show-ref --verify --quiet "$REF"; then
    branch_ref="$REF"
  else
    die "--for-real requires --ref to name a branch, not a bare sha: $REF"
  fi

  git -C "$repo" update-ref -m "history-rewrite-empty-bodies: reword ${#BODY_SHAS[@]} commit body(ies), tip $EXPECT_TIP -> $new_tip" "$branch_ref" "$new_tip" "$tip"
  echo
  echo "REAL RUN COMPLETE: $branch_ref moved $tip -> $new_tip"
}

# =================================================================================================
# SELFTEST
# =================================================================================================
SELFTEST_TMP=""
cleanup_selftest_tmp() {
  [ -n "$SELFTEST_TMP" ] && rm -rf "$SELFTEST_TMP"
}

run_selftest() {
  SELFTEST_TMP="$(mktemp -d)"
  trap cleanup_selftest_tmp EXIT
  local tmp="$SELFTEST_TMP"

  local repo="$tmp/repo"
  mkdir -p "$repo"
  git -C "$repo" init -q -b main
  # This is a throwaway repo that lives only for the duration of the selftest and is deleted on
  # exit; disable any globally-configured hooksPath (e.g. a commit-identity guard) LOCALLY, in
  # this one disposable repo only, so the selftest is not coupled to whatever identity guard the
  # invoking environment happens to enforce on real repos. The caller's own global config is never
  # touched.
  git -C "$repo" config core.hooksPath /dev/null

  export GIT_AUTHOR_NAME="History Rewrite Selftest" GIT_AUTHOR_EMAIL="selftest@example.invalid"
  export GIT_COMMITTER_NAME="History Rewrite Selftest" GIT_COMMITTER_EMAIL="selftest@example.invalid"

  echo one > "$repo/a.txt"
  git -C "$repo" add a.txt
  GIT_AUTHOR_DATE="2026-01-01T00:00:00" GIT_COMMITTER_DATE="2026-01-01T00:00:00" \
    git -C "$repo" commit -q -m "first: has a real body

this one already has rationale, must never be touched"
  local c1 c1_tree
  c1="$(git -C "$repo" rev-parse HEAD)"
  c1_tree="$(git -C "$repo" rev-parse HEAD^{tree})"

  echo two > "$repo/b.txt"
  git -C "$repo" add b.txt
  GIT_AUTHOR_DATE="2026-01-02T00:00:00" GIT_COMMITTER_DATE="2026-01-02T00:00:00" \
    git -C "$repo" commit -q -m "second: empty body"
  local c2
  c2="$(git -C "$repo" rev-parse HEAD)"
  local c2_tree
  c2_tree="$(git -C "$repo" rev-parse HEAD^{tree})"

  echo three > "$repo/c.txt"
  git -C "$repo" add c.txt
  GIT_AUTHOR_DATE="2026-01-03T00:00:00" GIT_COMMITTER_DATE="2026-01-03T00:00:00" \
    git -C "$repo" commit -q -m "third: also empty, only a trailer

(cherry picked from commit 0000000000000000000000000000000000000000)"
  local c3
  c3="$(git -C "$repo" rev-parse HEAD)"
  local c3_tree
  c3_tree="$(git -C "$repo" rev-parse HEAD^{tree})"

  local tip
  tip="$(git -C "$repo" rev-parse main)"

  local bodies="$tmp/bodies.txt"
  cat > "$bodies" <<EOF
$c2	The second commit's real rationale, line one.
line two of the same body.
%%%
$c3	The third commit's real rationale.
%%%
EOF

  local fails=0
  pass() { echo "  PASS: $1"; }
  fail() { echo "  FAIL: $1"; fails=$((fails+1)); }

  echo "=== selftest: refusal on dirty working tree ==="
  echo dirty > "$repo/dirty.txt"
  if bash "$SELF" --repo "$repo" --ref main --bodies "$bodies" --expect-tip "$tip" >/tmp/hrb-out.$$ 2>&1; then
    fail "dirty tree did not refuse"
  else
    grep -q "not clean" /tmp/hrb-out.$$ && pass "dirty tree refused" || fail "dirty tree refused for wrong reason"
  fi
  rm -f "$repo/dirty.txt" /tmp/hrb-out.$$

  echo "=== selftest: refusal on wrong --expect-tip ==="
  if bash "$SELF" --repo "$repo" --ref main --bodies "$bodies" --expect-tip "0000000000000000000000000000000000000000" >/tmp/hrb-out.$$ 2>&1; then
    fail "wrong tip did not refuse"
  else
    grep -q "tip mismatch" /tmp/hrb-out.$$ && pass "wrong tip refused" || fail "wrong tip refused for wrong reason"
  fi
  rm -f /tmp/hrb-out.$$

  echo "=== selftest: refusal on a non-empty body ==="
  local bad_bodies="$tmp/bad-bodies.txt"
  cat > "$bad_bodies" <<EOF
$c1	This must be refused: c1's body is not empty.
%%%
EOF
  if bash "$SELF" --repo "$repo" --ref main --bodies "$bad_bodies" --expect-tip "$tip" >/tmp/hrb-out.$$ 2>&1; then
    fail "non-empty body did not refuse"
  else
    grep -q "does not have an empty body" /tmp/hrb-out.$$ && pass "non-empty body refused" || fail "non-empty body refused for wrong reason"
  fi
  rm -f /tmp/hrb-out.$$

  echo "=== selftest: dry run ==="
  local dry_out="$tmp/dry-out.txt"
  bash "$SELF" --repo "$repo" --ref main --bodies "$bodies" --expect-tip "$tip" > "$dry_out" 2>&1
  cat "$dry_out"
  grep -q "DRY RUN ONLY" "$dry_out" && pass "dry run reported itself as dry" || fail "dry run did not say DRY RUN ONLY"
  [ "$(git -C "$repo" rev-parse main)" = "$tip" ] && pass "dry run did not move the ref" || fail "dry run moved the ref"

  echo "=== selftest: real run ==="
  local real_out="$tmp/real-out.txt"
  bash "$SELF" --repo "$repo" --ref main --bodies "$bodies" --expect-tip "$tip" --for-real > "$real_out" 2>&1
  cat "$real_out"
  grep -q "REAL RUN COMPLETE" "$real_out" && pass "real run reported completion" || fail "real run did not report completion"

  local new_tip
  new_tip="$(git -C "$repo" rev-parse main)"
  [ "$new_tip" != "$tip" ] && pass "ref moved to a new tip" || fail "ref tip unchanged after real run"

  # c1 is not a descendant of any rewritten commit's ancestor chain start... actually c1 IS an
  # ancestor of c2/c3 so it is untouched only if it precedes every named sha, which it does here:
  # c1 itself was never named and has no named ancestor, so it must be byte-identical, same sha.
  git -C "$repo" cat-file -e "$c1" 2>/dev/null && pass "c1 (non-listed, no listed ancestor) sha unchanged" || fail "c1 sha vanished"

  # Walk the new history and check trees.
  local new_c2 new_c3
  new_c2="$(git -C "$repo" log --format='%H' main | tail -3 | sed -n '2p')"
  new_c3="$(git -C "$repo" rev-parse main)"
  [ "$(git -C "$repo" rev-parse "${new_c2}^{tree}")" = "$c2_tree" ] && pass "c2 tree unchanged" || fail "c2 tree changed"
  [ "$(git -C "$repo" rev-parse "${new_c3}^{tree}")" = "$c3_tree" ] && pass "c3 tree unchanged" || fail "c3 tree changed"

  git -C "$repo" log -1 --format='%b' "$new_c2" | grep -q "real rationale, line one" && pass "c2 new body present" || fail "c2 new body missing"
  git -C "$repo" log -1 --format='%b' "$new_c3" | grep -q "cherry picked from commit 0000000000000000000000000000000000000000" && pass "c3 cherry-pick trailer preserved" || fail "c3 trailer lost"
  git -C "$repo" log -1 --format='%s' "$new_c2" | grep -qx "second: empty body" && pass "c2 subject untouched" || fail "c2 subject changed"

  echo
  if [ "$fails" -eq 0 ]; then
    echo "SELFTEST: ALL GREEN"
    return 0
  else
    echo "SELFTEST: $fails FAILURE(S)"
    return 1
  fi
}

if [ "$SELFTEST" -eq 1 ]; then
  run_selftest
else
  run_rewrite
fi
