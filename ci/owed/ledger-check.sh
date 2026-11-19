#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 6, THE GATE: no known holes. Reads ci/owed/LEDGER.tsv at a ref and answers two
# questions a reader cannot be trusted to answer by eye:
#   1. does every test a row names as its proof EXIST as a function at the ref (a proof that was
#      deleted, renamed or never landed is not a proof);
#   2. is every row closed: its state begins with PROVEN, or it is an owner act the owner closed
#      (state begins with CLOSED BY OWNER).
#
#   ledger-check.sh <git ref> [LEDGER.tsv]
#
# Output, tab-separated, one line per row that is not closed or names a missing test:
#   id, state (first word), missing tests (space-separated; empty when none)
# then a last line "open=<n> missing=<n> rows=<n>".
# Exit status: 0 when open=0 and missing=0; 1 otherwise. It never edits the ledger.
# A name is taken as a test name when it is snake_case with at least four underscores; names in
# the ledger's `row` column (the deleted test being replaced) are not checked, only `proof`.
set -eu
ref=$1
ledger=${2:-$(dirname "$0")/LEDGER.tsv}
names=$(mktemp "${TMPDIR:-/tmp}/owed-ledger.XXXXXX")
trap 'rm -f "$names"' EXIT

git grep -h -o -E 'fn [a-z][a-z0-9_]+' "$ref" -- '*.rs' | sed 's/^fn //' | sort -u > "$names"

awk -F '\t' -v names="$names" '
BEGIN { while ((getline line < names) > 0) have[line] = 1; OFS = "\t" }
NR == 1 { next }
{
  rows++
  id = $1; proof = $5; state = $6
  # Words after "none:", "DELETED", "partial:" or "candidates" still name tests that must exist
  # if the row leans on them; a row that leans on none has nothing to check.
  missing = ""; rest = proof
  while (match(rest, /[a-z][a-z0-9]*(_[a-z0-9]+)(_[a-z0-9]+)(_[a-z0-9]+)(_[a-z0-9]+)+/)) {
    name = substr(rest, RSTART, RLENGTH)
    rest = substr(rest, RSTART + RLENGTH)
    if (rest ~ /^(\.rs|\/|::)/ || (name in seen)) continue
    seen[name] = 1
    if (!(name in have)) missing = missing (missing == "" ? "" : " ") name
  }
  for (name in seen) delete seen[name]
  closed = (state ~ /^PROVEN/ || state ~ /^CLOSED BY OWNER/)
  # A row is only PROVEN when its state says nothing is left: "PROVEN ...; ... TO-WRITE" is open.
  if (closed && state ~ /TO-WRITE|WAITS|not written|not read/) closed = 0
  if (!closed) open++
  if (missing != "") gone++
  if (!closed || missing != "") {
    word = state; sub(/[ ;:(].*/, "", word)
    print id, word, missing
  }
}
END {
  printf "open=%d missing=%d rows=%d\n", open + 0, gone + 0, rows + 0
  exit (open + gone) ? 1 : 0
}' "$ledger"
