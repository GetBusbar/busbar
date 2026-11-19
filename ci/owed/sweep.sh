#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The mechanical first pass over a deletion's test table: for every row of a TESTS.tsv
# (test, file, fate, why), read the native tests its `why` names and check that each one EXISTS
# as a test function at a ref. It judges nothing about whether the named test proves the same
# property: that reading is the triage that follows, and it starts from this table.
#
#   sweep.sh <git ref> <TESTS.tsv> > SWEEP.tsv
#
# Output, tab-separated: test, file, fate, verdict, present, missing
#   verdict  kept            the row's fate is not a deletion (kept, repaired, rewritten, trimmed)
#            native-present  every native test the row names exists at the ref
#            native-missing  at least one named test does not exist at the ref (listed in `missing`)
#            none-named      a deleted test whose row names no native test: it is OWED until a
#                            reader names its proof or rules it not needed
# A name is taken as a test name when it is snake_case with at least four underscores and is not
# the row's own test name. Run from anywhere inside the repository.
set -eu
ref=$1
table=$2
names=$(mktemp "${TMPDIR:-/tmp}/owed-sweep.XXXXXX")
trap 'rm -f "$names"' EXIT

git grep -h -o -E 'fn [a-z][a-z0-9_]+' "$ref" -- '*.rs' | sed 's/^fn //' | sort -u > "$names"

awk -F '\t' -v names="$names" '
BEGIN {
  while ((getline line < names) > 0) have[line] = 1
  OFS = "\t"
  print "test", "file", "fate", "verdict", "present", "missing"
}
NR == 1 && $1 == "test" { next }
{
  if ($1 ~ /\//) {
    # The lower-crates table: file, test, kind, and a fourth column only when the row changed.
    test = $2; file = $1; why = $4; fate = why; sub(/[:(].*/, "", fate); sub(/ +$/, "", fate)
    if (fate == "") fate = "kept"
  } else {
    test = $1; file = $2; fate = $3; why = $4
  }
  if (fate !~ /^(deleted|unmounted|owed|OWED)/) { print test, file, fate, "kept", "", ""; next }
  present = ""; missing = ""; rest = why
  while (match(rest, /[a-z][a-z0-9]*(_[a-z0-9]+)(_[a-z0-9]+)(_[a-z0-9]+)(_[a-z0-9]+)+/)) {
    name = substr(rest, RSTART, RLENGTH)
    rest = substr(rest, RSTART + RLENGTH)
    # A file name (x_y_z_w.rs) or a path segment is not a test name.
    if (rest ~ /^(\.rs|\/|::)/) continue
    if (name == test || (name in seen_here)) continue
    seen_here[name] = 1
    if (name in have) present = present (present == "" ? "" : " ") name
    else missing = missing (missing == "" ? "" : " ") name
  }
  for (name in seen_here) delete seen_here[name]
  if (present == "" && missing == "") verdict = "none-named"
  else if (missing != "") verdict = "native-missing"
  else verdict = "native-present"
  print test, file, fate, verdict, present, missing
}' "$table"
