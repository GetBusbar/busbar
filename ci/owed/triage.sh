#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# The second mechanical pass over a deletion's test table: every row of a SWEEP.tsv whose
# verdict is none-named (a deleted test whose note names no native proof) is sorted by a fixed
# keyword rule into the rows a reader MUST rule (security or money by their words) and the rest,
# and each is checked for a surviving test of the same name at a ref.
#
#   triage.sh <git ref> <SWEEP.tsv> <TESTS.tsv> > TRIAGE.tsv
#
# Output, tab-separated: test, file, fate, same_name, class, ruling
#   same_name  the path of a test function of the same name at the ref, or "none"
#   class      CANDIDATE  the test's own name holds a security or money word: read first
#              CONTEXT    only its file path or its note does: read second
#              PLAIN      none of them does
#   ruling     empty: filled by the reader. For a CANDIDATE or CONTEXT row: "proven natively by <test>"
#              (body read), "owed" (a LEDGER row is added) or "not needed because <reason>"
#              (the owner rules every such row that is security or money).
# The rule never rules a row "not needed"; it only decides who must read it. The words are fixed
# here so two runs agree; widening the list re-sorts rows from PLAIN to CANDIDATE, never back.
set -eu
ref=$1
sweep=$2
tests=$3
names=$(mktemp "${TMPDIR:-/tmp}/owed-triage.XXXXXX")
trap 'rm -f "$names"' EXIT

# Every test function at the ref, with its path: "name<TAB>path".
git grep -n -E '^\s*(pub(\([a-z]+\))? )?(async )?fn [a-z][a-z0-9_]+' "$ref" -- '*.rs' \
  | sed -E 's/^[^:]+:([^:]+):[0-9]+:.*fn ([a-z][a-z0-9_]+).*/\2\t\1/' | sort -u > "$names"

awk -F '\t' -v names="$names" -v tests="$tests" '
BEGIN {
  OFS = "\t"
  while ((getline line < names) > 0) { split(line, part, "\t"); if (!(part[1] in at)) at[part[1]] = part[2] }
  # The note of each row, from the table the sweep read (either column layout).
  while ((getline line < tests) > 0) {
    n = split(line, col, "\t")
    if (col[1] ~ /\//) note[col[2] "\t" col[1]] = (n >= 4 ? col[4] : "")
    else note[col[1] "\t" col[2]] = (n >= 4 ? col[4] : "")
  }
  words = "auth|credential|secret|token|key|tls|mtls|cert|trust|grant|scope|pin|sign|seal|refus|reject|denied|forbid|revok|rotat|tamper|forge|replay|private|metadata|egress|allow|operator|admin|principal|identity|budget|money|fee|bill|charg|ledger|audit|journal|spend|cost|price|refund|meter|quota|limit|usage|settle|debt"
  print "test", "file", "fate", "same_name", "class", "ruling"
}
NR == 1 { next }
$4 != "none-named" { next }
{
  context = tolower($2 " " note[$1 "\t" $2])
  class = (tolower($1) ~ words) ? "CANDIDATE" : ((context ~ words) ? "CONTEXT" : "PLAIN")
  print $1, $2, $3, (($1 in at) ? at[$1] : "none"), class, ""
}' "$sweep"
