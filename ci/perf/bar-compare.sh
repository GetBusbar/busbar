#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 5, the verdict: one candidate binary against the v1.5.5 baseline, from the rows
# bar.sh wrote.
#
#   bar-compare.sh <rows.tsv> <baseline label> <candidate label>
#
# For every (mode, route, transport, client threads) and every measured quantity the candidate's
# MEDIAN over its repetitions is compared with the baseline's WORST repetition: the candidate
# meets the bar when it is no worse than v1.5.5 showed itself to be on the same machine in the
# same run. No tolerance is added. A row the baseline has and the candidate lacks is NOT MEASURED
# and fails the verdict: an unmeasured figure never passes.
# Quantities: median_us p99_us first_median_us cpu_us (keep, new) and per_conn_bytes (idle rows).
# Exit status: 0 every figure meets the bar; 1 at least one fails or is not measured.
set -eu
rows=$1
base=$2
cand=$3
table=$(mktemp "${TMPDIR:-/tmp}/perf-bar-verdict.XXXXXX")
status=0

awk -F '\t' -v base="$base" -v cand="$cand" '
function median(list, n,    i, j, t, a) {
  for (i = 1; i <= n; i++) a[i] = list[i]
  for (i = 2; i <= n; i++) { t = a[i]; for (j = i - 1; j >= 1 && a[j] > t; j--) a[j + 1] = a[j]; a[j + 1] = t }
  return (n % 2) ? a[(n + 1) / 2] : (a[n / 2] + a[n / 2 + 1]) / 2
}
function note(label, key, what, value) {
  if (value == "") return
  k = key "\t" what
  if (label == base) { seen[k] = 1; if (!(k in worst) || value + 0 > worst[k]) worst[k] = value + 0 }
  if (label == cand) { n[k]++; got[k, n[k]] = value + 0 }
}
/^#/ || $1 == "label" { next }
{
  key = $2 "\t" $3 "\t" $4 "\t" $5
  if ($2 == "keep" || $2 == "new") {
    note($1, key, "median_us", $7); note($1, key, "p99_us", $8)
    note($1, key, "first_median_us", $9); note($1, key, "cpu_us", $11)
  } else {
    note($1, key, "per_conn_bytes", $14)
  }
}
END {
  printf "mode\troute\ttransport\tthreads\tquantity\t%s_worst\t%s_median\tverdict\n", base, cand
  failed = 0
  for (k in seen) {
    if (!(k in n)) { printf "%s\t%s\t\tNOT MEASURED\n", k, worst[k]; failed = 1; continue }
    for (i = 1; i <= n[k]; i++) list[i] = got[k, i]
    m = median(list, n[k])
    verdict = (m <= worst[k]) ? "PASS" : "FAIL"
    if (verdict == "FAIL") failed = 1
    printf "%s\t%s\t%s\t%s\n", k, worst[k], m, verdict
  }
  exit failed
}' "$rows" > "$table" || status=$?
head -1 "$table"
tail -n +2 "$table" | sort
rm -f "$table"
exit "$status"
