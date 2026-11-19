#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 5, the verdict: one candidate binary against the v1.5.5 baseline, from the rows
# bar.sh wrote.
#
#   bar-compare.sh <rows.tsv> <baseline label> <candidate label>
#
# For every (mode, route, transport, client threads) and every measured quantity, the candidate's
# MIDDLE repetition is set beside the baseline's middle and worst repetitions:
#   PASS      the candidate's middle is no worse than the baseline's middle
#   PASS*     it is worse than the baseline's middle but no worse than the baseline's own worst
#             repetition in this run: inside the spread v1.5.5 showed on this machine today.
#             Shown apart so the owner sees every one; no tolerance is added anywhere.
#   FAIL      worse than every repetition of the baseline
#   NOT MEASURED  the baseline has the row and the candidate does not: never a pass
# Quantities: med_ns p99_ns first_med_ns server_cpu_ns_per_req (keep, new), and
# per_idle_connection_bytes per_used_connection_bytes (hold).
# Exit status: 0 no FAIL and nothing unmeasured; 1 otherwise.
set -eu
rows=$1
base=$2
cand=$3
table=$(mktemp "${TMPDIR:-/tmp}/perf-bar-verdict.XXXXXX")
status=0

awk -F '\t' -v base="$base" -v cand="$cand" '
function middle(who, k,    i, j, t, a, n) {
  n = count[who, k]
  for (i = 1; i <= n; i++) a[i] = got[who, k, i]
  for (i = 2; i <= n; i++) { t = a[i]; for (j = i - 1; j >= 1 && a[j] > t; j--) a[j + 1] = a[j]; a[j + 1] = t }
  return a[int((n + 1) / 2)]
}
function note(label, key, what, value,    k) {
  if (value == "" || (label != base && label != cand)) return
  k = key "\t" what
  if (label == base) { seen[k] = 1; if (!((base, k) in worst) || value + 0 > worst[base, k]) worst[base, k] = value + 0 }
  count[label, k]++
  got[label, k, count[label, k]] = value + 0
}
/^#/ || $1 == "label" { next }
{
  key = $2 "\t" $3 "\t" $4 "\t" $5
  if ($2 == "keep" || $2 == "new") {
    note($1, key, "med_ns", $7); note($1, key, "p99_ns", $8)
    note($1, key, "first_med_ns", $10); note($1, key, "server_cpu_ns_per_req", $14)
  } else if ($2 == "hold") {
    note($1, key, "per_idle_connection_bytes", $20); note($1, key, "per_used_connection_bytes", $21)
  }
}
END {
  printf "mode\troute\ttransport\tthreads\tquantity\t%s_middle\t%s_worst\t%s_middle\tverdict\n", base, base, cand
  failed = 0
  for (k in seen) {
    b = middle(base, k)
    if (!((cand, k) in count)) { printf "%s\t%s\t%s\t\tNOT MEASURED\n", k, b, worst[base, k]; failed = 1; continue }
    c = middle(cand, k)
    if (c <= b) verdict = "PASS"
    else if (c <= worst[base, k]) verdict = "PASS*"
    else { verdict = "FAIL"; failed = 1 }
    printf "%s\t%s\t%s\t%s\t%s\n", k, b, worst[base, k], c, verdict
  }
  exit failed
}' "$rows" > "$table" || status=$?
head -1 "$table"
tail -n +2 "$table" | sort
rm -f "$table"
exit "$status"
