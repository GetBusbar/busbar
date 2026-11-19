#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 7, THE TREADMILL'S JUDGE: what one lean round removed, by the one count.
#
#   round.sh <COUNT before the round> <COUNT after the round>
#
# Both files are count.sh output. A ROUND is: every packet of the round landed as ONE aggregate
# merge on the line, then one count of the line head. It prints every unit whose count changed,
# the totals, and the verdict:
#   REMOVED <n>          the total fell by n code lines: run another round
#   REMOVED NOTHING      the total did not fall: the treadmill has run dry
# A unit that GREW is listed with a plus sign whatever the verdict: growth inside a lean round is
# explained in the round's report or reverted. Exit status: 0 removed something, 3 removed nothing.
set -eu
before=$1
after=$2

awk -F '\t' '
FNR == 1 { file++ }
$1 == "unit"  { seen[$2] = 1; if (file == 1) was[$2] = $3; else now[$2] = $3 }
$1 == "total" { if (file == 1) total_was[$2] = $3; else total_now[$2] = $3 }
END {
  for (unit in seen) {
    delta = (now[unit] + 0) - (was[unit] + 0)
    if (delta != 0) printf "unit\t%s\t%d\t%d\t%+d\n", unit, was[unit] + 0, now[unit] + 0, delta | "sort"
  }
  close("sort")
  for (which in total_was)
    printf "total\t%s\t%d\t%d\t%+d\n", which, total_was[which], total_now[which] + 0, (total_now[which] + 0) - total_was[which]
  removed = total_was["all"] - (total_now["all"] + 0)
  if (removed > 0) { printf "REMOVED %d\n", removed; exit 0 }
  print "REMOVED NOTHING"
  exit 3
}' "$before" "$after"
