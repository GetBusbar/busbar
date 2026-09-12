#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# THE ARITHMETIC SWEEP, OVER THE WHOLE LAND QUEUE.
#
# `cargo xtask gate construction --raise-ledger <base> <head>` answers one question for one
# branch: did every ceiling key's declared raises sum to exactly its measured rise between two
# commits. This script asks the same question of every LIVE line in a land queue — the auditor's
# nightly check made runnable on demand, rather than by a human re-deriving the arithmetic by hand.
# A single-digit under-declaration is exactly the shape neither the prose nor the TOML disagrees
# with itself about; this is the one check that reads the tree instead of the claim.
#
# READ-ONLY. This script never edits the queue file, never edits a ceilings file, and writes
# nowhere but stdout/stderr and its own scratch directory under `$HOME/Developer/tmp` (never
# `/tmp`). It shells out to `cargo xtask`, which is itself read-only for this arm.
#
#   scripts/raise-ledger-sweep.sh <queue-file>
#
# LINE GRAMMAR — the same one `scripts/pr-queue.sh` reads: a quoted argv per line,
#   [--tests "pkg pkg"] [--families 'regex'] [--gate 'rule|rule'] [--prove] <hash>...
#   # …            a comment
#   STOP           consumption halts HERE, exactly as it does for the landing runner
#   (blank)        ignored
#
# ONLY A LINE CARRYING `--prove` IS LIVE FOR THIS SWEEP. A line with no `--prove` flag has not
# claimed to have measured anything on its own branch, and sweeping it would be inventing a claim
# on the line's behalf that its author never made.
#
# A LINE'S TIP IS ITS LAST HASH TOKEN. The queue is one landing per line, cherry-picked onto the
# target in order, so the last hash named is what the line's branch measures at.
#
# A LINE'S BASE is `merge-base(<tip>, origin/integration/oracle-phase0)`, falling back to
# `<tip>~1` when the merge-base IS the tip — the same rule
# `xtask/src/gates/construction/ceilings.rs::base_ref` applies to HEAD, applied here to a tip that
# is not HEAD. Getting this wrong is exactly AUDIT-pass31's closing correction: the base is the
# gate's own `base_ref`, never a second arithmetic against the git parent.
set -uo pipefail

sdir="$(cd "$(dirname "$0")" && pwd)"
here="$(git -C "$sdir" rev-parse --show-toplevel 2>/dev/null)" || {
  echo "raise-ledger-sweep.sh: not inside a git work tree" >&2
  exit 2
}
integration_ref="origin/integration/oracle-phase0"
scratch="${RAISE_LEDGER_SWEEP_SCRATCH:-$HOME/Developer/tmp/raise-ledger-sweep}"

queue="${1:-}"
if [ -z "$queue" ]; then
  echo "usage: $0 <queue-file>" >&2
  exit 2
fi
[ -f "$queue" ] || {
  echo "raise-ledger-sweep.sh: no queue file at $queue" >&2
  exit 2
}

mkdir -p "$scratch"
lines_tsv="$scratch/live-lines.$$.tsv"
trap 'rm -f "$lines_tsv"' EXIT

# THE SAME PARSE `pr-queue.sh` USES, and for the same reason: the documented grammar is a quoted
# argv (`--tests "pkg pkg"`), and word-splitting a read line with `set --` breaks exactly that
# case. One row per LIVE line: `<line number>\t<tip sha>`.
python3 - "$queue" "$lines_tsv" <<'PY'
import shlex
import sys

queue, out = sys.argv[1], sys.argv[2]
WITH_VALUE = {"--tests", "--families", "--gate"}
rows = []
for lineno, raw in enumerate(open(queue), 1):
    line = raw.strip()
    if not line or line.startswith("#"):
        continue
    if line == "STOP" or line.startswith("STOP "):
        break
    toks = shlex.split(line)
    live = False
    hashes = []
    i = 0
    while i < len(toks):
        t = toks[i]
        if t in WITH_VALUE:
            i += 2
        elif t == "--prove":
            live = True
            i += 1
        elif t.startswith("-"):
            i += 1
        else:
            hashes.append(t)
            i += 1
    if live and hashes:
        rows.append("%d\t%s" % (lineno, hashes[-1]))
open(out, "w").write("".join(r + "\n" for r in rows))
PY

if [ ! -s "$lines_tsv" ]; then
  echo "raise-ledger-sweep.sh: no live --prove line in $queue"
  exit 0
fi

bad=0
while IFS=$'\t' read -r lineno tip; do
  [ -n "$tip" ] || continue
  if ! git -C "$here" rev-parse --verify --quiet "${tip}^{commit}" >/dev/null; then
    echo "line $lineno ($tip): tip does not resolve in this repository — skipped" >&2
    bad=1
    continue
  fi
  base="$(git -C "$here" merge-base "$tip" "$integration_ref" 2>/dev/null)"
  if [ -z "$base" ] || [ "$base" = "$tip" ]; then
    base="$(git -C "$here" rev-parse "${tip}~1" 2>/dev/null)"
  fi
  if [ -z "$base" ]; then
    echo "line $lineno ($tip): no base could be established — skipped" >&2
    bad=1
    continue
  fi
  out="$(cargo run --quiet --manifest-path "$here/Cargo.toml" -p xtask -- \
    gate construction --raise-ledger "$base" "$tip" 2>&1)"
  code=$?
  # Every non-exact key line the run printed, prefixed with the queue line and its tip — one row
  # per line per non-exact key, which is the sweep's whole output.
  printf '%s\n' "$out" | grep -E '^qa/(construction|kind-isolation)\.toml:' | while IFS= read -r row; do
    printf 'line %s (%s): %s\n' "$lineno" "$tip" "$row"
  done
  if [ "$code" -ne 0 ]; then
    bad=1
  fi
done <"$lines_tsv"

exit "$bad"
