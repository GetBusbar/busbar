#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# PROVE THAT THE PINNED TIMEZONE STILL CHANGES THE ANSWER.
#
# The control legs run with TZ fixed to a NON-UTC zone. That looks like fussiness and it is not.
# a2a-go v2.4.0 serialises task status timestamps in the host's LOCAL zone instead of UTC, which
# violates SPEC 5.6.1 ("Timestamps MUST NOT include timezone offsets other than Z"). On a UTC host
# the local zone IS UTC, the offset is zero, the wire bytes end in `Z` anyway, and the defect
# DISAPPEARS. CI runners are UTC. So a suite that only ever ran in CI would have retired a real
# third-party finding without anyone noticing it had stopped looking.
#
# The `TZ:` line in the workflow is therefore load-bearing, and this script is the thing that keeps
# it load-bearing: it re-runs the same control under TZ=UTC and REQUIRES the pinned baseline to
# BREAK, on that exact test, in that exact direction. If the day comes that UTC and non-UTC agree,
# this script fails, and the failure means "the TZ pin is now decoration -- delete it or find out
# what changed", which is a far better outcome than a green tick over a setting nobody can justify.
#
# The check is therefore an assertion that a known failure still reproduces, held permanently
# rather than observed once and trusted thereafter.
set -uo pipefail

HERE="$(cd "$(dirname "$0")/.." && pwd)"
BIN="${A2AHT_CONTROL_BIN:-$HOME/.a2aht/bin}"
OUT="${A2AHT_OUT:-${TMPDIR:-/tmp}/a2aht-tz}"
PORT="${A2AHT_TZ_PORT:-9799}"
TEST_ID="core.timestamps_are_utc_z"
mkdir -p "$OUT"
cd "$HERE"

echo "=== TZ=UTC must BREAK the pinned control baseline, on ${TEST_ID} ==="
TZ=UTC python3 -m a2aht run \
  --launch "$BIN/a2a serve --echo --port $PORT --quiet" --port "$PORT" \
  --label "control:a2a-go/rest under TZ=UTC" --tier pre-release \
  --client-drive "$BIN/a2a send {url} tz-probe" \
  --known-deviations baselines/known-deviations-a2a-go.json \
  --json "$OUT/utc.json" --allow-red > "$OUT/utc-run.txt" 2>&1
run_rc=$?

if [ ! -s "$OUT/utc.json" ]; then
  echo "FAIL: the TZ=UTC control run produced no report (exit $run_rc). Nothing was proved." >&2
  tail -40 "$OUT/utc-run.txt" >&2
  exit 1
fi

python3 -m a2aht baseline --report "$OUT/utc.json" \
  --baseline baselines/control-a2a-go-rest.json > "$OUT/utc-baseline.txt" 2>&1
rc=$?
cat "$OUT/utc-baseline.txt"

if [ "$rc" -eq 0 ]; then
  cat >&2 <<EOF

FAIL: under TZ=UTC the control still MATCHED its pinned baseline.

That means the timezone the control legs run in no longer changes the verdict, so the \`TZ:\`
setting in the conformance workflow is proving nothing. Either a2a-go fixed its timestamp
serialisation (in which case re-record the baselines and delete the TZ pin and this script), or
the harness stopped checking SPEC 5.6.1 (in which case that is the bug).

Do NOT leave the TZ pin in place unexplained. A setting nobody can justify is a setting somebody
deletes during an unrelated cleanup, and the finding goes with it.
EOF
  exit 1
fi

if ! grep -q "$TEST_ID" "$OUT/utc-baseline.txt"; then
  cat >&2 <<EOF

FAIL: TZ=UTC did break the baseline, but NOT on ${TEST_ID}.

The point of this script is that ONE specific, understood, timezone-dependent finding moves. A
mismatch somewhere else means something unrelated is also broken and is being masked by this
expected failure. Read the mismatch above.
EOF
  exit 1
fi

if ! grep -qE "${TEST_ID}.*DEVIATION_FIXED" "$OUT/utc-baseline.txt"; then
  cat >&2 <<EOF

FAIL: ${TEST_ID} moved, but not to DEVIATION_FIXED.

Under UTC the recorded deviation should stop reproducing, which the harness reports as
DEVIATION_FIXED. Any other movement is a different fact and needs reading.
EOF
  exit 1
fi

echo
echo "OK: the timezone pin is load-bearing."
echo "    Under TZ=UTC, ${TEST_ID} reports DEVIATION_FIXED and the pinned baseline breaks."
echo "    The control legs' non-UTC TZ is what keeps SPEC 5.6.1 observable in CI."
