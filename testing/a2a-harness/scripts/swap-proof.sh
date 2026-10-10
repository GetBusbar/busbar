#!/usr/bin/env bash
# Swap proof: six states the gate must distinguish.
#
# The point is not that the battery passes. It is that the battery produces a
# DIFFERENT, CORRECT verdict in each of six situations, using nothing but a
# changed endpoint or a changed pin. A gate that cannot tell these apart will
# eventually report green for all six.
set -uo pipefail
cd "$(dirname "$0")/.."
BIN="${A2AHT_CONTROL_BIN:-/tmp/a2abin}"
mkdir -p reports
pass=0; fail=0
check () { # name expected actual
  if [ "$2" = "$3" ]; then echo "  OK   $1 (exit $3)"; pass=$((pass+1));
  else echo "  BAD  $1 expected exit $2 got $3"; fail=$((fail+1)); fi
}

echo "=== 1. CONTROL: the known-good reference must be GREEN ==="
python3 -m a2aht run --launch "$BIN/a2a serve --echo --port 9401 --quiet" \
  --port 9401 --label "control:a2a-go@v2.4.0/rest" --tier pre-release \
  --client-drive "$BIN/a2a send {url} hello-from-harness" \
  --known-deviations baselines/known-deviations-a2a-go.json \
  --json reports/sp-control.json > reports/sp-1.txt 2>&1
check "control green" 0 $?
grep -E "BASELINED=|BATTERY" reports/sp-1.txt | tail -2 | sed 's/^/       /'

echo
echo "=== 2. NEGATIVE CONTROL: a broken peer must be RED ==="
python3 -m a2aht fake-peer --port 9402 --broken > /tmp/sp-broken.log 2>&1 &
BP=$!; sleep 2
python3 -m a2aht run --endpoint http://127.0.0.1:9402 \
  --label "negative-control" --tier pull-request --role server \
  --json reports/sp-negative.json > reports/sp-2.txt 2>&1
check "negative control fails" 1 $?
grep -E "FAIL=|BATTERY" reports/sp-2.txt | tail -1 | sed 's/^/       /'
kill $BP 2>/dev/null

echo
echo "=== 3. SUBJECT UNREACHABLE: must refuse, not pass vacuously ==="
python3 -m a2aht run --endpoint http://127.0.0.1:59999 --label subject \
  --tier every-commit > reports/sp-3.txt 2>&1
check "unreachable refused" 3 $?
grep -E "NOT REACHABLE|REFUSES" reports/sp-3.txt | head -2 | sed 's/^/       /'

echo
echo "=== 4. PIN DRIFT: control behaving differently from its baseline ==="
python3 - <<'PY'
import json
b = json.load(open("baselines/control-a2a-go-rest.json"))
for r in b["results"]:
    if r["id"] == "core.get_task_roundtrip":
        r["outcome"] = "FAIL"   # pretend the baseline recorded something else
json.dump(b, open("reports/sp-drifted-baseline.json", "w"))
PY
python3 -m a2aht baseline --report reports/sp-control.json \
  --baseline reports/sp-drifted-baseline.json > reports/sp-4.txt 2>&1
check "pin drift detected" 1 $?
grep -E "MISMATCH|core.get_task" reports/sp-4.txt | head -2 | sed 's/^/       /'

echo
echo "=== 5. STALE PIN: a deviation record that no longer matches reality ==="
cat > reports/sp-stale-dev.json <<'JSON'
{ "control": "stale pin demo", "spec": "v1.0.1", "recorded_by": "swap proof",
  "deviations": [
    { "test": "core.get_task_roundtrip", "verdict": "real-defect-in-control",
      "clause": "SPEC 3.1.3", "evidence": "this never happens",
      "judgement": "A record kept past its usefulness, to prove staleness is caught." } ] }
JSON
python3 -m a2aht run --launch "$BIN/a2a serve --echo --port 9403 --quiet" \
  --port 9403 --label "control + STALE deviation record" --tier pull-request \
  --role server --known-deviations reports/sp-stale-dev.json \
  --json reports/sp-stale.json > reports/sp-5.txt 2>&1
check "stale pin detected" 1 $?
grep -E "DEVIATION_FIXED|stale" reports/sp-5.txt | head -2 | sed 's/^/       /'

echo
echo "=== 6. UNRECORDED DEVIATION: baselining a subset must NOT buy green ==="
cat > reports/sp-partial-dev.json <<'JSON'
{ "control": "partial deviation demo", "spec": "v1.0.1", "recorded_by": "swap proof",
  "deviations": [
    { "test": "card.required_fields", "verdict": "real-defect-in-control",
      "clause": "PROTO AgentCard: version is REQUIRED; SPEC 5.7",
      "evidence": "missing REQUIRED field(s): version",
      "judgement": "Deliberately introduced by the broken peer." } ] }
JSON
python3 -m a2aht fake-peer --port 9404 --broken > /tmp/sp-broken2.log 2>&1 &
BP2=$!; sleep 2
python3 -m a2aht run --endpoint http://127.0.0.1:9404 \
  --label "broken peer + PARTIAL deviations" --tier pull-request --role server \
  --known-deviations reports/sp-partial-dev.json \
  --json reports/sp-partial.json > reports/sp-6.txt 2>&1
check "unrecorded deviation still red" 1 $?
grep -E "BASELINED=|BATTERY" reports/sp-6.txt | tail -1 | sed 's/^/       /'
kill $BP2 2>/dev/null

echo
echo "================================================================"
echo "SWAP PROOF: $pass of $((pass+fail)) states produced the correct verdict"
[ "$fail" -eq 0 ] || { echo "SWAP PROOF FAILED"; exit 1; }
echo "The gate distinguishes all six states. Aiming it is one variable."
echo "================================================================"
