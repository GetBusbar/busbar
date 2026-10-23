#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): the Twilio metering leg's line diff, and why the A2A
# TCK subject and the battery's deep-nesting case fail. Compact output at the end of the log.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
bash testing/voice-conformance/voice-conformance.sh --leg twilio-metering >"$D/meter.out" 2>&1
cargo build --release --locked -p busbar >"$D/build.out" 2>&1
A2A_SUBJECT_BUSBAR_BIN="$R/target/release/busbar" A2A_TCK_WORK="$D/tck" A2A_TCK_OUT="$D/tck/out" \
  bash scripts/a2a-subject/boot.sh --tck >"$D/tck.log" 2>&1
echo "######## SUMMARY ########"
python3 - "$D/meter.out" <<'PY'
import sys
t=open(sys.argv[1],encoding="utf-8",errors="replace").read()
def lst(s, i):
    j=s.index("[", i); depth=0; q=False; k=j
    while True:
        c=s[k]
        if q:
            if c=="\\": k+=1
            elif c=='"': q=False
        elif c=='"': q=True
        elif c=="[": depth+=1
        elif c=="]":
            depth-=1
            if depth==0: return s[j:k+1], k+1
        k+=1
try:
    a,e=lst(t, t.index("the session reported "))
    b,_=lst(t, t.index("want ", e))
    import json
    got=json.loads(a); want=json.loads(b)
    for i,(g,w) in enumerate(zip(got,want)):
        if g!=w: print(f"METER[{i}] got {g[:140]}\n         want {w[:140]}")
    if len(got)!=len(want): print("METER len", len(got), len(want))
except Exception as ex:
    print("METER parse", ex); print(t[-600:])
PY
grep -E "^(FAILED|ERROR) " "$D/tck.log" | head -n 3 | cut -c1-230
grep -E "^E  " "$D/tck.log" | sort | uniq -c | sort -rn | head -n 6 | cut -c1-230
grep -iE "passed|failed" "$D/tck.log" | tail -n 2 | cut -c1-200
grep -iE "deep_nesting" -A3 testing/a2a-harness/reports/subject.json 2>/dev/null | head -n 6 | cut -c1-230
exit 1
