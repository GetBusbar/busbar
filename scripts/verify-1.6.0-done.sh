#!/usr/bin/env bash
# SCRATCH DIAGNOSTIC (draft PR, never to land): why the A2A subject refuses the TCK's sends as
# decode_failed. Compact, at the very end of the log.
set -uo pipefail
cd "$(dirname "$0")/.."
R="$(pwd)"; D="$R/target/vd-diag"; rm -rf "$D"; mkdir -p "$D"
cargo build --release --locked -p busbar >"$D/build.out" 2>&1; brc=$?
W2="$D/tck"; mkdir -p "$W2"
A2A_SUBJECT_BUSBAR_BIN="$R/target/release/busbar" A2A_TCK_WORK="$W2" A2A_TCK_OUT="$W2/out" \
  bash scripts/a2a-subject/boot.sh --tck >"$D/tck.log" 2>&1
S=.a2a-conformance/subject-run
echo "######## SUMMARY ########"
echo "BUILD rc=$brc"; ls "$S" | tr '\n' ' '; echo
echo "== busbar.log refusals"; grep -iE "decode|refus|warn|error" "$S/busbar.log" | sed -E 's/\x1b\[[0-9;]*m//g; s/^[0-9TZ:.-]+ +//' | cut -c1-230 | sort | uniq -c | sort -rn | head -n 14
echo "== scenario agent"; tail -n 4 "$S/scenario-agent.log" 2>/dev/null | cut -c1-200
python3 - "$W2/out/subject.json" <<'PY'
import json,sys
try: d=json.load(open(sys.argv[1]))
except Exception as e: print("no report", e); sys.exit()
s=json.dumps(d)
for k in ["CORE-SEND-002","DM-MSG-001","CORE-GET-002"]:
    i=s.find('"%s"'%k); print(s[i:i+420])
PY
grep -n -iE "CORE-SEND-001" "$D/tck.log" | head -n 4 | cut -c1-230
exit 1
