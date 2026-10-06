set +e
S=$1; rm -rf .p6-red; git init -q && git add -A && git -c user.email=lk@lk -c user.name=lk commit -qm lk
export CARGO_TARGET_DIR=$PWD/target-rig
for s in $S; do
cargo xtask conformance record --suite $s --out /tmp/rec-$s > /tmp/rec-$s.log 2>&1
grep -E '^  (mcp|oidf):|^conformance record|subject leg' /tmp/rec-$s.log
python3 -c "import json;d=json.load(open('/tmp/rec-$s/$s.json'));print('VERDICT',d.get('status'),'|',str(d.get('reason'))[:1200])"
done
L=$CARGO_TARGET_DIR/conformance-record
[ -f $L/mcp/fixture-absence.log ] && { echo "== fixture-absence"; grep -E 'AXIS|FAIL|ok:|PASS|clean' $L/mcp/fixture-absence.log | tail -15; }
[ -f $L/oidf/run-oidf-oauth2.log ] && { echo "== oidf modules"; grep -E 'Test \[|FINISHED|FAILED|PASSED|WARNING|INTERRUPTED' $L/oidf/run-oidf-oauth2.log | tail -60; }
exit 0
