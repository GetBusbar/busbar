set +e
rm -rf .p6-red; git init -q && git add -A && git -c user.email=lk@lk -c user.name=lk commit -qm lk
export CARGO_TARGET_DIR=$PWD/target-rig
cargo xtask conformance record --suite mcp --out /tmp/rec > /tmp/rec.log 2>&1
L=$CARGO_TARGET_DIR/conformance-record/mcp
echo "== battery-subject"; grep -vE ' INFO | DEBUG ' $L/battery-subject.log | grep -iE 'fail|red|error|✗|not ok|FAIL' | head -40; grep -vE ' INFO | DEBUG ' $L/battery-subject.log | tail -30
echo "== fixture-absence"; grep -vE ' INFO | DEBUG ' $L/fixture-absence.log | tail -40
exit 0
