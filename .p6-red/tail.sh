set +e
rm -rf .p6-red; git init -q && git add -A && git -c user.email=lk@lk -c user.name=lk commit -qm lk
export CARGO_TARGET_DIR=$PWD/target-rig
cargo xtask conformance record --suite oidf-oauth2 --out /tmp/rec > /tmp/rec.log 2>&1
L=$CARGO_TARGET_DIR/conformance-record/oidf/run-oidf-oauth2.log
grep -vE 'status changed to|Loading ' $L | tail -150
exit 0
