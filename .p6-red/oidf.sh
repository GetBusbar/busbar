set +e
rm -rf .p6-red; git init -q && git add -A && git -c user.email=lk@lk -c user.name=lk commit -qm lk
export CARGO_TARGET_DIR=$PWD/target-rig
cargo xtask conformance record --suite oidf-oauth2 --out /tmp/rec > /tmp/rec.log 2>&1
L=$CARGO_TARGET_DIR/conformance-record/oidf
echo "== run-oidf-oauth2.log"; head -80 $L/run-oidf-oauth2.log
ls $L; for f in $L/subject*.log $L/*boot*.log; do [ -f "$f" ] && { echo "== $f"; grep -vE ' INFO | DEBUG ' "$f" | tail -20; }; done
exit 0
