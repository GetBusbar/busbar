set +e
rm -rf .p6-red; git init -q && git add -A && git -c user.email=lk@lk -c user.name=lk commit -qm lk
export CARGO_TARGET_DIR=$PWD/target-gate
cargo clippy -p xtask --all-targets -- -D warnings > /tmp/c.log 2>&1; echo "CLIPPY_RC=$?"
cargo test -p xtask --test conformance_rigs 2>&1 | grep -E '^test result|FAILED'
cargo xtask gate --all --format=tsv > /tmp/gate.tsv 2>/tmp/gate.err; echo "GATE_RC=$?"; cat /tmp/gate.tsv
exit 0
