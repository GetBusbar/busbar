unset CARGO_TARGET_DIR
export XTASK_SHIP_TARGET=predev
cargo fmt --all --check > .fmt.log 2>&1; echo "STEP-RC FMT $?"
cargo clippy -p xtask --all-targets -- -D warnings > .xc.log 2>&1; echo "STEP-RC CLIPPY $?"; grep -E '^(error|warning)' -A8 .xc.log | head -40
for g in workflow-rules package-selectors qa-names design-bindings service-images; do cargo xtask gate $g > .g.log 2>&1; echo "STEP-RC GATE $g $?"; grep -v "^PASS" .g.log | tail -8 | cut -c1-300; done
cargo test -p xtask --lib > .xt.log 2>&1; echo "STEP-RC XTASK-LIB $?"; grep -E "FAILED|test result" .xt.log | head
cargo xtask selftest > .st.log 2>&1; echo "STEP-RC SELFTEST $?"; tail -2 .st.log | cut -c1-200
bash scripts/plugin-registry-check.sh --selftest > .p.log 2>&1; echo "STEP-RC PRC $?"
bash scripts/ci-branch-protection.sh --selftest > .p.log 2>&1; echo "STEP-RC CBP $?"
echo JOB-DONE
