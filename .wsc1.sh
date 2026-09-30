#!/bin/bash
# WIRE-STORE C1 proof: one job (PROOF POLICY)
set +e
export CI=1 XTASK_CEILING_BASE=23d8a6b46
step() { n=$1; shift; "$@" > /tmp/$n.log 2>&1; rc=$?; echo "== $n rc=$rc"; return 0; }
step build cargo build --workspace --all-targets
grep -E "^error" -A8 /tmp/build.log | head -20
step fmt cargo fmt --all -- --check
step test cargo test -p busbar-store-memory -p busbar-plugin-loader -p busbar-contract --no-fail-fast
grep -E "^error|^test .*FAILED|test result: FAILED" -A3 /tmp/test.log | head -20
grep -E "Running tests/store_money_acceptance" -A300 /tmp/test.log | grep -m1 "test result"
grep -E "legacy_usage::row_tests|miscount" /tmp/test.log | head
step drop cargo test -p busbar-store-memory --features dropped-in,cold-dropped-in --test dropped_in_door
step clippy cargo clippy -p busbar-store-memory -p busbar-plugin-loader -p busbar-contract --all-targets -- -D warnings
grep -E "^(error|warning)" -A6 /tmp/clippy.log | head -20
step clippy_door cargo clippy -p busbar-store-memory --features dropped-in --all-targets -- -D warnings
for g in "construction --posture" "kind-isolation --posture" "qa-names --posture" abi-location; do
  n=gate_$(echo $g | tr " -" "__"); step $n cargo xtask gate $g
  grep -E "posture: (NEW|RISE)|^(FAIL|RED) " /tmp/$n.log | head -8
done
step hygiene python3 scripts/public-hygiene-lint.py --root .
grep -E "public file|hit\(s\)" /tmp/hygiene.log | head -5
