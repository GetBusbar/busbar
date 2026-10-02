#!/usr/bin/env bash
set -u
rc() { echo "== $1 rc=$2"; }
cargo clippy -p xtask --all-targets --locked -- -D warnings 2>&1 | tail -40; rc clippy ${PIPESTATUS[0]}
cargo test -p xtask --lib --locked 2>&1 | grep -E "^test .*FAILED|panicked|^failures:|test result|^---- " | head -80; rc test-lib ${PIPESTATUS[0]}
for g in construction kind-isolation ship-ready; do
  cargo xtask gate $g 2>&1 | grep -E "FAIL|RED|GREEN" | cut -c1-300 | head -30; rc gate-$g ${PIPESTATUS[0]}
done
for g in construction kind-isolation ship-ready; do
  XTASK_GATE_CEILING_SECS_CONSTRUCTION=3600 XTASK_GATE_CEILING_SECS_KIND_ISOLATION=3600 cargo xtask gate $g --selftest 2>&1 | grep -E "FAIL|RED|GREEN|IMPOSSIBLE|infra|unproven|expected" | cut -c1-400 | head -60; rc selftest-$g ${PIPESTATUS[0]}
done
