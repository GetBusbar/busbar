#!/usr/bin/env bash
# §5.3.4 — THE COMPILE FENCE for the config-mutation transaction guard.
#
# `crates/busbar/src/admin/v1/json/tests/txn_fence.rs` is a NEGATIVE test: a transaction body that
# tries to reach a blocking store call (`store.list_keys()`, `txn.store()`) or to `.await` inside the
# section. It must FAIL to compile. This script builds it and inverts the verdict: a clean build is a
# FAILED fence, because it would mean `Txn` had grown a way to touch the store from the async thread
# (or the body had become async), re-opening the blocking-under-the-lock class.
#
# Why not `trybuild`: it builds ui cases as a crate that `use`s the crate under test, which needs a
# LIBRARY target. `busbar` is bin-only and the guard is `pub(crate)`, so no external crate can name
# it. Compiling the fence INSIDE the real crate checks the real `Txn`, not a copy of its signature.
set -euo pipefail
cd "$(dirname "$0")/.."

echo "== txn compile fence (this build MUST fail) =="
out=$(cargo check -p busbar --features txn-fence-red 2>&1) && status=0 || status=$?

if [ "$status" -eq 0 ]; then
  echo "  FENCE BREACHED: crates/busbar/src/admin/v1/json/tests/txn_fence.rs COMPILED."
  echo "  A transaction body must not be able to name a store, reach one through Txn, or .await."
  exit 1
fi

# Prove it failed for the RIGHT reasons, not because the file drifted into unrelated breakage.
missing=0
for want in \
  "cannot find value \`store\` in this scope" \
  "no method named \`store\` found" \
  "\`await\` is only allowed inside"
do
  if ! grep -qF "$want" <<<"$out"; then
    echo "  MISSING EXPECTED ERROR: $want"
    missing=1
  fi
done
if [ "$missing" -ne 0 ]; then
  echo "  The fence failed to compile, but not for the reasons it asserts. Full output:"
  echo "$out"
  exit 1
fi
echo "  ok — the body cannot name a store, cannot reach one through Txn, and cannot .await"
