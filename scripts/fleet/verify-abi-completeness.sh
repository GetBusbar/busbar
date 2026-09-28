#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# ABI-COMPLETENESS GATE: refuse to build a plugin artifact whose source implements RecordStore
# methods that the PINNED busbar ABI cannot carry.
#
# WHY THIS EXISTS. `.busbar-ref` pins the exact busbar commit a release builds and packs against.
# The plugin's `impl RecordStore for ...` is compiled against `busbar-contract` from that commit, and
# the wire is the same crate's `store_dispatch` (crates/busbar-contract/src/abi/sdk/mod.rs) — the
# match arm that turns a decoded store request into a call on the store.
# `busbar_contract::records::RecordStore` gives several methods a DEFAULT body, so a method the pinned
# dispatch never routes does not fail to compile: it compiles, ships, signs, attests, and then
# silently takes the default at runtime. busbar 74a1f9fa ("a task written through a plugin store is
# no longer discarded") is exactly that failure, already shipped once: a store that implemented
# `put_task` perfectly had every task DISCARDED at the ABI while `put_task` reported success.
#
# That class of defect is invisible to every other gate in this repo. The test suite exercises the
# in-process trait; fmt/clippy/build cannot see it; verify-assets only proves an asset exists. So this
# script checks the one thing nothing else does:
#
#   for every method this repo implements in `impl RecordStore for <T>`,
#   the pinned busbar's crates/busbar-contract/src/abi/sdk/mod.rs must actually call `store.<method>(`.
#
# A method implemented here but unrouted there is a SILENT DATA-LOSS PATH. It is a hard failure.
#
# This is deliberately generic — it is not a list of task methods. Any future RecordStore method
# added to a plugin ahead of the pinned engine trips it the same way, so the gate cannot go stale the
# way a hardcoded pin can.
#
# Lives in busbar (scripts/fleet/) and is run by plugin-release.yml for every kind:store plugin, so
# the check exists once for the whole fleet.
#
# Usage: verify-abi-completeness.sh <path-to-plugin-repo> <path-to-busbar-checkout>
set -euo pipefail

plugin_root="${1:?usage: verify-abi-completeness.sh <plugin-repo> <busbar-checkout>}"
busbar_root="${2:?usage: verify-abi-completeness.sh <plugin-repo> <busbar-checkout>}"

sdk="${busbar_root}/crates/busbar-contract/src/abi/sdk/mod.rs"
[ -f "$sdk" ] || { echo "::error::not a contract-era busbar checkout: ${sdk} does not exist" >&2; exit 1; }
grep -q 'fn store_dispatch' "$sdk" || { echo "::error::${sdk} defines no store_dispatch — the parser is wrong, not the ABI" >&2; exit 1; }

# The single `impl RecordStore for <T>` block in this repo's store crate. Found, not hardcoded, so
# one script serves every store plugin.
impl_re='^impl ([A-Za-z_][A-Za-z0-9_]*::)*RecordStore for '
impl_file="$(grep -rlE --include='*.rs' "$impl_re" "$plugin_root" \
  | grep -v '/target/' | head -1 || true)"
[ -n "$impl_file" ] || { echo "::error::no 'impl RecordStore for' block found under ${plugin_root}" >&2; exit 1; }

# Slice the impl block: from `impl RecordStore for` to the first column-0 `}`, then take the method
# names.
methods="$(awk -v re="$impl_re" '$0 ~ re {inblock=1} inblock{print} inblock&&/^\}/{exit}' "$impl_file" \
  | sed -n 's/^    fn \([a-z0-9_]*\)(.*/\1/p' | sort -u)"
[ -n "$methods" ] || { echo "::error::parsed ZERO methods out of ${impl_file} — the parser is wrong, not the ABI" >&2; exit 1; }

echo "plugin store impl : ${impl_file}"
echo "pinned dispatch   : ${sdk}"
echo "methods implemented here: $(echo "$methods" | wc -l | tr -d ' ')"
echo

missing=""
for m in $methods; do
  if grep -q "store\.${m}(" "$sdk"; then
    echo "  ok      ${m}"
  else
    echo "  MISSING ${m}"
    missing="${missing} ${m}"
  fi
done

if [ -n "$missing" ]; then
  echo
  echo "::error::ABI-COMPLETENESS FAILURE. The pinned busbar commit's store_dispatch does not" \
       "route these RecordStore methods that this plugin implements:${missing}." \
       "Packing a cdylib against this ABI would ship a plugin whose calls to those methods take" \
       "RecordStore's DEFAULT bodies at runtime — succeeding silently while dropping the data." \
       "Do not release. Advance the fleet pin (plugins.yaml fleet.busbar_ref, then cargo xtask fleet sync) to a busbar commit whose" \
       "busbar-contract store_dispatch carries these methods." >&2
  exit 1
fi

echo
echo "ABI-completeness OK: every RecordStore method implemented here is routed by the pinned busbar's dispatch."
