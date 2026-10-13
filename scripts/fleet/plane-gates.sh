#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
#
# BUSBAR'S PLANE GATES OVER A PLANE REPO'S CHANGE (ARCHITECT row 106 (A), condition 7).
#
# A plane that left busbar for its own repo is read by busbar's gates from the pinned checkout,
# laid at crates/<package> as every gate's base layer. This runs three of those gates — plane-purity,
# structure-lint and config-schema — over a busbar checkout at the plane repo's pin TWICE: once over
# the plane busbar pins, and once with the plane repo's own logic crate laid in its place
# (BUSBAR_PLANE_SOURCE). A row that passes over the pin and does not pass over the change is RED:
# the plane is judged where its source changes, by the same rows busbar holds it to. A gate that
# answers nothing over the change (it refused the tree) is RED too.
#
# Usage (from the busbar checkout): plane-gates.sh <plugin repo dir> <logic package>
#        plane-gates.sh --selftest
set -euo pipefail

GATES=(plane-purity structure-lint config-schema)

# The rows of one TSV verdict that PASS, by id.
passing() { awk -F'\t' '$2 == "PASS" {print $1}' | sort -u; }

# The rows passing in $1 (the pin's verdict) that do not pass in $2 (the change's).
regressed() { comm -23 <(printf '%s\n' "$1" | passing) <(printf '%s\n' "$2" | passing); }

if [ "${1:-}" = "--selftest" ]; then
  rc=0
  pin=$'a:one\tPASS\tt\td\na:two\tPASS\tt\td\na:three\tFAIL\tt\td'
  same=$'a:one\tPASS\tt\td\na:two\tPASS\tt\td\na:three\tFAIL\tt\td'
  worse=$'a:one\tPASS\tt\td\na:two\tFAIL\tt\td\na:three\tFAIL\tt\td'
  if [ -n "$(regressed "$pin" "$same")" ]; then echo "  [FAILED] an unchanged verdict regressed"; rc=1; else echo "  [ok]     an unchanged verdict is green"; fi
  if [ "$(regressed "$pin" "$worse")" = "a:two" ]; then echo "  [ok]     a row that stopped passing is named"; else echo "  [FAILED] a row that stopped passing went unnamed"; rc=1; fi
  if [ "$(regressed "$pin" "")" = $'a:one\na:two' ]; then echo "  [ok]     a verdict that answers nothing loses every passing row"; else echo "  [FAILED] an empty verdict was not red"; rc=1; fi
  exit "$rc"
fi

plugin="${1:?usage: plane-gates.sh <plugin repo dir> <logic package>}"
package="${2:?usage: plane-gates.sh <plugin repo dir> <logic package>}"
xtask="${PLUGIN_GATES:-target/debug/xtask}"

dir="$(cargo metadata --format-version 1 --no-deps --manifest-path "$plugin/Cargo.toml" | python3 -I -c '
import json, os, sys
for p in json.load(sys.stdin)["packages"]:
    if p["name"] == sys.argv[1]:
        print(os.path.dirname(p["manifest_path"])); break
' "$package")"
[ -n "$dir" ] || { echo "::error::$plugin has no package $package"; exit 1; }

rc=0
for g in "${GATES[@]}"; do
  pin="$("$xtask" gate "$g" --format=tsv 2>/dev/null || true)"
  change="$(BUSBAR_PLANE_SOURCE="$package=$dir" "$xtask" gate "$g" --format=tsv 2>/dev/null || true)"
  [ -n "$pin" ] || { echo "::error::$g answered nothing over busbar at the pin"; rc=1; continue; }
  lost="$(regressed "$pin" "$change")"
  if [ -n "$lost" ]; then
    echo "::error::$g: rows that pass over busbar's pinned $package fail over this change: $(printf '%s ' $lost)"
    printf '%s\n' "$change" | awk -F'\t' -v ids="$(printf '%s ' $lost)" 'BEGIN{n=split(ids,a," "); for(i=1;i<=n;i++) want[a[i]]=1} ($1 in want) {print}' >&2
    rc=1
  else
    echo "$g: every row that passes over busbar's pinned $package passes over this change"
  fi
done
exit "$rc"
