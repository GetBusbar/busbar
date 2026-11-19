#!/bin/sh
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DONE statement 7, THE COUNT: one fixed method, the same for every lean round.
#
#   count.sh <engine checkout> <plugin checkout> [<plugin checkout> ...] > COUNT.tsv
#
# The method is classify2.sh beside this file and nothing else: code lines of *.rs, where code is
# what is not a test (a file under tests/ or benches/ or named *_tests.rs, *_test.rs, tests.rs,
# test_*.rs, or an inline `#[cfg(test)] mod`), not a `///`, `//!` or `//` comment and not blank.
# Counted: the engine's `crates/` directory (not tools/, dist/ or testing/) and every Rust file of
# each plugin checkout given. By this method the figure of 18 Nov 2026 is 619,606
# (engine crates 478,687 + 35 plugin repositories 140,919).
#
# Output: one row per unit (an engine crate, or a plugin repository), then the three totals:
#   unit <name> <code lines>
#   total engine_crates <n>
#   total plugins <n>
#   total all <n>
# The caller checks each tree out at the ref the round measures; this script reads what is on
# disk and records each tree's commit in a `ref` row so two counts can be compared honestly.
set -eu
here=$(cd "$(dirname "$0")" && pwd)
engine=$1
shift

commit_of() {
  git -C "$1" rev-parse --short=10 HEAD 2>/dev/null || echo unknown
}

rows=$(mktemp "${TMPDIR:-/tmp}/lean-count.XXXXXX")
trap 'rm -f "$rows"' EXIT

printf 'ref\tengine\t%s\n' "$(commit_of "$engine")"
sh "$here/classify2.sh" "$engine" > "$rows"
awk '$1 ~ /^crates\// { split($1, part, "/"); by[part[2]] += $7 }
  END { for (crate in by) printf "unit\t%s\t%d\n", crate, by[crate] }' "$rows" | sort
engine_sum=$(awk '$1 ~ /^crates\// { total += $7 } END { printf "%d", total }' "$rows")

plugin_sum=0
for plugin in "$@"; do
  name=$(basename "$(cd "$plugin" && pwd)")
  n=$(sh "$here/classify2.sh" "$plugin" | awk '{ total += $7 } END { printf "%d", total }')
  printf 'ref\t%s\t%s\n' "$name" "$(commit_of "$plugin")"
  printf 'unit\t%s\t%d\n' "$name" "$n"
  plugin_sum=$((plugin_sum + n))
done

printf 'total\tengine_crates\t%d\n' "$engine_sum"
printf 'total\tplugins\t%d\n' "$plugin_sum"
printf 'total\tall\t%d\n' "$((engine_sum + plugin_sum))"
