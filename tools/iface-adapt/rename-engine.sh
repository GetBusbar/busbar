#!/bin/sh
# The engine-side rename as one script. Run from the repository root.
# Usage: rename-engine.sh <directory holding the two .sed files>
set -eu
here=$1
skip='^crates/(busbar-plugin-abi|busbar-plugin-core|busbar-plugin-host|busbar-kind-[a-z-]+|busbar-ffi|busbar-plugin-test)/'
git grep -lE 'busbar_plugin_abi' -- 'crates/*.rs' 'dist/*.rs' 'tools/*.rs' | grep -Ev "$skip" > rename-rs.list || true
git grep -lE '^busbar-plugin-abi = ' -- 'crates/*Cargo.toml' 'dist/*Cargo.toml' | grep -Ev "$skip" > rename-toml.list || true
while read -r f; do sed -E -f "$here/rename-engine.sed" "$f" > "$f.renamed" && mv "$f.renamed" "$f"; done < rename-rs.list
while read -r f; do sed -E -f "$here/rename-cargo.sed" "$f" > "$f.renamed" && mv "$f.renamed" "$f"; done < rename-toml.list
echo "renamed: $(wc -l < rename-rs.list) source files, $(wc -l < rename-toml.list) manifests"
left=$(git grep -lE 'busbar_plugin_abi|^busbar-plugin-abi = ' -- 'crates/*.rs' 'dist/*.rs' 'tools/*.rs' 'crates/*Cargo.toml' 'dist/*Cargo.toml' | grep -Ev "$skip" | wc -l)
rm -f rename-rs.list rename-toml.list
echo "files still naming the old crate: $left"
test "$left" -eq 0
