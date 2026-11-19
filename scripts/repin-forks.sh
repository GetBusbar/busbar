#!/bin/sh
# scripts/repin-forks.sh <repository checkout>...: move every fork pin of scripts/fork-pins.tsv from its
# old revision to its new one in each checkout's manifests (every Cargo.toml, fuzz manifests too).
# Text edits only: no cargo runs here. Afterwards, on a build machine, in each checkout:
#   cargo update -p http -p h2 -p hyper -p hyper-util -p serde-saphyr -p granit-parser   (those it locks)
# Prints one line per manifest changed, and fails if a checkout still names an old revision.
set -eu
pins=$(cd "$(dirname "$0")" && pwd)/fork-pins.tsv
left=0
for repo in "$@"; do
  grep -v '^#' "$pins" | while IFS="$(printf '\t')" read -r fork old new branch; do
    git -C "$repo" grep -lF "$old" -- '*Cargo.toml' | while read -r manifest; do
      sed "s/$old/$new/g" "$repo/$manifest" > "$repo/$manifest.new" && cat "$repo/$manifest.new" > "$repo/$manifest" && rm "$repo/$manifest.new"
      echo "$(basename "$repo")/$manifest: $fork $branch"
    done
  done
  if grep -v '^#' "$pins" | cut -f2 | git -C "$repo" grep -nFf - -- '*Cargo.toml'; then left=1; fi
done
exit "$left"
