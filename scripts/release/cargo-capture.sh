#!/usr/bin/env bash
# Usage: cargo-capture.sh begin|end DIR MANIFEST [PLATFORM]
# Brackets the release `cargo build ... --message-format=json >DIR/cargo-messages.jsonl`, which
# stays a plain line in the caller. begin records the locked metadata and Cargo.lock in a fresh
# DIR; end refuses when either changed during the build. Evidence only: it signs nothing.
set -euo pipefail
dir="$2"
meta=(cargo metadata --locked --format-version 1 --manifest-path "$3" ${4:+--filter-platform "$4"})
lock="$(dirname "$(cargo locate-project --workspace --message-format plain --manifest-path "$3")")/Cargo.lock"
case "$1" in
  begin) mkdir "$dir" && "${meta[@]}" >"$dir/cargo-metadata.json" && cp "$lock" "$dir/Cargo.lock" ;;
  end)
    cmp -s "$lock" "$dir/Cargo.lock" || { echo "cargo-capture: lock changed during build" >&2; exit 1; }
    "${meta[@]}" | cmp -s - "$dir/cargo-metadata.json" \
      || { echo "cargo-capture: resolved Cargo metadata changed during build" >&2; exit 1; } ;;
  *) echo "usage: cargo-capture.sh begin|end DIR MANIFEST [PLATFORM]" >&2; exit 2 ;;
esac
