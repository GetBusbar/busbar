#!/usr/bin/env bash
# Build only owner-declared test artifacts from the admitted immutable product vector.
# stdout is the generated data-only JSON file; build output goes to stderr.
set -eo pipefail
root=$(git rev-parse --show-toplevel)
target="${CARGO_TARGET_DIR:-$root/target}"
helper="$(dirname "$0")/architecture/product_artifacts.py"
exec python3 "$helper" --root "$root" --target "$target" --cache "${MODERNCI_CACHE_DIR:-$target}"
