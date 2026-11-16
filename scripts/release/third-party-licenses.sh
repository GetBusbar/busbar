#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# usage: third-party-licenses.sh <target-triple> <out-file>
# Writes the third-party attribution for every non-workspace crate in the locked graph for the
# target: name, version, SPDX expression and the full text of each LICENSE/COPYING/NOTICE file
# the crate ships. Shipped in every release archive and image beside LICENSE and NOTICE.
set -euo pipefail
cd "$(dirname "$0")/../.."
TARGET="${1:?target triple}"; OUT="${2:?out file}"
{ echo "Third-party software included in Busbar ($TARGET build)"; echo
  cargo metadata --locked --format-version 1 --filter-platform "$TARGET" \
    | jq -r '.packages[] | select(.source != null) | [.name, .version, (.license // "SEE LICENSE FILE"), (.manifest_path | sub("/Cargo.toml$"; ""))] | @tsv' | sort -u \
    | while IFS=$'\t' read -r name version license dir; do
        printf '================================================================\n%s %s\nLicense: %s\n\n' "$name" "$version" "$license"
        for f in "$dir"/LICENSE* "$dir"/LICENCE* "$dir"/COPYING* "$dir"/UNLICENSE* "$dir"/NOTICE*; do
          [ -f "$f" ] && { printf -- '--- %s ---\n' "$(basename "$f")"; cat "$f"; echo; }
        done
      done; } > "$OUT"
[ "$(grep -c '^License: ' "$OUT")" -gt 50 ] || { echo "third-party-licenses: implausibly few crates" >&2; exit 1; }
