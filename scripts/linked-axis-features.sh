#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# linked-axis-features.sh <axis> — the root package's DEFAULT features that carry linked axis <axis>,
# as a comma-separated `busbar/<feature>` list (empty when none).
#
# THE ONE SOURCE for "which default rows of an axis does a build keep". crates/busbar/Cargo.toml's
# `[package.metadata.busbar.linked-axes]` names every linked row's axes, and its `[features] default`
# names what ships; a CI row that varies one axis (the single-plane feature sets vary planes) keeps
# the others by reading them from here, so a new default export sink is carried by every such row
# without a workflow edit. `cargo xtask gate feature-sets` computes the same list the same way and
# reds a row whose effective feature list misses one.
#
# Usage: scripts/linked-axis-features.sh exports
#        scripts/linked-axis-features.sh --selftest
set -euo pipefail
cd "$(dirname "$0")/.."

derive() {  # derive <manifest> <axis>
  python3 - "$1" "$2" <<'PY'
import sys, tomllib
manifest, axis = sys.argv[1], sys.argv[2]
m = tomllib.load(open(manifest, "rb"))
default = set(m.get("features", {}).get("default", []))
axes = m.get("package", {}).get("metadata", {}).get("busbar", {}).get("linked-axes", {})
if not axes:
    sys.exit(f"{manifest}: no [package.metadata.busbar.linked-axes] table — nothing to derive from")
print(",".join(f"busbar/{f}" for f, a in axes.items() if axis in a.split() and f in default))
PY
}

if [ "${1:-}" = "--selftest" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  cat > "$tmp/Cargo.toml" <<'TOML'
[package]
name = "busbar"
[features]
default = ["export-a", "export-b", "plane-x"]
export-a = []
export-b = []
export-c = []
plane-x = []
[package.metadata.busbar.linked-axes]
export-a = "exports"
export-b = "exports"
export-c = "exports"
plane-x = "plane claims"
TOML
  got="$(derive "$tmp/Cargo.toml" exports)"
  [ "$got" = "busbar/export-a,busbar/export-b" ] || { echo "linked-axis-features selftest: FAILED — got '$got'"; exit 1; }
  printf '[package]\nname = "busbar"\n' > "$tmp/bare.toml"
  if derive "$tmp/bare.toml" exports >/dev/null 2>&1; then
    echo "linked-axis-features selftest: FAILED — a manifest with no linked-axes table derived a list"; exit 1
  fi
  echo "linked-axis-features selftest: default rows of the axis only (non-default and other axes left out); a missing table is refused"
  exit 0
fi

[ -n "${1:-}" ] || { echo "usage: $0 <axis> | --selftest" >&2; exit 2; }
derive crates/busbar/Cargo.toml "$1"
