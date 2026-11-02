#!/usr/bin/env bash
# dropin-probe.sh <target-triple> <out.tar.gz> builds the actual pinned memory store for the
# shipped-binary drop-in load checks. The probe remains unsigned and uses its own alias so the
# loader trust checks stay separate from the library/open proof.
set -euo pipefail
cd "$(dirname "$0")/../.."
TRIPLE="${1:?usage: dropin-probe.sh <target-triple> <out.tar.gz>}"
OUT="${2:?usage: dropin-probe.sh <target-triple> <out.tar.gz>}"

ROOT="$PWD"
WORK="$(mktemp -d "${TMPDIR:-/tmp}/busbar-memory-probe.XXXXXX")"
trap 'rm -rf "$WORK"' EXIT
MEMORY_REV="$(python3 - <<'PY_PIN'
import pathlib, re, tomllib
manifest = tomllib.loads(pathlib.Path("dist/default/Cargo.toml").read_text())
source = manifest["workspace"]["dependencies"]["busbar-store-memory"]
assert source["git"].removesuffix(".git") == "https://git.getbusbar.dev/GetBusbar/busbar-store-memory"
assert re.fullmatch("[0-9a-f]{40}", source["rev"])
print(source["rev"])
PY_PIN
)"
git -C "$WORK" init --quiet
git -C "$WORK" remote add origin https://git.getbusbar.dev/GetBusbar/busbar-store-memory
git -C "$WORK" fetch --quiet --depth 1 --no-tags origin "$MEMORY_REV"
git -C "$WORK" -c advice.detachedHead=false checkout --quiet FETCH_HEAD
[ "$(git -C "$WORK" rev-parse HEAD)" = "$MEMORY_REV" ]
cargo build --release --locked --manifest-path "$WORK/Cargo.toml" \
  -p busbar-store-memory-plugin --lib --target "$TRIPLE" --target-dir "$ROOT/target/dropin-probe"
case "$TRIPLE" in
  *-windows-*) LIB="$ROOT/target/dropin-probe/$TRIPLE/release/busbar_store_memory_plugin.dll" ;;
  *-apple-*)   LIB="$ROOT/target/dropin-probe/$TRIPLE/release/libbusbar_store_memory_plugin.dylib" ;;
  *)           LIB="$ROOT/target/dropin-probe/$TRIPLE/release/libbusbar_store_memory_plugin.so" ;;
esac
[ -f "$LIB" ] || { echo "dropin-probe.sh: the build produced no actual memory cdylib at $LIB" >&2; exit 1; }

# The packer runs on the build host (it reads the library's own Statement), so it is built for the
# host, not for $TRIPLE.
cargo run --release --locked -p busbar-plugin-loader --features pack --bin busbar-plugin-pack -- pack \
  --lib "$LIB" --name busbar-dropin-probe --alias dropin-probe --kind store \
  --publisher busbar-dropin-probe --out "$OUT" --allow-unsigned
echo "dropin-probe.sh: $OUT ($TRIPLE)"
