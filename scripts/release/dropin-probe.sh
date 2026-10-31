#!/usr/bin/env bash
# dropin-probe.sh <target-triple> <out.tar.gz> - the stub plugin the `dropin_loads` and
# `image_dropin_loads` contract rows boot the shipped binary on (W17).
#
# It is the in-tree stub store (crates/plugin-loader/stubs/store), its DROPPED-IN door (feature
# `dropped-in`, exporting `busbar_plugin_door`), built for <target-triple> with the same rules as
# every plugin cdylib (on Linux inside the glibc baseline: run it through scripts/release/in-baseline.sh;
# on Windows +crt-static from .cargo/config.toml), and packed UNSIGNED under a name no linked store
# answers to. Unsigned on purpose: the row tests the loader (dlopen, door, open), and trust has its
# own rows; the probe config sets plugins.trust.allow_unsigned for it alone.
#
# The verifier configures `store.module: dropin-probe`. A configured store that cannot load refuses
# boot, so a binary that boots and answers /healthz has dlopened this library.
set -euo pipefail
cd "$(dirname "$0")/../.."
TRIPLE="${1:?usage: dropin-probe.sh <target-triple> <out.tar.gz>}"
OUT="${2:?usage: dropin-probe.sh <target-triple> <out.tar.gz>}"

cargo build --release --locked -p busbar-stub-store-plugin --features dropped-in \
  --target "$TRIPLE" --target-dir target/dropin-probe
case "$TRIPLE" in
  *-windows-*) LIB="target/dropin-probe/$TRIPLE/release/busbar_stub_store_plugin.dll" ;;
  *-apple-*)   LIB="target/dropin-probe/$TRIPLE/release/libbusbar_stub_store_plugin.dylib" ;;
  *)           LIB="target/dropin-probe/$TRIPLE/release/libbusbar_stub_store_plugin.so" ;;
esac
[ -f "$LIB" ] || { echo "dropin-probe.sh: the build produced no cdylib at $LIB" >&2; exit 1; }

# The packer runs on the build host (it reads the library's own Statement), so it is built for the
# host, not for $TRIPLE.
cargo run --release --locked -p busbar-plugin-loader --features pack --bin busbar-plugin-pack -- pack \
  --lib "$LIB" --name busbar-dropin-probe --alias dropin-probe --kind store \
  --publisher busbar-dropin-probe --out "$OUT" --allow-unsigned
echo "dropin-probe.sh: $OUT ($TRIPLE)"
