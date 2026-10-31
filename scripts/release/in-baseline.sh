#!/usr/bin/env bash
# in-baseline.sh <command> [args...] - run a release command inside the pinned glibc baseline (W17).
#
# WHY. A linux-gnu binary requires the newest GLIBC_x.y symbol version of the glibc it was LINKED
# against, so the build host decides which distros can run it. A build on ubuntu-24.04 needs
# GLIBC_2.39 and will not start on RHEL 8, Debian 11 or Ubuntu 22.04, with no error at build time.
# Every linux-gnu row in .github/release-targets.json declares `glibc_max`; this runs the build in
# the image that row's floor names (`linux_build_image`: manylinux_2_28, glibc 2.28, GCC 14, binutils
# 2.41), digest-pinned, on the NATIVE architecture, so PGO training still runs the real binary.
# scripts/release-build.sh refuses a host glibc above `glibc_max`, and the `runtime_deps` contract
# row asserts the result on the shipped bytes: input, environment and output, all three.
#
# The container gets the repository at /w and a persistent cache (the Rust toolchain installed by the
# same sha-pinned BUSBAR_TOOL_SH every ModernCI check uses, and cargo's registry). It runs as the
# caller's uid, so everything it writes under target/ belongs to the caller.
#
# Usage, from a ModernCI check on a linux runner with docker:
#   scripts/release/in-baseline.sh python3 scripts/release/candidate.py core x86_64-unknown-linux-gnu --out DIR
#   scripts/release/in-baseline.sh scripts/release-build.sh aarch64-unknown-linux-gnu
#   scripts/release/in-baseline.sh scripts/release/dropin-probe.sh x86_64-unknown-linux-gnu OUT.tar.gz
set -euo pipefail
cd "$(dirname "$0")/../.."
[ $# -gt 0 ] || { echo "usage: in-baseline.sh <command> [args...]" >&2; exit 2; }

case "$(uname -m)" in
  x86_64|amd64) ARCH=x86_64 ;;
  aarch64|arm64) ARCH=aarch64 ;;
  *) echo "in-baseline.sh: no baseline image for $(uname -m)" >&2; exit 1 ;;
esac
IMAGE="$(python3 -c 'import json,sys; print(json.load(open(".github/release-targets.json"))["linux_build_image"][sys.argv[1]])' "$ARCH")"
case "$IMAGE" in
  *@sha256:????????????????????????????????????????????????????????????????) ;;
  *) echo "in-baseline.sh: linux_build_image.$ARCH must be digest-pinned (got '$IMAGE')" >&2; exit 1 ;;
esac

# The toolchain installer every check sources: .ci/tool.sh when the tree has one, else the
# BUSBAR_TOOL_SH the ModernCI branch file exports. Without either there is no pinned way to install
# Rust in the container, and an unpinned one is not offered.
if [ -f .ci/tool.sh ]; then
  TOOL_SH="$(cat .ci/tool.sh)"
elif [ -n "${BUSBAR_TOOL_SH:-}" ]; then
  TOOL_SH="$BUSBAR_TOOL_SH"
else
  echo "in-baseline.sh: neither .ci/tool.sh nor BUSBAR_TOOL_SH is available to install the pinned toolchain" >&2
  exit 1
fi

CACHE="${MODERNCI_CACHE_DIR:-$HOME/.cache}/busbar-baseline-$ARCH"
mkdir -p "$CACHE"

# Only the variables the release scripts read cross into the container; nothing else of the host's
# environment leaks into the build.
PASS=()
for v in BUSBAR_RELEASE_PUBKEY SOURCE_DATE_EPOCH PGO_TARGET PGO_TRAIN_ONLY BUSBAR_ARM64_BASELINE CYCLONEDX \
         CARGO_PROFILE_DEV_DEBUG CARGO_INCREMENTAL; do
  if [ -n "${!v+x}" ]; then PASS+=(-e "$v"); fi
done

echo "[in-baseline] $IMAGE ($ARCH): $*"
exec docker run --rm --platform "linux/$( [ "$ARCH" = x86_64 ] && echo amd64 || echo arm64 )" \
  -u "$(id -u):$(id -g)" -e HOME=/cache -e MODERNCI_CACHE_DIR=/cache -e BUSBAR_TOOL_SH="$TOOL_SH" \
  "${PASS[@]}" -v "$PWD:/w" -w /w -v "$CACHE:/cache" "$IMAGE" \
  bash -ec 'printf "[safe]\n\tdirectory = /w\n" > "$HOME/.gitconfig"
            _bbt_run() { eval "$BUSBAR_TOOL_SH"; }; _bbt_run rust
            ver="$(getconf GNU_LIBC_VERSION)"; echo "[in-baseline] container $ver"
            exec "$@"' in-baseline "$@"
