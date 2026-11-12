#!/bin/sh
# Reproducibly build the static busbar-ci controller from trusted source in the
# digest-pinned Rust image: no network, no registry, no candidate input.
# Usage: build-controller.sh SOURCE_DIR OUTPUT_DIR DOCKER_HOST
#   SOURCE_DIR  trusted tools/ci directory (immutable policy checkout)
#   OUTPUT_DIR  fresh absolute directory; receives busbar-ci
#   DOCKER_HOST explicit unix:// endpoint (never inherited from the environment)
set -eu
test "$#" -eq 3 || exit 2
src=$1 out=$2 host=$3
case "$src:$out" in /*:/*) ;; *) exit 2 ;; esac
case "$host" in unix:///*) ;; *) exit 2 ;; esac
image=$(sed -n 's/^image=\(.*\)$/\1/p' "$src/controller.pin")
case "$image" in *[!a-z0-9./:@-]*|'') exit 1 ;; esac
case "${image#*@sha256:}" in "$image"|*[!0-9a-f]*) exit 1 ;; esac
test "${#image}" -gt 72
# Reject links rather than importing source or configuration from elsewhere.
test -z "$(find "$src" -type l -print)"
test ! -e "$out"
mkdir -m 700 "$out" "$out/home" "$out/target"
docker() {
    env -i PATH="$PATH" HOME="$out/home" DOCKER_CONFIG="$out/home" \
        docker --host "$host" "$@"
}
docker image inspect "$image" >/dev/null 2>&1 || docker pull -q --platform linux/amd64 "$image" >/dev/null
# Fixed in-container paths keep the output byte-reproducible across hosts.
docker run --rm --pull=never --platform linux/amd64 --network=none --read-only \
    --cap-drop=ALL --security-opt=no-new-privileges --pids-limit=512 --memory=3g \
    --user "$(id -u):$(id -g)" --tmpfs /tmp:rw,nosuid,nodev,size=1g,mode=1777 \
    --mount "type=bind,src=$src,dst=/src,readonly" \
    --mount "type=bind,src=$out/target,dst=/target" \
    -e HOME=/tmp -e CARGO_HOME=/tmp/cargo -e CARGO_TARGET_DIR=/target -e TMPDIR=/tmp \
    -e SOURCE_DATE_EPOCH=0 --workdir /src --entrypoint cargo "$image" \
    build --release --locked --offline --target x86_64-unknown-linux-musl >/dev/null 2>&1
cp "$out/target/x86_64-unknown-linux-musl/release/busbar-ci" "$out/busbar-ci"
chmod 0555 "$out/busbar-ci"
