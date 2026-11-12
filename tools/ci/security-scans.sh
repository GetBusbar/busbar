#!/bin/sh
# Run the security-scans job from the verified immutable policy checkout.
# Usage: security-scans.sh TRUSTED WORK   (called only by ci/architecture-pipeline.yml)
#
# The controller binary is digest-pinned in controller.pin. It is fetched from
# core's existing generic package registry with the job token (sent only in a
# curl configuration read from stdin, never in arguments, files or logs) and is
# used only if its size and SHA-256 equal the pin. Otherwise it is rebuilt here,
# offline, from this trusted source in the pinned Rust image (build-controller.sh).
set -eu
test "$#" -eq 2 || exit 2
trusted=$1 work=$2
pin=$trusted/tools/ci/controller.pin
field() { sed -n "s/^$1=\\(.*\\)\$/\\1/p" "$pin"; }
expected=$(field sha256) bytes=$(field bytes) package=$(field package)
test "${#expected}" -eq 64
case "$expected" in *[!0-9a-f]*) exit 1 ;; esac
case "$bytes" in ''|*[!0-9]*) exit 1 ;; esac
case "$package" in
    https://github.com/api/v4/projects/3/packages/generic/busbar-ci-controller/*/busbar-ci) ;;
    *) exit 1 ;;
esac
case "$package" in *[!A-Za-z0-9./:_-]*) exit 1 ;; esac
controller=$work/controller
mkdir -m 700 "$controller"
binary=$controller/busbar-ci
if command -v curl >/dev/null 2>&1 && command -v sha256sum >/dev/null 2>&1 \
    && printf 'header = "JOB-TOKEN: %s"\n' "$CI_JOB_TOKEN" | curl --config - --silent --fail \
        --proto =https --max-time 60 --max-filesize "$bytes" --output "$binary" "$package" \
    && test "$(wc -c < "$binary" | tr -d ' ')" = "$bytes" \
    && test "$(sha256sum "$binary" | cut -d ' ' -f 1)" = "$expected"; then
    echo "busbar-ci controller $expected fetched by pinned digest"
else
    rm -f -- "$binary"
    echo "busbar-ci controller $expected unavailable from the package registry; building it from trusted source"
    sh "$trusted/tools/ci/build-controller.sh" "$trusted/tools/ci" "$controller/build" unix:///var/run/docker.sock
    binary=$controller/build/busbar-ci
    built=$(sha256sum "$binary" | cut -d ' ' -f 1)
    test "$built" = "$expected" || echo "warning: rebuilt controller $built differs from pin $expected"
fi
chmod 0555 "$binary"
"$binary" security-scans --trusted "$trusted" --checkout "$CI_PROJECT_DIR" --work "$work" \
    --output "$CI_PROJECT_DIR/boundary-evidence/security.json"
