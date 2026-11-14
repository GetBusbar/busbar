#!/bin/sh
# Deliver the busbar-ci controller for every trusted job, then run it.
# Usage: controller.sh TRUSTED WORK COMMAND [ARG...]  (called only by ci/architecture-pipeline.yml)
#
# controller.pin names one static, reproducible x86_64-musl binary by size and
# SHA-256, plus the digest of the exact build inputs it was produced from.
#   1. The pin is used only while its source digest equals the digest of this
#      trusted tools/ci tree: a pin left stale by a source change is never used.
#   2. The pinned binary is fetched from core's generic package registry with
#      the job token (sent only in a curl configuration read from stdin, never
#      in arguments, files or logs) and used only if size and SHA-256 match.
#   3. Otherwise it is rebuilt here, offline, from this trusted source in the
#      digest-pinned Rust image (build-controller.sh).
# The binary always lives under WORK (never TRUSTED or the candidate checkout).
set -eu
test "$#" -ge 3 || exit 2
trusted=$1 work=$2
shift 2
case "$trusted:$work" in /*:/*) ;; *) exit 2 ;; esac
src=$trusted/tools/ci
pin=$src/controller.pin
field() { sed -n "s/^$1=\\(.*\\)\$/\\1/p" "$pin"; }
image=$(field image) source=$(field source) expected=$(field sha256) bytes=$(field bytes) package=$(field package)
for digest in "$source" "$expected"; do
    test "${#digest}" -eq 64 || exit 1
    case "$digest" in *[!0-9a-f]*) exit 1 ;; esac
done
case "$bytes" in ''|*[!0-9]*) exit 1 ;; esac
case "$package" in
    https://git.getbusbar.dev/api/v4/projects/3/packages/generic/busbar-ci-controller/*/busbar-ci) ;;
    *) exit 1 ;;
esac
case "$package" in *[!A-Za-z0-9./:_-]*) exit 1 ;; esac
# Reject links rather than digesting or building source from elsewhere.
test -z "$(find "$src" -type l -print)"
# Build-input digest: sha256sum lines of every input in byte order, then the
# image reference. test_ci_bootstrap.py recomputes it against the pin.
actual=$(
    cd "$src"
    find Cargo.toml Cargo.lock build-controller.sh src -type f | LC_ALL=C sort | while IFS= read -r file; do
        sha256sum "$file"
    done
    printf 'image=%s\n' "$image"
) || exit 1
actual=$(printf '%s\n' "$actual" | sha256sum | cut -d ' ' -f 1)
controller=$work/controller
mkdir -m 700 "$controller"
binary=$controller/busbar-ci
fetched=
if test "$actual" != "$source"; then
    echo "busbar-ci controller pin is stale (source $actual, pinned $source); building it from trusted source"
elif command -v curl >/dev/null 2>&1 \
    && printf 'header = "JOB-TOKEN: %s"\n' "$CI_JOB_TOKEN" | curl --config - --silent --fail \
        --proto =https --max-time 60 --max-filesize "$bytes" --output "$binary" "$package" \
    && test "$(wc -c < "$binary" | tr -d ' ')" = "$bytes" \
    && test "$(sha256sum "$binary" | cut -d ' ' -f 1)" = "$expected"; then
    fetched=1
    echo "busbar-ci controller $expected fetched by pinned digest"
else
    echo "busbar-ci controller $expected unavailable from the package registry; building it from trusted source"
fi
if test -z "$fetched"; then
    rm -f -- "$binary"
    sh "$src/build-controller.sh" "$src" "$controller/build" unix:///var/run/docker.sock
    binary=$controller/build/busbar-ci
    built=$(sha256sum "$binary" | cut -d ' ' -f 1)
    test "$built" = "$expected" || echo "warning: rebuilt controller $built differs from pin $expected"
fi
chmod 0555 "$binary"
exec "$binary" "$@"
