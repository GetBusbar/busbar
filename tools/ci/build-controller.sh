#!/bin/sh
# Called only after the scheduler-selected immutable policy has been checked out.
# The caller supplies a fresh external directory, never the candidate workspace.
set -eu
test "$#" -eq 2 || exit 2
trusted=$1
build=$2
case "$trusted:$build" in /*:/*) ;; *) exit 2 ;; esac
test -d "$trusted/tools/ci"
test ! -e "$build"
mkdir -m 700 "$build"
mkdir -m 700 "$build/home" "$build/cargo-home" "$build/tmp"
# Reject links rather than importing configuration/source from outside the policy.
test -z "$(find "$trusted/tools/ci" -type l -print)"
cp "$trusted/tools/ci/Cargo.toml" "$trusted/tools/ci/Cargo.lock" "$build/"
cp -R "$trusted/tools/ci/src" "$build/src"
cd "$build"
# No candidate .cargo configuration, rust-toolchain, environment, registry token,
# wrapper, linker override or build output is consulted. Rustup is preinstalled
# on the existing native worker; this command does not install or upgrade it.
env -i PATH=/opt/cargo/bin:/usr/bin:/bin \
    HOME="$build/home" CARGO_HOME="$build/cargo-home" \
    RUSTUP_HOME=/opt/rustup RUSTUP_TOOLCHAIN=1.98.0 RUSTUP_AUTO_INSTALL=0 \
    TMPDIR="$build/tmp" LC_ALL=C.UTF-8 \
    /opt/cargo/bin/cargo build --locked --manifest-path "$build/Cargo.toml" \
        --target-dir "$build/target"
test -x "$build/target/debug/busbar-ci"
