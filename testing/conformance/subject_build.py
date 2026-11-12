#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""THE SHARED SUBJECT BUILDS of busbar's own core suites (core only: not rendered into plugins).

    python3 -I testing/conformance/subject_build.py busbar   # build dist/default busbar, print its path

tls, h2, oidf-oauth2 and the three evidence suites all judge the same subject: dist/default's shipped
`busbar`, plus (oidf-oauth2, evidence-rbac) busbar's OIDC module packed by the candidate's own
`busbar-plugin-pack`. testing/conformance/run.sh runs those suites one after another in one
CARGO_TARGET_DIR. Every suite builds each artefact with exactly the argv defined here, into exactly
the directory defined here, so the first suite that needs one compiles it and every later suite's
Cargo invocation is a freshness check over the current inputs (still always run before readback, so
a stale artefact is never judged). A per-suite flag, target directory or source path would change
Cargo's fingerprints and recompile the same graph again.
"""
import os
import subprocess
import sys
import time

# Full signed-history checks run in the functional subject (evidence-audit-trail). Optimize only the
# signature implementation, preserving dev assertions and every strict check; unoptimized vector
# arithmetic can otherwise consume the HTTP test budget. Applied to the one shared dist/default
# build, so every suite judges the same binary and none recompiles the crypto crates' dependents.
CRYPTO_OPT = ("--config", "profile.dev.package.ed25519-dalek.opt-level=3",
              "--config", "profile.dev.package.curve25519-dalek.opt-level=3")

OIDC_PACKAGE = "busbar-auth-oidc-plugin"


def target_root(checkout):
    return os.environ.get("CARGO_TARGET_DIR") or os.path.join(checkout, "target")


def busbar_argv(checkout, target):
    """The binary busbar SHIPS: the distribution workspace dist/default (its own lock), in a target
    directory of its own so it never relinks over the root workspace's core-only `busbar`."""
    return ["cargo", "build", "--locked", "--manifest-path", os.path.join(checkout, "dist", "default", "Cargo.toml"),
            "--target-dir", os.path.join(target, "dist-default"), "--bin", "busbar", *CRYPTO_OPT]


def busbar_path(target):
    return os.path.join(target, "dist-default", "debug", "busbar")


def pack_argv(target):
    """The candidate's own plugin packer, from the root workspace (run with cwd = the checkout)."""
    return ["cargo", "build", "--locked", "--target-dir", target, "-p", "busbar-plugin-loader",
            "--features", "pack", "--bin", "busbar-plugin-pack"]


def pack_path(target):
    return os.path.join(target, "debug", "busbar-plugin-pack")


def oidc_source(target, rev):
    """One fixed build copy of the pinned OIDC module source per rev: Cargo fingerprints a path
    package by its location, so every suite must build the module from this same path."""
    return os.path.join(target, "oidc-module-src", rev[:12])


def oidc_argv(source, target, patches):
    return ["cargo", "build", "--manifest-path", os.path.join(source, "Cargo.toml"), "-p", OIDC_PACKAGE,
            *patches, "--target-dir", os.path.join(target, "oidf-oidc-plugin")]


def oidc_library(target):
    name = "libbusbar_auth_oidc_plugin." + ("dylib" if sys.platform == "darwin" else "so")
    return os.path.join(target, "oidf-oidc-plugin", "debug", name)


def log_size(log):
    try:
        return os.path.getsize(log)
    except OSError:
        return 0


def summary(argv, log, offset, seconds):
    """One public line per build: how many crates it compiled (0 = reused) and how long it took."""
    compiled = 0
    try:
        with open(log, "rb") as stream:
            stream.seek(offset)
            compiled = sum(1 for line in stream if line.lstrip().startswith(b"Compiling "))
    except OSError:
        pass
    what = argv[argv.index("--bin") + 1] if "--bin" in argv else argv[argv.index("-p") + 1]
    return f"subject build {what}: {compiled} crate(s) compiled in {seconds:.0f}s"


def main(argv):
    if argv != ["busbar"]:
        print("usage: subject_build.py busbar", file=sys.stderr)
        return 2
    checkout = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
    target = target_root(checkout)
    command = busbar_argv(checkout, target)
    start = time.monotonic()
    rc = subprocess.call(command, cwd=checkout, stdin=subprocess.DEVNULL, stdout=sys.stderr)
    print(f"subject build busbar: exit {rc} in {time.monotonic() - start:.0f}s", file=sys.stderr)
    if rc != 0:
        return rc
    print(busbar_path(target))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
