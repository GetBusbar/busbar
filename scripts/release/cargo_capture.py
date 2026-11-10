#!/usr/bin/env python3
"""Capture locked metadata and JSON messages from the actual final Cargo build.

Runs wherever the protected controller runs the build (including confinement).
It neither signs nor upgrades candidate-generated output to trusted observation.
"""

import argparse
from pathlib import Path
import shutil
import subprocess
import sys

import native_provenance as p


def capture(directory, command):
    p.require(
        command and command[0] == "build" and "--locked" in command,
        "locked Cargo build required",
    )
    p.require(
        not any(x.startswith("--message-format") for x in command),
        "capture owns Cargo message format",
    )
    options = []
    for key in ("--manifest-path", "--features", "--target"):
        if key in command:
            p.require(
                command.count(key) == 1 and command.index(key) + 1 < len(command),
                "duplicate build selection",
            )
            options.extend(
                [
                    "--filter-platform" if key == "--target" else key,
                    command[command.index(key) + 1],
                ]
            )
    options += [
        key
        for key in ("--all-features", "--no-default-features", "--offline", "--frozen")
        if key in command
    ]
    metadata = subprocess.check_output(
        ["cargo", "metadata", "--locked", "--format-version", "1", *options]
    )
    document = p.decode(metadata)
    lock = Path(document["workspace_root"]) / "Cargo.lock"
    before_lock = lock.read_bytes()
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=False)
    try:
        (directory / "cargo-metadata.json").write_bytes(metadata)
        (directory / "Cargo.lock").write_bytes(before_lock)
        with (directory / "cargo-messages.jsonl").open("xb") as stream:
            result = subprocess.run(
                ["cargo", *command, "--message-format=json"], stdout=stream
            )
        p.require(result.returncode == 0, "Cargo build failed")
        p.require(lock.read_bytes() == before_lock, "lock changed during build")
        after = subprocess.check_output(
            ["cargo", "metadata", "--locked", "--format-version", "1", *options]
        )
        p.require(after == metadata, "resolved Cargo metadata changed during build")
    except BaseException:
        shutil.rmtree(directory)
        raise


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", required=True, type=Path)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    capture(
        args.directory, args.command[1:] if args.command[:1] == ["--"] else args.command
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("cargo-capture: refused (" + type(error).__name__ + ")", file=sys.stderr)
        sys.exit(1)
