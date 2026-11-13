#!/usr/bin/env python3
"""Capture and replay unsigned development artifact evidence, without release activation."""

import argparse
import gzip
import json
from pathlib import Path
import subprocess
import sys
import tarfile

# Isolated Python omits the script directory; load only protected adjacent modules.
sys.path.insert(0, str(Path(__file__).resolve().parent))

import build_closure
import cargo_capture
import native_provenance as p

CAPTURE = (
    "cargo-metadata.json",
    "Cargo.lock",
    "cargo-messages.jsonl",
    "build-context.json",
)
FILES = tuple("build/" + name for name in CAPTURE) + (
    "dependency-vector.json",
    "busbar-native.tar.gz",
    "build-closure.json",
    "sbom.cdx.json",
)


def regular(path, limit=64 * 1024**2):
    path = Path(path)
    p.require(
        path.is_file() and not path.is_symlink() and path.stat().st_size <= limit,
        "missing, indirect or oversized development evidence",
    )
    return path


def capture(directory, command):
    compiler = subprocess.check_output(["rustc", "-vV"], text=True)
    hosts = [
        line.removeprefix("host: ")
        for line in compiler.splitlines()
        if line.startswith("host: ")
    ]
    p.require(len(hosts) == 1, "compiler host is unavailable")
    target = (
        command[command.index("--target") + 1] if "--target" in command else hosts[0]
    )
    cargo_capture.capture(directory, command)
    p.write(
        Path(directory) / "build-context.json",
        p.canonical(
            {
                "command": command,
                "target": p.token(target),
                "rustc_verbose_version": compiler,
            }
        ),
    )


def derive(directory, binary, source, package, compiler_output):
    directory, binary = Path(directory), regular(binary, build_closure.MAX_FILE)
    for name in CAPTURE:
        regular(directory / "build" / name)
    context = p.load(directory / "build/build-context.json")
    metadata = p.load(directory / "build/cargo-metadata.json")
    versions = {
        row["version"] for row in metadata["packages"] if row["name"] == package
    }
    p.require(len(versions) == 1, "development package version is ambiguous")
    return build_closure.collect(
        directory / "busbar-native.tar.gz",
        directory / "build/cargo-metadata.json",
        directory / "build/Cargo.lock",
        directory / "build/cargo-messages.jsonl",
        binary,
        "busbar",
        package,
        source,
        context["target"],
        "busbar-development",
        next(iter(versions)),
        compiler_output=compiler_output,
    )


def verify(directory, binary, source, policy, sdk, receipt_sha256):
    """The caller obtains the receipt digest from the protected native job receipt."""
    directory = Path(directory)
    p.require(
        directory.is_dir() and not directory.is_symlink(), "indirect evidence directory"
    )
    receipt_path = regular(directory / "receipt.json")
    p.require(
        p.digest(receipt_path) == p.hex_value(receipt_sha256),
        "development receipt digest differs",
    )
    receipt = p.load(receipt_path)
    p.require(
        receipt.get("schema") == "busbar.development-artifact/1"
        and receipt.get("source") == p.hex_value(source, 40)
        and receipt.get("policy_revision") == p.hex_value(policy, 40)
        and receipt.get("sdk_revision") == p.hex_value(sdk, 40)
        and receipt.get("signed") is False
        and receipt.get("release_eligible") is False
        and receipt.get("supported_lifetime_retention_verified") is False,
        "development artifact identity or claim differs",
    )
    actual = {}
    for name in FILES:
        path = directory / name
        p.require(not path.parent.is_symlink(), "indirect evidence parent")
        regular(
            path, build_closure.MAX_FILE if name.endswith(".tar.gz") else 64 * 1024**2
        )
        actual[name] = {"sha256": p.digest(path), "size": path.stat().st_size}
    p.require(receipt.get("files") == actual, "development evidence bytes differ")
    p.require(
        p.digest(regular(binary, build_closure.MAX_FILE)) == receipt["binary_sha256"],
        "retained binary differs",
    )
    vector = p.load(directory / "dependency-vector.json")
    p.require(vector["sdk"] == sdk, "development vector uses another SDK")
    context = p.load(directory / "build/build-context.json")
    p.require(
        context["command"] == receipt["build_command"],
        "development build recipe differs",
    )
    closure = derive(
        directory, binary, source, receipt["package"], receipt["compiler_output"]
    )
    p.require(
        p.load(directory / "build-closure.json") == closure
        and p.load(directory / "sbom.cdx.json") == build_closure.sbom(closure),
        "SBOM does not describe the retained successful build",
    )
    return receipt


def finalize(
    directory,
    binary,
    source,
    policy,
    sdk,
    vector,
    package,
    compiler_output,
    command,
    retention_policy_sha256,
):
    """Controller-only: inputs have already crossed the bounded artifact collector."""
    directory, binary = Path(directory), regular(binary, build_closure.MAX_FILE)
    context = p.load(regular(directory / "build/build-context.json"))
    p.require(
        context["command"] == command,
        "captured build recipe differs from controller invocation",
    )
    data = p.load(vector)
    p.require(data["sdk"] == sdk, "development vector uses another SDK")
    p.write(directory / "dependency-vector.json", p.canonical(data))
    # Deterministic single-file archive, built from the collected binary only.
    with (directory / "busbar-native.tar.gz").open("xb") as stream:
        with gzip.GzipFile(
            fileobj=stream, mode="wb", filename="", mtime=0
        ) as compressed:
            with tarfile.open(fileobj=compressed, mode="w|") as archive:
                entry = tarfile.TarInfo("busbar")
                entry.mode, entry.size = 0o755, binary.stat().st_size
                with binary.open("rb") as compiled:
                    archive.addfile(entry, compiled)
    closure = derive(directory, binary, source, package, compiler_output)
    p.write(directory / "build-closure.json", p.canonical(closure))
    p.write(directory / "sbom.cdx.json", p.canonical(build_closure.sbom(closure)))
    receipt = {
        "schema": "busbar.development-artifact/1",
        "source": source,
        "policy_revision": policy,
        "sdk_revision": sdk,
        "package": package,
        "compiler_output": str(compiler_output),
        "build_command": command,
        "binary_sha256": p.digest(binary),
        "target": closure["target"],
        "files": {
            name: {
                "sha256": p.digest(directory / name),
                "size": (directory / name).stat().st_size,
            }
            for name in FILES
        },
        "signed": False,
        "release_eligible": False,
        "supported_lifetime_retention_verified": False,
        "retention_policy_sha256": p.hex_value(retention_policy_sha256),
        "inventory_scope": "cargo-compilation-including-build-tools",
    }
    p.write(directory / "receipt.json", p.canonical(receipt))
    return verify(
        directory, binary, source, policy, sdk, p.digest(directory / "receipt.json")
    )


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="operation", required=True)
    build = commands.add_parser("capture")
    build.add_argument("--directory", required=True, type=Path)
    build.add_argument("command", nargs=argparse.REMAINDER)
    for name in ("finalize", "verify"):
        action = commands.add_parser(name)
        for key in ("directory", "binary"):
            action.add_argument("--" + key, required=True, type=Path)
        for key in ("source", "policy", "sdk"):
            action.add_argument("--" + key, required=True)
        if name == "verify":
            action.add_argument("--receipt-sha256", required=True)
        else:
            action.add_argument("--vector", required=True, type=Path)
            for key in (
                "package",
                "compiler-output",
                "command-json",
                "retention-policy-sha256",
            ):
                action.add_argument("--" + key, required=True)
    args = vars(parser.parse_args())
    operation = args.pop("operation")
    if operation == "capture":
        command = args["command"]
        capture(args["directory"], command[1:] if command[:1] == ["--"] else command)
        print("development build capture complete; no signing performed")
        return
    elif operation == "finalize":
        args["command"] = json.loads(args.pop("command_json"))
        finalize(**args)
    else:
        verify(**args)
    print("development artifact evidence verified; unsigned, not release eligible")


if __name__ == "__main__":
    main()
