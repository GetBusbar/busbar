#!/usr/bin/env python3
"""Run required release engineering tests without creating release attestations.

Uses the existing protected offline instrument bundle when confined. The result
is test evidence only; the actual release subject remains unsigned/not-run.
"""

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import subprocess
import sys
import unittest

ROOT = Path(__file__).resolve().parents[2]
MODULES = [
    "test_build_closure",
    "test_cargo_capture",
    "test_release_producer",
    "test_release_verifier",
    "test_oci_provenance",
    "test_release_monitor",
    "test_audit_verifier_packaging",
    "test_security_gate",
    "test_artifacts",
    "test_scanner_retrieval",
    "test_development_stage",
]
MINIMUM_TESTS = 60


def digest(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def instruments():
    manifest = os.environ.get("BUSBAR_CONFORMANCE_INPUTS")
    if not manifest:
        if "CONFORMANCE_CAPABILITIES" in os.environ:
            raise ValueError("protected release engineering instruments required")
        return {"mode": "local", "manifest_sha256": None}
    data = json.loads(Path(manifest).read_text())
    bundle = data["bundles"]["release-engineering"]
    directory = Path(bundle["path"])
    arch = {"x86_64": "amd64", "aarch64": "arm64"}[platform.machine()]
    if platform.system() != "Linux" or sys.version_info[:2] != (3, 11):
        raise ValueError("offline release instruments require Linux Python 3.11")
    selected = "linux-" + arch + "/"
    files = {
        name: spec
        for name, spec in bundle["files"].items()
        if name.startswith(selected)
    }
    if selected + "bin/cosign" not in files or not files:
        raise ValueError("missing native Cosign instrument")
    for name, spec in files.items():
        path = directory / name
        if not path.is_file() or path.is_symlink() or digest(path) != spec["sha256"]:
            raise ValueError("protected release instrument changed")
    sys.path.insert(0, str(directory / selected / "python"))
    os.environ["PATH"] = (
        str(directory / selected / "bin") + os.pathsep + os.environ["PATH"]
    )
    return {
        "mode": "protected-offline",
        "manifest_sha256": digest(manifest),
        "bundle": "release-engineering",
        "cosign_sha256": files[selected + "bin/cosign"]["sha256"],
    }


def run(source, policy, output):
    if (
        subprocess.check_output(
            ["git", "-C", str(ROOT), "rev-parse", "HEAD"], text=True
        ).strip()
        != policy
    ):
        raise ValueError("engineering policy revision differs")
    runtime = instruments()
    import cryptography

    if runtime["mode"] == "protected-offline" and cryptography.__version__ != "50.0.2":
        raise ValueError("engineering cryptography version differs")
    sys.path[:0] = [str(ROOT / "scripts/release"), str(ROOT / "scripts/security")]
    files = {
        str(path.relative_to(ROOT)): digest(path)
        for directory in (ROOT / "scripts/release", ROOT / "scripts/security")
        for path in directory.glob("*.py")
    }
    for name in (
        "scripts/release-build.sh",
        "scripts/pgo-build.sh",
        "Dockerfile",
        "release/release-targets.json",
        "scripts/architecture/native_release_stage.py",
        "scripts/architecture/native.py",
        "testing/conformance/sigstore.py",
        "testing/conformance/slsa-verifier.sh",
    ):
        files[name] = digest(ROOT / name)
    suite = unittest.defaultTestLoader.loadTestsFromNames(MODULES)
    result = unittest.TextTestRunner(verbosity=2).run(suite)
    passed = (
        result.wasSuccessful()
        and result.testsRun >= MINIMUM_TESTS
        and not result.skipped
    )
    report = {
        "schema": "busbar.release-engineering/1",
        "status": "pass" if passed else "fail",
        "source": source,
        "policy_revision": policy,
        "modules": MODULES,
        "tests": result.testsRun,
        "failures": len(result.failures),
        "errors": len(result.errors),
        "skipped": len(result.skipped),
        "inputs": files,
        "runtime": runtime,
        "production_signing": False,
        "release_attestation_verified": False,
    }
    for name, expected in files.items():
        if digest(ROOT / name) != expected:
            raise ValueError("engineering source changed during tests")
    Path(output).write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
    return 0 if passed else 1


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", required=True)
    parser.add_argument("--policy", required=True)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    raise SystemExit(run(args.source, args.policy, args.output))
