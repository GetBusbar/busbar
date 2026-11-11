#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Verify a released blob's keyless Sigstore bundle, including its transparency proof.

This is a release-stage check. Missing release inputs are not-run, never pass.
It establishes signing of the approved artifact, not an independently issued
company certification or a SLSA build level.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import shutil
import subprocess
import tempfile
import urllib.request

VERSION = "v2.6.5"
TOOLS = {
    ("Linux", "x86_64"): ("linux-amd64", "c3b4f5410e608af03a5eb0aaac84a4313d8da131248e08ff1759ac70c79d1644"),
    ("Linux", "aarch64"): ("linux-arm64", "426193b4c5da4d4d643e822f48fe0cc8a476ca1782a272704831f5a0cef716d7"),
    ("Darwin", "x86_64"): ("darwin-amd64", "0f8a1a70c81de9740a2b62e91307ff396ce54e7dd80568d42411bb2d9d44269c"),
    ("Darwin", "arm64"): ("darwin-arm64", "4d41cc18f0563907c0c785b51db76e1d1af10db4422b605ba876b1758e1771ab"),
}


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def check_receipt(receipt, artifact, head):
    if not isinstance(receipt, dict):
        raise ValueError("release receipt must be an object")
    if receipt.get("sha") != head:
        raise ValueError("release receipt does not name the current source commit")
    if receipt.get("artifact_sha256") != digest(artifact):
        raise ValueError("release receipt does not name these exact artifact bytes")


def verify(tool, bundle, artifact, identity, issuer):
    # No regex identities, custom trust roots, or disabled transparency checks.
    return subprocess.run(
        [str(tool), "verify-blob", "--bundle", str(bundle),
         "--certificate-identity", identity, "--certificate-oidc-issuer", issuer,
         str(artifact)], capture_output=True, timeout=120, check=False,
    ).returncode == 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--require", action="store_true", help="missing release evidence fails this check")
    args = parser.parse_args()
    out = Path(os.environ["CONFORMANCE_OUT"])
    out.mkdir(parents=True, exist_ok=True)
    root = Path(__file__).resolve().parents[2]
    head = subprocess.check_output(["git", "-C", str(root), "rev-parse", "HEAD"], text=True).strip()
    result = {"suite": "sigstore", "repo": "GetBusbar/busbar", "commit": head,
              "core_pin": head, "status": "not-run", "armed": False,
              "standard": "Sigstore signing (cosign keyless)",
              "plan": "verify the approved released blob and Rekor bundle with exact identity and issuer"}
    names = ["BUSBAR_SIGSTORE_ARTIFACT", "BUSBAR_SIGSTORE_BUNDLE", "BUSBAR_SIGSTORE_RECEIPT",
             "BUSBAR_SIGSTORE_CERTIFICATE_IDENTITY", "BUSBAR_SIGSTORE_OIDC_ISSUER"]
    missing = [name for name in names if not os.environ.get(name)]
    try:
        if missing:
            if len(missing) != len(names):
                raise ValueError("incomplete supplied release evidence")
            result["reason"] = "release inputs not supplied: " + ", ".join(missing)
        else:
            artifact, bundle, receipt_path = [Path(os.environ[n]) for n in names[:3]]
            if receipt_path.stat().st_size > 65536:
                raise ValueError("release receipt is larger than 64 KiB")
            receipt = json.loads(receipt_path.read_text())
            check_receipt(receipt, artifact, head)
            identity, issuer = [os.environ[n] for n in names[3:]]
            target, expected = TOOLS[(platform.system(), platform.machine())]
            with tempfile.TemporaryDirectory(prefix="busbar-sigstore-") as scratch:
                scratch = Path(scratch)
                tool = scratch / "cosign"
                url = f"https://github.com/sigstore/cosign/releases/download/{VERSION}/cosign-{target}"
                with urllib.request.urlopen(url, timeout=60) as src, tool.open("wb") as dest:
                    remaining = 256 * 1024 * 1024
                    while chunk := src.read(min(1024 * 1024, remaining + 1)):
                        remaining -= len(chunk)
                        if remaining < 0:
                            raise ValueError("cosign download exceeds 256 MiB")
                        dest.write(chunk)
                if digest(tool) != expected:
                    raise ValueError("pinned cosign checksum mismatch")
                tool.chmod(0o700)
                if not verify(tool, bundle, artifact, identity, issuer):
                    raise ValueError("released artifact failed Sigstore verification")
                tampered = scratch / "tampered"
                shutil.copyfile(artifact, tampered)
                with tampered.open("ab") as stream:
                    stream.write(b"\0")
                if verify(tool, bundle, tampered, identity, issuer):
                    raise ValueError("tampered artifact was accepted")
                if verify(tool, bundle, artifact, identity + "/not-the-signer", issuer):
                    raise ValueError("wrong signing identity was accepted")
                if verify(tool, bundle, artifact, identity, "https://issuer.invalid"):
                    raise ValueError("wrong OIDC issuer was accepted")
            result.update(status="pass", armed=True, reason="approved blob verified; tampering and wrong identity/issuer refused")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError) as error:
        result.update(status="fail", armed=True, reason=str(error))
    (out / "verdict.json").write_text(json.dumps(result, indent=2) + "\n")
    print("sigstore:", result["status"], result["reason"])
    return 0 if result["status"] == "pass" or (result["status"] == "not-run" and not args.require) else 1


if __name__ == "__main__":
    raise SystemExit(main())
