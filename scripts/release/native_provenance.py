#!/usr/bin/env python3
"""Generate and verify native SLSA statements; sign only in a trusted operator step.

The independently supplied plan and receipt are private controller inputs. Only
the allowlisted statement is public. No SLSA Build level is asserted by this tool.
"""

from __future__ import annotations

import argparse
import base64
import datetime
import hashlib
import json
import re
import subprocess
import sys
from pathlib import Path

STATEMENT = "https://in-toto.io/Statement/v1"
PREDICATE = "https://slsa.dev/provenance/v1"
BUILD_TYPE = "urn:busbar:build-type:native-cargo:v1"
TOOLING_KEY = "729b1f2a42d3b73de464a4b38abfcc3b9e9d49af2944d1450bceed70a37defd0"
INPUTS = {
    "source-archive",
    "source-file-map",
    "lockgraph",
    "build-recipe",
    "toolchain",
    "builder-receipt",
}


def require(ok, reason):
    if not ok:
        raise ValueError(reason)


def digest(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def canonical(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()


def decode(data):
    def pairs(items):
        out = {}
        for key, value in items:
            require(key not in out, "duplicate JSON key")
            out[key] = value
        return out

    return json.loads(data, object_pairs_hook=pairs)


def load(path):
    return decode(Path(path).read_bytes())


def write(path, data):
    with Path(path).open("xb") as stream:
        stream.write(data)


def hex_value(value, length=64):
    require(
        isinstance(value, str) and re.fullmatch(r"[0-9a-f]{%d}" % length, value),
        "invalid digest",
    )
    return value


def token(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"[a-zA-Z0-9][a-zA-Z0-9._-]{0,150}", value),
        "unsafe public label",
    )
    return value


def timestamp(value):
    require(
        isinstance(value, str)
        and re.fullmatch(r"\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d(?:\.\d+)?Z", value),
        "invalid UTC timestamp",
    )
    return datetime.datetime.fromisoformat(value.replace("Z", "+00:00"))


def statement(plan, receipt, artifact):
    """Plan comes from the protected controller, never from candidate output."""
    require(
        plan["stage"] in ("qa", "main"), "provenance release stage must be qa or main"
    )
    for key in (
        "stage",
        "source_commit",
        "target",
        "builder_id",
        "invocation_id",
        "artifact_name",
        "artifact_sha256",
        "inputs",
        "started_on",
        "finished_on",
    ):
        require(
            receipt.get(key) == plan.get(key),
            "receipt differs from protected plan: " + key,
        )
    require(
        receipt.get("exit_code") == 0 and type(receipt.get("exit_code")) is int,
        "build did not succeed",
    )
    require(receipt.get("native") is True, "native builder receipt required")
    require(
        receipt.get("host_target") == plan["target"], "cross compilation is not native"
    )
    require(
        timestamp(receipt["started_on"]) <= timestamp(receipt["finished_on"]),
        "reversed build timestamps",
    )
    require(set(plan["inputs"]) == INPUTS, "incomplete or unknown input set")
    for value in plan["inputs"].values():
        hex_value(value)
    hex_value(plan["source_commit"], 40)
    hex_value(plan["artifact_sha256"])
    for key in ("target", "invocation_id", "artifact_name"):
        token(plan[key])
    require(
        re.fullmatch(r"urn:busbar:builder:[a-z0-9-]+:v[0-9]+", plan["builder_id"]),
        "unapproved builder URI shape",
    )
    require(Path(artifact).name == plan["artifact_name"], "artifact name mismatch")
    require(digest(artifact) == plan["artifact_sha256"], "artifact digest mismatch")
    dependencies = [
        {"uri": "urn:busbar:source:git", "digest": {"gitCommit": plan["source_commit"]}}
    ]
    dependencies += [
        {"uri": "urn:busbar:input:" + name, "digest": {"sha256": value}}
        for name, value in sorted(plan["inputs"].items())
    ]
    return {
        "_type": STATEMENT,
        "subject": [
            {
                "name": plan["artifact_name"],
                "digest": {"sha256": plan["artifact_sha256"]},
            }
        ],
        "predicateType": PREDICATE,
        "predicate": {
            "buildDefinition": {
                "buildType": BUILD_TYPE,
                "externalParameters": {
                    "source": "urn:busbar:source:git",
                    "revision": plan["source_commit"],
                    "target": plan["target"],
                    "stage": plan["stage"],
                },
                "resolvedDependencies": dependencies,
            },
            "runDetails": {
                "builder": {"id": plan["builder_id"]},
                "metadata": {
                    "invocationId": plan["invocation_id"],
                    "startedOn": receipt["started_on"],
                    "finishedOn": receipt["finished_on"],
                },
            },
        },
    }


def check_statement(path, plan, receipt, artifact):
    expected = statement(plan, receipt, artifact)
    require(
        load(path) == expected,
        "statement differs from exact artifact/source/input/builder expectations",
    )
    require(
        Path(path).read_bytes() == canonical(expected),
        "statement must use canonical public serialization",
    )
    return expected


def check_inputs(plan, files):
    require(set(files) == INPUTS, "input file set must be complete")
    for name, path in files.items():
        require(
            digest(path) == plan["inputs"][name],
            "input bytes differ from protected plan: " + name,
        )


def command(argv):
    # Never echo signer arguments, credentials, stdout or stderr to CI logs.
    result = subprocess.run([str(x) for x in argv], capture_output=True, timeout=180)
    require(result.returncode == 0, "trusted external tool failed")
    return result.stdout


def public_key(path, expected):
    from cryptography.hazmat.primitives import serialization

    key = serialization.load_pem_public_key(Path(path).read_bytes())
    der = key.public_bytes(
        serialization.Encoding.DER, serialization.PublicFormat.SubjectPublicKeyInfo
    )
    require(
        hashlib.sha256(der).hexdigest() == expected,
        "public key is not the independently pinned trust root",
    )
    return key


def detached_message(path):
    token(Path(path).name)
    return f"{Path(path).name}\n{digest(path)}\n".encode()


def verify_detached(path, signature, key_path):
    key = public_key(key_path, TOOLING_KEY)
    key.verify(
        base64.b64decode(Path(signature).read_bytes(), validate=True),
        detached_message(path),
    )


def sign_detached(path, signature, key_path, signer, signer_sha256):
    public_key(key_path, TOOLING_KEY)
    require(Path(signer).is_absolute(), "operator signer must use an absolute path")
    require(
        digest(signer) == hex_value(signer_sha256),
        "operator signer executable differs from custody receipt",
    )
    require(not Path(signature).exists(), "signature already exists")
    encoded = command(
        [signer, "release-signing", "sign", Path(path).name, digest(path)]
    ).strip()
    public_key(key_path, TOOLING_KEY).verify(
        base64.b64decode(encoded, validate=True), detached_message(path)
    )
    write(signature, encoded)


def cosign_trust(config):
    require(
        type(config["version"]) is int and config["version"] in (1, 2),
        "unknown Sigstore trust configuration",
    )
    if config["version"] == 2:
        require(
            config.get("purpose") == "release-attestation",
            "release trust must have an explicit purpose",
        )
    require(
        Path(config["cosign"]).is_absolute()
        and Path(config["trusted_root"]).is_absolute(),
        "pinned executable and trust root require absolute paths",
    )
    require(
        digest(config["cosign"]) == hex_value(config["cosign_sha256"]),
        "cosign executable not pinned",
    )
    require(
        digest(config["trusted_root"]) == hex_value(config["trusted_root_sha256"]),
        "Sigstore trusted root not pinned",
    )
    if config["mode"] == "key":
        require(
            Path(config["public_key"]).is_absolute(),
            "public key requires an absolute path",
        )
        if config["version"] == 1:
            public_key(config["public_key"], TOOLING_KEY)
        else:
            # The configuration digest is independently pinned by the controller
            # or consumer. A key downloaded beside a bundle is never its own root.
            from cryptography.hazmat.primitives.asymmetric import ec, ed25519

            key = public_key(
                config["public_key"], hex_value(config["public_key_sha256"])
            )
            algorithm = config.get("key_algorithm")
            require(
                (algorithm == "ed25519" and isinstance(key, ed25519.Ed25519PublicKey))
                or (
                    algorithm == "ecdsa-p256-sha256"
                    and isinstance(key, ec.EllipticCurvePublicKey)
                    and isinstance(key.curve, ec.SECP256R1)
                ),
                "release public key algorithm differs from approved trust",
            )
        return ["--key", config["public_key"]]
    require(config["mode"] == "identity", "unknown Sigstore signer mode")
    require(
        config.get("identity") and config.get("issuer"),
        "existing identity and issuer must be pinned",
    )
    # The exact issuer and identity come from the approved, digest-pinned trust
    # configuration; here they must have the only accepted shape: a bare https
    # GitLab origin, and that origin's protected-main CI configuration identity.
    issuer = config["issuer"]
    require(
        isinstance(issuer, str)
        and re.fullmatch(r"https://[a-z0-9]+(?:[.-][a-z0-9]+)*\.[a-z]{2,}", issuer)
        and isinstance(config["identity"], str)
        and re.fullmatch(
            re.escape(issuer) + r"/[A-Za-z0-9_.-]+(?:/[A-Za-z0-9_.-]+)+"
            r"//[A-Za-z0-9_./-]+\.yml(?:@[A-Za-z0-9_./-]+:[0-9a-f]{40})?@refs/heads/main",
            config["identity"],
        ),
        "exact GitLab issuer and protected main configuration identity required",
    )
    return [
        "--certificate-identity",
        config["identity"],
        "--certificate-oidc-issuer",
        config["issuer"],
    ]


def verify_bundle(path, bundle_path, artifact, config):
    require(
        config.get("builder_id")
        == load(path)["predicate"]["runDetails"]["builder"]["id"],
        "signer is not authorized for this builder",
    )
    verify_dsse(path, bundle_path, artifact, config, PREDICATE)


def verify_dsse(path, bundle_path, artifact, config, predicate_type, subject_name=None):
    """Verify exact statement bytes, subject and logged signature; caller checks policy."""
    trust = cosign_trust(config)
    statement_value = load(path)
    require(
        statement_value.get("_type") == STATEMENT
        and statement_value.get("predicateType") == predicate_type,
        "wrong statement or predicate type",
    )
    require(
        statement_value.get("subject")
        == [
            {
                "name": subject_name or Path(artifact).name,
                "digest": {"sha256": digest(artifact)},
            }
        ],
        "statement subject differs",
    )
    bundle = load(bundle_path)
    envelope = bundle["dsseEnvelope"]
    require(
        envelope["payloadType"] == "application/vnd.in-toto+json",
        "wrong DSSE payload type",
    )
    require(
        base64.b64decode(envelope["payload"], validate=True) == Path(path).read_bytes(),
        "bundle statement is not exact expected bytes",
    )
    entries = bundle["verificationMaterial"].get("tlogEntries", [])
    require(
        entries
        and all(
            entry.get("inclusionProof", {}).get("checkpoint", {}).get("envelope")
            for entry in entries
        ),
        "Rekor inclusion proof with checkpoint required",
    )
    # Presence is not proof: cosign verifies signatures, log inclusion and checkpoint
    # against the independently pinned Sigstore trust root. No ignore flags exist here.
    command(
        [
            config["cosign"],
            "verify-blob-attestation",
            "--bundle",
            bundle_path,
            "--type",
            predicate_type,
            "--trusted-root",
            config["trusted_root"],
            *trust,
            artifact,
        ]
    )


def attest(path, bundle, artifact, config, approved_sha256):
    cosign_trust(config)
    require(
        digest(path) == hex_value(approved_sha256),
        "public statement differs from approved payload",
    )
    require(
        config.get("builder_id")
        == load(path)["predicate"]["runDetails"]["builder"]["id"],
        "signer is not authorized for this builder",
    )
    require(not Path(bundle).exists(), "bundle already exists")
    require(
        digest(config["signing_config"]) == hex_value(config["signing_config_sha256"]),
        "Sigstore signing configuration not pinned",
    )
    args = [
        config["cosign"],
        "attest-blob",
        "--statement",
        path,
        "--bundle",
        bundle,
        "--signing-config",
        config["signing_config"],
        "--trusted-root",
        config["trusted_root"],
        "--oidc-disable-ambient-providers",
        "--yes",
    ]
    if config["mode"] == "key":
        handle = config.get("key_handle", "")
        require(
            handle.startswith(
                ("hashivault://", "awskms://", "gcpkms://", "azurekms://", "pkcs11:")
            ),
            "existing trusted signing service handle required; no raw private keys",
        )
        args += ["--key", handle]
    else:
        require(
            config.get("identity_token_file"),
            "trusted step must supply an explicit identity token file",
        )
        args += ["--identity-token", config["identity_token_file"]]
    command(args)
    verify_bundle(path, bundle, artifact, config)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "operation",
        choices=(
            "generate",
            "check",
            "sign",
            "verify-signature",
            "attest",
            "verify-bundle",
        ),
    )
    for name in ("plan", "receipt", "artifact", "statement", "input-files"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--signature", type=Path)
    parser.add_argument("--public-key", type=Path)
    parser.add_argument("--signer", type=Path)
    parser.add_argument("--signer-sha256")
    parser.add_argument("--sigstore-config", type=Path)
    parser.add_argument("--bundle", type=Path)
    parser.add_argument("--approved-public-sha256")
    args = parser.parse_args()
    plan, receipt = load(args.plan), load(args.receipt)
    check_inputs(plan, load(args.input_files))
    if args.operation == "generate":
        write(args.statement, canonical(statement(plan, receipt, args.artifact)))
    else:
        check_statement(args.statement, plan, receipt, args.artifact)
        if args.operation == "sign":
            sign_detached(
                args.statement,
                args.signature,
                args.public_key,
                args.signer,
                args.signer_sha256,
            )
        elif args.operation == "verify-signature":
            verify_detached(args.statement, args.signature, args.public_key)
        elif args.operation == "attest":
            attest(
                args.statement,
                args.bundle,
                args.artifact,
                load(args.sigstore_config),
                args.approved_public_sha256,
            )
        elif args.operation == "verify-bundle":
            verify_bundle(
                args.statement, args.bundle, args.artifact, load(args.sigstore_config)
            )
    print(
        json.dumps(
            {
                "operation": args.operation,
                "verified": True,
                "statement_sha256": digest(args.statement),
                "slsa_build_level": "not-assessed",
            }
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        # External diagnostics and malformed input values may contain private material.
        print(
            "native-provenance: refused (" + type(error).__name__ + ")", file=sys.stderr
        )
        sys.exit(1)
