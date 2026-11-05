#!/usr/bin/env python3
"""One native/ModernCI QA or main gate over a protected artifact inventory.

Prepare has no signing credentials or network operations. Verify requires a real
Sigstore bundle for every artifact. The manifest is mounted by the trusted
controller, never loaded from a candidate checkout.
"""

import argparse
import hashlib
import json
from pathlib import Path
import sys

import native_provenance as p


def stage(operation, stage_name, manifest_path, manifest_sha256):
    p.require(stage_name in ("qa", "main"), "expected qa or main")
    p.require(
        p.digest(manifest_path) == p.hex_value(manifest_sha256),
        "protected inventory digest mismatch",
    )
    manifest = p.load(manifest_path)
    p.require(
        manifest["version"] == 1 and manifest["stage"] == stage_name,
        "wrong protected stage inventory",
    )
    entries = manifest["artifacts"]
    p.require(isinstance(entries, list) and entries, "empty artifact inventory")
    if stage_name == "main":
        p.require(
            operation == "verify", "main reuses the judged QA artifact and statement"
        )
        qa_path = manifest["qualified_qa_inventory"]
        p.require(
            p.digest(qa_path) == p.hex_value(manifest["qualified_qa_inventory_sha256"]),
            "QA inventory digest mismatch",
        )
        qa = p.load(qa_path)
        p.require(qa["stage"] == "qa" and qa["version"] == 1, "wrong QA inventory")
        p.require(
            len(entries) == len(qa["artifacts"]), "main artifact set differs from QA"
        )
        p.require(
            sorted(row["plan_sha256"] for row in entries)
            == sorted(row["plan_sha256"] for row in qa["artifacts"]),
            "main must reuse exact QA plans without rebuilding",
        )
    seen = set()
    verified = []
    for entry in entries:
        p.require(
            p.digest(entry["plan"]) == p.hex_value(entry["plan_sha256"]),
            "protected plan digest mismatch",
        )
        plan, receipt = p.load(entry["plan"]), p.load(entry["receipt"])
        p.require(plan["stage"] == "qa", "artifact must come from the judged QA build")
        p.require(plan["artifact_name"] not in seen, "duplicate artifact")
        seen.add(plan["artifact_name"])
        p.check_inputs(plan, p.load(entry["input_files"]))
        expected = p.canonical(p.statement(plan, receipt, entry["artifact"]))
        if operation == "prepare":
            p.write(entry["statement"], expected)
        elif operation == "verify":
            p.check_statement(entry["statement"], plan, receipt, entry["artifact"])
            p.require(
                p.digest(entry["sigstore_config"])
                == p.hex_value(entry["sigstore_config_sha256"]),
                "signer-builder trust configuration differs",
            )
            config = p.load(entry["sigstore_config"])
            p.require(
                config["builder_id"] == plan["builder_id"],
                "signer is not authorized for this builder",
            )
            p.verify_bundle(
                entry["statement"], entry["bundle"], entry["artifact"], config
            )
        else:
            raise ValueError("unknown stage operation")
        verified.append(
            {
                "artifact": plan["artifact_name"],
                "sha256": plan["artifact_sha256"],
                "statement_sha256": hashlib.sha256(expected).hexdigest(),
            }
        )
    return {
        "stage": stage_name,
        "operation": operation,
        "artifacts": verified,
        "sigstore_verified": operation == "verify",
        "slsa_build_level": "not-assessed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "verify"))
    parser.add_argument("stage", choices=("qa", "main"))
    parser.add_argument("--manifest", type=Path, required=True)
    parser.add_argument("--manifest-sha256", required=True)
    args = parser.parse_args()
    result = stage(args.operation, args.stage, args.manifest, args.manifest_sha256)
    print(json.dumps(result, sort_keys=True))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            "provenance-stage: refused (" + type(error).__name__ + ")", file=sys.stderr
        )
        sys.exit(1)
