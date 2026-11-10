#!/usr/bin/env python3
"""Verify a complete downloaded release using independently pinned trust/inventory.

Prepared consumer contract; production signing and publication are not activated.
No source checkout, build receipt, private input file or GitHub identity is needed.
"""

import argparse
import json
from pathlib import Path
import sys

import build_closure as build
import native_provenance as p
import oci_provenance as oci

SCHEMA = "busbar.release-inventory/1"
SCHEMA_V2 = "busbar.release-inventory/2"
SCHEMA_V3 = "busbar.release-inventory/3"
SBOM_PREDICATE = "https://cyclonedx.org/bom"
PREDICATE = "urn:busbar:release-inventory:v1"
INVENTORY = "release-inventory.json"
STATEMENT = "release-inventory.intoto.json"
BUNDLE = "release-inventory.sigstore.json"
PLAN_FIELDS = {
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
}


def regular(root, name):
    p.token(name)
    path = root / name
    p.require(
        path.is_file() and not path.is_symlink(), "missing or nonregular release file"
    )
    return path


def inventory_statement(inventory, inventory_sha256, builder_id):
    """Controller may emit this public statement; this function never signs."""
    return {
        "_type": p.STATEMENT,
        "subject": [
            {"name": INVENTORY, "digest": {"sha256": p.hex_value(inventory_sha256)}}
        ],
        "predicateType": PREDICATE,
        "predicate": {
            "release": p.token(inventory["release"]),
            "builder_id": builder_id,
        },
    }


def sbom_statement(plan, bom):
    return {
        "_type": p.STATEMENT,
        "subject": [
            {
                "name": plan["artifact_name"],
                "digest": {"sha256": plan["artifact_sha256"]},
            }
        ],
        "predicateType": SBOM_PREDICATE,
        "predicate": bom,
    }


def verify(root, inventory_sha256, trust_path, trust_sha256):
    root = Path(root)
    p.require(root.is_dir() and not root.is_symlink(), "invalid release directory")
    p.require(
        p.digest(trust_path) == p.hex_value(trust_sha256),
        "trust configuration digest differs",
    )
    trust = p.load(trust_path)
    p.require(
        trust.get("version") == 2 and trust.get("purpose") == "release-attestation",
        "release-specific trust required",
    )
    # Validate pins before invoking any external executable or processing bundles.
    p.cosign_trust(trust)
    inventory_path = regular(root, INVENTORY)
    p.require(
        p.digest(inventory_path) == p.hex_value(inventory_sha256),
        "release inventory digest differs",
    )
    inventory = p.load(inventory_path)
    v3 = inventory.get("schema") == SCHEMA_V3
    v2 = inventory.get("schema") in (SCHEMA_V2, SCHEMA_V3)
    p.require(
        set(inventory)
        == {"schema", "release", "artifacts"} | ({"oci"} if v2 else set())
        and inventory["schema"] in (SCHEMA, SCHEMA_V2, SCHEMA_V3),
        "unsupported release inventory",
    )
    p.token(inventory["release"])
    rows = inventory["artifacts"]
    p.require(isinstance(rows, list) and rows, "empty release inventory")
    expected_files = {INVENTORY, STATEMENT, BUNDLE}
    verified, closures = [], {}
    bound_files = {}

    def bind(item):
        p.require(set(item) == {"name", "sha256"}, "invalid file binding")
        name = p.token(item["name"])
        p.require(name not in expected_files, "duplicate or reused release file")
        expected_files.add(name)
        path = regular(root, name)
        p.require(
            p.digest(path) == p.hex_value(item["sha256"]), "release file digest differs"
        )
        bound_files[name] = item["sha256"]
        return path

    # First bind every input byte and exact subject set before trusting any pass.
    for row in rows:
        p.require(
            set(row)
            == {"plan", "statement", "bundle", "sbom", "component_name"}
            | ({"sbom_statement", "sbom_bundle"} if v2 else set())
            | ({"build_closure"} if v3 else set()),
            "unsupported release subject",
        )
        plan = row["plan"]
        p.require(
            set(plan) == PLAN_FIELDS and plan["stage"] == "qa",
            "public plan must be the exact qualified QA plan",
        )
        p.require(plan["builder_id"] == trust["builder_id"], "unapproved builder")
        files = {
            "artifact": {
                "name": plan["artifact_name"],
                "sha256": plan["artifact_sha256"],
            },
            **{key: row[key] for key in ("statement", "bundle", "sbom")},
            **(
                {key: row[key] for key in ("sbom_statement", "sbom_bundle")}
                if v2
                else {}
            ),
        }
        if v3:
            files["build_closure"] = row["build_closure"]
        paths = {kind: bind(item) for kind, item in files.items()}
        # Reconstruct public expectations only. These asserted receipt fields do
        # not claim that this consumer observed a build or read private inputs.
        receipt = {
            **plan,
            "exit_code": 0,
            "native": True,
            "host_target": plan["target"],
        }
        p.check_statement(paths["statement"], plan, receipt, paths["artifact"])
        bom = p.load(paths["sbom"])
        component = bom.get("metadata", {}).get("component", {})
        p.token(row["component_name"])
        p.require(
            bom.get("bomFormat") == "CycloneDX"
            and isinstance(bom.get("components"), list)
            and bom["components"]
            and component.get("name") == row["component_name"]
            and component.get("version") == inventory["release"],
            "SBOM inventory or release identity differs",
        )
        if v3:
            closure = build.validate(
                p.load(paths["build_closure"]),
                plan,
                paths["artifact"],
                row["component_name"],
                inventory["release"],
            )
            p.require(
                bom == build.sbom(closure), "SBOM differs from compiled build closure"
            )
            closures[plan["artifact_name"]] = closure
        if v2:
            p.require(
                paths["sbom_statement"].read_bytes()
                == p.canonical(sbom_statement(plan, bom)),
                "SBOM statement differs from artifact and SBOM bytes",
            )
        verified.append((plan, paths))
    verified_oci = []
    oci_rows = inventory.get("oci", [])
    p.require(isinstance(oci_rows, list), "invalid OCI inventory")
    oci_refs = set()
    for row in oci_rows:
        p.require(
            set(row)
            == {"reference", "platforms", "archive", "index", "statement", "bundle"},
            "unsupported OCI release subject",
        )
        ref = row["reference"]
        p.require(ref not in oci_refs, "duplicate OCI reference")
        oci_refs.add(ref)
        paths = {
            kind: bind(row[kind])
            for kind in ("archive", "index", "statement", "bundle")
        }
        closure, index_bytes = oci.inspect_archive(
            paths["archive"],
            ref,
            row["platforms"],
            {plan["artifact_name"]: plan for plan, _ in verified},
            closures=closures if v3 else None,
        )
        expected_oci = oci.statement(
            ref, closure, inventory["release"], trust["builder_id"]
        )
        p.require(
            paths["index"].read_bytes() == index_bytes
            and paths["statement"].read_bytes() == p.canonical(expected_oci),
            "OCI index or statement differs from exported bytes",
        )
        verified_oci.append((row, paths, expected_oci))
    p.require(
        {path.name for path in root.iterdir()} == expected_files,
        "downloaded release file set differs from inventory",
    )
    expected = inventory_statement(inventory, inventory_sha256, trust["builder_id"])
    statement_path = regular(root, STATEMENT)
    p.require(
        statement_path.read_bytes() == p.canonical(expected),
        "inventory statement differs",
    )
    bundle_path = regular(root, BUNDLE)
    bundle_sha256 = p.digest(bundle_path)
    p.verify_dsse(statement_path, bundle_path, inventory_path, trust, PREDICATE)
    for plan, paths in verified:
        p.verify_bundle(paths["statement"], paths["bundle"], paths["artifact"], trust)
        if v2:
            p.verify_dsse(
                paths["sbom_statement"],
                paths["sbom_bundle"],
                paths["artifact"],
                trust,
                SBOM_PREDICATE,
            )
    for row, paths, expected_oci in verified_oci:
        p.verify_dsse(
            paths["statement"],
            paths["bundle"],
            paths["index"],
            trust,
            oci.PREDICATE,
            subject_name=row["reference"].split("@", 1)[0],
        )
        oci.verify_registry(row["reference"], expected_oci, trust)
    # Detect substitution during the external verifications too. Consumers must
    # keep this download directory private until using the verified bytes.
    p.require(
        p.digest(regular(root, INVENTORY)) == inventory_sha256
        and p.digest(trust_path) == trust_sha256
        and regular(root, STATEMENT).read_bytes() == p.canonical(expected)
        and p.digest(regular(root, BUNDLE)) == bundle_sha256
        and {path.name for path in root.iterdir()} == expected_files,
        "verification inputs changed",
    )
    for name, expected_hash in bound_files.items():
        p.require(
            p.digest(regular(root, name)) == expected_hash,
            "release bytes changed during verification",
        )
    return {
        "release": inventory["release"],
        "artifacts": len(verified),
        "oci_indexes": len(verified_oci),
        "registry_verified": bool(verified_oci),
        "build_closure_verified": v3,
        "image_binary_equivalence_verified": v3 and bool(verified_oci),
        "subjects": [
            {
                "name": plan["artifact_name"],
                "sha256": plan["artifact_sha256"],
                "target": plan["target"],
                "source_commit": plan["source_commit"],
            }
            for plan, _ in verified
        ],
        "inventory_sha256": inventory_sha256,
        "sigstore_verified": True,
        "slsa_build_level": "not-assessed",
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory", type=Path, required=True)
    parser.add_argument("--inventory-sha256", required=True)
    parser.add_argument("--trust", type=Path, required=True)
    parser.add_argument("--trust-sha256", required=True)
    args = parser.parse_args()
    print(
        json.dumps(
            verify(
                args.directory, args.inventory_sha256, args.trust, args.trust_sha256
            ),
            sort_keys=True,
        )
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            "release-verifier: refused (" + type(error).__name__ + ")", file=sys.stderr
        )
        sys.exit(1)
