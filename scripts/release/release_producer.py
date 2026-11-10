#!/usr/bin/env python3
"""Collect qualified QA bytes and emit public release/SBOM/OCI statements.

No signing, cloud provisioning or registry writes. All plan digests come from the
protected controller. Prepare emits additional signing requests; finalize requires
their real logged bundles before emitting the aggregate inventory signing request.
"""

import argparse
import json
import os
from pathlib import Path
import shutil
import stat
import sys

import native_provenance as p
import oci_provenance as oci
import provenance_stage as stage
import release_verifier as v

SCHEMA = "busbar.release-publication/1"
ISOLATION_CONTROLS = {
    "controller_separated",
    "private_pid_mount_network",
    "policy_readonly",
    "receipts_unmounted",
    "no_host_docker_socket",
    "no_metadata_credentials",
    "descendants_reaped",
    "collected_regular_files",
}


def pinned_file(binding):
    p.require(set(binding) == {"path", "sha256"}, "invalid protected file binding")
    path = Path(binding["path"])
    p.require(
        path.is_absolute() and path.is_file() and not path.is_symlink(),
        "protected input must be a regular absolute path",
    )
    p.require(
        p.digest(path) == p.hex_value(binding["sha256"]),
        "protected input digest differs",
    )
    return path


def publication(plan_path, plan_sha256):
    p.require(
        p.digest(plan_path) == p.hex_value(plan_sha256),
        "publication plan digest differs",
    )
    plan = p.load(plan_path)
    p.require(
        set(plan)
        == {
            "schema",
            "release",
            "qa_manifest",
            "subjects",
            "oci",
            "isolation_policy_sha256",
            "isolation_observations",
        }
        and plan["schema"] == SCHEMA,
        "unsupported publication plan",
    )
    p.token(plan["release"])
    qa_path = pinned_file(plan["qa_manifest"])
    qa = p.load(qa_path)
    p.require(
        qa["version"] == 1 and qa["stage"] == "qa", "qualified QA inventory required"
    )
    p.require(
        isinstance(plan["subjects"], dict) and plan["subjects"],
        "empty publication subjects",
    )
    names = [
        p.load(pinned_file({"path": row["plan"], "sha256": row["plan_sha256"]}))[
            "artifact_name"
        ]
        for row in qa["artifacts"]
    ]
    p.require(
        len(names) == len(set(names)) and set(names) == set(plan["subjects"]),
        "publication artifact set differs from independently required subjects",
    )
    p.require(isinstance(plan["oci"], list), "invalid OCI publication plan")
    p.require(
        set(plan["isolation_observations"]) == set(names),
        "every native artifact requires independent isolation evidence",
    )
    policy_sha256 = p.hex_value(plan["isolation_policy_sha256"])
    for row in qa["artifacts"]:
        native = p.load(row["plan"])
        observation = p.load(
            pinned_file(plan["isolation_observations"][native["artifact_name"]])
        )
        p.require(
            observation.get("schema") == "busbar.native-execution-observation/1"
            and observation.get("policy_sha256") == policy_sha256,
            "unqualified native execution policy",
        )
        for key in ("builder_id", "source_commit", "invocation_id", "artifact_sha256"):
            p.require(
                observation.get(key) == native[key],
                "native isolation observation belongs to another build",
            )
        controls = observation.get("controls")
        p.require(
            isinstance(controls, dict)
            and set(controls) == ISOLATION_CONTROLS
            and all(value is True for value in controls.values())
            and type(observation.get("candidate_uid")) is int
            and observation["candidate_uid"] > 0
            and type(observation.get("exit_code")) is int
            and observation["exit_code"] == 0,
            "native execution did not enforce the release boundary",
        )
        p.hex_value(observation["runtime_sha256"])
        p.hex_value(observation["toolchain_image_sha256"])
        p.require(
            p.timestamp(observation["finished_on"])
            >= p.timestamp(native["finished_on"]),
            "native observation predates the collected artifact",
        )
    return plan, qa


def transfer(source, target, expected_sha256):
    """No shell/archive extraction, links, devices or overwrite; hash copied bytes."""
    p.require(not Path(source).is_symlink(), "indirect artifact input")
    fd = os.open(source, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    with os.fdopen(fd, "rb") as stream:
        p.require(
            stat.S_ISREG(os.fstat(stream.fileno()).st_mode), "nonregular artifact input"
        )
        with target.open("xb") as out:
            shutil.copyfileobj(stream, out)
    p.require(
        p.digest(target) == p.hex_value(expected_sha256),
        "collected artifact bytes differ",
    )


def prepare(plan_path, plan_sha256, output):
    plan, qa = publication(plan_path, plan_sha256)
    # This uses private controller receipt/input bytes, not reconstructed public assertions.
    stage.stage(
        "verify", "qa", plan["qa_manifest"]["path"], plan["qa_manifest"]["sha256"]
    )
    output = Path(output)
    output.mkdir(mode=0o700, parents=False, exist_ok=False)
    try:
        rows, requests, artifacts = [], [], {}
        for entry in qa["artifacts"]:
            native = p.load(entry["plan"])
            name = native["artifact_name"]
            p.require(
                set(native) == v.PLAN_FIELDS, "private fields in public native plan"
            )
            artifacts[name] = native
            subject = plan["subjects"][name]
            p.require(
                set(subject) == {"sbom", "component_name"},
                "invalid SBOM publication mapping",
            )
            sbom_path = pinned_file(subject["sbom"])
            bom = p.load(sbom_path)
            component = bom.get("metadata", {}).get("component", {})
            p.require(
                bom.get("bomFormat") == "CycloneDX"
                and isinstance(bom.get("components"), list)
                and bom["components"]
                and component.get("name") == subject["component_name"]
                and component.get("version") == plan["release"],
                "SBOM closure or release identity absent",
            )
            row = {"plan": native, "component_name": p.token(subject["component_name"])}
            transfer(
                entry["artifact"], output / p.token(name), native["artifact_sha256"]
            )
            for kind, source, suffix, digest in (
                (
                    "statement",
                    entry["statement"],
                    ".intoto.json",
                    p.digest(entry["statement"]),
                ),
                (
                    "bundle",
                    entry["bundle"],
                    ".sigstore.json",
                    p.digest(entry["bundle"]),
                ),
                ("sbom", sbom_path, ".cdx.json", subject["sbom"]["sha256"]),
            ):
                filename = p.token(name + suffix)
                transfer(source, output / filename, digest)
                row[kind] = {"name": filename, "sha256": digest}
            p.check_statement(
                output / row["statement"]["name"],
                native,
                p.load(entry["receipt"]),
                output / name,
            )
            filename = p.token(name + ".sbom.intoto.json")
            p.write(output / filename, p.canonical(v.sbom_statement(native, bom)))
            row["sbom_statement"] = {
                "name": filename,
                "sha256": p.digest(output / filename),
            }
            row["sbom_bundle"] = {"name": p.token(name + ".sbom.sigstore.json")}
            requests.append(
                {
                    "statement": filename,
                    "statement_sha256": row["sbom_statement"]["sha256"],
                    "bundle": row["sbom_bundle"]["name"],
                    "artifact": name,
                    "predicate_type": v.SBOM_PREDICATE,
                }
            )
            rows.append(row)
        indexes, seen = [], set()
        for i, entry in enumerate(plan["oci"]):
            p.require(
                set(entry) == {"reference", "archive", "platforms"},
                "invalid OCI publication entry",
            )
            ref = entry["reference"]
            p.require(ref not in seen, "duplicate OCI index")
            seen.add(ref)
            source = pinned_file(entry["archive"])
            prefix = "oci-" + str(i)
            archive = output / (prefix + ".tar")
            transfer(source, archive, entry["archive"]["sha256"])
            closure, index_bytes = oci.inspect_archive(
                archive, ref, entry["platforms"], artifacts
            )
            index = output / (prefix + ".index.json")
            statement = output / (prefix + ".intoto.json")
            p.write(index, index_bytes)
            builders = {native["builder_id"] for native in artifacts.values()}
            p.require(len(builders) == 1, "publication must have one approved builder")
            p.write(
                statement,
                p.canonical(
                    oci.statement(ref, closure, plan["release"], next(iter(builders)))
                ),
            )
            row = {
                "reference": ref,
                "platforms": entry["platforms"],
                **{
                    kind: {"name": path.name, "sha256": p.digest(path)}
                    for kind, path in (
                        ("archive", archive),
                        ("index", index),
                        ("statement", statement),
                    )
                },
                "bundle": {"name": prefix + ".sigstore.json"},
            }
            indexes.append(row)
            requests.append(
                {
                    "statement": statement.name,
                    "statement_sha256": p.digest(statement),
                    "bundle": row["bundle"]["name"],
                    "artifact": index.name,
                    "subject_name": ref.split("@", 1)[0],
                    "predicate_type": oci.PREDICATE,
                    "registry_reference": ref,
                }
            )
        p.require(
            p.digest(plan_path) == plan_sha256
            and p.digest(plan["qa_manifest"]["path"]) == plan["qa_manifest"]["sha256"],
            "protected publication inputs changed",
        )
        draft = {
            "schema": v.SCHEMA_V2,
            "release": plan["release"],
            "artifacts": rows,
            "oci": indexes,
        }
        # Draft/request files stay private, outside the public download directory.
        return {
            "publication_plan_sha256": plan_sha256,
            "inventory": draft,
            "signing_requests": requests,
        }
    except BaseException:
        shutil.rmtree(output)
        raise


def finalize(draft_path, draft_sha256, output, trust_path, trust_sha256):
    p.require(
        p.digest(draft_path) == p.hex_value(draft_sha256),
        "protected draft digest differs",
    )
    draft = p.load(draft_path)
    p.require(
        p.digest(trust_path) == p.hex_value(trust_sha256), "trust configuration differs"
    )
    trust = p.load(trust_path)
    p.require(
        trust.get("version") == 2 and trust.get("purpose") == "release-attestation",
        "release-specific trust required",
    )
    p.cosign_trust(trust)
    output = Path(output)
    p.require(
        output.is_dir() and not output.is_symlink(), "invalid publication directory"
    )
    for request in draft["signing_requests"]:
        statement = v.regular(output, request["statement"])
        p.require(
            p.digest(statement) == request["statement_sha256"],
            "approved signing payload changed",
        )
        p.verify_dsse(
            statement,
            v.regular(output, request["bundle"]),
            v.regular(output, request["artifact"]),
            trust,
            request["predicate_type"],
            subject_name=request.get("subject_name"),
        )
    inventory = draft["inventory"]
    expected_files = set()

    def check_binding(binding):
        name = binding["name"]
        p.require(name not in expected_files, "duplicate publication file")
        expected_files.add(name)
        path = v.regular(output, name)
        if "sha256" in binding:
            p.require(
                p.digest(path) == binding["sha256"],
                "publication bytes changed before finalization",
            )
        return path

    for row in inventory["artifacts"]:
        p.require(
            row["plan"]["builder_id"] == trust["builder_id"], "unapproved builder"
        )
        check_binding(
            {
                "name": row["plan"]["artifact_name"],
                "sha256": row["plan"]["artifact_sha256"],
            }
        )
        for key in ("statement", "bundle", "sbom", "sbom_statement", "sbom_bundle"):
            check_binding(row[key])
        # Reverify native bundles under the final release trust, not merely QA's choice.
        p.verify_bundle(
            v.regular(output, row["statement"]["name"]),
            v.regular(output, row["bundle"]["name"]),
            v.regular(output, row["plan"]["artifact_name"]),
            trust,
        )
        row["sbom_bundle"]["sha256"] = p.digest(
            v.regular(output, row["sbom_bundle"]["name"])
        )
    for row in inventory["oci"]:
        for key in ("archive", "index", "statement", "bundle"):
            check_binding(row[key])
        row["bundle"]["sha256"] = p.digest(v.regular(output, row["bundle"]["name"]))
        oci.verify_registry(
            row["reference"], p.load(v.regular(output, row["statement"]["name"])), trust
        )
    p.require(
        {path.name for path in output.iterdir()} == expected_files,
        "publication directory has extra files",
    )
    p.require(
        p.digest(draft_path) == draft_sha256 and p.digest(trust_path) == trust_sha256,
        "protected finalization inputs changed",
    )
    path = output / v.INVENTORY
    p.write(path, p.canonical(inventory))
    statement = output / v.STATEMENT
    p.write(
        statement,
        p.canonical(
            v.inventory_statement(inventory, p.digest(path), trust["builder_id"])
        ),
    )
    return {
        "inventory_sha256": p.digest(path),
        "statement_sha256": p.digest(statement),
        "bundle_required": v.BUNDLE,
        "publication_ready": False,
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("prepare", "finalize"))
    parser.add_argument("--input", type=Path, required=True)
    parser.add_argument("--input-sha256", required=True)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--trust", type=Path)
    parser.add_argument("--trust-sha256")
    parser.add_argument(
        "--result",
        type=Path,
        required=True,
        help="private protected result, outside output directory",
    )
    args = parser.parse_args()
    p.require(
        not args.result.resolve().is_relative_to(args.output.resolve()),
        "private result cannot enter public output",
    )
    result = (
        prepare(args.input, args.input_sha256, args.output)
        if args.operation == "prepare"
        else finalize(
            args.input, args.input_sha256, args.output, args.trust, args.trust_sha256
        )
    )
    p.write(args.result, p.canonical(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            "release-producer: refused (" + type(error).__name__ + ")", file=sys.stderr
        )
        sys.exit(1)
