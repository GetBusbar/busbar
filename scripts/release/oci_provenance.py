#!/usr/bin/env python3
"""Bind an immutable OCI index, its complete exported bytes and native subjects.

No registry writes or signing. The protected producer supplies the expected
platform/native-artifact map; the verifier checks the actual OCI byte closure.
"""

import base64
import hashlib
import json
from pathlib import PurePosixPath
import re
import tarfile

import native_provenance as p

PREDICATE = "urn:busbar:oci-release:v1"
INDEX_TYPES = {
    "application/vnd.oci.image.index.v1+json",
    "application/vnd.docker.distribution.manifest.list.v2+json",
}
MANIFEST_TYPES = {
    "application/vnd.oci.image.manifest.v1+json",
    "application/vnd.docker.distribution.manifest.v2+json",
}


def reference(value):
    p.require(
        isinstance(value, str)
        and re.fullmatch(
            r"[a-z0-9][a-z0-9.:-]*/[a-z0-9][a-z0-9._/-]*@sha256:[0-9a-f]{64}", value
        )
        and ".." not in value.split("@", 1)[0].split("/"),
        "immutable OCI reference required",
    )
    return value.rsplit(":", 1)[1]


def inspect_archive(archive, ref, platforms, artifacts):
    """Hash all regular tar members without extraction; reject incomplete/extra blobs."""
    index_digest = reference(ref)
    p.require(
        isinstance(platforms, dict)
        and platforms
        and set(platforms) <= {"linux/amd64", "linux/arm64"},
        "unsupported OCI platform map",
    )
    hashes, documents, sizes, document_bytes = {}, {}, {}, {}
    with tarfile.open(archive, "r:*") as tar:
        for member in tar:
            name = member.name.removeprefix("./")
            path = PurePosixPath(name)
            p.require(
                not path.is_absolute() and ".." not in path.parts, "unsafe OCI member"
            )
            if member.isdir():
                p.require(
                    name.rstrip("/") in (".", "blobs", "blobs/sha256"),
                    "unexpected OCI directory",
                )
                continue
            p.require(
                member.isfile()
                and name not in hashes
                and (
                    name in ("index.json", "oci-layout")
                    or re.fullmatch(r"blobs/sha256/[0-9a-f]{64}", name)
                ),
                "unsupported or duplicate OCI member",
            )
            stream = tar.extractfile(member)
            hashes[name] = hashlib.file_digest(stream, "sha256").hexdigest()
            sizes[name] = member.size
            if name.startswith("blobs/"):
                p.require(
                    hashes[name] == name.rsplit("/", 1)[1], "OCI blob digest differs"
                )
            if member.size <= 8 * 1024 * 1024:
                stream = tar.extractfile(member)
                raw = stream.read()
                try:
                    documents[name] = p.decode(raw)
                    document_bytes[name] = raw
                except (ValueError, UnicodeDecodeError):
                    pass
    p.require(
        documents.get("oci-layout") == {"imageLayoutVersion": "1.0.0"},
        "unsupported OCI layout",
    )
    layout = documents.get("index.json", {})
    used = {"index.json", "oci-layout"}

    def blob(descriptor):
        digest = descriptor.get("digest", "")
        p.require(
            re.fullmatch(r"sha256:[0-9a-f]{64}", digest) and not descriptor.get("urls"),
            "external or unpinned OCI descriptor",
        )
        name = "blobs/sha256/" + digest[7:]
        p.require(
            name in hashes
            and type(descriptor.get("size")) is int
            and descriptor["size"] == sizes[name],
            "missing or wrong-sized OCI blob",
        )
        used.add(name)
        return name

    if hashes.get("index.json") == index_digest:
        index = layout
        index_name = "index.json"
    else:
        descriptors = layout.get("manifests", [])
        p.require(
            len(descriptors) == 1
            and descriptors[0].get("digest") == "sha256:" + index_digest,
            "exported layout differs from registry index",
        )
        index_name = blob(descriptors[0])
        index = documents.get(index_name, {})
    p.require(
        index.get("schemaVersion") == 2 and index.get("mediaType") in INDEX_TYPES,
        "multi-platform OCI index required",
    )
    subjects = []
    seen = set()
    for descriptor in index.get("manifests", []):
        platform = descriptor.get("platform", {})
        label = platform.get("os", "") + "/" + platform.get("architecture", "")
        p.require(
            label in platforms
            and label not in seen
            and platform.get("variant", "") in ("", "v8"),
            "unexpected, duplicate or unsupported OCI platform",
        )
        seen.add(label)
        manifest = documents.get(blob(descriptor), {})
        p.require(
            manifest.get("schemaVersion") == 2
            and manifest.get("mediaType") in MANIFEST_TYPES,
            "unsupported image manifest",
        )
        config = documents.get(blob(manifest["config"]), {})
        p.require(
            config.get("os") == platform["os"]
            and config.get("architecture") == platform["architecture"],
            "OCI config platform differs",
        )
        layers = manifest.get("layers")
        p.require(isinstance(layers, list) and layers, "empty OCI image")
        for layer in layers:
            blob(layer)
        artifact = platforms[label]
        p.require(
            artifact in artifacts, "OCI platform has no qualified native artifact"
        )
        plan = artifacts[artifact]
        expected_arch = "x86_64" if label == "linux/amd64" else "aarch64"
        p.require(
            plan["target"].startswith(expected_arch + "-")
            and "-linux-" in plan["target"],
            "native target differs from OCI platform",
        )
        subjects.append(
            {
                "platform": label,
                "manifest_sha256": descriptor["digest"][7:],
                "config_sha256": manifest["config"]["digest"][7:],
                "layers": [layer["digest"] for layer in layers],
                "artifact": artifact,
                "artifact_sha256": plan["artifact_sha256"],
                "source_commit": plan["source_commit"],
            }
        )
    p.require(seen == set(platforms), "OCI platform set incomplete")
    p.require(set(hashes) == used, "unreferenced OCI bytes in export")
    return (
        {
            "archive_sha256": p.digest(archive),
            "platforms": sorted(subjects, key=lambda row: row["platform"]),
        },
        document_bytes[index_name],
    )


def statement(ref, closure, release, builder_id):
    return {
        "_type": p.STATEMENT,
        "subject": [
            {"name": ref.split("@", 1)[0], "digest": {"sha256": reference(ref)}}
        ],
        "predicateType": PREDICATE,
        "predicate": {"release": p.token(release), "builder_id": builder_id, **closure},
    }


def verify_registry(ref, expected, config):
    """Cosign checks registry subject/signature/log; exact payload checks our policy."""
    reference(ref)
    trust = p.cosign_trust(config)
    output = p.command(
        [
            config["cosign"],
            "verify-attestation",
            "--type",
            PREDICATE,
            "--trusted-root",
            config["trusted_root"],
            *trust,
            ref,
        ]
    )
    text = output.decode()
    decoder = json.JSONDecoder()
    envelopes = []
    while text.strip():
        value, end = decoder.raw_decode(text.lstrip())
        envelopes.extend(value if isinstance(value, list) else [value])
        text = text.lstrip()[end:]
    p.require(envelopes, "registry returned no verified attestations")
    for envelope in envelopes:
        p.require(
            envelope.get("payloadType") == "application/vnd.in-toto+json"
            and base64.b64decode(envelope["payload"], validate=True)
            == p.canonical(expected),
            "registry attestation differs from approved release",
        )
