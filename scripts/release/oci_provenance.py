#!/usr/bin/env python3
"""Bind an immutable OCI index, its complete exported bytes and native subjects.

No registry writes or signing. The protected producer supplies the expected
platform/native-artifact map; the verifier checks the actual OCI byte closure.
"""

import base64
import hashlib
import gzip
import json
from pathlib import PurePosixPath
import re
import tarfile

import native_provenance as p
import build_closure as build

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


def image_binary(archive, layers, config, image_path, expected):
    """Apply OCI whiteouts and overlays in order, without writing image paths to disk."""
    p.require(
        image_path.startswith("/") and not image_path.startswith("//"),
        "absolute image binary path required",
    )
    wanted = build.member_name(image_path[1:])
    p.require(
        config.get("config", {}).get("Entrypoint") == [image_path],
        "image entrypoint differs from qualified native executable",
    )
    rootfs = config.get("rootfs", {})
    p.require(
        rootfs.get("type") == "layers"
        and len(rootfs.get("diff_ids", [])) == len(layers),
        "OCI uncompressed layer commitments missing",
    )
    filesystem = {}

    def remove(path, children_only=False):
        for key in list(filesystem):
            if (
                (not children_only and key == path)
                or key.startswith(path + "/")
                or not path
            ):
                del filesystem[key]

    with tarfile.open(archive, "r:*") as outer:
        outer_members = {entry.name.removeprefix("./"): entry for entry in outer}
        for index, descriptor in enumerate(layers):
            media = descriptor["mediaType"]
            p.require(
                media
                in (
                    "application/vnd.oci.image.layer.v1.tar",
                    "application/vnd.oci.image.layer.v1.tar+gzip",
                    "application/vnd.docker.image.rootfs.diff.tar.gzip",
                ),
                "unsupported OCI layer compression",
            )
            entry = outer_members["blobs/sha256/" + descriptor["digest"][7:]]
            raw = outer.extractfile(entry)
            stream = (
                gzip.GzipFile(fileobj=raw)
                if media.endswith(("+gzip", ".gzip"))
                else raw
            )
            digest, count = hashlib.sha256(), 0
            while block := stream.read(1024 * 1024):
                count += len(block)
                p.require(
                    count <= 8 * 1024 * 1024 * 1024, "expanded OCI layer exceeds limit"
                )
                digest.update(block)
            p.require(
                rootfs["diff_ids"][index] == "sha256:" + digest.hexdigest(),
                "OCI diff_id differs",
            )
            additions, whiteouts, seen = {}, [], set()
            with tarfile.open(fileobj=outer.extractfile(entry), mode="r:*") as layer:
                for member in layer:
                    if member.isdir() and member.name in (".", "./"):
                        continue
                    key = build.member_name(member.name)
                    p.require(
                        key not in seen and len(seen) < build.MAX_FILES,
                        "duplicate or excessive OCI layer paths",
                    )
                    seen.add(key)
                    name = PurePosixPath(key).name
                    parent = str(PurePosixPath(key).parent)
                    parent = "" if parent == "." else parent
                    if name.startswith(".wh."):
                        p.require(
                            member.isfile() and member.size == 0, "invalid OCI whiteout"
                        )
                        if name == ".wh..wh..opq":
                            whiteouts.append((parent, True))
                        else:
                            target = build.member_name(
                                (parent + "/" if parent else "") + name[4:]
                            )
                            whiteouts.append((target, False))
                        continue
                    if member.isfile():
                        additions[key] = {
                            "kind": "file",
                            "sha256": build.stream_digest(
                                layer.extractfile(member), member.size
                            ),
                            "size": member.size,
                            "executable": bool(member.mode & 0o111),
                        }
                    elif member.isdir():
                        additions[key] = {"kind": "directory"}
                    elif member.issym() or member.islnk():
                        additions[key] = {"kind": "link"}
                    else:
                        p.require(False, "unsupported special OCI filesystem member")
            for key, opaque in whiteouts:
                remove(key, children_only=opaque)
            for key, value in sorted(
                additions.items(), key=lambda item: (item[0].count("/"), item[0])
            ):
                if (
                    value["kind"] != "directory"
                    or filesystem.get(key, {}).get("kind") != "directory"
                ):
                    remove(key)
                for parent in PurePosixPath(key).parents:
                    if str(parent) != ".":
                        p.require(
                            filesystem.get(str(parent), {"kind": "directory"})["kind"]
                            == "directory",
                            "OCI member traverses nondirectory",
                        )
                        filesystem.setdefault(str(parent), {"kind": "directory"})
                filesystem[key] = value
            p.require(
                len(filesystem) <= build.MAX_FILES, "OCI filesystem exceeds limit"
            )
    actual = filesystem.get(wanted, {})
    p.require(
        actual.get("kind") == "file"
        and actual.get("executable") is True
        and actual.get("sha256") == expected["sha256"]
        and actual.get("size") == expected["size"],
        "final image binary differs from qualified native archive",
    )
    p.require(
        all(
            filesystem.get(str(parent), {}).get("kind") == "directory"
            for parent in PurePosixPath(wanted).parents
            if str(parent) != "."
        ),
        "image binary parent is not a directory",
    )
    return {"path": image_path, "sha256": actual["sha256"], "size": actual["size"]}


def inspect_archive(archive, ref, platforms, artifacts, closures=None):
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
        mapping = platforms[label]
        if closures is not None:
            p.require(
                isinstance(mapping, dict)
                and set(mapping) == {"artifact", "member", "path"},
                "OCI requires exact native member and image path",
            )
            artifact = mapping["artifact"]
        else:
            artifact = mapping
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
        equivalence = {}
        if closures is not None:
            closure = closures[artifact]
            member = mapping["member"]
            p.require(
                member in closure["binaries"], "OCI member was not a compiled binary"
            )
            equivalence = {
                "native_member": member,
                "binary": image_binary(
                    archive, layers, config, mapping["path"], closure["members"][member]
                ),
            }
        subjects.append(
            {
                **equivalence,
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
