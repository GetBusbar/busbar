#!/usr/bin/env python3
"""Derive a Cargo build inventory from locked metadata, compiler messages and shipped bytes.

The controller captures inputs from the actual build. This records the compilation
closure (including build tools), not a claim that every dependency is linked at runtime.
No source paths, Cargo credentials or compiler diagnostics enter public evidence.
"""

import argparse
import hashlib
from pathlib import Path, PurePosixPath
import stat
import sys
import tarfile
import tomllib
from urllib.parse import quote
import zipfile

import native_provenance as p

SCHEMA = "busbar.build-closure/1"
MAX_FILE = 2 * 1024 * 1024 * 1024
MAX_FILES = 100000


def member_name(value):
    p.require(
        isinstance(value, str) and value and len(value) <= 1024 and "\\" not in value,
        "invalid archive member",
    )
    while value.startswith("./"):
        value = value[2:]
    value = value.rstrip("/")
    path = PurePosixPath(value)
    p.require(
        value
        and not path.is_absolute()
        and all(x not in ("", ".", "..") for x in value.split("/")),
        "unsafe archive member",
    )
    return value


def stream_digest(stream, size):
    p.require(0 <= size <= MAX_FILE, "archive member exceeds limit")
    digest, count = hashlib.sha256(), 0
    while block := stream.read(min(1024 * 1024, size - count + 1)):
        count += len(block)
        p.require(count <= size, "archive member size differs")
        digest.update(block)
    p.require(count == size, "truncated archive member")
    return digest.hexdigest()


def archive_members(path):
    """Inventory regular files, never extract; reject ambiguous paths and all links."""
    files, seen = {}, set()

    def add(name, size, stream):
        files[name] = {"sha256": stream_digest(stream, size), "size": size}

    def name(value):
        result = member_name(value)
        p.require(
            result not in seen and len(seen) < MAX_FILES,
            "duplicate or excessive archive members",
        )
        seen.add(result)
        return result

    if zipfile.is_zipfile(path):
        with zipfile.ZipFile(path) as archive:
            for entry in archive.infolist():
                key = name(entry.filename)
                mode = entry.external_attr >> 16
                p.require(
                    not entry.flag_bits & 1
                    and stat.S_IFMT(mode) in (0, stat.S_IFREG, stat.S_IFDIR),
                    "unsupported ZIP member",
                )
                if entry.is_dir():
                    continue
                with archive.open(entry) as stream:
                    add(key, entry.file_size, stream)
    else:
        with tarfile.open(path, "r:*") as archive:
            for entry in archive:
                if entry.name in (".", "./") and entry.isdir():
                    continue
                key = name(entry.name)
                p.require(
                    entry.isfile() or entry.isdir(), "nonregular native archive member"
                )
                if entry.isfile():
                    add(key, entry.size, archive.extractfile(entry))
    p.require(files, "empty native archive")
    for key in files:
        p.require(
            not any(str(parent) in files for parent in PurePosixPath(key).parents),
            "file shadows archive directory",
        )
    return dict(sorted(files.items()))


def collect(
    artifact,
    metadata_path,
    lock_path,
    messages_path,
    binary,
    member,
    package,
    source_commit,
    target,
    component_name,
    version,
    compiler_output=None,
):
    """Actual successful Cargo JSON stream + exact lock/metadata + archive/output equality."""
    metadata = p.load(metadata_path)
    packages = {row["id"]: row for row in metadata["packages"]}
    nodes = {row["id"]: row for row in metadata["resolve"]["nodes"]}
    p.require(
        len(packages) == len(metadata["packages"])
        and len(nodes) == len(metadata["resolve"]["nodes"]),
        "duplicate Cargo package",
    )
    messages = [
        p.decode(line)
        for line in Path(messages_path).read_bytes().splitlines()
        if line.strip()
    ]
    p.require(
        messages
        and messages[-1] == {"reason": "build-finished", "success": True}
        and sum(row.get("reason") == "build-finished" for row in messages) == 1,
        "one complete successful Cargo build stream required",
    )
    compiled = {
        row["package_id"]
        for row in messages
        if row.get("reason") == "compiler-artifact"
    }
    p.require(
        compiled and compiled <= packages.keys() and compiled <= nodes.keys(),
        "compiled package missing from locked metadata",
    )
    binary = Path(binary).absolute()
    p.require(
        binary.is_file() and not binary.is_symlink(), "nonregular compiled output"
    )
    output_identity = Path(compiler_output) if compiler_output else binary
    p.require(
        output_identity.is_absolute() and ".." not in output_identity.parts,
        "invalid original compiler output path",
    )
    roots = {
        row["package_id"]
        for row in messages
        if row.get("reason") == "compiler-artifact"
        and any(
            Path(filename).absolute() == output_identity
            for filename in row.get("filenames", [])
        )
        and packages[row["package_id"]]["name"] == package
    }
    p.require(
        len(roots) == 1,
        "shipped binary was not an output of the selected Cargo package",
    )
    root = next(iter(roots))
    features = {}
    for row in messages:
        if row.get("reason") == "compiler-artifact":
            features.setdefault(row["package_id"], set()).update(row["features"])

    def dependencies(identifier):
        return {
            dep["pkg"]
            for dep in nodes[identifier]["deps"]
            if any(kind["kind"] != "dev" for kind in dep["dep_kinds"])
        }

    lock = tomllib.loads(Path(lock_path).read_text())
    locked = {
        (row["name"], row["version"], row.get("source")): row for row in lock["package"]
    }
    public, refs = [], {}
    # Include additional compiled units too: compilation/build tooling is part of this inventory.
    for identifier in sorted(compiled):
        row = packages[identifier]
        source = row.get("source")
        key = (row["name"], row["version"], source)
        p.require(key in locked, "compiled package absent from Cargo.lock")
        ref = "cargo:" + hashlib.sha256(p.canonical(list(key))).hexdigest()
        refs[identifier] = ref
        item = {
            "bom-ref": ref,
            "type": "library",
            "name": row["name"],
            "version": row["version"],
            "purl": "pkg:cargo/"
            + quote(row["name"], safe="")
            + "@"
            + quote(row["version"], safe=""),
            "properties": [
                {
                    "name": "busbar:cargo:features",
                    "value": ",".join(sorted(features[identifier])),
                }
            ],
        }
        if source:
            # Reject credential-bearing or private source URLs from public evidence.
            from urllib.parse import urlsplit

            parsed = urlsplit(
                source.removeprefix("registry+").removeprefix("git+").split("#", 1)[0]
            )
            p.require(
                parsed.scheme in ("https", "sparse+https")
                and parsed.hostname
                and not parsed.username
                and not parsed.password,
                "unsafe dependency source",
            )
            item["properties"].append(
                {
                    "name": "busbar:cargo:source-sha256",
                    "value": hashlib.sha256(source.encode()).hexdigest(),
                }
            )
        checksum = locked[key].get("checksum")
        if checksum:
            item["hashes"] = [{"alg": "SHA-256", "content": p.hex_value(checksum)}]
        public.append(item)
    members = archive_members(artifact)
    member = member_name(member)
    p.require(
        member in members and members[member]["sha256"] == p.digest(binary),
        "native archive does not contain the compiled bytes",
    )
    return {
        "schema": SCHEMA,
        "source_commit": p.hex_value(source_commit, 40),
        "target": p.token(target),
        "component_name": p.token(component_name),
        "version": p.token(version),
        "artifact": {"name": Path(artifact).name, "sha256": p.digest(artifact)},
        "inputs": {
            kind: p.digest(path)
            for kind, path in (
                ("cargo_metadata", metadata_path),
                ("cargo_lock", lock_path),
                ("cargo_messages", messages_path),
            )
        },
        "members": members,
        "binaries": {member: refs[root]},
        "components": public,
        "dependencies": [
            {
                "ref": refs[key],
                "dependsOn": sorted(
                    refs[dep] for dep in dependencies(key) if dep in compiled
                ),
            }
            for key in sorted(compiled)
        ],
    }


def validate(closure, plan, artifact, component_name, version):
    p.require(
        set(closure)
        == {
            "schema",
            "source_commit",
            "target",
            "component_name",
            "version",
            "artifact",
            "inputs",
            "members",
            "binaries",
            "components",
            "dependencies",
        }
        and closure["schema"] == SCHEMA,
        "unsupported build closure",
    )
    p.require(
        closure["source_commit"] == plan["source_commit"]
        and closure["target"] == plan["target"]
        and closure["component_name"] == component_name
        and closure["version"] == version
        and closure["artifact"]
        == {"name": plan["artifact_name"], "sha256": plan["artifact_sha256"]}
        and p.digest(artifact) == plan["artifact_sha256"],
        "build closure belongs to another artifact",
    )
    p.require(
        set(closure["inputs"]) == {"cargo_metadata", "cargo_lock", "cargo_messages"},
        "incomplete build inputs",
    )
    for digest in closure["inputs"].values():
        p.hex_value(digest)
    p.require(
        closure["members"] == archive_members(artifact),
        "build closure archive members differ",
    )
    refs = [row["bom-ref"] for row in closure["components"]]
    p.require(
        refs and len(refs) == len(set(refs)), "duplicate or empty build components"
    )
    p.require(
        closure["binaries"]
        and set(closure["binaries"]) <= closure["members"].keys()
        and set(closure["binaries"].values()) <= set(refs),
        "invalid shipped binary mapping",
    )
    p.require(
        {row["ref"] for row in closure["dependencies"]} == set(refs)
        and len(closure["dependencies"]) == len(refs)
        and all(set(row["dependsOn"]) <= set(refs) for row in closure["dependencies"]),
        "incomplete build dependency graph",
    )
    return closure


def sbom(closure):
    """Deterministic CycloneDX with graph, exact artifact hash and closure commitment."""
    root = "release:" + closure["artifact"]["sha256"]
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "bom-ref": root,
                "name": closure["component_name"],
                "version": closure["version"],
                "hashes": [
                    {"alg": "SHA-256", "content": closure["artifact"]["sha256"]}
                ],
            },
            "properties": [
                {
                    "name": "busbar:build-closure:sha256",
                    "value": hashlib.sha256(p.canonical(closure)).hexdigest(),
                },
                {
                    "name": "busbar:inventory:scope",
                    "value": "cargo-compilation-including-build-tools",
                },
            ],
        },
        "components": closure["components"],
        "dependencies": [
            {"ref": root, "dependsOn": sorted(set(closure["binaries"].values()))},
            *closure["dependencies"],
        ],
    }


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for key in ("artifact", "metadata", "lock", "messages", "binary", "output"):
        parser.add_argument("--" + key, required=True, type=Path)
    for key in (
        "member",
        "package",
        "source-commit",
        "target",
        "component-name",
        "version",
    ):
        parser.add_argument("--" + key, required=True)
    args = parser.parse_args()
    closure = collect(
        args.artifact,
        args.metadata,
        args.lock,
        args.messages,
        args.binary,
        args.member,
        args.package,
        args.source_commit,
        args.target,
        args.component_name,
        args.version,
    )
    p.write(args.output, p.canonical(closure))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print("build-closure: refused (" + type(error).__name__ + ")", file=sys.stderr)
        sys.exit(1)
