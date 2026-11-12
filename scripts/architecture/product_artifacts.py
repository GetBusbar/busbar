"""Bounded owner declarations for the admitted fleet's native test artifacts.

Only typed environment bindings are owner data. Build commands, source identity,
package selection, output locations and packing policy remain controller-owned.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path, PurePosixPath
import re
import subprocess
import sys
import tarfile
import tomllib

from check import Policy, Violation, read, vector_revisions


KINDS = {"cdylib": ("CDYLIB", "PLUGIN"), "manifest": ("MANIFEST",),
         "declares": ("DECLARES",), "empty-settings": ("SETTINGS",)}
ENV_KEY = re.compile(r"BUSBAR_(?:[A-Z0-9]+_)*TEST_(?:[A-Z0-9]+_)*(CDYLIB|PLUGIN|MANIFEST|DECLARES|SETTINGS)")
IDENT = re.compile(r"[a-z][a-z0-9_-]{0,127}")


def require(condition, message):
    if not condition:
        raise Violation(message)


def pairs(items):
    result = {}
    for key, value in items:
        require(key not in result, "duplicate product input")
        result[key] = value
    return result


def relative_path(value):
    require(isinstance(value, str) and 0 < len(value) <= 512
            and re.fullmatch(r"[A-Za-z0-9_./-]+", value), "invalid product source path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(p not in ("", ".", "..") for p in value.split("/")),
            "product source path must be relative and confined")
    return value


def confined_path(path, root):
    path, root = Path(path), Path(root)
    require(path.is_absolute() and root.is_absolute() and path.is_relative_to(root)
            and ".." not in path.parts, "product input escapes candidate workspace")
    for current in (path, *path.parents):
        require(not current.is_symlink(), "indirect product input")
    return path


def regular_under(path, root):
    path, root = confined_path(path, root), Path(root)
    require(path.is_file() and path.resolve().is_relative_to(root.resolve()),
            "missing or nonregular product input")
    return path


def git(source, *args):
    try:
        return subprocess.check_output([
            "git", "--no-pager", "--no-replace-objects", "-c", "core.fsmonitor=false",
            "-C", str(source), *args,
        ], stderr=subprocess.PIPE)
    except subprocess.CalledProcessError as error:
        raise Violation("cannot read exact artifact owner Git source") from error


def blob(source, revision, relative, limit, *, git_reader=git):
    relative_path(relative)
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "immutable artifact owner revision required")
    source = Path(source)
    require(source.is_dir() and not any(p.is_symlink() for p in (source, *source.parents)),
            "indirect or missing artifact owner source")
    entry = git_reader(source, "ls-tree", revision, "--", relative).decode().rstrip("\n")
    fields = entry.split("\t")
    require(len(fields) == 2 and fields[1] == relative, "missing declared owner source")
    mode, kind, oid = fields[0].split()
    require(mode == "100644" and kind == "blob", "owner metadata must be a regular Git blob")
    require(int(git_reader(source, "cat-file", "-s", oid)) <= limit, "owner metadata exceeds limit")
    data = git_reader(source, "cat-file", "blob", oid)
    require(len(data) <= limit, "owner metadata exceeds limit")
    return data


def declarations(metadata):
    require(isinstance(metadata, dict) and not set(metadata) - KINDS.keys(),
            "unknown artifact declaration fields")
    seen = set()
    for kind, keys in metadata.items():
        require(isinstance(keys, list) and 0 < len(keys) <= 16, "artifact binding count exceeds limit")
        for key in keys:
            match = ENV_KEY.fullmatch(key) if isinstance(key, str) and len(key) <= 128 else None
            require(match and match[1] in KINDS[kind], "unknown or mistyped artifact environment key")
            require(key not in seen, "duplicate artifact environment key")
            seen.add(key)
    return metadata


def plan(policy, vector, sources, target, cache, revision, platform=None, *, git_reader=git):
    """Read independently from exact canonical Git commits, never candidate JSON."""
    require(isinstance(vector, dict) and isinstance(vector.get("products"), list)
            and 0 < len(vector["products"]) <= 128, "invalid product vector size")
    vector_revisions(policy, vector)
    require(re.fullmatch(r"[0-9a-f]{40}", revision), "immutable assembly revision required")
    platform = platform or sys.platform
    require(platform in ("darwin", "linux"), "unsupported native artifact platform")
    suffix = ".dylib" if platform == "darwin" else ".so"
    work = Path(cache) / "ci-product-inputs" / revision
    result, values = [], {}
    for row in vector["products"]:
        require(all(isinstance(row.get(k), str) and IDENT.fullmatch(row[k])
                    for k in ("repo", "package", "kind", "alias")), "invalid artifact identity")
        relative_path(row["declares"])
        entries = policy.data["repositories"]["GetBusbar/" + row["repo"]]["packages"]
        wrappers = [entry for entry in entries if entry["name"] == row["package"] and entry["role"] == "wrapper"]
        require(len(wrappers) == 1, "artifact package is not its classified wrapper")
        source = sources(row)
        lock = blob(source, row["commit"], "Cargo.lock", 16 * 1024 * 1024, git_reader=git_reader)
        require(hashlib.sha256(lock).hexdigest() == row["lock_sha256"], "artifact owner lock differs from vector")
        manifest = tomllib.loads(blob(source, row["commit"], wrappers[0]["manifest"], 256 * 1024,
                                     git_reader=git_reader).decode())
        require(manifest["package"]["name"] == row["package"], "artifact wrapper package mismatch")
        metadata = declarations(manifest["package"].get("metadata", {}).get("busbar", {}).get("test-artifacts", {}))
        if not metadata:
            continue
        library = manifest.get("lib", {})
        name = library.get("name", row["package"].replace("-", "_"))
        require(isinstance(name, str) and re.fullmatch(r"[a-z][a-z0-9_]{0,127}", name)
                and "cdylib" in library.get("crate-type", [])
                and row["image"] == "lib" + name + ".so", "artifact image differs from wrapper target")
        checkout = work / "sources" / (row["repo"] + "-" + row["commit"])
        paths = {"cdylib": str(Path(target) / "debug" / ("lib" + name + suffix)),
                 "manifest": str(work / row["repo"] / "manifest.json"),
                 "declares": str(checkout / row["declares"]), "empty-settings": "{}"}
        for kind, path in paths.items():
            if kind != "empty-settings":
                confined_path(path, target if kind == "cdylib" else cache)
        require(paths["cdylib"] not in [item["image"] for item in result],
                "artifact owners collide on image path")
        if "declares" in metadata or "manifest" in metadata:
            blob(source, row["commit"], row["declares"], 1024 * 1024, git_reader=git_reader)
        for kind, keys in metadata.items():
            for key in keys:
                require(key not in values, "artifact owners collide on environment key")
                values[key] = paths[kind]
        require(len(values) <= 256, "total artifact bindings exceed limit")
        result.append({"product": row, "checkout": checkout, "metadata": metadata,
                       "image": paths["cdylib"], "manifest": paths["manifest"],
                       "dropped_in": "dropped-in" in manifest.get("features", {})})
    require(values, "no owner-declared product inputs")
    return result, values


def checkout_product(row, source):
    confined_path(source, source)
    if not source.exists():
        source.mkdir(parents=True)
        subprocess.run(["git", "-C", str(source), "init", "-q"], check=True, stdout=sys.stderr)
        subprocess.run(["git", "-C", str(source), "fetch", "--depth", "1", row["url"], row["commit"]],
                       check=True, stdout=sys.stderr)
        subprocess.run(["git", "-C", str(source), "checkout", "--detach", "FETCH_HEAD"],
                       check=True, stdout=sys.stderr)
    require(not any(p.is_symlink() for p in (source, *source.parents)), "indirect product checkout")
    require(git(source, "rev-parse", "HEAD").decode().strip() == row["commit"]
            and not git(source, "status", "--porcelain", "--untracked-files=all", "--ignored=matching"),
            "product checkout differs from admitted pin")
    lock = regular_under(source / "Cargo.lock", source)
    require(hashlib.sha256(lock.read_bytes()).hexdigest() == row["lock_sha256"], "product lock mismatch")


# Exactly the one dev-profile command that builds a product's test image. The
# trusted image producer (native_product_images) runs this same function, so a
# restored image comes from the same argv, toolchain and Cargo configuration.
CARGO = ("cargo", "+1.98.0", "build", "--locked")
# Controller-owned, read-only: trusted prebuilt images and their digests. Only
# the protected controller mounts it, and only for the product-inputs step.
PREBUILT = Path("/__busbar_product_images")


def image_argv(item, target):
    row, source = item["product"], item["checkout"]
    args = [*CARGO, "--manifest-path", str(source / "Cargo.toml"), "-p", row["package"],
            "--lib", "--target-dir", str(target)]
    if item["dropped_in"]:
        args += ["--features", "dropped-in"]
    return args


def prebuilt_images(root=PREBUILT):
    """The controller's verified index, or nothing: absence always builds."""
    index = root / "index.json"
    if not index.is_file() or index.is_symlink():
        return {}
    data = json.loads(index.read_text(), object_pairs_hook=pairs)
    require(isinstance(data, dict) and len(data) <= 128, "invalid prebuilt image index")
    return data


def install_prebuilt(entry, row, destination, root=PREBUILT):
    """Copy one trusted image to the exact path Cargo would have written."""
    require(entry.get("commit") == row["commit"] and entry.get("image") == row["image"]
            and entry.get("lock_sha256") == row["lock_sha256"]
            and destination.name == row["image"], "prebuilt image differs from its pin")
    relative = relative_path(entry["file"])
    source = regular_under(root / relative, root)
    data = source.read_bytes()
    require(hashlib.sha256(data).hexdigest() == entry["sha256"], "prebuilt image digest differs")
    destination.parent.mkdir(parents=True, exist_ok=True)
    require(not destination.is_symlink() and not destination.parent.is_symlink(), "indirect artifact output")
    temporary = destination.with_name(destination.name + ".prebuilt")
    temporary.unlink(missing_ok=True)
    temporary.write_bytes(data)
    temporary.chmod(0o755)
    os.replace(temporary, destination)
    print("product-inputs: " + row["repo"] + ": trusted prebuilt image sha256=" + entry["sha256"],
          file=sys.stderr, flush=True)


def build_image(root, target, cache, policy, repo):
    """Trusted producer only: build exactly one product's image, nothing else."""
    vector = json.loads((root / "scripts/ci-product-pins.json").read_text(), object_pairs_hook=pairs)
    vector_revisions(policy, vector)
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    canonical = cache.parent / "canonical-inputs"
    require(canonical.is_dir(), "image production requires the trusted canonical inputs")
    products, _ = plan(policy, vector, lambda row: canonical / row["repo"], target, cache, revision)
    selected = [item for item in products if item["product"]["repo"] == repo]
    require(len(selected) == 1, "product declares no test image")
    item = selected[0]
    checkout_product(item["product"], item["checkout"])
    subprocess.run(image_argv(item, target), check=True, stdout=sys.stderr)
    return regular_under(item["image"], target)


def build(root, target, cache, policy):
    vector = json.loads((root / "scripts/ci-product-pins.json").read_text(), object_pairs_hook=pairs)
    vector_revisions(policy, vector)
    revision = git(root, "rev-parse", "HEAD").decode().strip()
    work = cache / "ci-product-inputs" / revision
    canonical = cache.parent / "canonical-inputs"
    if canonical.is_dir():
        sources = lambda row: canonical / row["repo"]
    else:
        # Direct local use has no trusted collector; fetch the same immutable
        # public vector before discovering which owners declare test artifacts.
        for row in vector["products"]:
            checkout_product(row, work / "sources" / (row["repo"] + "-" + row["commit"]))
        sources = lambda row: work / "sources" / (row["repo"] + "-" + row["commit"])
    products, values = plan(policy, vector, sources, target, cache, revision)
    prebuilt = prebuilt_images()
    if any("manifest" in item["metadata"] for item in products):
        # The packer is candidate code: always built here, never prebuilt.
        subprocess.run([*CARGO, "-p", "busbar-plugin-loader", "--features", "pack", "--bin",
                        "busbar-plugin-pack", "--target-dir", str(target)], cwd=root, check=True, stdout=sys.stderr)
    for item in products:
        row, source = item["product"], item["checkout"]
        checkout_product(row, source)
        if row["repo"] in prebuilt:
            install_prebuilt(prebuilt[row["repo"]], row, Path(item["image"]))
        else:
            subprocess.run(image_argv(item, target), check=True, stdout=sys.stderr)
        regular_under(item["image"], target)
        if "declares" in item["metadata"] or "manifest" in item["metadata"]:
            regular_under(source / row["declares"], source)
        if "manifest" in item["metadata"]:
            archive = work / (row["repo"] + ".tar.gz")
            confined_path(archive, work)
            env = dict(os.environ)
            env.pop("BUSBAR_SIGN_KEY", None)
            subprocess.run([str(target / "debug/busbar-plugin-pack"), "pack", "--lib", item["image"],
                            "--name", row["repo"], "--alias", row["alias"], "--kind", row["kind"],
                            "--publisher", "busbar", "--license", "Apache-2.0", "--declares-file",
                            str(source / row["declares"]), "--allow-unsigned", "--out", str(archive)],
                           check=True, env=env, stdout=sys.stderr)
            regular_under(archive, work)
            with tarfile.open(archive, "r:gz") as bundle:
                manifests = [item for item in bundle.getmembers() if item.name == "manifest.json"]
                require(len(manifests) == 1, "packed artifact must contain one manifest")
                member = manifests[0]
                require(member.isfile() and member.size <= 1024 * 1024, "invalid packed artifact manifest")
                data = bundle.extractfile(member).read(1024 * 1024 + 1)
                require(len(data) == member.size, "invalid packed artifact manifest size")
            destination = Path(item["manifest"])
            destination.parent.mkdir(exist_ok=True)
            require(not destination.is_symlink() and not destination.parent.is_symlink(), "indirect artifact output")
            destination.write_bytes(data)
    filename = work / "environment.json"
    require(not filename.is_symlink(), "indirect product input map")
    encoded = json.dumps(values, sort_keys=True) + "\n"
    require(len(encoded.encode()) <= 128 * 1024, "product input map exceeds limit")
    filename.write_text(encoded)
    return filename


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--root", required=True, type=Path)
    parser.add_argument("--target", required=True, type=Path)
    parser.add_argument("--cache", required=True, type=Path)
    parser.add_argument("--image-only", help="trusted image producer: build only this product repo")
    args = parser.parse_args()
    policy = Policy(read(Path(__file__).resolve().parents[2] / "ci/architecture.toml"))
    if args.image_only:
        print(build_image(args.root.resolve(), args.target.absolute(), args.cache.absolute(), policy,
                          args.image_only))
        return
    print(build(args.root.resolve(), args.target.absolute(), args.cache.absolute(), policy))


if __name__ == "__main__":
    main()
