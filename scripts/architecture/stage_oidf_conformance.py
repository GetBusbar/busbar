#!/usr/bin/env python3
"""Controller-only staging of the four fixed OIDF release images and official runner.

Never run this helper inside a candidate job. It creates no running containers and
copies no Docker socket or credentials. The native controller measures and mounts
its regular-file bundles read-only. Cached images are preferred; a missing image
gets one bounded pull. Image symlinks are resolved against the image, never the host.
"""
import argparse
import hashlib
import json
import os
from pathlib import Path
import posixpath
import re
import shutil
import stat
import struct
import subprocess
import tarfile
import urllib.request
import urllib.parse
import uuid

SUITE_REPO = "https://gitlab.com/openid/conformance-suite.git"
SUITE_COMMIT = "7d420f716e49d44f8a6b04f0a3e240ad6d68ab55"
IMAGES = {
    "server": "registry.gitlab.com/openid/conformance-suite@sha256:377ab51f011d821c4b6f7729053e85adf062d691e51a3615f40507fd900a2436",
    "nginx": "registry.gitlab.com/openid/conformance-suite/nginx@sha256:d80183af68cb51c72c86b498780d94d6192cbc6adcc70a7d28ac6a01eff0d0db",
    "mongo": "mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070",
    "python": "python@sha256:bf12ecc0bea3f171d55145dd02c78b5eeb09f30ee2ac9cc2b4c9e4e8f5e30741",
}
BINARIES = {
    "server": ["opt/java/openjdk/bin/java", "opt/java/openjdk/bin/keytool", "usr/bin/openssl"],
    "nginx": ["usr/sbin/nginx"], "mongo": ["usr/bin/mongod"], "python": ["usr/local/bin/python3"],
}
EXTRA = {
    "server": ["opt/java/openjdk", "server", "usr/share/fonts", "etc/fonts"],
    "nginx": ["etc/nginx"], "mongo": [], "python": ["usr/local/lib/python3.13"],
}


WHEELS = [
    ("https://files.pythonhosted.org/packages/12/b8/4bd346e22b28902df4d651910f5242c28d84e4a5c2435ca5c3f797ed7e2e/anyio-4.15.1-py3-none-any.whl",
     "6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101"),
    ("https://files.pythonhosted.org/packages/32/d1/a3652fe2c19134d0d15922177821d863cbd7e842d53a21bbe7e8e3a1b5ac/certifi-2026.10.23-py3-none-any.whl",
     "e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1"),
    ("https://files.pythonhosted.org/packages/04/4b/29cac41a4d98d144bf5f6d33995617b185d14b22401f75ca86f384e87ff1/h11-0.16.0-py3-none-any.whl",
     "63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86"),
    ("https://files.pythonhosted.org/packages/7e/f5/f66802a942d491edb555dd61e3a9961140fd64c90bce1eafd741609d334d/httpcore-1.0.9-py3-none-any.whl",
     "2d400746a40668fc9dec9810239072b40b4484b640a8c38fd654a024c7a1bf55"),
    ("https://files.pythonhosted.org/packages/2a/39/e50c7c3a983047577ee07d2a9e53faf5a69493943ec3f6a384bdc792deb2/httpx-0.28.1-py3-none-any.whl",
     "d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad"),
    ("https://files.pythonhosted.org/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl",
     "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c"),
    ("https://files.pythonhosted.org/packages/38/bb/d215ee7c73b61497b28a5503f9f53523f294fcc936762b7caf90e0c1c2b5/pyparsing-3.3.3-py3-none-any.whl",
     "ece8c00a69cf01b45d0b1dedabb469c90d8caf996d4fda40f147627a122849a4"),
    ("https://files.pythonhosted.org/packages/49/d3/b8441a820a491ddfc024b0b0cf0393375b75ea13866d9c66727e54c2fc80/typing_extensions-4.16.0-py3-none-any.whl",
     "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8"),
]

def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def command(argv, **kwargs):
    return subprocess.run(argv, check=True, timeout=kwargs.pop("timeout", 300), **kwargs)


class ImageFiles:
    """Read an exported image as a virtual filesystem; flatten only requested runtime paths."""
    def __init__(self, archives):
        self.tars = []
        self.members = {}
        self.sources = {}
        self.children = {}
        for archive in archives if isinstance(archives, list) else [archives]:
            source = tarfile.open(archive)
            self.tars.append(source)
            layer = {}
            for member in source:
                name = member.name.rstrip("/").removeprefix("./")
                if not name or name == ".":
                    continue
                if name.startswith("/") or ".." in Path(name).parts or name in layer:
                    raise ValueError("unsafe or duplicate image archive path")
                layer[name] = member
            # OCI whiteouts delete lower-layer entries before this layer's additions.
            for name in layer:
                leaf = posixpath.basename(name)
                if leaf.startswith(".wh."):
                    parent = posixpath.dirname(name)
                    opaque = leaf == ".wh..wh..opq"
                    target = parent if opaque else posixpath.join(parent, leaf[4:])
                    for prior in list(self.members):
                        if (prior == target and not opaque) or prior.startswith(target + "/") or not target:
                            self.members.pop(prior)
                            self.sources.pop(prior)
            for name, member in layer.items():
                if posixpath.basename(name).startswith(".wh."):
                    continue
                if not member.isdir() and name in self.members and self.members[name].isdir():
                    for prior in list(self.members):
                        if prior.startswith(name + "/"):
                            self.members.pop(prior)
                            self.sources.pop(prior)
                self.members[name] = member
                self.sources[name] = source
        for name in self.members:
            self.children.setdefault(posixpath.dirname(name), []).append(name)

    def resolve(self, name):
        for _ in range(40):
            parts = name.split("/")
            for index in range(1, len(parts) + 1):
                prefix = "/".join(parts[:index])
                member = self.members.get(prefix)
                if member is not None and (member.issym() or member.islnk()):
                    target = member.linkname
                    base = "" if member.islnk() or target.startswith("/") else posixpath.dirname(prefix)
                    name = posixpath.normpath(posixpath.join(base, target.lstrip("/"), *parts[index:]))
                    if name == ".." or name.startswith("../"):
                        raise ValueError("image link escapes its filesystem")
                    break
            else:
                if name not in self.members:
                    raise ValueError(f"missing image runtime path {name}")
                return name
        raise ValueError("cyclic image link")

    def copy(self, name, destination, ancestors=()):
        resolved = self.resolve(name)
        member = self.members[resolved]
        if member.isdir():
            if resolved in ancestors:
                raise ValueError("cyclic image directory link")
            destination.mkdir(parents=True, exist_ok=True)
            for child in self.children.get(resolved, []):
                self.copy(child, destination / posixpath.basename(child), (*ancestors, resolved))
        elif member.isfile():
            if member.size > 512 * 1024**2:
                raise ValueError("oversized image runtime file")
            destination.parent.mkdir(parents=True, exist_ok=True)
            with self.sources[resolved].extractfile(member) as source, destination.open("wb") as output:
                shutil.copyfileobj(source, output)
            destination.chmod(0o755 if member.mode & 0o111 else 0o644)
        else:
            raise ValueError(f"special image runtime file {name}")

    def close(self):
        for source in self.tars:
            source.close()


def interpreter(path, architecture=None):
    """ELF64 PT_INTERP; do not execute downloaded binaries while staging."""
    with path.open("rb") as stream:
        header = stream.read(64)
        if header[:6] != b"\x7fELF\x02\x01":
            raise ValueError("runtime binary is not little-endian ELF64")
        if architecture and struct.unpack_from("<H", header, 18)[0] != {"amd64": 62, "arm64": 183}[architecture]:
            raise ValueError("runtime ELF machine differs from requested architecture")
        offset = struct.unpack_from("<Q", header, 32)[0]
        size, count = struct.unpack_from("<HH", header, 54)
        if size != 56 or count > 100:
            raise ValueError("invalid ELF program headers")
        for index in range(count):
            stream.seek(offset + size * index)
            entry = stream.read(size)
            if struct.unpack_from("<I", entry)[0] == 3:
                location, length = struct.unpack_from("<Q", entry, 8)[0], struct.unpack_from("<Q", entry, 32)[0]
                if length > 4096:
                    raise ValueError("invalid ELF interpreter")
                stream.seek(location)
                return stream.read(length).rstrip(b"\0").decode().lstrip("/")
    raise ValueError("runtime ELF has no interpreter")


def image_runtime(name, architecture, destination, scratch):
    image = IMAGES[name]
    inspect = ["docker", "image", "inspect", "--platform", "linux/" + architecture, image]
    cached = subprocess.run(inspect, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=30)
    if cached.returncode:
        command(["docker", "pull", "--platform", "linux/" + architecture, image], timeout=600)
    info = json.loads(command(inspect, capture_output=True, text=True).stdout)[0]
    if info["Architecture"] != architecture or image not in info["RepoDigests"]:
        raise ValueError("cached image architecture or digest differs")
    container = "busbar-oidf-stage-" + uuid.uuid4().hex
    archive = scratch / (name + ".tar")
    try:
        command(["docker", "create", "--platform", "linux/" + architecture, "--network", "none",
                 "--name", container, image], stdout=subprocess.DEVNULL)
        command(["docker", "export", "--output", str(archive), container], timeout=600)
    finally:
        subprocess.run(["docker", "rm", "--force", container], stdout=subprocess.DEVNULL, timeout=60)
    files = ImageFiles(archive)
    try:
        extract_runtime(files, name, architecture, destination)
    finally:
        files.close()
        archive.unlink()


def extract_runtime(files, name, architecture, destination):
    triple = {"amd64": "x86_64-linux-gnu", "arm64": "aarch64-linux-gnu"}[architecture]
    # Keep the dynamic library closure, not unrelated package managers/compiler caches.
    for base in ("lib", "lib64", "usr/lib", "usr/local/lib", "lib/" + triple, "usr/lib/" + triple):
        try:
            resolved = files.resolve(base)
        except ValueError:
            continue
        for child in files.children.get(resolved, []):
            leaf = posixpath.basename(child)
            if ".so" in leaf or leaf in ("gconv", "ossl-modules"):
                files.copy(child, destination / base / leaf)
    roots = ["etc/ssl", *EXTRA[name], *BINARIES[name]]
    for root in roots:
        if root in files.members:
            files.copy(root, destination / root)
    loaders = {}
    for binary in BINARIES[name]:
        loader = interpreter(destination / binary, architecture)
        files.copy(loader, destination / loader)
        loaders[binary] = loader
    libraries = sorted({str(path.parent.relative_to(destination)) for path in destination.rglob("*")
                        if path.is_file() and (".so" in path.name or path.name.startswith("ld-"))})
    (destination / "runtime.json").write_text(json.dumps({"loaders": loaders, "library_dirs": libraries}) + "\n")


class PublicRegistry:
    """Anonymous, bounded retrieval from the fixed public image registries only."""
    ACCEPT = ", ".join(("application/vnd.oci.image.index.v1+json",
                        "application/vnd.docker.distribution.manifest.list.v2+json",
                        "application/vnd.oci.image.manifest.v1+json",
                        "application/vnd.docker.distribution.manifest.v2+json"))

    def __init__(self, image):
        repository = image.split("@")[0]
        if repository.startswith("registry.gitlab.com/"):
            self.host, self.repository = repository.split("/", 1)
            auth = "https://gitlab.com/jwt/auth?" + urllib.parse.urlencode({
                "service": "container_registry", "scope": "repository:" + self.repository + ":pull"})
        else:
            self.host, self.repository = "registry-1.docker.io", "library/" + repository
            auth = "https://auth.docker.io/token?" + urllib.parse.urlencode({
                "service": "registry.docker.io", "scope": "repository:" + self.repository + ":pull"})
        with urllib.request.urlopen(auth, timeout=60) as response:
            token = json.load(response)
        self.token = token.get("token") or token["access_token"]

    def fetch(self, kind, sha, destination, expected_size=None):
        if destination.is_file() and digest(destination) == sha.removeprefix("sha256:"):
            return destination
        if not re.fullmatch("sha256:[a-f0-9]{64}", sha):
            raise ValueError("invalid OCI digest")
        url = f"https://{self.host}/v2/{self.repository}/{kind}/{sha}"
        request = urllib.request.Request(url, headers={"Authorization": "Bearer " + self.token,
                                                       "Accept": self.ACCEPT})
        temporary = destination.with_suffix(".part")
        limit = 1024**3 if kind == "blobs" else 16 * 1024**2
        try:
            with urllib.request.urlopen(request, timeout=120) as response, temporary.open("wb") as output:
                size = 0
                while chunk := response.read(1024**2):
                    size += len(chunk)
                    if size > limit or (expected_size is not None and size > expected_size):
                        raise ValueError("OCI download exceeds byte limit")
                    output.write(chunk)
            if (expected_size is not None and size != expected_size) or digest(temporary) != sha[7:]:
                raise ValueError("OCI content digest or length differs")
            temporary.replace(destination)
        finally:
            temporary.unlink(missing_ok=True)
        return destination


def oci_runtime(name, architecture, destination, scratch):
    image = IMAGES[name]
    registry = PublicRegistry(image)
    index_digest = image.split("@")[1]
    index = registry.fetch("manifests", index_digest, scratch / (name + "-index.json"))
    document = json.loads(index.read_bytes())
    selected = index_digest
    if "manifests" in document:
        children = [child for child in document["manifests"]
                    if child.get("platform", {}).get("os") == "linux"
                    and child.get("platform", {}).get("architecture") == architecture]
        if len(children) != 1:
            raise ValueError("pinned OCI index has no unique requested platform")
        child = children[0]
        selected = child["digest"]
        manifest = registry.fetch("manifests", selected, scratch / (name + "-manifest.json"), child["size"])
        document = json.loads(manifest.read_bytes())
    descriptor = document["config"]
    config = registry.fetch("blobs", descriptor["digest"], scratch / (name + "-config.json"), descriptor["size"])
    config = json.loads(config.read_bytes())
    if config["os"] != "linux" or config["architecture"] != architecture:
        raise ValueError("pinned OCI config architecture differs")
    layers = []
    for layer in document["layers"]:
        if layer["mediaType"] not in ("application/vnd.oci.image.layer.v1.tar+gzip",
                                      "application/vnd.oci.image.layer.v1.tar",
                                      "application/vnd.docker.image.rootfs.diff.tar.gzip"):
            raise ValueError("unsupported OCI layer compression")
        path = scratch / (layer["digest"][7:] + ".tar")
        registry.fetch("blobs", layer["digest"], path, layer["size"])
        layers.append(path)
        print(name, architecture, layer["digest"], layer["size"], flush=True)
    files = ImageFiles(layers)
    try:
        extract_runtime(files, name, architecture, destination)
        (destination / "oci-provenance.json").write_text(json.dumps({
            "image": image, "platform": "linux/" + architecture, "manifest": selected,
            "config": descriptor, "layers": document["layers"]}, sort_keys=True) + "\n")
    finally:
        files.close()
        for path in layers:
            path.unlink()


def manifest(directory, origins):
    files = {}
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("bundle contains an indirect or special file")
        executable = bool(info.st_mode & 0o111)
        path.chmod(0o555 if executable else 0o444)
        files[path.relative_to(directory).as_posix()] = {"sha256": digest(path), "executable": executable}
    return {"path": str(directory.resolve()), "files": files, "provenance": origins}


def stage(destination, architecture, image_source="docker"):
    destination.mkdir(parents=True, exist_ok=False)
    scratch = destination / "downloads"
    scratch.mkdir()
    bundle = destination / "oidf"
    bundle.mkdir()
    origins = []
    for name, image in IMAGES.items():
        (oci_runtime if image_source == "oci" else image_runtime)(name, architecture, bundle / name, scratch)
        origins.append({"uri": "https://" + (image if "/" in image else "registry-1.docker.io/library/" + image),
                        "sha256": image.split("sha256:")[1]})
    checkout = scratch / "source"
    command(["git", "clone", "--quiet", "--depth", "1", "--branch", "release-v5.3.3", SUITE_REPO, str(checkout)])
    head = command(["git", "-C", str(checkout), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != SUITE_COMMIT:
        raise ValueError("official suite source revision differs")
    archive = scratch / "source.tar"
    command(["git", "-C", str(checkout), "archive", "--format=tar", "--output=" + str(archive), SUITE_COMMIT])
    files = ImageFiles(archive)
    try:
        for name in files.children.get("", []):
            files.copy(name, bundle / "source" / name)
    finally:
        files.close()
    origins.append({"uri": "https://gitlab.com/openid/conformance-suite/-/tree/" + SUITE_COMMIT,
                    "sha256": digest(archive)})
    wheels = bundle / "wheels"
    wheels.mkdir()
    requirements = []
    for url, sha in WHEELS:
        path = wheels / url.rsplit("/", 1)[1]
        with urllib.request.urlopen(url, timeout=60) as source, path.open("xb") as output:
            shutil.copyfileobj(source, output)
        if digest(path) != sha:
            raise ValueError("official runner wheel checksum differs")
        package, version = path.name.split("-")[:2]
        requirements.append(f"{package.replace('_', '-')}=={version} --hash=sha256:{sha}")
        origins.append({"uri": url, "sha256": sha})
    (wheels / "requirements.txt").write_text("\n".join(requirements) + "\n")
    (bundle / "identity.json").write_text(json.dumps({"suite_commit": SUITE_COMMIT, "images": list(IMAGES.values()),
                         "architecture": {"amd64": "x86_64", "arm64": "aarch64"}[architecture]}) + "\n")
    record = {"schema": "busbar.native-conformance-inputs/1", "bundles": {"oidf": manifest(bundle, origins)}}
    (destination / "inputs.json").write_text(json.dumps(record, sort_keys=True, indent=2) + "\n")
    shutil.rmtree(scratch)
    return destination / "inputs.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path)
    parser.add_argument("--architecture", choices=("amd64", "arm64"), required=True)
    parser.add_argument("--image-source", choices=("docker", "oci"), default="docker",
                        help="OCI verifies and extracts public blobs on the host without Docker")
    args = parser.parse_args()
    print(stage(args.destination.resolve(), args.architecture, args.image_source))


if __name__ == "__main__":
    main()
