#!/usr/bin/env python3
"""Controller-only collection of pinned public OTLP conformance instruments.

Run before admission, never from a candidate suite. No candidate code, Docker
socket, registry credentials, or download capability enters the resulting bundles.
The native controller independently validates every file against this manifest.
"""
import argparse
import hashlib
import json
from pathlib import Path
import shutil
import stat
import subprocess
import tarfile
import urllib.request
import uuid


# Pins belong to busbar-export-otlp testing/{otlp,weaver}-conformance/run.*.
COLLECTOR = "otel/opentelemetry-collector-contrib@sha256:7f22d2a6748110ffb6a59bc0df448bccbf501cdb667d610ede4c61d3863d5849"
TELEMETRYGEN = "ghcr.io/open-telemetry/opentelemetry-collector-contrib/telemetrygen@sha256:569b79a39f8313db839a727e8eac161c66b8a6c2e633f2da4ad352ce7b383c23"
WEAVER_VERSION = "0.28.0"
REGISTRY_COMMIT = "fb30ca17193b551473b1f43c315482918ab6987c"
REGISTRY_SHA = "aefd780086389034d492f3cbe52e180dd74e6057700ce1663c59d21c8a497818"
WEAVER = {
    "amd64": ("x86_64-unknown-linux-musl", "69069769ec3509c358ddbfbc29ff9965590fe4f8dd8b03e1c1e1be1ae56122e8"),
    "arm64": ("aarch64-unknown-linux-musl", "55a47e3d6226a372570b65853e56413266c149aaa7716172bdffb0dc8422d544"),
}


def digest(path):
    with path.open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def fetch(url, sha, destination):
    with urllib.request.urlopen(url, timeout=60) as response, destination.open("xb") as output:
        size = 0
        while chunk := response.read(1024 * 1024):
            size += len(chunk)
            if size > 128 * 1024 * 1024:
                raise ValueError("public instrument exceeds archive byte limit")
            output.write(chunk)
    if digest(destination) != sha:
        raise ValueError("public instrument checksum mismatch")


def unpack(archive, destination):
    destination.mkdir()
    with tarfile.open(archive) as source:
        size = 0
        for member in source.getmembers():
            path = Path(member.name)
            size += member.size
            if (path.is_absolute() or ".." in path.parts or member.issym()
                    or member.islnk() or not (member.isdir() or member.isfile())
                    or size > 512 * 1024 * 1024):
                raise ValueError("unsafe or oversized public instrument archive")
        source.extractall(destination)


def cached_image(image, architecture):
    """A digest reference is usable only when its requested platform is local."""
    result = subprocess.run(
        ["docker", "image", "inspect", "--platform", "linux/" + architecture, image],
        capture_output=True, text=True, timeout=60)
    if result.returncode:
        if "No such image:" in result.stderr:
            return False
        # Daemon/CLI failures are not cache misses and must not trigger downloads.
        raise subprocess.CalledProcessError(result.returncode, result.args,
                                            output=result.stdout, stderr=result.stderr)
    records = json.loads(result.stdout)
    if not isinstance(records, list) or len(records) != 1:
        raise ValueError("invalid cached image inspection")
    record = records[0]
    references = {ref.removeprefix("docker.io/") for ref in record.get("RepoDigests", [])}
    return (record.get("Os") == "linux" and record.get("Architecture") == architecture
            and image.removeprefix("docker.io/") in references)


def public_image(image, architecture):
    if cached_image(image, architecture):
        return image
    # Hub traffic has one permitted mirror, with no direct-Hub fallback/retry.
    source = image if image.startswith("ghcr.io/") else "mirror.gcr.io/" + image.removeprefix("docker.io/")
    if source != image and cached_image(source, architecture):
        return source
    subprocess.run(["docker", "pull", "--platform", "linux/" + architecture, source],
                   check=True, timeout=300)
    if not cached_image(source, architecture):
        raise ValueError("downloaded image does not match the pinned digest and platform")
    return source


def image_binary(image, architecture, binary, destination):
    """Copy from a never-started pinned image; Docker remains controller-only."""
    source = public_image(image, architecture)
    name = "busbar-otlp-stage-" + uuid.uuid4().hex
    created = False
    try:
        subprocess.run(["docker", "create", "--platform", "linux/" + architecture,
                        "--pull", "never", "--name", name, "--network", "none", source],
                       check=True, timeout=60)
        created = True
        subprocess.run(["docker", "cp", name + ":/" + binary, str(destination)],
                       check=True, timeout=60)
    finally:
        if created:
            subprocess.run(["docker", "rm", "--force", name], check=True, timeout=60)


def bundle(directory, provenance):
    files = {}
    for path in sorted(directory.rglob("*")):
        info = path.lstat()
        if stat.S_ISDIR(info.st_mode):
            continue
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("bundle contains an indirect or special file")
        executable = bool(info.st_mode & 0o111)
        path.chmod(0o555 if executable else 0o444)
        files[path.relative_to(directory).as_posix()] = {
            "sha256": digest(path), "executable": executable}
    return {"path": str(directory.resolve()), "files": files, "provenance": provenance}


def stage(destination, architecture):
    destination.mkdir(parents=True, exist_ok=False)
    scratch = destination / "downloads"
    scratch.mkdir()
    otlp, weaver = destination / "otlp", destination / "weaver"
    otlp.mkdir()
    weaver.mkdir()
    image_binary(COLLECTOR, architecture, "otelcol-contrib", otlp / "otelcol-contrib")
    image_binary(TELEMETRYGEN, architecture, "telemetrygen", otlp / "telemetrygen")
    for path in otlp.iterdir():
        path.chmod(0o555)
    triple, sha = WEAVER[architecture]
    tool_url = f"https://github.com/open-telemetry/weaver/releases/download/v{WEAVER_VERSION}/weaver-{triple}.tar.xz"
    registry_url = f"https://codeload.github.com/open-telemetry/semantic-conventions/tar.gz/{REGISTRY_COMMIT}"
    fetch(tool_url, sha, scratch / "weaver.tar.xz")
    unpack(scratch / "weaver.tar.xz", scratch / "tool")
    shutil.copyfile(scratch / "tool" / ("weaver-" + triple) / "weaver", weaver / "weaver")
    (weaver / "weaver").chmod(0o555)
    fetch(registry_url, REGISTRY_SHA, scratch / "semconv.tar.gz")
    unpack(scratch / "semconv.tar.gz", scratch / "semconv")
    shutil.copytree(scratch / "semconv" / ("semantic-conventions-" + REGISTRY_COMMIT) / "model",
                    weaver / "registry", symlinks=True)
    record = {"schema": "busbar.native-conformance-inputs/1", "bundles": {
        "otlp": bundle(otlp, [
            {"uri": "https://registry-1.docker.io/v2/otel/opentelemetry-collector-contrib/manifests/" + COLLECTOR.split("@")[1],
             "sha256": COLLECTOR.split("sha256:")[1]},
            {"uri": "https://ghcr.io/v2/open-telemetry/opentelemetry-collector-contrib/telemetrygen/manifests/" + TELEMETRYGEN.split("@")[1],
             "sha256": TELEMETRYGEN.split("sha256:")[1]}]),
        "weaver": bundle(weaver, [{"uri": tool_url, "sha256": sha},
                                   {"uri": registry_url, "sha256": REGISTRY_SHA}])}}
    (destination / "inputs.json").write_text(json.dumps(record, indent=2, sort_keys=True) + "\n")
    shutil.rmtree(scratch)
    return destination / "inputs.json"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("destination", type=Path, help="new controller-owned staging directory")
    parser.add_argument("--architecture", choices=sorted(WEAVER), required=True)
    args = parser.parse_args()
    print(stage(args.destination.resolve(), args.architecture))


if __name__ == "__main__":
    main()
