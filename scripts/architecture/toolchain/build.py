#!/usr/bin/env python3
"""Build an independently pinned preparation context on an existing local daemon."""

import argparse
import json
import os
from pathlib import Path
import re
import subprocess

from prepare import pinned, require, sha


def build(
    context,
    expected,
    docker,
    docker_sha256,
    buildx,
    buildx_sha256,
    endpoint,
    tag,
    output,
    no_cache=False,
):
    context = Path(context).resolve()
    require(
        sha(context / "context.sha256.json") == expected,
        "prepared context digest differs",
    )
    inventory = json.loads((context / "context.sha256.json").read_text())
    files = {str(p.relative_to(context)) for p in context.rglob("*") if not p.is_dir()}
    require(
        files == set(inventory) | {"context.sha256.json"},
        "prepared context file set differs",
    )
    for name, digest in inventory.items():
        pinned(context, name, digest)
    require(
        Path(docker).is_absolute() and sha(docker) == docker_sha256,
        "Docker client digest differs",
    )
    require(
        Path(buildx).is_absolute() and sha(buildx) == buildx_sha256,
        "Buildx executable digest differs",
    )
    require(
        re.fullmatch(r"unix:///[\w/.-]+", endpoint),
        "existing local Unix daemon required",
    )
    require(
        re.fullmatch(r"busbar-native-task:[a-z0-9-]+", tag),
        "task-local image tag required",
    )
    output = Path(output).resolve()
    output.mkdir(parents=True, exist_ok=False)
    home = output / "docker-home"
    home.mkdir(mode=0o700)
    env = {
        "PATH": os.defpath,
        "HOME": str(home),
        "DOCKER_CONFIG": str(home),
        "DOCKER_HOST": endpoint,
    }
    recipe = json.loads((context / "recipe.json").read_text())
    command = [
        buildx,
        "build",
        "--progress=plain",
        "--provenance=false",
        "--sbom=false",
        "--platform",
        recipe["platform"],
        "--output=type=oci,rewrite-timestamp=true,dest=" + str(output / "image.tar"),
        "--tag",
        tag,
        "--build-arg",
        "SOURCE_DATE_EPOCH=" + str(recipe["source_date_epoch"]),
        "--metadata-file",
        str(output / "build-metadata.json"),
    ]
    if no_cache:
        command.append("--no-cache")
    with (output / "build.log").open("wb") as log:
        subprocess.run(
            [*command, str(context)],
            env=env,
            stdout=log,
            stderr=subprocess.STDOUT,
            check=True,
            timeout=1200,
        )
    subprocess.run(
        [
            docker,
            "--host",
            endpoint,
            "image",
            "load",
            "--input",
            str(output / "image.tar"),
        ],
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
        timeout=300,
    )
    inspected = json.loads(
        subprocess.check_output(
            [docker, "--host", endpoint, "image", "inspect", tag], env=env
        )
    )[0]
    require(
        inspected["Config"]["Labels"]["busbar.native.input-plan-sha256"]
        == recipe["plan_sha256"],
        "built image plan label differs",
    )
    metadata = json.loads((output / "build-metadata.json").read_text())
    digest = metadata["containerimage.digest"]
    reference = tag.split(":")[0] + "@" + digest
    # An immutable local reference must actually resolve; never substitute the tag.
    subprocess.run(
        [docker, "--host", endpoint, "image", "inspect", reference],
        env=env,
        check=True,
        stdout=subprocess.DEVNULL,
    )
    result = {
        "schema": "busbar.native-toolchain-build/1",
        "image": reference,
        "image_id": inspected["Id"],
        "context_sha256": expected,
        "docker_sha256": docker_sha256,
        "buildx_sha256": buildx_sha256,
        "plan_sha256": recipe["plan_sha256"],
        "vector_sha256": recipe["vector_sha256"],
        "release_eligible": False,
    }
    (output / "result.json").write_text(json.dumps(result, indent=2) + "\n")
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("context", "output"):
        parser.add_argument("--" + name, required=True, type=Path)
    for name in (
        "context-sha256",
        "docker",
        "docker-sha256",
        "buildx",
        "buildx-sha256",
        "endpoint",
        "tag",
    ):
        parser.add_argument("--" + name, required=True)
    parser.add_argument("--no-cache", action="store_true")
    args = parser.parse_args()
    print(
        json.dumps(
            build(
                args.context,
                args.context_sha256,
                args.docker,
                args.docker_sha256,
                args.buildx,
                args.buildx_sha256,
                args.endpoint,
                args.tag,
                args.output,
                args.no_cache,
            )
        )
    )


if __name__ == "__main__":
    main()
