#!/usr/bin/env python3
"""Prepare an exact-vector offline native image context; never run candidate code."""

import argparse
import hashlib
import json
from pathlib import Path
import re
import shutil
import tomllib
import urllib.request

HERE = Path(__file__).resolve().parent
REGISTRY = "registry+https://github.com/rust-lang/crates.io-index"
GIT = re.compile(
    r"git\+(https://github\.com/[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+)\?rev=([0-9a-f]{40})#([0-9a-f]{40})"
)


def require(value, message):
    if not value:
        raise ValueError(message)


def sha(path):
    with Path(path).open("rb") as stream:
        return hashlib.file_digest(stream, "sha256").hexdigest()


def relative(value):
    require(
        isinstance(value, str)
        and value
        and not value.startswith("/")
        and all(part not in ("", ".", "..") for part in value.split("/")),
        "unsafe input path",
    )
    return Path(value)


def pinned(root, name, expected):
    path = Path(root) / relative(name)
    require(re.fullmatch("[0-9a-f]{64}", expected), "invalid input digest")
    require(
        not any(p.is_symlink() for p in (path, *path.parents)) and path.is_file(),
        "missing or indirect input",
    )
    require(sha(path) == expected, "input digest differs: " + name)
    return path


def packages(lock):
    result = []
    for row in lock.get("package", []):
        source = row.get("source")
        if source is None:
            continue
        require(
            re.fullmatch("[A-Za-z0-9_-]+", row["name"])
            and re.fullmatch("[0-9][A-Za-z0-9.+-]*", row["version"]),
            "invalid Cargo package identity",
        )
        if source == REGISTRY:
            require(
                re.fullmatch("[0-9a-f]{64}", row.get("checksum", "")),
                "registry checksum required",
            )
        else:
            match = GIT.fullmatch(source)
            require(
                match and match[2] == match[3], "unsupported or unpinned Git source"
            )
        result.append(
            {k: row[k] for k in ("name", "version", "source", "checksum") if k in row}
        )
    return sorted(result, key=lambda p: (p["name"], p["version"], p["source"]))


def synthetic_manifest(rows, name):
    lines = [
        "[workspace]",
        "[package]",
        "name=" + json.dumps(name),
        'version="0.0.0"',
        'edition="2021"',
        "[dependencies]",
    ]
    for index, row in enumerate(rows):
        fields = {
            "package": row["name"],
            "version": "=" + row["version"],
            "default-features": False,
        }
        if row["source"] != REGISTRY:
            match = GIT.fullmatch(row["source"])
            fields.update(git=match[1], rev=match[2])
        lines.append(
            "dependency_"
            + str(index)
            + "={"
            + ",".join(k + "=" + json.dumps(v) for k, v in fields.items())
            + "}"
        )
    return "\n".join(lines) + "\n"


def prepare(plan_path, expected, source, output, downloads):
    require(sha(plan_path) == expected, "approved preparation plan digest differs")
    plan = json.loads(Path(plan_path).read_text())
    require(
        set(plan)
        == {
            "schema",
            "platform",
            "source_date_epoch",
            "toolchain",
            "vector",
            "locks",
            "git",
        },
        "closed native input plan required",
    )
    require(plan["schema"] == "busbar.native-toolchain-inputs/1", "unknown input plan")
    pins = json.loads((HERE / "pins.json").read_text())
    require(plan["platform"] in pins["platforms"], "unsupported native platform")
    require(
        type(plan["source_date_epoch"]) is int
        and 0 <= plan["source_date_epoch"] <= 2**32,
        "fixed source timestamp required",
    )
    require(
        set(plan["toolchain"]) == set(plan["vector"]) == {"path", "sha256"},
        "input binding differs",
    )
    toolchain = pinned(
        source,
        **{"name": plan["toolchain"]["path"], "expected": plan["toolchain"]["sha256"]},
    )
    declared = tomllib.loads(toolchain.read_text())["toolchain"]
    require(
        declared["channel"] == pins["rust"]
        and sorted(declared["components"]) == ["clippy", "rustfmt"],
        "repository toolchain differs from approved image recipe",
    )
    pinned(source, plan["vector"]["path"], plan["vector"]["sha256"])
    require(
        isinstance(plan["locks"], dict) and plan["locks"],
        "complete expected lock inventory required",
    )
    locks = {}
    git_urls = set()
    for name, digest in plan["locks"].items():
        require(
            name.endswith("/Cargo.lock") or name == "Cargo.lock",
            "only explicit Cargo locks accepted",
        )
        path = pinned(source, name, digest)
        rows = packages(tomllib.loads(path.read_text()))
        locks[name] = (path, rows)
        git_urls.update(
            GIT.fullmatch(p["source"])[1] for p in rows if p["source"] != REGISTRY
        )
    require(
        set(plan["git"]) == git_urls,
        "every exact Git input requires a precollected credential-free bare repository",
    )
    require(not Path(output).exists(), "output context must be fresh")
    output = Path(output)
    output.mkdir(parents=True)
    settings = {}
    for index, (url, entry) in enumerate(sorted(plan["git"].items())):
        require(
            set(entry) == {"path", "files"} and entry["files"],
            "closed Git object inventory required",
        )
        root = Path(source) / relative(entry["path"])
        require(not any(p.is_symlink() for p in root.rglob("*")), "indirect Git input")
        actual = {str(p.relative_to(root)) for p in root.rglob("*") if not p.is_dir()}
        require(actual == set(entry["files"]), "Git object inventory differs")
        destination = output / "git" / str(index)
        destination.mkdir(parents=True)
        (destination / "objects").mkdir()
        (destination / "refs").mkdir()
        for name, expected_file in entry["files"].items():
            path = pinned(root, name, expected_file)
            # Clone config, hooks, FETCH_HEAD and alternates never enter the image.
            if (
                name == "HEAD"
                or name == "packed-refs"
                or name == "shallow"
                or name.startswith(("objects/", "refs/"))
            ):
                require(
                    name != "objects/info/alternates",
                    "external Git object stores are forbidden",
                )
                target = destination / relative(name)
                target.parent.mkdir(parents=True, exist_ok=True)
                shutil.copyfile(path, target)
        (destination / "config").write_text(
            "[core]\nrepositoryformatversion=0\nbare=true\n"
        )
        settings[url] = "/inputs/git/" + str(index)
    expected_packages = {}
    for index, (name, (path, rows)) in enumerate(sorted(locks.items())):
        destination = output / "locks" / str(index)
        (destination / "src").mkdir(parents=True)
        (destination / "src/lib.rs").write_text(
            "// Generated dependency collector; no candidate source.\n"
        )
        (destination / "Cargo.toml").write_text(
            synthetic_manifest(rows, "busbar-seed-" + str(index))
        )
        shutil.copyfile(path, destination / "Cargo.lock")
        expected_packages[str(index)] = rows
    platform = pins["platforms"][plan["platform"]]
    downloads = Path(downloads)
    downloads.mkdir(parents=True, exist_ok=True)
    components = []
    for name, item in sorted(platform["components"].items()):
        require(
            item["url"].startswith("https://static.rust-lang.org/dist/"),
            "unexpected component origin",
        )
        path = downloads / item["url"].rsplit("/", 1)[1]
        if not path.exists():
            with urllib.request.urlopen(item["url"], timeout=60) as response, path.open(
                "xb"
            ) as target:
                shutil.copyfileobj(response, target)
        require(sha(path) == item["sha256"], "component archive digest differs")
        shutil.copyfile(path, output / path.name)
        components.append({"file": path.name, "sha256": item["sha256"]})
    recipe = {
        "schema": "busbar.native-seed-recipe/1",
        "plan_sha256": expected,
        "toolchain_sha256": plan["toolchain"]["sha256"],
        "vector_sha256": plan["vector"]["sha256"],
        "locks": plan["locks"],
        "expected_packages": expected_packages,
        "git": settings,
        "base": platform["base"],
        "platform": plan["platform"],
        "rust": pins["rust"],
        "triple": platform["triple"],
        "source_date_epoch": plan["source_date_epoch"],
        "components": components,
    }
    (output / "recipe.json").write_text(
        json.dumps(recipe, sort_keys=True, indent=2) + "\n"
    )
    for name in ("prepare.py", "seed.py", "install.py"):
        shutil.copyfile(HERE / name, output / name)
    dockerfile = f"""FROM {platform['base']} AS collect
COPY . /inputs/
RUN /usr/bin/python3 -I -B /inputs/seed.py
FROM {platform['base']}
ARG SOURCE_DATE_EPOCH={plan['source_date_epoch']}
COPY --from=collect /opt/busbar-native/cargo-seed/ /opt/busbar-native/cargo-seed/
COPY --from=collect /opt/busbar-native/seed.json /opt/busbar-native/seed.json
COPY install.py prepare.py recipe.json {' '.join(item['file'] for item in components)} /inputs/
RUN --network=none /usr/bin/python3 -I -B /inputs/install.py
ENV PATH=/usr/local/cargo/bin:/usr/local/bin:/usr/bin:/bin CARGO_HOME=/opt/busbar-native/cargo-seed RUSTUP_HOME=/usr/local/rustup CARGO_NET_OFFLINE=true
LABEL busbar.native.input-plan-sha256="{expected}" busbar.native.vector-sha256="{plan['vector']['sha256']}"
WORKDIR /work
ENTRYPOINT []
CMD ["/bin/bash"]
"""
    (output / "Dockerfile").write_text(dockerfile)
    inventory = {
        str(p.relative_to(output)): sha(p)
        for p in sorted(output.rglob("*"))
        if p.is_file()
    }
    (output / "context.sha256.json").write_text(
        json.dumps(inventory, sort_keys=True, indent=2) + "\n"
    )
    return recipe


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("plan", "source", "output", "downloads"):
        parser.add_argument("--" + name, required=True, type=Path)
    parser.add_argument("--plan-sha256", required=True)
    args = parser.parse_args()
    recipe = prepare(
        args.plan, args.plan_sha256, args.source, args.output, args.downloads
    )
    print(
        json.dumps(
            {
                "context": str(args.output),
                "plan_sha256": recipe["plan_sha256"],
                "release_eligible": False,
                "vector_sha256": recipe["vector_sha256"],
            }
        )
    )


if __name__ == "__main__":
    main()
