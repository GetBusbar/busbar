"""Offline image assembly from exact component archives and measured Cargo seed."""

import json
from pathlib import Path
import shutil
import subprocess
import tarfile

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prepare import require, sha


def main():
    inputs = Path("/inputs")
    recipe = json.loads((inputs / "recipe.json").read_text())
    sysroot = Path("/usr/local/rustup/toolchains") / (
        recipe["rust"] + "-" + recipe["triple"]
    )
    require(sysroot.is_dir(), "base image Rust toolchain differs")
    for item in recipe["components"]:
        archive = inputs / item["file"]
        require(sha(archive) == item["sha256"], "component changed during assembly")
        unpack = inputs / "unpack"
        unpack.mkdir()
        with tarfile.open(archive, "r:xz") as source:
            for entry in source.getmembers():
                require(
                    not entry.name.startswith("/")
                    and ".." not in Path(entry.name).parts
                    and (entry.isfile() or entry.isdir()),
                    "unsafe component archive member",
                )
            seen = set()
            for entry in source.getmembers():
                require(entry.name not in seen, "duplicate component archive member")
                seen.add(entry.name)
                target = unpack / entry.name
                if entry.isdir():
                    target.mkdir(parents=True, exist_ok=True)
                else:
                    target.parent.mkdir(parents=True, exist_ok=True)
                    with source.extractfile(entry) as incoming, target.open(
                        "xb"
                    ) as outgoing:
                        shutil.copyfileobj(incoming, outgoing)
                    target.chmod(entry.mode & 0o755)
        roots = list(unpack.iterdir())
        require(len(roots) == 1, "unexpected component archive root")
        subprocess.run(
            [
                "bash",
                str(roots[0] / "install.sh"),
                "--prefix=" + str(sysroot),
                "--disable-ldconfig",
            ],
            check=True,
            timeout=60,
        )
        shutil.rmtree(unpack)
    for executable in ("rustc", "cargo", "clippy-driver", "rustfmt"):
        result = subprocess.check_output(
            [str(sysroot / "bin" / executable), "--version"], text=True
        )
        expected = (
            "clippy 0.1." + recipe["rust"].split(".")[1]
            if executable == "clippy-driver"
            else (
                "rustfmt "
                if executable == "rustfmt"
                else executable + " " + recipe["rust"]
            )
        )
        require(result.startswith(expected), "installed tool version differs")
    cache = Path("/opt/busbar-native/cargo-seed")
    seed = json.loads(Path("/opt/busbar-native/seed.json").read_text())
    actual = {
        str(p.relative_to(cache)): sha(p)
        for p in sorted(cache.rglob("*"))
        if p.is_file()
    }
    require(
        actual == seed["files"] and seed["plan_sha256"] == recipe["plan_sha256"],
        "seed changed during assembly",
    )
    Path("/opt/busbar-native/recipe.json").write_text(
        json.dumps(recipe, sort_keys=True, indent=2) + "\n"
    )
    subprocess.run(
        [
            "find",
            "/usr/local/rustup",
            "/opt/busbar-native",
            "-exec",
            "touch",
            "-h",
            "-d",
            "@" + str(recipe["source_date_epoch"]),
            "{}",
            "+",
        ],
        check=True,
    )
    shutil.rmtree(inputs)


if __name__ == "__main__":
    main()
