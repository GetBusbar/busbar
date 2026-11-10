"""Network collector: generated manifests only; Cargo fetch never compiles code."""

import json
from pathlib import Path
import shutil
import subprocess

import sys

sys.path.insert(0, str(Path(__file__).resolve().parent))

from prepare import packages, require, sha


def main():
    inputs = Path("/inputs")
    recipe = json.loads((inputs / "recipe.json").read_text())
    root = Path("/opt/busbar-native")
    cache = root / "cargo-seed"
    cache.mkdir(parents=True)
    home = Path("/tmp/collector-home")
    home.mkdir(mode=0o700)
    env = {
        "PATH": "/usr/local/cargo/bin:/usr/bin:/bin",
        "HOME": str(home),
        "CARGO_HOME": str(cache),
        "RUSTUP_HOME": "/usr/local/rustup",
        "RUSTUP_TOOLCHAIN": recipe["rust"],
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_ALLOW_PROTOCOL": "file",
        "CARGO_REGISTRIES_CRATES_IO_PROTOCOL": "sparse",
        "CARGO_REGISTRIES_CRATES_IO_INDEX": "sparse+https://index.crates.io/",
        "CARGO_NET_GIT_FETCH_WITH_CLI": "true",
        "CARGO_TERM_COLOR": "never",
        "GIT_CONFIG_COUNT": str(len(recipe["git"])),
    }
    for index, (url, path) in enumerate(sorted(recipe["git"].items())):
        env["GIT_CONFIG_KEY_" + str(index)] = "url.file://" + path + ".insteadOf"
        env["GIT_CONFIG_VALUE_" + str(index)] = url
    observed = {}
    import tomllib

    for name, expected in recipe["expected_packages"].items():
        directory = inputs / "locks" / name
        subprocess.run(
            ["cargo", "fetch", "--manifest-path", str(directory / "Cargo.toml")],
            cwd=directory,
            env=env,
            check=True,
            timeout=900,
        )
        actual = packages(tomllib.loads((directory / "Cargo.lock").read_text()))
        require(
            actual == expected,
            "dependency fetch changed the approved lock closure: " + name,
        )
        subprocess.run(
            [
                "cargo",
                "fetch",
                "--frozen",
                "--manifest-path",
                str(directory / "Cargo.toml"),
            ],
            cwd=directory,
            env=env,
            check=True,
            timeout=60,
        )
        observed[name] = sha(directory / "Cargo.lock")
    # Git's checkout index and reflogs contain filesystem identities and wall time.
    # Rebuild the index from the immutable tree without checking out files or hooks.
    # Cargo retains the actual committed sources, HEAD and object database.
    for metadata in cache.glob("git/checkouts/*/*/.git"):
        require(
            metadata.is_dir() and not metadata.is_symlink(),
            "unexpected Git checkout metadata",
        )
        shutil.rmtree(metadata / "logs", ignore_errors=True)
        clean_index = metadata / "index.reproducible"
        clean_index.unlink(missing_ok=True)
        git_env = dict(env, GIT_INDEX_FILE=str(clean_index))
        subprocess.run(
            [
                "git",
                "-c",
                "core.hooksPath=/dev/null",
                "-c",
                "core.fsmonitor=false",
                "--git-dir=" + str(metadata),
                "read-tree",
                "HEAD",
            ],
            env=git_env,
            check=True,
            timeout=30,
        )
        clean_index.replace(metadata / "index")
    for path in cache.glob(".*cache*"):
        require(path.is_file(), "unexpected cache state")
        path.unlink()
    files = {}
    for path in sorted(cache.rglob("*")):
        require(not path.is_symlink(), "indirect seed file")
        if path.is_file():
            files[str(path.relative_to(cache))] = sha(path)
        else:
            require(path.is_dir(), "special seed file")
    (root / "seed.json").write_text(
        json.dumps(
            {
                "schema": "busbar.native-cargo-seed/1",
                "plan_sha256": recipe["plan_sha256"],
                "vector_sha256": recipe["vector_sha256"],
                "toolchain_sha256": recipe["toolchain_sha256"],
                "approved_locks": recipe["locks"],
                "collector_locks": observed,
                "files": files,
                "packages": recipe["expected_packages"],
                "release_eligible": False,
            },
            sort_keys=True,
            indent=2,
        )
        + "\n"
    )
    shutil.rmtree(home)


if __name__ == "__main__":
    main()
