#!/usr/bin/env python3
"""A writable output location for cargo-cyclonedx's manifest-adjacent SBOMs.

The pinned producer has no output-directory option. Copy only the distribution
manifest and lock, byte-for-byte, and link the other source paths into a private
view. No dependency, feature, target, or source manifest is rewritten.
"""
from pathlib import Path
import shutil
import sys


def stage(repository, destination):
    repository, destination = Path(repository).resolve(), Path(destination).resolve()
    destination.mkdir(parents=True, exist_ok=False)
    for entry in repository.iterdir():
        if entry.name not in ("dist", "target", ".git"):
            (destination / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    distribution = destination / "dist/default"
    distribution.mkdir(parents=True)
    for entry in (repository / "dist").iterdir():
        if entry.name != "default":
            (destination / "dist" / entry.name).symlink_to(entry, target_is_directory=entry.is_dir())
    for entry in (repository / "dist/default").iterdir():
        output = distribution / entry.name
        if entry.name in ("Cargo.toml", "Cargo.lock"):
            # copyfile deliberately does not preserve source read-only modes.
            shutil.copyfile(entry, output)
        elif entry.name != "target" and not entry.name.endswith(".cdx.json"):
            output.symlink_to(entry, target_is_directory=entry.is_dir())
    for name in ("Cargo.toml", "Cargo.lock"):
        if not (distribution / name).is_file():
            raise ValueError("missing shipped distribution " + name)
    return distribution / "Cargo.toml"


if __name__ == "__main__":
    print(stage(*sys.argv[1:]))
