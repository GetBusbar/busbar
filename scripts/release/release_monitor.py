#!/usr/bin/env python3
"""Read-only delivery/inclusion monitor and no-overwrite archive for supported releases.

A protected, independently pinned catalog names every byte and approved HTTPS URL.
No signing, registry write, remote retention change, credential discovery or deletion.
Local archival is NOT WORM or a claim about a provider's retention enforcement.
"""

import argparse
import datetime as dt
import hashlib
import os
from pathlib import Path
import shutil
import sys
import tempfile
import urllib.parse
import urllib.request

import native_provenance as p
import release_verifier as verifier

SCHEMA = "busbar.release-monitor/1"
MAX_FILE = 4 * 1024 * 1024 * 1024
MAX_RELEASE = 32 * 1024 * 1024 * 1024


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        raise ValueError("release download redirect is not pinned")


def fetch(url, destination, expected, size):
    parsed = urllib.parse.urlsplit(url)
    p.require(
        parsed.scheme == "https"
        and parsed.hostname
        and not parsed.username
        and not parsed.password
        and not parsed.fragment
        and not parsed.query,
        "explicit credential-free HTTPS artifact URL required",
    )
    p.require(
        type(size) is int and 0 <= size <= MAX_FILE,
        "release download size exceeds limit",
    )
    digest, count = hashlib.sha256(), 0
    request = urllib.request.Request(url, headers={"Accept-Encoding": "identity"})
    with urllib.request.build_opener(NoRedirect).open(
        request, timeout=60
    ) as response, destination.open("xb") as out:
        p.require(
            response.status == 200
            and response.headers.get("Content-Encoding", "identity") == "identity",
            "unexpected release download response",
        )
        while block := response.read(min(1024 * 1024, size - count + 1)):
            count += len(block)
            p.require(count <= size, "release download exceeds approved size")
            digest.update(block)
            out.write(block)
        out.flush()
        os.fsync(out.fileno())
    p.require(
        count == size and digest.hexdigest() == p.hex_value(expected),
        "release download bytes differ",
    )


def archive(root, release, files):
    """Add one verified inventory directory; existing copies must remain exact."""
    root = Path(root)
    p.require(
        root.is_absolute()
        and root.is_dir()
        and not any(x.is_symlink() for x in (root, *root.parents)),
        "existing protected archive root required",
    )
    name = p.digest(release / verifier.INVENTORY)
    destination = root / name
    if destination.exists():
        p.require(
            destination.is_dir()
            and not destination.is_symlink()
            and {x.name for x in destination.iterdir()} == set(files),
            "retained release file set changed",
        )
        for filename, binding in files.items():
            p.require(
                p.digest(verifier.regular(destination, filename)) == binding["sha256"],
                "retained release bytes changed",
            )
        return
    # Keep partial copies distinguishable; failed copies are removed, never an existing archive.
    staging = root / (".collect-" + name)
    staging.mkdir(mode=0o700)
    try:
        for filename, binding in files.items():
            target = staging / filename
            with verifier.regular(release, filename).open("rb") as source, target.open(
                "xb"
            ) as out:
                shutil.copyfileobj(source, out)
                out.flush()
                os.fsync(out.fileno())
            p.require(p.digest(target) == binding["sha256"], "archive copy changed")
            target.chmod(0o400)
        # No replacement of an existing directory; concurrent monitors fail closed.
        destination.mkdir(mode=0o700)
        for path in staging.iterdir():
            path.rename(destination / path.name)
        destination.chmod(0o500)
    finally:
        shutil.rmtree(staging)


def monitor(catalog_path, catalog_sha256, scratch, archive_root=None, now=None):
    p.require(
        p.digest(catalog_path) == p.hex_value(catalog_sha256),
        "protected monitor catalog changed",
    )
    catalog = p.load(catalog_path)
    p.require(
        set(catalog) == {"schema", "valid_until", "releases"}
        and catalog["schema"] == SCHEMA,
        "unsupported release monitor catalog",
    )
    now = now or dt.datetime.now(dt.timezone.utc)
    p.require(p.timestamp(catalog["valid_until"]) > now, "monitor catalog expired")
    p.require(
        isinstance(catalog["releases"], list) and catalog["releases"],
        "no supported release monitoring configured",
    )
    results, seen = [], set()
    scratch = Path(scratch)
    p.require(
        scratch.is_absolute() and scratch.is_dir() and not scratch.is_symlink(),
        "existing private scratch required",
    )
    for entry in catalog["releases"]:
        p.require(
            set(entry)
            == {"release", "support_until", "inventory_sha256", "trust", "files"},
            "invalid monitor release",
        )
        p.require(entry["release"] not in seen, "duplicate monitored release")
        seen.add(entry["release"])
        p.token(entry["release"])
        until = p.timestamp(entry["support_until"])
        p.require(until > now, "expired support entry requires explicit catalog review")
        trust = entry["trust"]
        p.require(
            set(trust) == {"path", "sha256"} and Path(trust["path"]).is_absolute(),
            "protected trust binding required",
        )
        files = entry["files"]
        p.require(
            isinstance(files, dict)
            and 3 < len(files) <= 4096
            and verifier.INVENTORY in files,
            "incomplete monitor file catalog",
        )
        p.require(
            files[verifier.INVENTORY]["sha256"] == entry["inventory_sha256"],
            "monitor inventory pin differs",
        )
        p.require(
            sum(binding["size"] for binding in files.values()) <= MAX_RELEASE,
            "release download exceeds total limit",
        )
        with tempfile.TemporaryDirectory(
            prefix="release-monitor-", dir=scratch
        ) as temporary:
            directory = Path(temporary)
            for filename, binding in files.items():
                p.token(filename)
                p.require(
                    set(binding) == {"url", "sha256", "size"},
                    "invalid monitored file binding",
                )
                fetch(
                    binding["url"],
                    directory / filename,
                    binding["sha256"],
                    binding["size"],
                )
            result = verifier.verify(
                directory, entry["inventory_sha256"], trust["path"], trust["sha256"]
            )
            p.require(
                result["release"] == entry["release"]
                and result["build_closure_verified"],
                "monitored release lacks current build evidence",
            )
            checkpoints = {}
            for filename in files:
                if filename.endswith(".sigstore.json"):
                    for row in p.load(directory / filename)["verificationMaterial"][
                        "tlogEntries"
                    ]:
                        envelope = row["inclusionProof"]["checkpoint"]["envelope"]
                        checkpoints.setdefault(filename, []).append(
                            hashlib.sha256(envelope.encode()).hexdigest()
                        )
            if archive_root:
                archive(archive_root, directory, files)
            results.append(
                {
                    "release": entry["release"],
                    "support_until": entry["support_until"],
                    "inventory_sha256": result["inventory_sha256"],
                    "files_checked": len(files),
                    "verified_checkpoint_sha256": checkpoints,
                    "registry_verified": result["registry_verified"],
                }
            )
    p.require(
        p.digest(catalog_path) == catalog_sha256,
        "monitor catalog changed during verification",
    )
    return {
        "schema": "busbar.release-monitor-result/1",
        "status": "pass",
        "checked_at": now.isoformat().replace("+00:00", "Z"),
        "catalog_sha256": catalog_sha256,
        "releases": results,
        "archive_checked": archive_root is not None,
        "storage_retention_enforced": False,
        "log_consistency_observed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--catalog", required=True, type=Path)
    parser.add_argument("--catalog-sha256", required=True)
    parser.add_argument("--scratch", required=True, type=Path)
    parser.add_argument("--archive-root", type=Path)
    parser.add_argument("--result", required=True, type=Path)
    args = parser.parse_args(argv)
    result = monitor(args.catalog, args.catalog_sha256, args.scratch, args.archive_root)
    p.write(args.result, p.canonical(result))


if __name__ == "__main__":
    try:
        main()
    except Exception as error:
        print(
            "release-monitor: refused (" + type(error).__name__ + ")", file=sys.stderr
        )
        sys.exit(1)
