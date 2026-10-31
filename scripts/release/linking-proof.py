#!/usr/bin/env python3
"""linking-proof.py - the W17 linking rows, run on a release CANDIDATE before anything is published.

scripts/verify-artifact.py runs the whole artifact contract against a PUBLISHED artifact, and several
of its rows (attestation, build_evidence against the downloaded digest) cannot run before the
release exists. The linking design is decided at BUILD time, though: a candidate that cannot load a
dropped-in plugin, or that needs a newer glibc than its floor, must never reach the owner's publish
step. So the qa move runs exactly these rows on each candidate slice, through the SAME row functions
verify-artifact.py implements (imported, not copied: one implementation per row):

  binary target  runtime_deps   the binary needs only the OS C runtime (ELF: glibc <= glibc_max)
                 dropin_loads   the binary boots with a dropped-in stub store as store.module
  image target   image_matches_packaged_binary  the image carries the linux-gnu binary, byte for byte
                 image_dropin_loads             the image boots with the same dropped-in stub store

Every named row must run and pass; there is no flag that skips one, and a missing input is a FAIL.
This is a pre-publish gate in addition to the full contract, never instead of it.

Usage:
  linking-proof.py --target x86_64-unknown-linux-gnu --archive DIR/busbar-x86_64-unknown-linux-gnu.tar.gz \
                   --dropin-plugin PROBE.tar.gz
  linking-proof.py --target image-linux-amd64 --image <ref@sha256 or loaded id> \
                   --packaged-from <the linux-gnu binary> --dropin-plugin PROBE.tar.gz
"""

import argparse
import importlib.util
import json
import os
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(os.path.dirname(HERE))

_spec = importlib.util.spec_from_file_location("verify_artifact", os.path.join(ROOT, "scripts", "verify-artifact.py"))
va = importlib.util.module_from_spec(_spec)
_spec.loader.exec_module(va)

BINARY_ROWS = ["runtime_deps", "dropin_loads"]
IMAGE_ROWS = ["image_matches_packaged_binary", "image_dropin_loads"]


def main(argv=None) -> int:
    ap = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    ap.add_argument("--target", required=True)
    ap.add_argument("--archive", default="")
    ap.add_argument("--image", default="")
    ap.add_argument("--packaged-from", default="")
    ap.add_argument("--dropin-plugin", default="")
    a = ap.parse_args(argv)

    contract = json.load(open(va.DEFAULT_CONTRACT, encoding="utf-8"))
    targets = json.load(open(va.DEFAULT_TARGETS, encoding="utf-8"))
    rows = va._assert_contract_is_whole(contract)
    specs = {t["target"]: t for t in targets["targets"]}
    if a.target not in specs:
        raise SystemExit("linking-proof: target %r is not declared in release-targets.json" % a.target)
    spec = specs[a.target]
    want = IMAGE_ROWS if spec.get("kind") == "image" else BINARY_ROWS
    declared = {r["id"]: r for r in rows}
    missing = [r for r in want if r not in declared or not va.applies(declared[r], spec)]
    if missing:
        raise SystemExit("linking-proof: rows %s are not declared for %s in the contract" % (missing, a.target))

    ctx = va.Ctx()
    ctx.target, ctx.spec, ctx.targets = a.target, spec, targets
    ctx.contract_rows = declared
    ctx.repo_root = ROOT
    ctx.work = tempfile.mkdtemp(prefix="busbar-linking-proof-")
    ctx.image = a.image
    ctx.packaged_from = a.packaged_from
    ctx.dropin_plugin = os.path.abspath(a.dropin_plugin) if a.dropin_plugin else ""
    ctx.archive = os.path.abspath(a.archive) if a.archive else ""
    unpack_error = None
    if spec.get("kind") != "image":
        unpack = os.path.join(ctx.work, "unpack")
        os.makedirs(unpack, exist_ok=True)
        try:
            va.extract_archive(ctx.archive, unpack)
        except Exception as exc:  # a missing or broken archive fails every row, never skips one
            unpack_error = "the archive could not be unpacked: %s" % exc
        ctx.exe = os.path.join(unpack, spec["exe"])
        if os.path.exists(ctx.exe):
            os.chmod(ctx.exe, 0o755)

    failed = []
    for rid in want:
        try:
            if unpack_error:
                raise va.RowFailure(unpack_error)
            note = va.CHECKS[rid](ctx)
            print("PASS %-30s %s" % (rid, note))
        except Exception as exc:  # RowFailure, AssertionError, or a crash: all are FAIL
            failed.append(rid)
            print("FAIL %-30s %s" % (rid, exc))
    if failed:
        print("\nlinking-proof: %s FAILED %s" % (a.target, failed))
        return 1
    print("\nlinking-proof: %s holds %s" % (a.target, want))
    return 0


if __name__ == "__main__":
    sys.exit(main())
