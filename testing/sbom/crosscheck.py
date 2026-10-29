#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""SBOM cross-check: the SBOM must list every crate cargo resolves for the shipped binary.

  crosscheck.py check   <sbom.json> <cargo-metadata.json>
  crosscheck.py corrupt <sbom.json> <out.json> missing-name|drop-crate

`check` walks `cargo metadata`'s resolve graph from the `busbar` package over normal and build
dependency edges (the metadata was taken with --filter-platform = the SBOM's target) and compares
name@version with the SBOM's components. A crate the closure has and the SBOM lacks is a failure
(exit 1) and is named. A component the closure does not have is also a failure: the SBOM would be
claiming a crate the binary does not contain.

`corrupt` writes a damaged copy for the negative controls: `missing-name` deletes a component's
required `name`; `drop-crate` removes one whole component (the document stays schema-valid, which
is exactly what `check` exists to catch). It prints the name@version it damaged.
"""
import json
import sys


def closure(meta: dict) -> set:
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    pk = {p["id"]: p for p in meta["packages"]}
    roots = [p["id"] for p in meta["packages"] if p["name"] == "busbar" and p["source"] is None]
    if len(roots) != 1:
        raise SystemExit(f"crosscheck: expected exactly one workspace package named busbar, found {len(roots)}")
    seen, stack = {roots[0]}, [roots[0]]
    while stack:
        for d in nodes[stack.pop()]["deps"]:
            if any(k["kind"] in (None, "build") for k in d["dep_kinds"]) and d["pkg"] not in seen:
                seen.add(d["pkg"])
                stack.append(d["pkg"])
    return {(pk[i]["name"], pk[i]["version"]) for i in seen if i != roots[0]}


def listed(sbom: dict) -> set:
    return {(c["name"], c["version"]) for c in sbom.get("components", [])}


def check(sbom_path: str, meta_path: str) -> int:
    want, have = closure(json.load(open(meta_path))), listed(json.load(open(sbom_path)))
    missing, extra = sorted(want - have), sorted(have - want)
    print(f"crosscheck: cargo metadata lists {len(want)} crates for the shipped closure, the SBOM {len(have)}")
    for n, v in missing:
        print(f"crosscheck: MISSING from the SBOM: {n}@{v}")
    for n, v in extra:
        print(f"crosscheck: SBOM lists a crate outside the closure: {n}@{v}")
    if not want:
        print("crosscheck: the closure is empty (the metadata is not the shipped closure)")
        return 1
    return 1 if missing or extra else 0


def corrupt(src: str, dst: str, how: str) -> int:
    doc = json.load(open(src))
    comps = doc["components"]
    # A deterministic victim that is in the middle of the list, never the first or last.
    i = len(comps) // 2
    victim = f"{comps[i]['name']}@{comps[i]['version']}"
    if how == "missing-name":
        del comps[i]["name"]
    elif how == "drop-crate":
        del comps[i]
    else:
        return 2
    json.dump(doc, open(dst, "w"), indent=2)
    print(victim)
    return 0


if __name__ == "__main__":
    a = sys.argv[1:]
    if len(a) == 3 and a[0] == "check":
        sys.exit(check(a[1], a[2]))
    if len(a) == 4 and a[0] == "corrupt":
        sys.exit(corrupt(a[1], a[2], a[3]))
    print(__doc__)
    sys.exit(2)
