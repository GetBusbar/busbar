#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render conformance/manifest.json from conformance/registry.toml and conformance/verdicts/*.json.

    python3 scripts/conformance/sync.py            # print the manifest
    python3 scripts/conformance/sync.py --write    # write conformance/manifest.json

A pure function of the two inputs (generated_at is the latest verdict's), so the same inputs always
give the same bytes. It replaces `cargo xtask gate conformance-sync --write`, deleted with the gate
machinery.

Each verdict is held to conformance/verdicts/verdict.schema.json's rules before it is read: its
`suite` is the id it is filed under and is registered, its status is pass|fail|not-run, and an
unarmed verdict is not-run. A verdict that breaks one is refused (exit 1), never rendered.

Freshness is per suite (owner, 2026-10-26): suites are judged in different repos, each against its
own core pin, so there is no single anchor commit. Each suite entry carries its verdict's `repo`,
`commit` and `core_pin`, and the manifest-level `commit` is empty. `claim` is a pure function of the
registry tier and the status, and is null for anything but a pass.
"""
import json
import sys
import tomllib
from pathlib import Path

SCHEMA = "busbar.conformance.manifest/1"
VERDICT_SCHEMA = "busbar.conformance.verdict/1"
RELEASE = "1.6.0"
BANNER = "by `python3 scripts/conformance/sync.py --write`; DO NOT EDIT"
VERDICT_KEYS = {"schema", "suite", "standard", "plan", "spec_version", "status", "armed", "commit",
                "run_id", "evidence", "generated_at", "reason", "cert_id", "issuer", "expires",
                "repo", "core_pin"}
TIERS = {"certified", "conformant", "spec-conformant", "capable", "evidence-only"}


class Refused(Exception):
    pass


def claim_for(suite, status, issuer=None):
    if status != "pass":
        return None
    tier = suite["tier"]
    if tier == "certified":
        return f"Certified — {issuer or suite['standard']}"
    if tier == "conformant":
        return f"Conformant — passes {suite['plan']}"
    if tier == "spec-conformant":
        return f"Spec-conformant — {suite['standard']}"
    if tier == "capable":
        return f"{suite['label']}-capable"
    return f"Provides evidence for {suite['standard']}"


def read_registry(path):
    suites = tomllib.loads(Path(path).read_text())["suite"]
    seen = set()
    for s in suites:
        for k in ("id", "standard", "plan", "tier", "label", "verdict", "public"):
            if k not in s:
                raise Refused(f"registry: suite {s.get('id')!r} has no `{k}`")
        if s["tier"] not in TIERS:
            raise Refused(f"registry: suite {s['id']} tier {s['tier']!r} is not one of {sorted(TIERS)}")
        if s["id"] in seen:
            raise Refused(f"registry: suite {s['id']} is registered twice")
        seen.add(s["id"])
    return suites


def read_verdicts(directory, registered):
    out = {}
    for f in sorted(Path(directory).glob("*.json")):
        if f.name == "verdict.schema.json":
            continue
        v = json.loads(f.read_text())
        sid = f.stem
        if v.get("schema") != VERDICT_SCHEMA:
            raise Refused(f"{f.name}: schema is {v.get('schema')!r}, not {VERDICT_SCHEMA}")
        if v.get("suite") != sid:
            raise Refused(f"{f.name}: names suite {v.get('suite')!r}, filed under {sid!r}")
        if sid not in registered:
            raise Refused(f"{f.name}: suite {sid} is not in the registry")
        extra = set(v) - VERDICT_KEYS
        if extra:
            raise Refused(f"{f.name}: unknown fields {sorted(extra)}")
        for k in ("status", "armed", "commit"):
            if k not in v:
                raise Refused(f"{f.name}: no `{k}`")
        if v["status"] not in ("pass", "fail", "not-run"):
            raise Refused(f"{f.name}: status {v['status']!r}")
        if v["armed"] is not True and v["status"] != "not-run":
            raise Refused(f"{f.name}: an unarmed verdict says {v['status']}")
        out[sid] = v
    return out


def render(registry_path, verdicts_dir):
    suites = read_registry(registry_path)
    verdicts = read_verdicts(verdicts_dir, {s["id"] for s in suites})
    entries = []
    for s in sorted(suites, key=lambda s: s["id"]):
        v = verdicts.get(s["id"])
        e = {
            "suite": s["id"],
            "standard": s["standard"],
            "plan": s["plan"],
            "tier": s["tier"],
            "public": str(s["public"]).lower() == "true",
        }
        if v is None:
            e.update(status="not-run", claim=None, reason="no verdict artifact for this commit")
        else:
            e["status"] = v["status"]
            e["claim"] = claim_for(s, v["status"], v.get("issuer"))
            for src, dst in (("spec_version", "spec_version"), ("evidence", "evidence"),
                             ("commit", "commit"), ("repo", "repo"), ("core_pin", "core_pin"),
                             ("generated_at", "verified_at"), ("expires", "expires")):
                if v.get(src):
                    e[dst] = v[src]
            if v["status"] != "pass":
                e["reason"] = v.get("reason") or f"the suite's verdict is {v['status']}"
        entries.append(dict(sorted(e.items())))
    stamps = [v["generated_at"] for v in verdicts.values() if v.get("generated_at")]
    doc = {
        "_generated": BANNER,
        "commit": "",
        "generated_at": max(stamps) if stamps else "",
        "release": RELEASE,
        "schema": SCHEMA,
        "suites": entries,
    }
    return json.dumps(doc, indent=2, ensure_ascii=False) + "\n"


def main(argv):
    root = Path(__file__).resolve().parents[2] / "conformance"
    try:
        text = render(root / "registry.toml", root / "verdicts")
    except (Refused, ValueError, KeyError) as e:
        print(f"conformance sync: REFUSED: {e}", file=sys.stderr)
        return 1
    if "--write" in argv:
        (root / "manifest.json").write_text(text)
    else:
        sys.stdout.write(text)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
