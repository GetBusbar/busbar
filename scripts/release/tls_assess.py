#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""tls-assess: the RELEASED image's TLS, measured on a public host and judged by assertions.

This replaces the old "testssl grade against a loopback subject". That check minted its own CA, ran
the dev tree, and passed on a letter grade. Here the subject is the released image, by digest,
terminating TLS itself on a public name with a public-CA certificate. Every result is a named
assertion from scripts/release/tls-assert.json.

  tls_assess.py run   --host H --version V --image-digest sha256:… --variant ecdsa|rsa --out DIR
      runs the pinned testssl.sh (TESTSSL=<path>; version measured from its scan banner) with
        --wide -p -E -S -P -h -U --ip one --warnings off --color 0 --jsonfile DIR/testssl-<variant>.json
      and then `judge`.
  tls_assess.py judge --testssl FILE [--scan-log LOG] --version V --image-digest D --host H --variant X --out DIR
      writes DIR/assertions-<variant>.json and exits 1 if any assertion fails.
      Flat JSON needs --scan-log with the actual scan banner; pretty JSON carries
      its own version. Missing, duplicate or conflicting versions are refused.

The judge fails CLOSED. If a scan carries no protocol or cipher rows (a scan that did not happen, or
a testssl output this parser does not know), every assertion depending on them is `fail`, never
`pass`. HSTS is `not-claimed` until busbar sends the header (plan P6), and the site renders no HSTS
claim from it.

Outbound TLS (busbar refusing bad upstream certificates) is not measured here. It belongs to busbar's
own test matrix (plan section 7), and `assertions-*.json` records it as `not-run`.
"""

from __future__ import annotations

import datetime as dt
import hashlib
import json
import os
import re
import subprocess
import sys
from pathlib import Path

POLICY = Path(__file__).resolve().parent / "tls-assert.json"
ORDER = ["SSLv2", "SSLv3", "TLS1", "TLS1_1", "TLS1_2", "TLS1_3"]


def load_rows(path: Path) -> list:
    data = json.loads(path.read_text())
    if isinstance(data, dict) and "scanResult" in data:  # tolerate the pretty form: flatten it
        rows = []
        for sr in data["scanResult"]:
            for v in sr.values():
                if isinstance(v, list):
                    rows.extend(r for r in v if isinstance(r, dict) and "id" in r)
        return rows
    if not isinstance(data, list):
        raise ValueError("testssl JSON is neither the flat list nor the pretty form")
    return data


def judge(rows: list, policy: dict, now: dt.datetime) -> list:
    by_id: dict = {}
    for r in rows:
        by_id.setdefault(r.get("id", ""), []).append(r)
    out = []

    def add(name, ok, detail, result=None):
        out.append({"name": name, "result": result or ("pass" if ok else "fail"), "detail": detail})

    # Protocols.
    offered = {}
    for p in ORDER:
        fs = [r.get("finding", "").lower() for r in by_id.get(p, [])]
        # Any row saying offered wins: a protocol is proven absent only when no row offers it.
        offered[p] = None if not fs else any("offered" in f and "not offered" not in f for f in fs)
    if all(v is None for v in offered.values()):
        add("protocols", False, "no protocol rows in the scan (did the scan run?)")
    else:
        floor = ORDER.index(policy["min_protocol"])
        low = [p for p in ORDER[:floor] if offered.get(p)]
        add("min_protocol", not low, f"offered below {policy['min_protocol']}: {low or 'none'}")
        for p in policy["require_protocols"]:
            add(f"offers_{p}", offered.get(p) is True, f"{p} offered: {offered.get(p)}")
        bad = [p for p in policy["forbid_protocols"] if offered.get(p) is not False]
        add("forbidden_protocols_absent", not bad, f"not proven absent: {bad or 'none'}")

    # Ciphers, per protocol (-E rows: id `cipher-<proto>_x<hex>` or `cipher_x<hex>`).
    seen, disallowed = [], []
    for rid, rs in by_id.items():
        m = re.match(r"^cipher[-_](?:[a-z0-9_]+_)?(x[0-9a-f]+)$", rid)
        if not m:
            continue
        for r in rs:
            fnd = r.get("finding", "").lower()
            if "not offered" in fnd or "not a/v" in fnd or "not available" in fnd:
                continue
            seen.append(m.group(1))
            if m.group(1) not in policy["allowed_ciphers"]:
                disallowed.append(f"{m.group(1)} ({r.get('finding', '').split()[2] if len(r.get('finding', '').split()) > 2 else '?'})")
    if not seen:
        add("ciphers_allowed", False, "no per-cipher rows in the scan (-E did not run or the format changed)")
    else:
        add("ciphers_allowed", not disallowed, f"{len(set(seen))} offered; outside the allow-list: {sorted(set(disallowed)) or 'none'}")

    # Certificate chain, key size, expiry.
    chain = " ".join(r.get("finding", "") for r in by_id.get("cert_chain_of_trust", [])).lower()
    add("chain_trusted", chain.startswith(policy["chain"]), chain or "no cert_chain_of_trust row")
    keys = [r.get("finding", "") for r in by_id.get("cert_keySize", [])]
    okk = bool(keys)
    for k in keys:
        m = re.match(r"(EC|RSA)\D*(\d+)", k)
        if not m or int(m.group(2)) < policy["min_key"].get(m.group(1), 10**9):
            okk = False
    add("key_size", okk, "; ".join(keys) or "no cert_keySize row")
    exp = [r.get("finding", "") for r in by_id.get("cert_notAfter", [])]
    days = None
    for e in exp:
        try:
            na = dt.datetime.strptime(e.strip()[:16], "%Y-%m-%d %H:%M").replace(tzinfo=dt.timezone.utc)
            d = (na - now).days
            days = d if days is None else min(days, d)
        except ValueError:
            pass
    add("expiry", days is not None and days >= policy["min_expiry_days"], f"{days} days left" if days is not None else "no parseable cert_notAfter")

    # HSTS: not claimed until busbar sends it.
    h = " ".join(r.get("finding", "") for r in by_id.get("HSTS", []))
    if policy["hsts"] == "required":
        add("hsts", "max-age" in h.lower(), h or "no HSTS row")
    else:
        add("hsts", True, h or "no HSTS row", result="not-claimed")

    # Any HIGH/CRITICAL finding anywhere.
    sev = [f"{r.get('id')}: {r.get('finding', '')[:80]}" for r in rows if r.get("severity") in policy["forbid_severities"]]
    add("no_high_findings", not sev, "; ".join(sev[:10]) or "none")
    add("outbound_tls", True, "busbar's own client matrix (not part of this scan)", result="not-run")
    return out


def scanner_identity(scan: Path, log: Path | None = None) -> dict:
    """Measure the scan's upstream version; never label unknown output as a pin."""
    payload = scan.read_bytes()
    data = json.loads(payload)
    versions = []
    evidence = {"scan_sha256": hashlib.sha256(payload).hexdigest()}
    if isinstance(data, dict) and "scanResult" in data and "version" in data:
        match = re.fullmatch(r"(\d+\.\d+\.\d+)(?: [^\r\n]*)?", str(data["version"]))
        if not match:
            raise ValueError("unrecognized testssl JSON version")
        versions.append(match.group(1))
    if log is not None:
        output = log.read_bytes()
        banners = re.findall(r"^\s*testssl\.sh version (\d+\.\d+\.\d+) from \S+[^\r\n]*$",
                             output.decode("utf-8", errors="replace"), re.M)
        if len(banners) != 1:
            raise ValueError("missing or duplicate testssl scan version banner")
        versions.extend(banners)
        evidence["scan_log_sha256"] = hashlib.sha256(output).hexdigest()
    if not versions or len(set(versions)) != 1:
        raise ValueError("missing or conflicting testssl scan version")
    return {"tool": "testssl.sh " + versions[0], "tool_evidence": evidence}


def cmd_judge(a: dict) -> int:
    policy = json.loads(POLICY.read_text())
    try:
        scan = Path(a["testssl"])
        rows = load_rows(scan)
        identity = scanner_identity(scan, Path(a["scan-log"]) if a.get("scan-log") else None)
    except (OSError, ValueError) as e:
        print(f"tls-assess: cannot read the scan: {e}")
        return 3
    now = dt.datetime.now(dt.timezone.utc)
    res = judge(rows, policy, now)
    out = Path(a["out"])
    out.mkdir(parents=True, exist_ok=True)
    doc = {"version": a["version"], "image_digest": a["image-digest"], "host": a["host"], "variant": a["variant"],
           "date": now.strftime("%Y-%m-%dT%H:%M:%SZ"), **identity, "policy": str(POLICY.name),
           "assertions": res}
    (out / f"assertions-{a['variant']}.json").write_text(json.dumps(doc, indent=2) + "\n")
    # The one file the site reads (signed by ModernCI as a check output): every variant of this
    # image, each assertion named `<variant>/<name>`.
    parts = [json.loads(f.read_text()) for f in sorted(out.glob("assertions-*.json"))]
    parts = [d for d in parts if d["version"] == a["version"] and d["image_digest"] == a["image-digest"]]
    if any(d.get("tool") != doc["tool"] or not d.get("tool_evidence") for d in parts):
        (out / "assertions.json").unlink(missing_ok=True)
        print("tls-assess: cannot aggregate variants with unknown or conflicting scanner versions")
        return 3
    (out / "assertions.json").write_text(json.dumps({
        "version": a["version"], "image_digest": a["image-digest"], "host": a["host"],
        "date": max(d["date"] for d in parts), "tool": doc["tool"],
        "tool_evidence": {d["variant"]: d["tool_evidence"] for d in parts},
        "assertions": [dict(r, name=f"{d['variant']}/{r['name']}") for d in parts for r in d["assertions"]],
    }, indent=2) + "\n")
    fails = [r for r in res if r["result"] == "fail"]
    for r in res:
        print(f"{r['result'].upper():12} {r['name']}: {r['detail']}")
    print(f"tls-assess: {len(fails)} failed assertion(s)")
    return 1 if fails else 0


def cmd_run(a: dict) -> int:
    testssl = os.environ.get("TESTSSL", "")
    if not testssl or not Path(testssl).is_file():
        print("tls-assess: TESTSSL=<path to the pinned testssl.sh> is required; cannot run")
        return 3
    out = Path(a["out"])
    out.mkdir(parents=True, exist_ok=True)
    js = out / f"testssl-{a['variant']}.json"
    js.unlink(missing_ok=True)
    scan_log = out / f"testssl-{a['variant']}.log"
    with scan_log.open("wb") as output:
        subprocess.run([testssl, "--wide", "-p", "-E", "-S", "-P", "-h", "-U", "--ip", "one", "--warnings", "off",
                        "--color", "0", "--jsonfile", str(js), f"https://{a['host']}"],
                       stdout=output, stderr=subprocess.STDOUT)
    print(scan_log.read_text(errors="replace"), end="")
    if not js.is_file():
        print("tls-assess: testssl wrote no JSON; the scan did not happen")
        return 3
    return cmd_judge({**a, "testssl": str(js), "scan-log": str(scan_log)})


def main(argv: list) -> int:
    if not argv or argv[0] not in ("run", "judge"):
        print(__doc__)
        return 2
    a, it = {}, iter(argv[1:])
    for k in it:
        if not k.startswith("--"):
            print(__doc__)
            return 2
        a[k[2:]] = next(it, "")
    need = ["host", "version", "image-digest", "variant", "out"] + (["testssl"] if argv[0] == "judge" else [])
    if any(not a.get(k) for k in need):
        print(__doc__)
        return 2
    return cmd_run(a) if argv[0] == "run" else cmd_judge(a)


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
