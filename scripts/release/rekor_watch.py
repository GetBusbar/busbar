#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""rekor-watch: compare the public Rekor log with what we released. Run on a ModernCI `schedule:`.

Each run does two things for every K2 key in release/allowed_signers:
- It asks Rekor for every entry signed by that key. An entry whose artifact digest is NOT a file
  listed in release/released.tsv is an ALARM: someone signed something with a release key that we
  never released. That means a stolen key or a stolen touch.
- It asks the reverse question. A row of release/released.tsv with no entry in Rekor is an ALARM:
  that release skipped the log.

Exit 0 means the log and the list agree. Exit 1 means an alarm, and every line names the entry or
the row. Exit 3 means Rekor could not be read, which is never a pass.

release/released.tsv has one line per signed release file, `<version>\\t<file>\\t<sha256>`. The
owner commits the rows that `publish_gate.py upload` writes to out/released.tsv.
"""

from __future__ import annotations

import base64
import json
import sys
import urllib.error
import urllib.request
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
REKOR = "https://rekor.sigstore.dev"


def post(path: str, body: dict):
    req = urllib.request.Request(REKOR + path, data=json.dumps(body).encode(),
                                 headers={"Content-Type": "application/json", "Accept": "application/json"})
    with urllib.request.urlopen(req, timeout=30) as r:
        return json.loads(r.read())


def get(path: str):
    with urllib.request.urlopen(REKOR + path, timeout=30) as r:
        return json.loads(r.read())


def keys() -> list:
    out = []
    for line in (ROOT / "release" / "allowed_signers").read_text().splitlines():
        if line.strip() and not line.startswith("#"):
            f = line.split()
            # principals [options] keytype base64 [comment]
            i = next(i for i, x in enumerate(f) if x.startswith(("sk-ssh-", "ssh-", "sk-ecdsa-", "ecdsa-")))
            out.append(f"{f[i]} {f[i + 1]}")
    return out


def released() -> dict:
    rows = {}
    p = ROOT / "release" / "released.tsv"
    for line in p.read_text().splitlines() if p.is_file() else []:
        if line.strip() and not line.startswith("#"):
            version, name, digest = line.split("\t")
            rows[digest.lower()] = f"{version} {name}"
    return rows


def main() -> int:
    ks, rel = keys(), released()
    if not ks:
        print("rekor-watch: release/allowed_signers holds no K2 key yet; nothing to watch (not a pass of anything)")
        return 0 if not rel else 1
    alarms, seen = [], set()
    try:
        for k in ks:
            uuids = post("/api/v1/index/retrieve", {"publicKey": {"format": "ssh", "content": base64.b64encode(k.encode()).decode()}}) or []
            for u in uuids:
                entry = next(iter(get(f"/api/v1/log/entries/{u}").values()))
                body = json.loads(base64.b64decode(entry["body"]))
                digest = (((body.get("spec") or {}).get("data") or {}).get("hash") or {}).get("value", "").lower()
                seen.add(digest)
                if digest not in rel:
                    alarms.append(f"ALARM rekor entry {u} (logIndex {entry.get('logIndex')}): key {k[:40]}… signed "
                                  f"sha256:{digest or '?'}, which release/released.tsv does not list")
    except (urllib.error.URLError, TimeoutError, ValueError, KeyError, StopIteration) as e:
        print(f"rekor-watch: cannot read Rekor: {e}")
        return 3
    for digest, what in sorted(rel.items()):
        if digest not in seen:
            alarms.append(f"ALARM {what} (sha256:{digest}) is released but has no Rekor entry under a K2 key")
    for a in alarms:
        print(a)
    print(f"rekor-watch: {len(ks)} key(s), {len(seen)} log entr(ies), {len(rel)} released file(s), {len(alarms)} alarm(s)")
    return 1 if alarms else 0


if __name__ == "__main__":
    sys.exit(main())
