#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Merge several record.sh outputs (recorded with disjoint --filter sets) into one recording.

    merge-recordings.py --out <dir> [--allow-harness-skew] [--note TEXT] [--cells cells.json] <part>...
    merge-recordings.py --selftest

A recording is a set of cells: `cells/<id>.json`, `raw/<id>/`, one ledger row each, and a
`meta.json` that names the binary, its digest, the harness revision and the host. Recording in
parts is how a full golden fits under a wall-clock cap, runs on several cores, or has ONE stale
cell replaced by a fresh recording from the same published binary. A cell id present in two parts
is refused: the parts must be disjoint, or the merged ledger would carry two verdicts for one cell.

── WHAT IDENTIFIES A RECORDING'S SOURCE ────────────────────────────────────────────────────────
    IDENTITY = version + binary_sha256 + host_triple.  Mismatch -> refused, always.

A PATH IS WHERE A FILE WAS, NOT WHAT IT WAS. meta.json's `binary` is the --bin argument as typed:
`/Users/runner/.cache/busbar-oracle/1.5.5/busbar` on a CI runner, `/Users/<you>/.cache/...` on a
laptop, both the same 11 MB of bytes with the same sha256. This file used to compare that string,
so the ONLY supported way to re-record one stale cell of a CI-recorded golden was to be that CI
runner — and the alternative people reached for instead was hand-editing golden cell files, which
is the one thing the shadow oracle must never do. binary_sha256 answers "is this the same binary?"
exactly, and fetch-golden.sh --check-golden already pins that digest to the published artifact.
The paths are not discarded: every part's own `binary` is recorded in the merged `merged_from`.

`harness_rev` (cells.json, the normalizer, the recorder, the fixtures — see harness-rev.sh) is a
different question: it says what was recorded and how it is normalized, so two parts under two revs
may genuinely disagree about a cell's bytes. It is REPORTED, not silently accepted:

  * parts agree                    -> merged as-is
  * parts differ, no flag          -> REFUSED, naming both revs
  * parts differ, --allow-harness-skew + --note
                                   -> merged; the rev of the LAST-RECORDED part (max `at`) becomes
                                      the merged `harness_rev`, every other distinct rev is pushed
                                      onto `harness_rev_history`, and --note is prepended to
                                      `harness_rev_note`. That note is the only place a reader
                                      learns WHICH cells were re-recorded under which rev and why,
                                      so it is REQUIRED for a skewed merge, not optional.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys
import tempfile

# What actually identifies the source of a recording. `binary` (a filesystem path) is deliberately
# NOT here; `harness_rev` is handled separately because it is reportable rather than fatal.
IDENTITY = ("version", "binary_sha256", "host_triple")


def machine_independent_binary(path: str) -> str:
    """The `binary` bookkeeping path with the operator's name and home layout removed.

    A merged golden's meta.json is COMMITTED, and an absolute path under a personal home directory
    names a person and a machine — scripts/public-hygiene-lint.py's `machine-path` rule refuses
    exactly that in a published file. It is safe to rewrite because this field was never the
    identity: IDENTITY above is (version, binary_sha256, host_triple), and `binary` is carried only
    so a reader knows WHICH well-known location a part came from. That much is kept:

        under the repo          -> <repo>/target/release/busbar
        under the oracle cache  -> <oracle-cache>/1.5.5/busbar   (BUSBAR_ORACLE_CACHE or ~/.cache/busbar-oracle)
        elsewhere under $HOME   -> <home>/some/path/busbar
        elsewhere               -> unchanged (/usr/local/bin/busbar names no person)

    The SAME rule record.sh applies when it writes a fresh meta.json, so a merge of fresh parts is
    a no-op here and only an OLD part (recorded before that rule existed) is rewritten — and when
    one is, merge() says so on stdout rather than doing it silently.
    """
    if not isinstance(path, str) or not path.startswith("/"):
        return path
    repo = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", ".."))
    home = os.environ.get("HOME") or "/nonexistent"
    cache = os.environ.get("BUSBAR_ORACLE_CACHE") or os.path.join(home, ".cache", "busbar-oracle")
    for root, token in ((repo, "<repo>"), (cache, "<oracle-cache>"), (home, "<home>")):
        if root and path.startswith(root.rstrip("/") + "/"):
            return token + "/" + path[len(root.rstrip("/")) + 1:]
    return path


def _load_meta(p: str) -> dict:
    mp = os.path.join(p, "meta.json")
    if not os.path.isfile(mp):
        sys.exit(f"merge-recordings: {p} has no meta.json (an unfinished or failed recording)")
    with open(mp, encoding="utf-8") as f:
        return json.load(f)


def merge(parts, out, allow_harness_skew=False, note=None, cells_json=None) -> int:
    metas = [(p, _load_meta(p)) for p in parts]
    base_p, base = metas[0]
    for p, m in metas[1:]:
        for k in IDENTITY:
            if m.get(k) != base.get(k):
                sys.exit(f"merge-recordings: {p} {k}={m.get(k)!r} but {base_p} {k}={base.get(k)!r}; "
                         "parts of one recording must come from the same binary on the same host")
    # The binary PATH is bookkeeping, not identity: say so out loud rather than refusing on it.
    # The merged meta.json is committed, so every `binary` that reaches it — the base's and each
    # part's in merged_from — is written in the machine-independent form (see the docstring above).
    # Announced, never silent: a reader of the merge output learns the path was rewritten.
    for p, m in metas:
        b = m.get("binary")
        nb = machine_independent_binary(b)
        if nb != b:
            print(f"merge-recordings: {os.path.basename(os.path.normpath(p))} recorded its binary as "
                  f"an absolute path; writing it as {nb} (the digest is the identity, not the path)")
            m["binary"] = nb
    paths = {m.get("binary") for _, m in metas}
    if len(paths) > 1:
        print(f"merge-recordings: parts name {len(paths)} different paths for the same binary "
              f"{base.get('binary_sha256', '?')[:12]} — merging on the digest, recording every path "
              "in merged_from")
    revs = {m.get("harness_rev") for _, m in metas}
    if len(revs) > 1:
        named = ", ".join(f"{os.path.basename(os.path.normpath(p))}={str(m.get('harness_rev'))[:12]}"
                          for p, m in metas)
        if not allow_harness_skew:
            sys.exit(f"merge-recordings: parts were recorded under {len(revs)} different harness "
                     f"revisions ({named}); their cells may differ because the harness changed, not "
                     "because the binary did. Re-record every part under one harness, or pass "
                     "--allow-harness-skew --note '<which cells, which rev, why>'.")
        if not note:
            sys.exit("merge-recordings: --allow-harness-skew needs --note saying which cells were "
                     "re-recorded under which harness_rev and why; a skewed merge with no note is "
                     "an unexplained golden")
        print(f"merge-recordings: HARNESS SKEW ALLOWED — {named}")
    if os.path.exists(out):
        sys.exit(f"merge-recordings: {out} exists; refusing to merge over it")
    os.makedirs(os.path.join(out, "cells"))
    os.makedirs(os.path.join(out, "raw"))
    seen, rows, recorded = {}, [], 0
    for p, m in metas:
        with open(os.path.join(p, "ledger.tsv"), encoding="utf-8") as f:
            for line in f:
                if not line.strip():
                    continue
                cid = line.split("\t", 1)[0]
                if cid in seen:
                    sys.exit(f"merge-recordings: cell {cid!r} is in both {seen[cid]} and {p}; parts must be disjoint")
                seen[cid] = p
                rows.append(line if line.endswith("\n") else line + "\n")
        for sub in ("cells", "raw"):
            src = os.path.join(p, sub)
            if not os.path.isdir(src):
                continue
            for name in os.listdir(src):
                dst = os.path.join(out, sub, name)
                if os.path.exists(dst):
                    sys.exit(f"merge-recordings: {sub}/{name} is in two parts; parts must be disjoint")
                s = os.path.join(src, name)
                shutil.copytree(s, dst) if os.path.isdir(s) else shutil.copy2(s, dst)
        recorded += int(m.get("recorded", 0))
    # IN cells.json ORDER, not part-by-part. record.sh walks cells.json and appends as it goes, so
    # every recording's ledger is in that order — concatenating the parts instead moves a
    # re-recorded cell's row to the end of the file, and the checked-in golden then shows 2N changed
    # ledger lines for N rows whose bytes did not change at all. An id cells.json does not know
    # keeps its encounter order, after the ones it does.
    if cells_json and os.path.isfile(cells_json):
        with open(cells_json, encoding="utf-8") as f:
            order = {c["id"]: i for i, c in enumerate(json.load(f)["cells"])}
        rows.sort(key=lambda ln: order.get(ln.split("\t", 1)[0], len(order)))
    with open(os.path.join(out, "ledger.tsv"), "w", encoding="utf-8") as f:
        f.writelines(rows)
    meta = dict(base)
    meta["recorded"] = recorded
    meta["merged_from"] = [{"part": os.path.basename(os.path.normpath(p)), "recorded": m.get("recorded", 0),
                            "at": m.get("at"), "binary": m.get("binary"), "harness_rev": m.get("harness_rev")}
                           for p, m in metas]
    meta["at"] = max(m.get("at", "") for _, m in metas)
    if len(revs) > 1:
        # The merged recording is stamped with the rev of the part recorded LAST, and every other
        # rev its cells actually came from is kept in the history rather than dropped on the floor.
        newest = max(metas, key=lambda pm: pm[1].get("at", ""))[1]
        meta["harness_rev"] = newest.get("harness_rev")
        history = list(meta.get("harness_rev_history", []))
        for r in sorted(revs - {newest.get("harness_rev")}):
            if r and r not in history:
                history.append(r)
        meta["harness_rev_history"] = history
    if note:
        prev = meta.get("harness_rev_note")
        meta["harness_rev_note"] = f"{note} | Earlier note: {prev}" if prev else note
    with open(os.path.join(out, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f, indent=2, ensure_ascii=False)
        f.write("\n")
    print(f"merged {len(metas)} parts, {len(rows)} ledger rows, {recorded} recorded -> {out}")
    return 0


# ── self-test ───────────────────────────────────────────────────────────────────────────────────
# The provenance rule is the whole point of this file, so it proves itself before anyone trusts a
# merged golden: the pair that MUST merge (one binary, two paths) and the pairs that MUST NOT.
def _part(root, name, cell_ids, **meta_over):
    d = os.path.join(root, name)
    os.makedirs(os.path.join(d, "cells"))
    meta = {"binary": "/Users/runner/.cache/busbar-oracle/1.5.5/busbar", "version": "busbar 1.5.5",
            "recorded": len(cell_ids), "binary_sha256": "48e2800c", "harness_rev": "aaaa",
            "host_triple": "aarch64-apple-darwin", "at": "2026-09-06T00:00:00Z"}
    meta.update(meta_over)
    with open(os.path.join(d, "meta.json"), "w", encoding="utf-8") as f:
        json.dump(meta, f)
    with open(os.path.join(d, "ledger.tsv"), "w", encoding="utf-8") as f:
        for c in cell_ids:
            f.write(f"{c}\tPASS\tidentical\t\n")
    for c in cell_ids:
        with open(os.path.join(d, "cells", c.replace("|", "__") + ".json"), "w", encoding="utf-8") as f:
            json.dump({"status": 200}, f)
    return d


def selftest() -> int:
    me = os.path.abspath(__file__)
    fails = 0

    def case(name, parts, args, want_rc, want_in=""):
        nonlocal fails
        with tempfile.TemporaryDirectory() as t:
            dirs = [_part(t, n, ids, **over) for n, ids, over in parts]
            r = subprocess.run([sys.executable, me, "--out", os.path.join(t, "merged")] + args + dirs,
                               capture_output=True, text=True)
            blob = r.stdout + r.stderr
            ok = (r.returncode == 0) == (want_rc == 0) and (want_in in blob)
            print(("PASS  " if ok else "FAIL  ") + name + ("" if ok else f"  rc={r.returncode} out={blob.strip()[:200]}"))
            if not ok:
                fails += 1
            return t

    # THE CASE THIS FILE WAS FIXED FOR: same binary bytes, two different filesystem paths.
    # (The second path is deliberately NOT under a home directory: this file is itself public, and a
    # `/Users/<person>/...` literal here is the very thing the machine-path rule keeps out.)
    case("same sha256, different binary PATH -> merges",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"binary": "/opt/busbar-oracle-cache/1.5.5/busbar"})],
         [], 0, "merged 2 parts")
    # A COMMITTED meta.json MAY NOT NAME A PERSON: a part recorded before that rule (or by a caller
    # that passed an absolute --bin) gets its `binary` written machine-independently, out loud.
    case("a part's binary under $HOME -> rewritten, announced",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"binary": os.path.join(os.environ.get("HOME", "/nonexistent"),
                                                                     ".cache/busbar-oracle/1.5.5/busbar")})],
         [], 0, "<oracle-cache>/1.5.5/busbar")
    case("different binary_sha256 -> refused",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"binary_sha256": "deadbeef"})],
         [], 1, "binary_sha256")
    case("different host_triple -> refused",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"host_triple": "x86_64-unknown-linux-gnu"})],
         [], 1, "host_triple")
    case("different version -> refused",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"version": "busbar 1.6.0"})],
         [], 1, "version")
    case("overlapping cell id -> refused",
         [("a", ["x|1"], {}), ("b", ["x|1"], {})],
         [], 1, "disjoint")
    case("different harness_rev, no flag -> refused",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"harness_rev": "bbbb"})],
         [], 1, "harness revisions")
    case("different harness_rev, --allow-harness-skew but no --note -> refused",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"harness_rev": "bbbb"})],
         ["--allow-harness-skew"], 1, "--note")
    case("different harness_rev, skew allowed and noted -> merges",
         [("a", ["x|1"], {}), ("b", ["x|2"], {"harness_rev": "bbbb", "at": "2026-09-06T01:00:00Z"})],
         ["--allow-harness-skew", "--note", "x|2 re-recorded under bbbb"], 0, "HARNESS SKEW ALLOWED")

    # the skewed merge's meta must be stamped with the LAST-recorded rev and keep the other in history
    with tempfile.TemporaryDirectory() as t:
        a = _part(t, "a", ["x|1"])
        b = _part(t, "b", ["x|2"], harness_rev="bbbb", at="2026-09-06T01:00:00Z")
        subprocess.run([sys.executable, me, "--out", os.path.join(t, "m"), "--allow-harness-skew",
                        "--note", "N", a, b], capture_output=True, text=True)
        m = json.load(open(os.path.join(t, "m", "meta.json"), encoding="utf-8"))
        ok = (m["harness_rev"] == "bbbb" and "aaaa" in m.get("harness_rev_history", [])
              and m["recorded"] == 2 and m["harness_rev_note"] == "N"
              and {e["binary"] for e in m["merged_from"]} == {"/Users/runner/.cache/busbar-oracle/1.5.5/busbar"})
        print(("PASS  " if ok else "FAIL  ") + "skewed merge stamps the newest rev, keeps the older in history, sums `recorded`, notes the parts"
              + ("" if ok else f"  meta={m}"))
        fails += 0 if ok else 1

    # the merged ledger is written in cells.json order, not part-by-part concatenation order
    with tempfile.TemporaryDirectory() as t:
        cj = os.path.join(t, "cells.json")
        with open(cj, "w", encoding="utf-8") as f:
            json.dump({"cells": [{"id": "z|first"}, {"id": "a|second"}]}, f)
        a = _part(t, "a", ["a|second"])
        b = _part(t, "b", ["z|first"])
        subprocess.run([sys.executable, me, "--out", os.path.join(t, "m"), "--cells", cj, a, b],
                       capture_output=True, text=True)
        got = [ln.split("\t", 1)[0] for ln in open(os.path.join(t, "m", "ledger.tsv"), encoding="utf-8")]
        ok = got == ["z|first", "a|second"]
        print(("PASS  " if ok else "FAIL  ") + "merged ledger is in cells.json order, not part order"
              + ("" if ok else f"  got={got}"))
        fails += 0 if ok else 1

    print()
    print("merge-recordings selftest: " + ("GREEN" if fails == 0 else f"RED ({fails})"))
    return 0 if fails == 0 else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--out")
    ap.add_argument("--allow-harness-skew", action="store_true",
                    help="merge parts recorded under different harness revisions (needs --note)")
    ap.add_argument("--note", default="",
                    help="prepended to the merged meta.json's harness_rev_note; required for a skewed merge")
    ap.add_argument("--cells", default=os.path.join(os.path.dirname(os.path.abspath(__file__)), "cells.json"),
                    help="cells.json whose order the merged ledger is written in (record.sh's own order)")
    ap.add_argument("--selftest", action="store_true", help="prove the provenance rule, then exit")
    ap.add_argument("parts", nargs="*")
    a = ap.parse_args()
    if a.selftest:
        return selftest()
    if not a.out or not a.parts:
        sys.exit("usage: merge-recordings.py --out <dir> [--allow-harness-skew] [--note TEXT] <part>...")
    return merge(a.parts, a.out, a.allow_harness_skew, a.note, a.cells)


if __name__ == "__main__":
    sys.exit(main())
