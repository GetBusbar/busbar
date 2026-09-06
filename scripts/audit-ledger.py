#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# audit-ledger.py -- THE AUDIT LEDGER.
#
# One place that knows, for every piece of code in this workspace, whether it has been audited, by
# whom, in which round, with what result -- and that RESETS that answer automatically the moment the
# code underneath it changes. An audit result is a statement about a specific tree; once the tree
# moves the statement expires. Nothing here trusts a human to remember that.
#
# The register is qa/audit-ledger.json. Its scope list is GENERATED from the tree, never hand-kept,
# so a new crate cannot appear uncovered: `sync` derives the scopes the tree implies, adds what is
# missing and flags what is gone, and `--check` is red if any tracked production file belongs to no
# scope at all.
#
#   sync [--write]   derive the scopes from the tree; print what would be added/removed; --write
#                    applies (audit records on surviving scopes are preserved verbatim)
#   status           print the table and regenerate docs/design/AUDIT-STATUS.md
#   record           stamp an audit result onto a scope at the current tree hash and HEAD
#   fixed            stamp the fix commit onto a scope with findings and re-hash it
#   next             the ordered worklist an orchestrator launches auditors from
#   --check          red if any scope is `open` at HIGH/MEDIUM, or if coverage is incomplete
#   --selftest       the instrument proves itself in a scratch repo before it judges this one
#
# STATUS is derived, never stored:
#   unaudited    nobody has looked
#   in_progress  a round is running against a recorded tree hash right now
#   open         findings recorded, no fix commit stamped yet
#   stale        the tree hash moved since the audit -- the result no longer describes this code
#   fixed        findings were fixed at the recorded hash; due a confirming round
#   clean        a `zero` result whose tree hash is still the tree hash
#
# TREE HASH. A scope's hash is sha256 over the sorted `path\tblob-oid` list of every tracked file in
# the scope at HEAD. A bare `git rev-parse HEAD:<dir>` cannot be used directly because a production
# scope is a crate's src/ MINUS its src/tests/ -- the excluded subtree would move the directory oid
# and expire an audit that nothing production touched. File-level oids give the same guarantee (an
# identical file set hashes identically, any content change moves the hash) while honouring the
# exclusion.
#
# This is a QA instrument: python3 stdlib + git only, no workspace code, so it cannot be broken by
# the thing it measures. Deterministic output; no wall-clock anywhere, only commit hashes.

import argparse
import hashlib
import json
import os
import subprocess
import sys

LEDGER_REL = "qa/audit-ledger.json"
REPORT_REL = "docs/design/AUDIT-STATUS.md"

SEVERITIES = ("HIGH", "MEDIUM", "LOW", "NIT")
RESULTS = ("zero", "findings", "in_progress", "unaudited")

# Instrument/QA paths that are code too, and are audited as their own scopes. Everything under
# testing/ is derived per rig (shadow-oracle, fleet-fixtures, the conformance harnesses), because a
# harness that decides whether the product is correct is exactly as worth auditing as the product.
INSTRUMENT_PATHS = (
    "scripts",
    "qa",
    ".github/workflows",
)

# The crate whose src/ is split, because its production code is two very different things: the
# composition root and the binary's entry point.
SPLIT_CRATE = "busbar"

# Tracked files that are deliberately in no scope. Manifests are governed by workspace-deps-lint and
# the construction gate, not by a code audit; xtask/fixtures are fixture trees for those gates.
UNCOVERED_BY_DESIGN = (
    ("crates/*/Cargo.toml", "crate manifest -- governed by workspace-deps-lint, not a code audit"),
    ("crates/*/Cargo.lock", "resolved lockfile -- governed by the build gates, not a code audit"),
    ("crates/*/fixtures/*", "fixture inputs a crate's own gate reads; not shipped code"),
    ("xtask/Cargo.toml", "crate manifest -- governed by workspace-deps-lint, not a code audit"),
    ("xtask/fixtures/*", "fixture trees the workspace-deps gate builds against"),
)


# ---------------------------------------------------------------------------- git


class Git:
    def __init__(self, repo):
        self.repo = repo

    def run(self, *args):
        out = subprocess.run(
            ["git", "-C", self.repo, *args],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        if out.returncode != 0:
            raise RuntimeError(
                "git %s failed: %s" % (" ".join(args), out.stderr.decode("utf-8", "replace").strip())
            )
        return out.stdout.decode("utf-8", "replace")

    def head(self):
        return self.run("rev-parse", "HEAD").strip()

    def files_at_head(self):
        """{path: blob-oid} for every tracked file at HEAD."""
        table = {}
        for line in self.run("ls-tree", "-r", "HEAD", "--full-tree").splitlines():
            if not line:
                continue
            meta, path = line.split("\t", 1)
            _mode, kind, oid = meta.split()
            if kind == "blob":
                table[path] = oid
        return table

    def line_counts(self, oids):
        """{oid: line count} in one batched cat-file, so LOC costs one process, not N."""
        if not oids:
            return {}
        ordered = sorted(oids)
        proc = subprocess.Popen(
            ["git", "-C", self.repo, "cat-file", "--batch"],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
        )
        out, _ = proc.communicate(("\n".join(ordered) + "\n").encode())
        counts = {}
        pos = 0
        for oid in ordered:
            nl = out.find(b"\n", pos)
            if nl < 0:
                break
            header = out[pos:nl].split()
            size = int(header[2])
            body = out[nl + 1 : nl + 1 + size]
            counts[oid] = body.count(b"\n") + (1 if body and not body.endswith(b"\n") else 0)
            pos = nl + 1 + size + 1
        return counts

    def commits_between(self, old, new):
        try:
            return int(self.run("rev-list", "--count", "%s..%s" % (old, new)).strip())
        except RuntimeError:
            return None

    def dir_exists(self, path):
        return os.path.isdir(os.path.join(self.repo, path))

    def path_exists(self, path):
        return os.path.exists(os.path.join(self.repo, path))


# ---------------------------------------------------------------------------- scopes


def derive_scopes(git):
    """The scope list the tree implies. Deterministic order: production, tests, instruments."""
    prod, tests = [], []
    crates_dir = os.path.join(git.repo, "crates")
    crates = sorted(d for d in os.listdir(crates_dir)) if os.path.isdir(crates_dir) else []
    for crate in crates:
        base = "crates/%s" % crate
        if not git.path_exists("%s/Cargo.toml" % base):
            continue
        src = "%s/src" % base
        if git.dir_exists(src):
            if crate == SPLIT_CRATE:
                prod.append(scope("%s/root" % src, "production"))
                prod.append(scope("%s/main.rs" % src, "production"))
            else:
                prod.append(scope(src, "production", exclude=["%s/tests" % src]))
            if git.dir_exists("%s/tests" % src):
                tests.append(scope("%s/tests" % src, "test"))
        if git.path_exists("%s/build.rs" % base):
            prod.append(scope("%s/build.rs" % base, "production"))
        for sub in ("tests", "benches"):
            if git.dir_exists("%s/%s" % (base, sub)):
                tests.append(scope("%s/%s" % (base, sub), "test"))
    if git.dir_exists("xtask/src"):
        prod.append(scope("xtask/src", "production", exclude=["xtask/src/tests"]))
        if git.dir_exists("xtask/src/tests"):
            tests.append(scope("xtask/src/tests", "test"))
    inst = [scope(p, "instrument") for p in INSTRUMENT_PATHS if git.path_exists(p)]
    testing_dir = os.path.join(git.repo, "testing")
    if os.path.isdir(testing_dir):
        rigs = sorted(d for d in os.listdir(testing_dir) if os.path.isdir(os.path.join(testing_dir, d)))
        for rig in rigs:
            inst.append(scope("testing/%s" % rig, "instrument"))
        # The loose drivers that sit directly in testing/ are a scope too, or they would be the one
        # place a file could land uncovered forever.
        inst.append(scope("testing", "instrument", exclude=["testing/%s" % r for r in rigs]))
    return prod + tests + inst


def scope(path, kind, exclude=None):
    s = {
        "id": path,
        "kind": kind,
        "paths": [path],
        "tree_hash": None,
        "audited_at": None,
        "round": None,
        "result": "unaudited",
        "counts": {},
        "report": None,
        "auditor": None,
        "fixed_at": None,
    }
    if exclude:
        s["exclude"] = list(exclude)
    return s


def under(path, prefix):
    return path == prefix or path.startswith(prefix.rstrip("/") + "/")


def scope_files(sc, all_files):
    """The tracked files a scope owns at HEAD: everything under `paths`, minus `exclude`."""
    excl = sc.get("exclude", [])
    owned = {}
    for path, oid in all_files.items():
        if not any(under(path, p) for p in sc["paths"]):
            continue
        if any(under(path, e) for e in excl):
            continue
        owned[path] = oid
    return owned


def tree_hash(sc, all_files):
    owned = scope_files(sc, all_files)
    if not owned:
        return None
    h = hashlib.sha256()
    for path in sorted(owned):
        h.update(("%s\t%s\n" % (path, owned[path])).encode())
    return h.hexdigest()


def status_of(sc, current_hash):
    result = sc.get("result", "unaudited")
    if result == "unaudited" or sc.get("audited_at") is None:
        return "unaudited"
    if result == "in_progress":
        return "in_progress"
    if result == "findings" and not sc.get("fixed_at"):
        return "open"
    if sc.get("tree_hash") != current_hash:
        return "stale"
    if result == "findings":
        return "fixed"
    return "clean"


# The worklist order: what is most dangerous to leave unseen goes first. `in_progress` is omitted --
# an auditor is already on it and launching a second is duplicated work.
NEXT_ORDER = ("open", "unaudited", "stale", "fixed", "clean")
NEXT_WHY = {
    "open": "findings recorded, no fix stamped",
    "unaudited": "never audited",
    "stale": "code changed since the audit",
    "fixed": "findings fixed, owes a confirming round",
    "clean": "fresh-eyes confirmation",
}


# ---------------------------------------------------------------------------- ledger io


def load(path):
    with open(path, encoding="utf-8") as fh:
        return json.load(fh)


def save(path, doc):
    with open(path, "w", encoding="utf-8") as fh:
        json.dump(doc, fh, indent=1, ensure_ascii=False, sort_keys=False)
        fh.write("\n")


def new_doc(scopes):
    return {
        "_comment": [
            "GENERATED scope list -- `scripts/audit-ledger.py sync --write` derives it from the tree.",
            "Audit records (round/result/report/auditor/fixed_at/tree_hash) are hand-stamped by",
            "`record` and `fixed` and are preserved across sync.",
            "tree_hash = sha256 over the sorted `path<TAB>blob-oid` list of the scope's tracked files at",
            "the audited commit; when it stops matching the tree, the audit result has expired.",
            "status is DERIVED at report time, never stored. See docs/design/AUDIT-STATUS.md.",
        ],
        "uncovered_by_design": [{"glob": g, "reason": r} for g, r in UNCOVERED_BY_DESIGN],
        "scopes": scopes,
    }


def enrich(doc, git):
    """Attach the derived view (files, hash, loc, status, age) without mutating the register."""
    all_files = git.files_at_head()
    head = git.head()
    oids = set()
    owned = {}
    for sc in doc["scopes"]:
        owned[sc["id"]] = scope_files(sc, all_files)
        oids.update(owned[sc["id"]].values())
    counts = git.line_counts(oids)
    rows = []
    for sc in doc["scopes"]:
        files = owned[sc["id"]]
        cur = tree_hash(sc, all_files)
        st = status_of(sc, cur)
        age = git.commits_between(sc["audited_at"], head) if sc.get("audited_at") else None
        rows.append(
            {
                "scope": sc,
                "current_hash": cur,
                "status": st,
                "loc": sum(counts.get(o, 0) for o in files.values()),
                "files": len(files),
                "age": age,
            }
        )
    return rows, all_files, head


# ---------------------------------------------------------------------------- commands


def cmd_sync(args, git, ledger_path, write):
    derived = derive_scopes(git)
    existing = load(ledger_path)["scopes"] if os.path.exists(ledger_path) else []
    by_id = {s["id"]: s for s in existing}
    merged, added = [], []
    for d in derived:
        old = by_id.get(d["id"])
        if old is None:
            merged.append(d)
            added.append(d["id"])
        else:
            keep = dict(d)
            for key in ("tree_hash", "audited_at", "round", "result", "counts", "report", "auditor", "fixed_at"):
                if key in old:
                    keep[key] = old[key]
            merged.append(keep)
    removed = [s["id"] for s in existing if s["id"] not in {d["id"] for d in derived}]

    for sid in added:
        print("+ %s" % sid)
    for sid in removed:
        print("- %s  (path gone from the tree; its audit record goes with it)" % sid)
    if not added and not removed:
        print("sync: no change -- the scope list already matches the tree (%d scopes)" % len(derived))
    if write:
        doc = new_doc(merged)
        save(ledger_path, doc)
        print("sync: wrote %s (%d scopes)" % (os.path.relpath(ledger_path, git.repo), len(merged)))
    elif added or removed:
        print("sync: dry run -- pass --write to apply")
    return 0


def coverage_gaps(doc, git):
    """Every tracked file that belongs to no scope and is not excused by design."""
    import fnmatch

    all_files = git.files_at_head()
    owned = set()
    for sc in doc["scopes"]:
        owned.update(scope_files(sc, all_files))
    excused = [e["glob"] for e in doc.get("uncovered_by_design", [])]
    universe = ("crates/", "xtask/", "scripts/", "qa/", "testing/", ".github/workflows/")
    gaps = []
    for path in sorted(all_files):
        if not path.startswith(universe):
            continue
        if path in owned:
            continue
        if any(fnmatch.fnmatch(path, g) for g in excused):
            continue
        gaps.append(path)
    return gaps


def bar(rows, key):
    total = sum(r["loc"] for r in rows) or 1
    got = sum(r["loc"] for r in rows if r["status"] == key)
    return got, 100.0 * got / total


def cmd_status(args, git, ledger_path, report_path):
    doc = load(ledger_path)
    rows, _all_files, head = enrich(doc, git)
    rows.sort(key=lambda r: (r["scope"]["kind"], r["scope"]["id"]))

    lines = []
    lines.append("%-46s %-11s %-12s %5s %6s %7s" % ("SCOPE", "KIND", "STATUS", "ROUND", "AGE", "LOC"))
    lines.append("-" * 92)
    for r in rows:
        sc = r["scope"]
        lines.append(
            "%-46s %-11s %-12s %5s %6s %7d"
            % (
                sc["id"],
                sc["kind"],
                r["status"],
                sc["round"] if sc["round"] is not None else "-",
                r["age"] if r["age"] is not None else "-",
                r["loc"],
            )
        )
    prod = [r for r in rows if r["scope"]["kind"] == "production"]
    lines.append("")
    lines.append("PRODUCTION LOC BY STATUS (%d scopes, %d LOC)" % (len(prod), sum(r["loc"] for r in prod)))
    for key in ("clean", "fixed", "in_progress", "stale", "open", "unaudited"):
        got, pct = bar(prod, key)
        lines.append("  %-12s %7d LOC  %5.1f%%" % (key, got, pct))
    lines.append("")
    lines.append("HEAD %s" % head)
    text = "\n".join(lines)
    print(text)

    md = ["# busbar audit status", ""]
    md.append("GENERATED by `scripts/audit-ledger.py status` from `qa/audit-ledger.json`. Do not hand-edit.")
    md.append("")
    md.append("An audit result describes one tree. When a scope's tree hash moves, its result expires and")
    md.append("the scope reads `stale` -- the code must be looked at again. Nothing here is a wall clock;")
    md.append("`age` is commits between the audited commit and HEAD.")
    md.append("")
    md.append("HEAD at generation: `%s`" % head)
    md.append("")
    md.append("## Totals over production LOC")
    md.append("")
    md.append("| status | LOC | share |")
    md.append("| --- | ---: | ---: |")
    for key in ("clean", "fixed", "in_progress", "stale", "open", "unaudited"):
        got, pct = bar(prod, key)
        md.append("| %s | %d | %.1f%% |" % (key, got, pct))
    md.append("")
    for kind in ("production", "test", "instrument"):
        sel = [r for r in rows if r["scope"]["kind"] == kind]
        if not sel:
            continue
        md.append("## %s scopes (%d)" % (kind, len(sel)))
        md.append("")
        md.append("| scope | status | round | age (commits) | LOC | result | auditor | report |")
        md.append("| --- | --- | ---: | ---: | ---: | --- | --- | --- |")
        for r in sel:
            sc = r["scope"]
            counts = sc.get("counts") or {}
            res = sc.get("result") or "unaudited"
            if counts:
                res += " (" + ", ".join("%s=%s" % (k, counts[k]) for k in SEVERITIES if k in counts) + ")"
            elif res == "findings":
                res += " (severities unrecorded)"
            md.append(
                "| `%s` | %s | %s | %s | %d | %s | %s | %s |"
                % (
                    sc["id"],
                    r["status"],
                    sc["round"] if sc["round"] is not None else "-",
                    r["age"] if r["age"] is not None else "-",
                    r["loc"],
                    res,
                    sc.get("auditor") or "-",
                    ("`%s`" % sc["report"]) if sc.get("report") else "-",
                )
            )
        md.append("")
    md.append("## Statuses")
    md.append("")
    for key in NEXT_ORDER + ("in_progress",):
        md.append("- `%s` -- %s" % (key, NEXT_WHY.get(key, "a round is running against a recorded tree hash")))
    md.append("")
    os.makedirs(os.path.dirname(report_path), exist_ok=True)
    with open(report_path, "w", encoding="utf-8") as fh:
        fh.write("\n".join(md))
    print("wrote %s" % os.path.relpath(report_path, git.repo))
    return 0


def cmd_next(args, git, ledger_path):
    doc = load(ledger_path)
    rows, _all_files, _head = enrich(doc, git)
    ranked = []
    for r in rows:
        if r["status"] not in NEXT_ORDER:
            continue
        band = NEXT_ORDER.index(r["status"])
        if r["status"] == "clean":
            key = (band, -(r["age"] or 0), r["scope"]["id"])
        else:
            key = (band, -r["loc"], r["scope"]["id"])
        ranked.append((key, r))
    ranked.sort(key=lambda x: x[0])
    print("%-4s %-46s %-11s %-12s %7s  %s" % ("#", "SCOPE", "KIND", "STATUS", "LOC", "WHY"))
    for i, (_k, r) in enumerate(ranked, 1):
        print(
            "%-4d %-46s %-11s %-12s %7d  %s"
            % (i, r["scope"]["id"], r["scope"]["kind"], r["status"], r["loc"], NEXT_WHY[r["status"]])
        )
    return 0


def cmd_record(args, git, ledger_path):
    doc = load(ledger_path)
    sc = find(doc, args.scope)
    all_files = git.files_at_head()
    counts = {}
    if args.counts:
        for part in args.counts.split(","):
            if not part.strip():
                continue
            k, _, v = part.partition("=")
            k = k.strip().upper()
            if k not in SEVERITIES:
                die("unknown severity %r (want one of %s)" % (k, ", ".join(SEVERITIES)))
            counts[k] = int(v)
    at = git.run("rev-parse", args.at).strip() if args.at else git.head()
    sc["round"] = args.round
    sc["result"] = args.result
    sc["counts"] = counts
    sc["report"] = args.report
    sc["auditor"] = args.auditor
    sc["tree_hash"] = tree_hash(sc, all_files)
    sc["audited_at"] = at
    sc["fixed_at"] = None
    save(ledger_path, doc)
    print("recorded %s: round %s %s at %s (%s)" % (sc["id"], args.round, args.result, sc["audited_at"][:8], sc["tree_hash"][:12]))
    return 0


def cmd_fixed(args, git, ledger_path):
    doc = load(ledger_path)
    sc = find(doc, args.scope)
    if sc.get("result") != "findings":
        die("%s has result %r -- only a `findings` scope can be marked fixed" % (sc["id"], sc.get("result")))
    all_files = git.files_at_head()
    sc["fixed_at"] = git.run("rev-parse", args.commit).strip() if getattr(args, "commit", None) else git.head()
    sc["tree_hash"] = tree_hash(sc, all_files)
    save(ledger_path, doc)
    print("fixed %s at %s (re-hashed %s)" % (sc["id"], sc["fixed_at"][:8], sc["tree_hash"][:12]))
    return 0


def cmd_check(args, git, ledger_path):
    doc = load(ledger_path)
    rows, _all_files, _head = enrich(doc, git)
    red = 0

    gaps = coverage_gaps(doc, git)
    if gaps:
        red = 1
        print("audit ledger: %d tracked file(s) belong to NO scope -- coverage is incomplete:" % len(gaps))
        for path in gaps[:20]:
            print("  %s" % path)
        if len(gaps) > 20:
            print("  ... and %d more" % (len(gaps) - 20))
        print("  run: scripts/audit-ledger.py sync --write")

    drift = derive_scopes(git)
    have = {s["id"] for s in doc["scopes"]}
    missing = [d["id"] for d in drift if d["id"] not in have]
    if missing:
        red = 1
        print("audit ledger: %d scope(s) the tree implies are not in the register:" % len(missing))
        for sid in missing:
            print("  + %s" % sid)

    opens = []
    for r in rows:
        if r["status"] != "open":
            continue
        counts = r["scope"].get("counts") or {}
        # No counts on an OPEN scope is red too: an unrecorded severity is not evidence that the
        # findings are below HIGH/MEDIUM, and the safe reading of "we do not know" is "not yet".
        if not counts or counts.get("HIGH", 0) or counts.get("MEDIUM", 0):
            opens.append(r)
    if opens:
        red = 1
        print("audit ledger: %d scope(s) OPEN at HIGH/MEDIUM (findings recorded, no fix stamped):" % len(opens))
        for r in opens:
            counts = r["scope"].get("counts") or {}
            print(
                "  %s  round %s  %s"
                % (
                    r["scope"]["id"],
                    r["scope"]["round"],
                    ", ".join("%s=%s" % (k, counts[k]) for k in SEVERITIES if counts.get(k)) or "severities unrecorded",
                )
            )

    if red:
        print("audit ledger --check: RED")
        return 1
    prod = [r for r in rows if r["scope"]["kind"] == "production"]
    _clean, pct = bar(prod, "clean")
    print(
        "audit ledger --check: GREEN -- %d scopes, coverage complete, no scope open at HIGH/MEDIUM "
        "(%.1f%% of production LOC clean)" % (len(rows), pct)
    )
    return 0


def find(doc, sid):
    for sc in doc["scopes"]:
        if sc["id"] == sid:
            return sc
    die("no scope %r in the register (see `status` for the list)" % sid)


def die(msg):
    print("audit-ledger: %s" % msg, file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------- self-test


def selftest(work_dir):
    """A scratch repo with two scopes: record zero, touch a file, stale; fixed re-clears.

    The instrument is driven end to end against a repo it has never seen, so every branch that the
    real run depends on -- hashing, status derivation, --check's red conditions -- is exercised
    where the expected answer is known by construction.
    """
    import shutil

    print("== audit ledger SELF-TEST (the instrument proves itself before it judges the tree) ==")
    cases = [0, 0]

    def say(ok, what):
        cases[0] += 1
        if not ok:
            cases[1] += 1
        print("%s  %s" % ("PASS" if ok else "FAIL", what))

    root = os.path.join(work_dir, "selftest-repo")
    shutil.rmtree(root, ignore_errors=True)
    os.makedirs(os.path.join(root, "crates/alpha/src"))
    os.makedirs(os.path.join(root, "crates/beta/src"))
    for crate in ("alpha", "beta"):
        with open(os.path.join(root, "crates/%s/Cargo.toml" % crate), "w") as fh:
            fh.write("[package]\nname = \"%s\"\n" % crate)
        with open(os.path.join(root, "crates/%s/src/lib.rs" % crate), "w") as fh:
            fh.write("pub fn one() -> u8 { 1 }\n")

    # The scratch repo is HERMETIC: no global/system config, no hooks path. Otherwise whatever
    # identity policy or commit hook the developer's machine carries decides whether this
    # instrument's self-test can run at all, and a self-test that a laptop setting can veto is not
    # a self-test.
    hooks = os.path.join(work_dir, "no-hooks")
    os.makedirs(hooks, exist_ok=True)
    env = dict(os.environ)
    env.update(
        {
            "GIT_CONFIG_GLOBAL": os.devnull,
            "GIT_CONFIG_SYSTEM": os.devnull,
            "GIT_AUTHOR_NAME": "audit ledger selftest",
            "GIT_AUTHOR_EMAIL": "selftest@example.invalid",
            "GIT_COMMITTER_NAME": "audit ledger selftest",
            "GIT_COMMITTER_EMAIL": "selftest@example.invalid",
            "GIT_AUTHOR_DATE": "2026-01-01T00:00:00+00:00",
            "GIT_COMMITTER_DATE": "2026-01-01T00:00:00+00:00",
        }
    )

    def git_(*args):
        subprocess.run(
            ["git", "-C", root, "-c", "core.hooksPath=%s" % hooks, "-c", "commit.gpgsign=false", *args],
            check=True,
            env=env,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

    git_("init", "-q", "-b", "main")
    git_("add", "-A")
    git_("commit", "-q", "-m", "seed")

    git = Git(root)
    ledger = os.path.join(root, "ledger.json")
    report = os.path.join(root, "docs/AUDIT-STATUS.md")

    # (a) sync derives exactly the two production scopes the tree implies
    cmd_sync(None, git, ledger, write=True)
    doc = load(ledger)
    ids = sorted(s["id"] for s in doc["scopes"] if s["kind"] == "production")
    say(ids == ["crates/alpha/src", "crates/beta/src"], "sync derives one production scope per crate: %s" % ids)

    # (b) everything starts unaudited
    rows, _f, _h = enrich(load(ledger), git)
    say(all(r["status"] == "unaudited" for r in rows), "a fresh register reads unaudited everywhere")

    # (c) a `zero` result on an unchanged tree reads clean
    class A:
        pass

    a = A()
    a.scope, a.round, a.result, a.report, a.auditor, a.counts = "crates/alpha/src", 1, "zero", "docs/r1.md", "opus", None
    a.at = a.commit = None
    cmd_record(a, git, ledger)
    rows, _f, _h = enrich(load(ledger), git)
    st = {r["scope"]["id"]: r["status"] for r in rows}
    say(st["crates/alpha/src"] == "clean", "record zero -> clean")
    say(st["crates/beta/src"] == "unaudited", "the other scope is untouched by that record")

    # (d) touching a file in the audited scope expires the result
    with open(os.path.join(root, "crates/alpha/src/lib.rs"), "a") as fh:
        fh.write("pub fn two() -> u8 { 2 }\n")
    git_("add", "-A")
    git_("commit", "-q", "-m", "touch alpha")
    rows, _f, _h = enrich(load(ledger), git)
    st = {r["scope"]["id"]: r["status"] for r in rows}
    say(st["crates/alpha/src"] == "stale", "the code changed under a clean audit -> stale")

    # (e) ... and touching the OTHER crate does not move it back or disturb it
    a.scope = "crates/alpha/src"
    cmd_record(a, git, ledger)
    with open(os.path.join(root, "crates/beta/src/lib.rs"), "a") as fh:
        fh.write("pub fn three() -> u8 { 3 }\n")
    git_("add", "-A")
    git_("commit", "-q", "-m", "touch beta")
    rows, _f, _h = enrich(load(ledger), git)
    st = {r["scope"]["id"]: r["status"] for r in rows}
    say(st["crates/alpha/src"] == "clean", "a change in another scope does not expire this one")

    # (f) findings with no fix -> open, and --check is red on HIGH
    a.scope, a.round, a.result, a.counts = "crates/beta/src", 2, "findings", "HIGH=1,LOW=2"
    cmd_record(a, git, ledger)
    rows, _f, _h = enrich(load(ledger), git)
    st = {r["scope"]["id"]: r["status"] for r in rows}
    say(st["crates/beta/src"] == "open", "findings with no fix stamped -> open")
    rc = cmd_check(None, git, ledger)
    say(rc != 0, "--check is RED while a scope is open at HIGH/MEDIUM (rc=%s)" % rc)

    # (f2) findings whose severities were never recorded is red too -- "we do not know" is not a pass
    a.counts = None
    cmd_record(a, git, ledger)
    rc = cmd_check(None, git, ledger)
    say(rc != 0, "--check is RED on an open scope whose severities are unrecorded (rc=%s)" % rc)
    a.counts = "HIGH=1,LOW=2"
    cmd_record(a, git, ledger)

    # (g) fixed re-clears the open and re-hashes
    before = find(load(ledger), "crates/beta/src")["tree_hash"]
    with open(os.path.join(root, "crates/beta/src/lib.rs"), "a") as fh:
        fh.write("pub fn four() -> u8 { 4 }\n")
    git_("add", "-A")
    git_("commit", "-q", "-m", "fix beta")
    cmd_fixed(a, git, ledger)
    beta = find(load(ledger), "crates/beta/src")
    rows, _f, _h = enrich(load(ledger), git)
    st = {r["scope"]["id"]: r["status"] for r in rows}
    say(beta["tree_hash"] != before, "fixed re-hashes the scope at the fix commit")
    say(st["crates/beta/src"] == "fixed", "a fixed findings scope reads `fixed` (due a confirming round), not open")
    rc = cmd_check(None, git, ledger)
    say(rc == 0, "--check is GREEN once the open finding is fixed (rc=%s)" % rc)

    # (g2) a record and a fix can be stamped at a NAMED commit, not only HEAD -- which is how a
    #      ledger is seeded honestly from history instead of back-dated to whenever it was built.
    older = git.run("rev-parse", "HEAD~2").strip()
    a.scope, a.result, a.counts, a.at = "crates/alpha/src", "zero", None, older
    cmd_record(a, git, ledger)
    say(find(load(ledger), "crates/alpha/src")["audited_at"] == older, "record --at stamps the named commit, not HEAD")
    a.at = None
    a.scope, a.result, a.counts = "crates/alpha/src", "findings", "LOW=1"
    cmd_record(a, git, ledger)
    a.commit = older
    cmd_fixed(a, git, ledger)
    say(find(load(ledger), "crates/alpha/src")["fixed_at"] == older, "fixed --commit stamps the named commit, not HEAD")
    a.commit = None
    a.scope, a.result, a.counts = "crates/alpha/src", "zero", None
    cmd_record(a, git, ledger)

    # (h) a new crate nobody synced is a coverage hole, and --check says so
    os.makedirs(os.path.join(root, "crates/gamma/src"))
    with open(os.path.join(root, "crates/gamma/Cargo.toml"), "w") as fh:
        fh.write("[package]\nname = \"gamma\"\n")
    with open(os.path.join(root, "crates/gamma/src/lib.rs"), "w") as fh:
        fh.write("pub fn five() -> u8 { 5 }\n")
    git_("add", "-A")
    git_("commit", "-q", "-m", "new crate")
    rc = cmd_check(None, git, ledger)
    say(rc != 0, "a new crate no scope covers makes --check RED (rc=%s)" % rc)
    cmd_sync(None, git, ledger, write=True)
    say(cmd_check(None, git, ledger) == 0, "sync --write adds it and --check goes GREEN")
    say(
        find(load(ledger), "crates/alpha/src")["audited_at"] is not None,
        "sync preserved the audit record on the surviving scopes",
    )

    # (i) status writes the markdown report and the worklist orders unaudited before clean
    cmd_status(None, git, ledger, report)
    say(os.path.exists(report), "status writes the markdown report")
    rows, _f, _h = enrich(load(ledger), git)
    order = [r["status"] for r in sorted(rows, key=lambda r: NEXT_ORDER.index(r["status"]) if r["status"] in NEXT_ORDER else 99)]
    say(order.index("unaudited") < order.index("clean"), "next puts unaudited ahead of clean")

    print("")
    if cases[1] == 0:
        print("audit ledger selftest: GREEN (%d cases)" % cases[0])
        return 0
    print("audit ledger selftest: RED (%d/%d cases failed)" % (cases[1], cases[0]))
    return 1


# ---------------------------------------------------------------------------- main


def main(argv):
    here = os.path.dirname(os.path.abspath(__file__))
    default_repo = os.path.dirname(here)

    ap = argparse.ArgumentParser(prog="audit-ledger.py", description="the workspace audit ledger")
    ap.add_argument("--repo", default=default_repo)
    ap.add_argument("--ledger", default=None)
    ap.add_argument("--report", dest="report_md", default=None)
    ap.add_argument("--check", action="store_true", help="red on an open HIGH/MEDIUM scope or incomplete coverage")
    ap.add_argument("--selftest", action="store_true")
    sub = ap.add_subparsers(dest="cmd")

    p = sub.add_parser("sync")
    p.add_argument("--write", action="store_true")
    sub.add_parser("status")
    sub.add_parser("next")

    p = sub.add_parser("record")
    p.add_argument("--scope", required=True)
    p.add_argument("--round", required=True, type=int)
    p.add_argument("--result", required=True, choices=RESULTS)
    p.add_argument("--report", required=True)
    p.add_argument("--auditor", required=True)
    p.add_argument("--counts", default=None, help="HIGH=..,MEDIUM=..,LOW=..,NIT=..")
    p.add_argument("--at", default=None, help="the commit the round was run against (default HEAD)")

    p = sub.add_parser("fixed")
    p.add_argument("--scope", required=True)
    p.add_argument("--commit", default=None, help="the fix commit to stamp (default HEAD)")

    args = ap.parse_args(argv)
    repo = os.path.abspath(args.repo)
    ledger_path = os.path.abspath(args.ledger) if args.ledger else os.path.join(repo, LEDGER_REL)
    report_path = os.path.abspath(args.report_md) if args.report_md else os.path.join(repo, REPORT_REL)

    if args.selftest:
        work = os.path.join(repo, ".ledger-work")
        os.makedirs(work, exist_ok=True)
        return selftest(work)

    git = Git(repo)
    if args.check:
        return cmd_check(args, git, ledger_path)
    if args.cmd == "sync":
        return cmd_sync(args, git, ledger_path, args.write)
    if args.cmd == "status":
        return cmd_status(args, git, ledger_path, report_path)
    if args.cmd == "next":
        return cmd_next(args, git, ledger_path)
    if args.cmd == "record":
        return cmd_record(args, git, ledger_path)
    if args.cmd == "fixed":
        return cmd_fixed(args, git, ledger_path)
    ap.print_help()
    return 2


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
