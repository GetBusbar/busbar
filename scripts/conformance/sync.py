#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""Render conformance/manifest.json from conformance/registry.toml and conformance/verdicts/*.json.

    python3 scripts/conformance/sync.py            # print the manifest
    python3 scripts/conformance/sync.py --write    # write conformance/manifest.json

    # A RELEASE (docs/design/conformance-release.md): only ModernCI's outputs count.
    python3 scripts/conformance/sync.py --release <V> --commit <T> --from-modernci <DIR> [--write | --out FILE]

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

A RELEASE render (`--release`) reads no file of conformance/verdicts/. It reads DIR, which
scripts/release/conformance_gate.py fetched from ModernCI: one `<owner>/<name>/receipt.json` per repo
(what ModernCI's `artifact` answered) with that check's `verdicts/<id>.json` beside it. Every
registered suite is rendered; a suite's verdict counts only when its stamp names the suite's registry
`repo`, the commit it ships at (T for busbar, the plugin's shipped pin P), core pin T, the run id and
the ModernCI move of that commit. Anything else is `not-run`, with the reason. The manifest-level
`commit` is T. The bytes are canonical: sorted keys, LF.
"""
import json
import re
import subprocess
import sys
import tomllib
from pathlib import Path
from urllib.parse import parse_qs, urlsplit

SCHEMA = "busbar.conformance.manifest/1"
VERDICT_SCHEMA = "busbar.conformance.verdict/1"
RELEASE = "1.6.0"
BANNER = "by `python3 scripts/conformance/sync.py --write`; DO NOT EDIT"
VERDICT_KEYS = {"schema", "suite", "standard", "plan", "spec_version", "status", "armed", "commit",
                "run_id", "evidence", "generated_at", "reason", "cert_id", "issuer", "expires",
                "repo", "core_pin"}
TIERS = {"certified", "conformant", "spec-conformant", "capable", "evidence-only"}
CORE_REPO = "GetBusbar/busbar"
REPO_RE = re.compile(r"GetBusbar/[A-Za-z0-9._-]+")
SHA_RE = re.compile(r"[0-9a-f]{40}")
EXCEPTIONS_SCHEMA = "busbar.conformance.exceptions/1"


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
        for k in ("id", "repo", "standard", "plan", "tier", "label", "verdict", "public"):
            if k not in s:
                raise Refused(f"registry: suite {s.get('id')!r} has no `{k}`")
        if not REPO_RE.fullmatch(s["repo"]):
            raise Refused(f"registry: suite {s['id']} repo {s['repo']!r} is not GetBusbar/<name>")
        if s["tier"] not in TIERS:
            raise Refused(f"registry: suite {s['id']} tier {s['tier']!r} is not one of {sorted(TIERS)}")
        if s["id"] in seen:
            raise Refused(f"registry: suite {s['id']} is registered twice")
        seen.add(s["id"])
    return suites


def verdict_problem(v, sid):
    """Why `v`, filed under `sid`, breaks verdict.schema.json's rules; None when it keeps them."""
    if not isinstance(v, dict):
        return "the verdict is not a JSON object"
    if v.get("schema") != VERDICT_SCHEMA:
        return f"schema is {v.get('schema')!r}, not {VERDICT_SCHEMA}"
    if v.get("suite") != sid:
        return f"names suite {v.get('suite')!r}, filed under {sid!r}"
    extra = set(v) - VERDICT_KEYS
    if extra:
        return f"unknown fields {sorted(extra)}"
    for k in ("status", "armed", "commit"):
        if k not in v:
            return f"no `{k}`"
    if v["status"] not in ("pass", "fail", "not-run"):
        return f"status {v['status']!r}"
    if v["armed"] is not True and v["status"] != "not-run":
        return f"an unarmed verdict says {v['status']}"
    return None


def read_verdicts(directory, registered):
    out = {}
    for f in sorted(Path(directory).glob("*.json")):
        if f.name == "verdict.schema.json":
            continue
        v = json.loads(f.read_text())
        sid = f.stem
        if sid not in registered and isinstance(v, dict) and v.get("suite") == sid:
            raise Refused(f"{f.name}: suite {sid} is not in the registry")
        why = verdict_problem(v, sid)
        if why:
            raise Refused(f"{f.name}: {why}")
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


# ── the release render ───────────────────────────────────────────────────────────────────────────


def shipped_pins(root):
    """{"GetBusbar/<name>": sha}: each plugin's shipped commit at this tree. dist/default/Cargo.lock
    names what is compiled in; release/plugin-pins.tsv (when present) names the tarball plugins. A
    repo pinned at two commits is refused: what ships must be one commit."""
    root = Path(root)
    pins = {}

    def put(repo, sha, where):
        full = f"GetBusbar/{repo}"
        if pins.setdefault(full, sha) != sha:
            raise Refused(f"{full} ships at two commits: {pins[full]} and {sha} ({where})")

    lock = root / "dist" / "default" / "Cargo.lock"
    if lock.is_file():
        for repo, sha in sorted(set(re.findall(
                r'source = "git\+https://(?:github\.com|git\.getbusbar\.dev)/GetBusbar/([A-Za-z0-9._-]+?)(?:\.git)?'
                r'(?:\?[^#"]*)?#([0-9a-f]{40})"', lock.read_text()))):
            if repo != "busbar":
                put(repo, sha, "dist/default/Cargo.lock")
    tsv = root / "release" / "plugin-pins.tsv"
    if tsv.is_file():
        for i, line in enumerate(tsv.read_text().splitlines(), 1):
            if not line.strip() or line.startswith("#"):
                continue
            parts = line.split("\t")
            if len(parts) != 3 or not SHA_RE.fullmatch(parts[2]):
                raise Refused(f"release/plugin-pins.tsv:{i} is not <repo>\\t<tag>\\t<40-hex commit>")
            put(parts[0], parts[2], "release/plugin-pins.tsv")
    return pins


def read_exceptions(root, release):
    """release/conformance-exceptions.json's suite exceptions for `release`, as {suite: {status,
    reason}}. UNVERIFIED: the render only records them; G-C (scripts/release/conformance_gate.py)
    checks the K2 signature and refuses the tag on a bad one."""
    f = Path(root) / "release" / "conformance-exceptions.json"
    if not f.is_file():
        return {}
    doc = json.loads(f.read_text())
    if doc.get("schema") != EXCEPTIONS_SCHEMA or doc.get("release") != release:
        return {}
    return {e["suite"]: {"status": e.get("status"), "reason": e.get("reason", "")}
            for e in doc.get("suites", []) if isinstance(e, dict) and "suite" in e}


def load_fetched(directory):
    """{repo: {"receipt": {...}, "verdicts": {sid: raw}}} from what conformance_gate.py fetched. Only
    a file beside a receipt that names its own directory's repo, with no `missing`, is read."""
    out = {}
    for rec_file in sorted(Path(directory).glob("*/*/receipt.json")):
        try:
            rec = json.loads(rec_file.read_text())
        except ValueError:
            continue
        repo = f"{rec_file.parent.parent.name}/{rec_file.parent.name}"
        if not isinstance(rec, dict) or rec.get("repo") != repo:
            continue
        verdicts = {}
        if not rec.get("missing"):
            for f in sorted((rec_file.parent / "verdicts").glob("*.json")):
                try:
                    verdicts[f.stem] = json.loads(f.read_text())
                except ValueError as e:
                    verdicts[f.stem] = f"not JSON: {e}"
        out[repo] = {"receipt": rec, "verdicts": verdicts}
    return out


def stamp_problem(v, repo, head, core):
    """Why a schema-valid verdict is not the run.sh judge's stamp for `repo` at `head` on core `core`."""
    if v.get("repo") != repo:
        return f"stamped for repo {v.get('repo')!r}, not {repo}"
    if v.get("commit") != head:
        return f"stamped for commit {str(v.get('commit'))[:12]}, not the shipped {head[:12]}"
    if v.get("core_pin") != core:
        return f"judged against core {str(v.get('core_pin'))[:12]}, not the release commit {core[:12]}"
    if v.get("run_id") != f"modernci:{repo}@{head}:conformance":
        return f"run_id {v.get('run_id')!r} is not ModernCI's conformance run of {repo}@{head[:12]}"
    ev = urlsplit(str(v.get("evidence", "")))
    q = parse_qs(ev.query)
    if ev.scheme != "https" or ev.path != "/move" or q.get("repo") != [repo] or q.get("head") != [head]:
        return f"evidence {v.get('evidence')!r} is not the ModernCI move of {repo}@{head[:12]}"
    return None


def render_release(registry_path, fetched_dir, *, release, commit, pins, exceptions):
    suites = read_registry(registry_path)
    fetched = load_fetched(fetched_dir)
    entries, stamps = [], []
    for s in sorted(suites, key=lambda s: s["id"]):
        sid, repo = s["id"], s["repo"]
        head = commit if repo == CORE_REPO else pins.get(repo)
        e = {"suite": sid, "standard": s["standard"], "plan": s["plan"], "tier": s["tier"],
             "public": str(s["public"]).lower() == "true", "repo": repo, "status": "not-run", "claim": None}
        rec = fetched.get(repo)
        v = None
        if head is None:
            e["reason"] = f"{repo} ships no pin at this release: the suite judges nothing that ships"
        else:
            e["commit"] = head
            if rec is None:
                e["reason"] = f"no ModernCI conformance output was fetched for {repo}@{head[:12]}"
            elif rec["receipt"].get("missing"):
                e["reason"] = f"ModernCI has no conformance output for {repo}@{head[:12]}: {rec['receipt']['missing']}"
            elif rec["receipt"].get("head") != head:
                e["reason"] = f"ModernCI answered {repo}@{str(rec['receipt'].get('head'))[:12]}, not the shipped {head[:12]}"
            elif sid not in rec["verdicts"]:
                e["reason"] = f"{repo}@{head[:12]}'s conformance check wrote no verdict for {sid}"
            else:
                raw = rec["verdicts"][sid]
                why = verdict_problem(raw, sid) or stamp_problem(raw, repo, head, commit)
                rerun = rec["receipt"].get("rerun") or {}
                if why and rerun.get("refused"):
                    why += f"; no re-run against {commit[:12]} was possible: {rerun['refused']}"
                if why:
                    e["reason"] = f"the verdict is not used: {why}"
                else:
                    v = raw
        if v is not None:
            e["status"] = v["status"]
            e["claim"] = claim_for(s, v["status"], v.get("issuer"))
            for src, dst in (("spec_version", "spec_version"), ("evidence", "evidence"), ("core_pin", "core_pin"),
                             ("generated_at", "verified_at"), ("expires", "expires")):
                if v.get(src):
                    e[dst] = v[src]
            if v["status"] != "pass":
                e["reason"] = v.get("reason") or f"the suite's verdict is {v['status']}"
            if v.get("generated_at"):
                stamps.append(v["generated_at"])
        x = exceptions.get(sid)
        if x and e["status"] != "pass" and x.get("status") == e["status"]:
            e["reason"] = f"owner exception (signed): {x.get('reason', '')}; {e.get('reason', '')}"
        entries.append(e)
    doc = {
        "_generated": BANNER.replace("--write", f"--release {release} --commit {commit} --from-modernci"),
        "commit": commit,
        "generated_at": max(stamps) if stamps else "",
        "release": release,
        "schema": SCHEMA,
        "suites": entries,
    }
    return json.dumps(doc, indent=2, sort_keys=True, ensure_ascii=False) + "\n"


def release_main(argv, opts):
    root = Path(__file__).resolve().parents[2]
    rel, commit, src = opts.get("release"), opts.get("commit"), opts.get("from-modernci")
    if not (rel and commit and src) or not SHA_RE.fullmatch(commit) or not Path(src).is_dir():
        print("usage: sync.py --release <V> --commit <40-hex T> --from-modernci <DIR> [--write | --out FILE]",
              file=sys.stderr)
        return 2
    head = subprocess.run(["git", "-C", str(root), "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    if head != commit:
        print(f"conformance sync: REFUSED: this tree is at {head or 'no commit'}, not the release commit {commit}; "
              "the registry and the shipped pins are read from the tree", file=sys.stderr)
        return 1
    try:
        text = render_release(root / "conformance" / "registry.toml", src, release=rel, commit=commit,
                              pins=shipped_pins(root), exceptions=read_exceptions(root, rel))
    except (Refused, ValueError, KeyError) as e:
        print(f"conformance sync: REFUSED: {e}", file=sys.stderr)
        return 1
    if "--write" in argv:
        (root / "conformance" / "manifest.json").write_text(text)
    if opts.get("out"):
        Path(opts["out"]).write_text(text)
    if "--write" not in argv and not opts.get("out"):
        sys.stdout.write(text)
    return 0


def main(argv):
    opts, it = {}, iter(argv)
    for a in it:
        if a in ("--release", "--commit", "--from-modernci", "--out"):
            opts[a[2:]] = next(it, None)
    if opts:
        return release_main(argv, opts)
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
