#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""conformance-gate: the release's conformance manifest, from ModernCI's verdicts only, and G-C.

Design: docs/design/conformance-release.md.

  conformance_gate.py manifest --release V --commit T --out DIR
      inside `candidate`. Fetches the `conformance` check outputs from ModernCI:
        - for a core suite, busbar at T;
        - for a plugin suite, the plugin at its shipped pin P (dist/default/Cargo.lock,
          release/plugin-pins.tsv).
      A plugin verdict judged against another core is re-run against T where ModernCI can; where it
      cannot, it stays unused. Writes:
        - DIR/conformance/<owner>/<name>/{receipt.json, verdicts/*.json};
        - DIR/conformance-manifest.json (scripts/conformance/sync.py's release render).
  conformance_gate.py gate --candidate DIR --release V --commit T --allowed-signers FILE
      G-C on its own: the same rule publish_gate.py runs in `verify`.

G-C refuses the tag, one `REFUSED G-C ...` line each, when:
  - the manifest is not the render of the fetched outputs;
  - a `public = "true"` suite is not `pass` for T/P on core T, and no signed owner exception records
    its real status (`fail` or `not-run`, never `pass`);
  - a shipped plugin pin is not the commit whose verdict was used;
  - a suite-owning plugin's pin is not its repo's dev head (pin freshness), unless a signed exception
    names that repo and commit.

The exceptions are release/conformance-exceptions.json, committed at T, with its K2 signature
(`ssh-keygen -Y sign -n busbar-release`) in release/conformance-exceptions.json.sig.

Exit: 0 admitted, 1 refused, 2 usage, 3 a rule could not run (never a pass).
"""

from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import shutil
import subprocess
import sys
import tarfile
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parent / "conformance"))
import sync  # noqa: E402

CHECK = "conformance"
K2_NAMESPACE = "busbar-release"
K2_IDENTITY = "busbar-release"
EXIT_OK, EXIT_REFUSED, EXIT_USAGE, EXIT_CANNOT_RUN = 0, 1, 2, 3


class NoOutput(Exception):
    """ModernCI kept no `conformance` output for that repo at that head."""


class CannotRerun(Exception):
    """ModernCI cannot re-run a plugin's check against another core."""


class CannotRun(Exception):
    """A lookup could not run: exit 3, never a pass."""


# ── ModernCI, injectable for tests ───────────────────────────────────────────────────────────────


class ModernCI:
    """Read-only ModernCI access through the `modernci` client (`modernci call artifact`)."""

    def __init__(self, mci: str | None = None, tenant: str = "busbar"):
        self.mci = mci or shutil.which("modernci") or str(Path.home() / ".local/bin/modernci")
        self.tenant = tenant

    def _artifact_from(self, repo: str, frm: str, head: str) -> tuple:
        buf, offset, meta = b"", 0, None
        while True:
            req = {"repo": repo, "from": frm, "check": CHECK, "head": head, "offset": offset}
            p = subprocess.run([self.mci, "call", "--tenant", self.tenant, "artifact", json.dumps(req)],
                               capture_output=True, text=True)
            if p.returncode != 0:
                err = (p.stderr or p.stdout).strip()
                if "404" in err:
                    raise NoOutput(err.splitlines()[0] if err else "404")
                raise CannotRun(f"modernci artifact {repo}@{head}: {err}")
            d = json.loads(p.stdout)
            buf += base64.b64decode(d["data"])
            meta = meta or {k: d.get(k) for k in ("repo", "from", "head", "state", "sha")}
            if not d.get("next"):
                break
            offset = d["next"]
        if meta["head"] != head:
            raise NoOutput(f"ModernCI answered head {meta['head']}, not {head}")
        if meta.get("sha") and hashlib.sha256(buf).hexdigest() != meta["sha"]:
            raise CannotRun(f"modernci artifact {repo}@{head}: the bytes do not hash to the sha ModernCI named")
        return meta, buf

    def artifact(self, repo: str, head: str) -> tuple:
        """(meta, tar.gz bytes) of the `conformance` check's outputs at `head`. The branch the move
        came from is not known here, so each plausible one is asked; the head must match exactly."""
        whys = []
        for frm in (("qa", "dev", "main") if repo == sync.CORE_REPO else ("dev",)):
            try:
                return self._artifact_from(repo, frm, head)
            except NoOutput as e:
                whys.append(f"from {frm}: {e}")
        raise NoOutput("; ".join(whys))

    def rerun(self, repo: str, head: str, core: str) -> tuple:
        raise CannotRerun("ModernCI `measure` takes repo, from, check, again and change only; it has no "
                          "core-pin override to re-run a plugin's conformance against the release commit")

    def dev_head(self, repo: str) -> str:
        p = subprocess.run(["git", "ls-remote", f"https://git.getbusbar.dev/{repo}.git", "refs/heads/dev"],
                           capture_output=True, text=True)
        m = re.match(r"([0-9a-f]{40})\s", p.stdout)
        if p.returncode != 0 or not m:
            raise CannotRun(f"git ls-remote {repo} dev: {p.stderr.strip() or 'no dev branch'}")
        return m.group(1)


# ── fetch and render (inside `candidate`) ────────────────────────────────────────────────────────


def verdicts_in(data: bytes) -> dict:
    """{suite id: raw verdict} from a check's output archive: its `.../verdicts/<id>.json` members."""
    out = {}
    with tarfile.open(fileobj=io.BytesIO(data), mode="r:*") as t:
        for m in t.getmembers():
            parts = m.name.split("/")
            if m.isfile() and len(parts) >= 2 and parts[-2] == "verdicts" and m.name.endswith(".json"):
                raw = t.extractfile(m).read()
                try:
                    out[parts[-1][:-5]] = json.loads(raw)
                except ValueError as e:
                    out[parts[-1][:-5]] = f"not JSON: {e}"
    return out


def fetch(client: ModernCI, root: Path, commit: str, out: Path) -> None:
    """Writes out/conformance/<owner>/<name>/ for every repo that owns a registered suite."""
    suites = sync.read_registry(root / "conformance" / "registry.toml")
    pins = sync.shipped_pins(root)
    base = out / "conformance"
    for repo in sorted({s["repo"] for s in suites}):
        head = commit if repo == sync.CORE_REPO else pins.get(repo)
        if head is None:
            continue  # ships nothing: the render says so
        d = base / repo
        d.mkdir(parents=True, exist_ok=True)
        rec = {"repo": repo, "check": CHECK, "head": head}
        try:
            meta, data = client.artifact(repo, head)
        except NoOutput as e:
            rec["missing"] = str(e)
            (d / "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")
            continue
        rec.update({"from": meta.get("from"), "head": meta.get("head"), "state": meta.get("state"),
                    "sha": hashlib.sha256(data).hexdigest()})
        verdicts = verdicts_in(data)
        stale = [sid for sid, v in verdicts.items() if isinstance(v, dict) and v.get("core_pin") != commit]
        if repo != sync.CORE_REPO and stale:
            try:
                meta2, data2 = client.rerun(repo, head, commit)
                verdicts = verdicts_in(data2)
                rec["rerun"] = {"core": commit, "head": meta2.get("head"), "sha": hashlib.sha256(data2).hexdigest()}
            except CannotRerun as e:
                rec["rerun"] = {"core": commit, "refused": str(e)}
        (d / "verdicts").mkdir(exist_ok=True)
        for sid, v in sorted(verdicts.items()):
            body = v if isinstance(v, dict) else {"unreadable": v}
            (d / "verdicts" / f"{sid}.json").write_text(json.dumps(body, indent=2, sort_keys=True) + "\n")
        (d / "receipt.json").write_text(json.dumps(rec, indent=2, sort_keys=True) + "\n")


def render(root: Path, cand: Path, commit: str, release: str) -> str:
    return sync.render_release(root / "conformance" / "registry.toml", cand / "conformance", release=release,
                               commit=commit, pins=sync.shipped_pins(root),
                               exceptions=sync.read_exceptions(root, release))


def build_manifest(client: ModernCI, root: Path, *, commit: str, release: str, out: Path) -> str:
    out.mkdir(parents=True, exist_ok=True)
    fetch(client, root, commit, out)
    text = render(root, out, commit, release)
    (out / "conformance-manifest.json").write_text(text)
    return text


# ── G-C ──────────────────────────────────────────────────────────────────────────────────────────


def verify_exceptions(root: Path, release: str, allowed_signers: list, refuse) -> tuple:
    """({suite: exc}, {(repo, commit): exc}) from a K2-signed release/conformance-exceptions.json; no
    file means none. A bad file refuses the tag; it is never silently ignored."""
    f = root / "release" / "conformance-exceptions.json"
    if not f.is_file():
        return {}, {}
    sig = Path(str(f) + ".sig")
    name = "release/conformance-exceptions.json"
    if not sig.is_file():
        refuse(name, "a K2 signature beside it (.sig)", "none", "Sign it: ssh-keygen -Y sign -n busbar-release.")
        return {}, {}
    keygen = shutil.which("ssh-keygen")
    if not keygen:
        raise CannotRun("`ssh-keygen` is not on PATH; the owner exceptions cannot be verified")
    with tempfile.NamedTemporaryFile("w", suffix=".signers", delete=False) as s:
        s.write("\n".join(allowed_signers) + "\n")
    try:
        p = subprocess.run([keygen, "-Y", "verify", "-f", s.name, "-I", K2_IDENTITY, "-n", K2_NAMESPACE, "-s", str(sig)],
                           input=f.read_bytes(), capture_output=True)
    finally:
        Path(s.name).unlink()
    if p.returncode != 0:
        refuse(name, "a K2 signature verifying against your allowed_signers", "none that verifies",
               "An unsigned or altered exception is never honoured; sign the file you mean.")
        return {}, {}
    try:
        doc = json.loads(f.read_text())
    except ValueError as e:
        refuse(name, "JSON", str(e), "Fix and re-sign it.")
        return {}, {}
    if doc.get("schema") != sync.EXCEPTIONS_SCHEMA:
        refuse(name, f"schema {sync.EXCEPTIONS_SCHEMA}", repr(doc.get("schema")), "Fix and re-sign it.")
        return {}, {}
    if doc.get("release") != release:
        return {}, {}  # another release's exceptions cover nothing here
    suites, pins = {}, {}
    for e in doc.get("suites", []):
        if not isinstance(e, dict) or e.get("status") not in ("fail", "not-run") or not e.get("suite"):
            refuse(name, "suite exceptions that record fail or not-run", json.dumps(e),
                   "An exception records the real status and is never a pass.")
            continue
        suites[e["suite"]] = e
    for e in doc.get("pins", []):
        repo = str(e.get("repo", "")) if isinstance(e, dict) else ""
        repo = repo if repo.startswith("GetBusbar/") else f"GetBusbar/{repo}"
        if not isinstance(e, dict) or not sync.SHA_RE.fullmatch(str(e.get("commit", ""))) or not e.get("reason"):
            refuse(name, "pin exceptions naming repo, a 40-hex commit and a reason", json.dumps(e), "Fix and re-sign it.")
            continue
        pins[(repo, e["commit"])] = e
    return suites, pins


def gate_c(root: Path, cand: Path, *, commit: str, release: str, allowed_signers: list, client: ModernCI) -> list:
    refusals: list = []

    def refuse(subject, expected, found, todo):
        line = f"REFUSED G-C {subject}: expected {expected}; found {found}. {todo}"
        refusals.append(line)
        print(line)

    suite_exc, pin_exc = verify_exceptions(root, release, allowed_signers, refuse)
    try:
        suites = sync.read_registry(root / "conformance" / "registry.toml")
        pins = sync.shipped_pins(root)
        mine = render(root, cand, commit, release)
    except (sync.Refused, ValueError, KeyError) as e:
        refuse("conformance", "a registry and shipped pins that render", str(e), "Fix the tree at the release commit.")
        return refusals
    mf = cand / "conformance-manifest.json"
    theirs = mf.read_bytes() if mf.is_file() else None
    if theirs != mine.encode():
        refuse("conformance-manifest.json", "the render of the candidate's fetched ModernCI outputs",
               "missing" if theirs is None else "different bytes",
               "The manifest is generated, never edited; rebuild the candidate's conformance-manifest slice.")
    m = json.loads(mine)
    if (m["commit"], m["release"]) != (commit, release):
        refuse("conformance-manifest.json", f"commit {commit}, release {release}", f"{m['commit']}, {m['release']}",
               "Render it for this release.")
    entries = {e["suite"]: e for e in m["suites"]}
    for s in suites:
        if str(s["public"]).lower() != "true":
            continue
        sid, repo = s["id"], s["repo"]
        want = commit if repo == sync.CORE_REPO else pins.get(repo)
        e = entries.get(sid, {})
        if (e.get("status") == "pass" and e.get("repo") == repo and want and e.get("commit") == want
                and e.get("core_pin") == commit):
            continue
        x = suite_exc.get(sid)
        if x and e.get("status") != "pass" and x.get("status") == e.get("status"):
            continue
        refuse(f"suite {sid}", f"pass for {repo}@{(want or 'no shipped pin')[:12]} on core {commit[:12]}",
               f"{e.get('status', 'absent')}: {e.get('reason', '')}",
               "Green means green: fix it red-first and re-judge, or the owner signs an exception that records it as it is.")
    # Each shipped pin is the commit whose verdict was used, and is its repo's dev head.
    owners = sorted({s["repo"] for s in suites} - {sync.CORE_REPO})
    for repo in owners:
        p = pins.get(repo)
        if p is None:
            continue
        rec_file = cand / "conformance" / repo / "receipt.json"
        if rec_file.is_file():
            got = json.loads(rec_file.read_text()).get("head")
            if got != p:
                refuse(f"{repo} pin", f"the judged commit {str(got)[:12]}", p[:12],
                       "dist/default and release/plugin-pins.tsv must ship the commit ModernCI judged.")
        dev = client.dev_head(repo)
        if dev != p and (repo, p) not in pin_exc:
            refuse(f"{repo} pin", f"its dev head {dev[:12]}", p[:12],
                   "The release ships each plugin's dev head (WEBSITE-CLAIMS 2a #4): repin, or the owner signs a pin exception.")
    return refusals


def evidence(root: Path, cand: Path, release: str) -> dict:
    """What release-evidence.json records for G-C (the K2 hook)."""
    mf = cand / "conformance-manifest.json"
    m = json.loads(mf.read_text())
    excepted = sync.read_exceptions(root, release)
    return {
        "conformance_manifest_sha256": hashlib.sha256(mf.read_bytes()).hexdigest(),
        "conformance": {"rule": "G-C",
                        "public_pass": sum(1 for e in m["suites"] if e["public"] and e["status"] == "pass"),
                        "excepted": sorted(e["suite"] for e in m["suites"]
                                           if e["suite"] in excepted and e["status"] != "pass")},
    }


# ── CLI ──────────────────────────────────────────────────────────────────────────────────────────

USAGE = """usage:
  conformance_gate.py manifest --release V --commit T --out DIR
  conformance_gate.py gate     --candidate DIR --release V --commit T --allowed-signers FILE"""


def main(argv: list) -> int:
    if not argv or argv[0] not in ("manifest", "gate"):
        print(USAGE)
        return EXIT_USAGE
    cmd, opts, it = argv[0], {}, iter(argv[1:])
    for a in it:
        if not a.startswith("--"):
            print(USAGE)
            return EXIT_USAGE
        opts[a[2:]] = next(it, None)
    need = {"manifest": {"release", "commit", "out"}, "gate": {"candidate", "release", "commit", "allowed-signers"}}[cmd]
    if set(opts) != need or not all(opts.values()) or not sync.SHA_RE.fullmatch(opts["commit"]):
        print(USAGE)
        return EXIT_USAGE
    root = HERE.parents[1]
    try:
        if cmd == "manifest":
            build_manifest(ModernCI(), root, commit=opts["commit"], release=opts["release"], out=Path(opts["out"]))
            print(f"conformance-gate: wrote {Path(opts['out']) / 'conformance-manifest.json'}")
            return EXIT_OK
        signers = [l.strip() for l in Path(opts["allowed-signers"]).read_text().splitlines()
                   if l.strip() and not l.startswith("#")]
        refusals = gate_c(root, Path(opts["candidate"]), commit=opts["commit"], release=opts["release"],
                          allowed_signers=signers, client=ModernCI())
    except CannotRun as e:
        print(f"CANNOT RUN: {e}\nconformance-gate: a rule could not run; this is never a pass.")
        return EXIT_CANNOT_RUN
    except (OSError, ValueError, KeyError, sync.Refused) as e:
        print(f"CANNOT RUN: {type(e).__name__}: {e}")
        return EXIT_CANNOT_RUN
    if refusals:
        print(f"conformance-gate: REFUSED ({len(refusals)}). The tag may not be published.")
        return EXIT_REFUSED
    print("conformance-gate: G-C admitted.")
    return EXIT_OK


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
