#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Apply ONE boot-mutation (fixtures/boot-mutations.json) to the oracle's baseline config.

  apply-mutation.py --baseline <config.yaml> --providers <providers.yaml> --mutation <BOOT-id> --out <dir>

Writes <out>/config.yaml (and <out>/providers.yaml when the mutation targets it), prints extra
KEY=VALUE env lines on stdout (for `env` ops) and writes <out>/mutation-args.json (for `args` ops).
Exit 3 with a one-line reason on stderr when the mutation is `op: null` (needs a fixture) — the
recorder records that cell as a named gap, never a pass.

Mutation ops (applied in order to the PARSED YAML document, so a typo key or a shape change lands
exactly where the inventory row says):
  {"set": "a.b.c", "value": <json>}     set a dotted path (creating maps as needed; list index as int)
  {"delete": "a.b.c"}                   remove a key
  {"raw_yaml": "text"}                  append raw text to the document (for `${VAR}` cases etc.)
  {"replace_yaml": "text"}              replace the whole document with this text
  {"providers_set": "p.k", "value": v}  same as set, on providers.yaml
  {"providers_delete": "p.k"}
  {"env": {"VAR": "value"}}             environment for the process
  {"args": ["--flag", ...]}             extra CLI arguments
  {"plugin_dir": ["<repo-name>", ...]}  stage a REAL, digest-pinned, published plugin tarball (see
                                        fetch-plugin.sh / plugin-digests.tsv) per named repo into a
                                        fresh <out>/plugins/ directory and point `plugins.dir` at it
                                        (merged into any `plugins:` map a prior `set` op already
                                        wrote — dir is the only key this op touches). Lets a boot
                                        mutation put a REAL signed artifact of a KNOWN kind (hook /
                                        auth / store / secret) in front of a config reference that
                                        expects a different kind, without needing a purpose-built
                                        broken plugin.
  {"plugin_dir_corrupt": {"name": "<repo-name>", "truncate_bytes": N}}
                                        same staging as `plugin_dir`, but truncates the copied
                                        tarball to N bytes first — a real signed artifact whose
                                        archive/manifest is now unreadable (BOOT-135's `plugin
                                        validation failed` family), as opposed to a wrong-KIND but
                                        otherwise-intact one.
  {"plugin_dir_unsigned": ["<repo-name>", ...]}
                                        same staging as `plugin_dir`, but flips one hex nibble in
                                        the copied manifest's `signature` field (same length, still
                                        valid hex, no longer the real ed25519 signature) before
                                        repacking. The archive and manifest stay well-formed — the
                                        published dylib runs unmodified — but `busbar-plugin-sign`
                                        now sees a TAMPERED signature over a `publisher: busbar`
                                        (or third-party) manifest, i.e. "unsigned" in trust-policy
                                        terms: REJECTED under `allow_unsigned: false` (the
                                        `plugin present but NOT loaded (trust policy)` family) or
                                        `Verdict::Allowed` (UNVERIFIED) under `allow_unsigned: true`
                                        — without needing a from-source unsigned plugin build.
  {"overlay": {...}}                   write the given JSON object verbatim as
                                        <out>/busbar-overlay.json (or <out>/boot-overlay.json when
                                        the mutation also sets mode: boot — see NOTE below), i.e. the
                                        durable overlay busbar reads next to config.yaml by default.
                                        The op vocabulary otherwise writes only config.yaml /
                                        providers.yaml; this is the one escape hatch for mutations
                                        that are only reachable through the overlay layer (a runtime
                                        `HookCfg` key config.yaml's `HookDefCfg` never exposes, an
                                        overlay schema version newer than this binary understands,
                                        a named-map patch this binary's typed parse rejects, etc).
                                        NOTE: record.sh's `boot` mode copies the mutated config.yaml
                                        to `<out>/boot.yaml` and rewrites BUSBAR_CONFIG to point at
                                        it, but the config's DIRECTORY is unchanged (`<out>`), so a
                                        `busbar-overlay.json` written here lands in the same
                                        directory `boot.yaml` resolves its default overlay from
                                        either way — one code path serves both modes.
"""
import argparse
import json
import os
import shutil
import subprocess
import sys

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    print("apply-mutation: PyYAML is required (pip3 install pyyaml)", file=sys.stderr)
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))


def _fetch_plugin(repo: str) -> str:
    """Resolve the cached, digest-verified tarball path for a plugin-digests.tsv repo name, fetching
    it (network) on a cache miss — the exact same path oracle-config.sh / record.sh already use, so a
    mutation's plugin is provably the same artifact the golden's other plugin cells were proven against."""
    out = subprocess.run(["bash", os.path.join(HERE, "fetch-plugin.sh"), repo],
                          capture_output=True, text=True, check=True)
    return out.stdout.strip()


def _stage_plugin_dir(out_dir: str, repos: list, corrupt: dict | None = None) -> str:
    """Copy each named published plugin's tarball into <out_dir>/plugins/ (optionally truncating one
    of them per `corrupt`), returning the absolute plugins dir path."""
    plugins_dir = os.path.join(out_dir, "plugins")
    os.makedirs(plugins_dir, exist_ok=True)
    for repo in repos:
        src = _fetch_plugin(repo)
        dst = os.path.join(plugins_dir, os.path.basename(src))
        shutil.copyfile(src, dst)
        if corrupt and corrupt.get("name") == repo:
            n = int(corrupt["truncate_bytes"])
            with open(dst, "r+b") as f:
                f.truncate(n)
    return plugins_dir


def _stage_plugin_dir_unsigned(out_dir: str, repos: list) -> str:
    """Copy each named published plugin's tarball into <out_dir>/plugins/, tampering the copy's
    manifest `signature` field (one hex nibble flipped, same length) so the artifact no longer
    verifies — the archive stays well-formed and the dylib is untouched, only the ed25519 signature
    is now wrong. Returns the absolute plugins dir path. tarfile round-trip preserves member order
    and names; only manifest.json's bytes change (and therefore the .tar.gz's compressed bytes, but
    never its members)."""
    import tarfile
    import io

    plugins_dir = os.path.join(out_dir, "plugins")
    os.makedirs(plugins_dir, exist_ok=True)
    for repo in repos:
        src = _fetch_plugin(repo)
        dst = os.path.join(plugins_dir, os.path.basename(src))
        with tarfile.open(src, "r:gz") as tin:
            members = []
            datas = {}
            for m in tin.getmembers():
                members.append(m)
                if m.isfile():
                    datas[m.name] = tin.extractfile(m).read()
        manifest_name = next((n for n in datas if n.endswith("manifest.json")), None)
        if manifest_name is None:
            raise RuntimeError(f"plugin_dir_unsigned: {repo} tarball carries no manifest.json")
        manifest = json.loads(datas[manifest_name])
        sig = manifest.get("signature", "")
        if not sig:
            raise RuntimeError(f"plugin_dir_unsigned: {repo} manifest carries no signature to tamper")
        # flip one hex nibble in the middle of the signature — same length, still valid hex, no
        # longer the real ed25519 signature over this artifact's sha256.
        mid = len(sig) // 2
        flipped = "0" if sig[mid] != "0" else "1"
        manifest["signature"] = sig[:mid] + flipped + sig[mid + 1:]
        datas[manifest_name] = json.dumps(manifest).encode("utf-8")
        with tarfile.open(dst, "w:gz") as tout:
            for m in members:
                if m.name in datas:
                    payload = datas[m.name]
                    m2 = tarfile.TarInfo(m.name)
                    m2.size = len(payload)
                    m2.mode = m.mode
                    m2.mtime = m.mtime
                    tout.addfile(m2, io.BytesIO(payload))
                else:
                    tout.addfile(m)
    return plugins_dir


def walk_set(doc, path: str, value):
    parts = path.split(".")
    cur = doc
    for i, k in enumerate(parts):
        last = i == len(parts) - 1
        if isinstance(cur, list):
            k = int(k)
            if last:
                if k == len(cur):
                    cur.append(value)
                else:
                    cur[k] = value
                return
            cur = cur[k]
            continue
        if last:
            cur[k] = value
            return
        if k not in cur or cur[k] is None:
            cur[k] = {}
        cur = cur[k]


def walk_delete(doc, path: str):
    parts = path.split(".")
    cur = doc
    for k in parts[:-1]:
        if isinstance(cur, list):
            cur = cur[int(k)]
        else:
            if k not in cur:
                return
            cur = cur[k]
    k = parts[-1]
    if isinstance(cur, list):
        del cur[int(k)]
    else:
        cur.pop(k, None)


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--baseline", required=True)
    ap.add_argument("--providers", required=True)
    ap.add_argument("--mutation", required=True)
    ap.add_argument("--out", required=True)
    ap.add_argument("--fixture", default=os.path.join(HERE, "fixtures", "boot-mutations.json"))
    a = ap.parse_args()
    fx = json.load(open(a.fixture, encoding="utf-8"))
    mut = next((m for m in fx["mutations"] if m["id"] == a.mutation), None)
    if mut is None:
        print(f"apply-mutation: no mutation {a.mutation}", file=sys.stderr); return 2
    if mut.get("op") is None:
        print(f"{a.mutation}: {mut.get('notes', 'needs a fixture')}", file=sys.stderr); return 3

    cfg_text = open(a.baseline, encoding="utf-8").read()
    prov_text = open(a.providers, encoding="utf-8").read()
    cfg = yaml.safe_load(cfg_text) or {}
    prov = yaml.safe_load(prov_text) or {}
    raw_tail, replace_all, prov_touched = [], None, False
    env_lines, args, overlay_doc = [], [], None
    for op in mut["op"]:
        if "set" in op:
            walk_set(cfg, op["set"], op.get("value"))
        elif "delete" in op:
            walk_delete(cfg, op["delete"])
        elif "raw_yaml" in op:
            raw_tail.append(op["raw_yaml"])
        elif "replace_yaml" in op:
            replace_all = op["replace_yaml"]
        elif "providers_set" in op:
            walk_set(prov, op["providers_set"], op.get("value")); prov_touched = True
        elif "providers_delete" in op:
            walk_delete(prov, op["providers_delete"]); prov_touched = True
        elif "env" in op:
            env_lines += [f"{k}={v}" for k, v in op["env"].items()]
        elif "args" in op:
            args += list(op["args"])
        elif "plugin_dir" in op:
            os.makedirs(a.out, exist_ok=True)
            plugins_dir = _stage_plugin_dir(a.out, op["plugin_dir"])
            cfg.setdefault("plugins", {})["dir"] = plugins_dir
        elif "plugin_dir_corrupt" in op:
            os.makedirs(a.out, exist_ok=True)
            spec = op["plugin_dir_corrupt"]
            plugins_dir = _stage_plugin_dir(a.out, [spec["name"]], corrupt=spec)
            cfg.setdefault("plugins", {})["dir"] = plugins_dir
        elif "plugin_dir_unsigned" in op:
            os.makedirs(a.out, exist_ok=True)
            plugins_dir = _stage_plugin_dir_unsigned(a.out, op["plugin_dir_unsigned"])
            cfg.setdefault("plugins", {})["dir"] = plugins_dir
        elif "overlay" in op:
            overlay_doc = op["overlay"]
        else:
            print(f"apply-mutation: unknown op {op}", file=sys.stderr); return 2

    os.makedirs(a.out, exist_ok=True)
    if replace_all is not None:
        out_text = replace_all
    else:
        out_text = yaml.safe_dump(cfg, sort_keys=False, default_flow_style=False, allow_unicode=True)
        if raw_tail:
            out_text += "\n" + "\n".join(raw_tail) + "\n"
    open(os.path.join(a.out, "config.yaml"), "w", encoding="utf-8").write(out_text)
    if prov_touched:
        open(os.path.join(a.out, "providers.yaml"), "w", encoding="utf-8").write(
            yaml.safe_dump(prov, sort_keys=False, default_flow_style=False, allow_unicode=True))
    if overlay_doc is not None:
        open(os.path.join(a.out, "busbar-overlay.json"), "w", encoding="utf-8").write(
            json.dumps(overlay_doc))
    json.dump({"args": args}, open(os.path.join(a.out, "mutation-args.json"), "w"))
    for ln in env_lines:
        print(ln)
    return 0


if __name__ == "__main__":
    sys.exit(main())
