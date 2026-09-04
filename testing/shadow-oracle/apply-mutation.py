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
"""
import argparse
import json
import os
import sys

try:
    import yaml  # PyYAML
except ImportError:  # pragma: no cover
    print("apply-mutation: PyYAML is required (pip3 install pyyaml)", file=sys.stderr)
    sys.exit(2)

HERE = os.path.dirname(os.path.abspath(__file__))


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
    env_lines, args = [], []
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
    json.dump({"args": args}, open(os.path.join(a.out, "mutation-args.json"), "w"))
    for ln in env_lines:
        print(ln)
    return 0


if __name__ == "__main__":
    sys.exit(main())
