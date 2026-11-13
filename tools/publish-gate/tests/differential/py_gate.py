#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Differential driver: runs the PYTHON scripts/release/publish_gate.py over one fixture world, with
the same file-backed lookups as examples/harness.rs, so tests/parity.rs can require identical
decisions, messages and evidence from both. It exists only for the port and goes with the Python.

  py_gate.py <spec.json>
"""
import builtins
import json
import sys
import traceback
from pathlib import Path
from unittest import mock

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE.parents[3] / "scripts" / "release"))
import conformance_gate as cg  # noqa: E402
import publish_gate as pg  # noqa: E402

spec = json.loads(Path(sys.argv[1]).read_text())
STATE = Path(spec["state"])


def mangle(r):
    return r.replace("/", "_").replace(":", "_")


def map_get(name, key):
    f = STATE / name
    return json.loads(f.read_text()).get(key) if f.is_file() else None


class StateNet(pg.Net):
    def release_exists(self, repo, tag):
        return (STATE / "releases" / repo / tag).is_dir()

    def release_published(self, repo, tag):
        return (STATE / "releases" / repo / tag / ".published").is_file()

    def registry_digest(self, ref):
        f = STATE / "registry" / mangle(ref)
        return f.read_text() if f.is_file() else None

    def repo_full_name(self, repo):
        return map_get("full_names.json", repo)

    def remote_tag(self, repo, tag):
        return map_get("remote_tags.json", f"{repo} {tag}")

    def repo_file(self, repo, path, ref):
        return (STATE / "busbar-ref").read_text()


class StateMCI(cg.ModernCI):
    def __init__(self):
        pass

    def dev_head(self, repo):
        head = map_get("dev_heads.json", repo)
        if head is None:
            raise cg.CannotRun(f"no dev head for {repo}")
        return head


def main():
    patches = []
    if spec.get("security") == "fixture":
        def gs(_inp, verdict):
            verdict.ok("G-S")
            return {"schema": "busbar.artifact-security/1", "status": "pass"}

        def gsp(_inp, verdict, *_a):
            verdict.ok("G-S")
            return {"status": "pass"}
        patches += [mock.patch.object(pg, "gs_security", side_effect=gs),
                    mock.patch.object(pg, "gs_plugin_security", side_effect=gsp)]

    def ask(prompt=""):
        print(prompt, end="")
        if spec.get("confirm") is None:
            raise EOFError("EOF when reading a line")
        return spec["confirm"]
    patches.append(mock.patch.object(builtins, "input", ask))
    for p in patches:
        p.start()
    try:
        inp = pg.Inputs(root=Path(spec["root"]), cand=Path(spec["cand"]), trust=pg.load_trust(Path(spec["trust"])),
                        pack=spec["pack"], net=StateNet(), require_hardware_k2=spec.get("require_hardware_k2", True),
                        mci=StateMCI())
        out = Path(spec["out"])
        cmd = spec["command"]
        if cmd == "verify":
            return pg.cmd_verify(inp, out)
        if cmd == "sign":
            return pg.cmd_sign(inp, out, spec["k1_sign_cmd"], spec["k2_key"])
        if cmd == "upload":
            return pg.cmd_upload(inp, out)
        if cmd == "plugin-release":
            return pg.cmd_plugin_release(inp, out, spec["repo"], spec["tag"], Path(spec["plugins"]),
                                         spec["k1_sign_cmd"], spec["k2_key"])
        if cmd == "index":
            cj = json.loads((inp.cand / "candidate.json").read_text())
            out.write_bytes(pg.render_plugin_index(inp.root, inp.cand, cj["plugins"], inp.net))
            return 0
        raise SystemExit(f"unknown command {cmd}")
    except pg.CannotRun as e:
        print(f"CANNOT RUN: {e}")
        print("publish-gate: a rule could not run; this is never a pass.")
        return pg.EXIT_CANNOT_RUN
    except (OSError, ValueError, KeyError) as e:
        print(f"CANNOT RUN: {type(e).__name__}: {e}")
        return pg.EXIT_CANNOT_RUN
    except Exception:  # an uncaught exception: the CLI's traceback, exit 1
        sys.stdout.flush()
        traceback.print_exc()
        return 1


code = main()
sys.stdout.flush()
sys.exit(code)
