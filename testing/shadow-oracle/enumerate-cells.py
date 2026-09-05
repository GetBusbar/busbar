#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Enumerate the shadow-oracle golden-corpus cells — DERIVED, never hand-listed.

The oracle records the current binary's exact behavior (bytes + effects) per cell and replays it
against any later binary. Its cell list must be a function of what busbar claims to support, so a
new method, dialect or transport becomes a new cell automatically (an uncovered cell is RED), and
no one can forget one.

Sources (GENERATED or pinned, all already gated):
  qa/method-inventory.json  -- MCP + A2A: method x originator x role x transport (230 cells, 10 N/A)
  qa/field-inventory.json   -- LLM: the dialects + directions + streaming flag
  tests/migration-corpus/   -- every real config.yaml shipped since v0.10 (config.migrate family)
  fixtures/openapi-1.5.5.json + fixtures/admin-bodies.json -- the 66 admin operations (admin.ops)
  fixtures/admin-readback.json -- the follow-up GET each mutating admin op is checked against, so a
    write's SIDE EFFECT is part of the golden, not just its own response
  fixtures/boot-mutations.json -- one config mutation per inventoried boot refusal/warning
  the routes inventory (docs/design/inventory/1.5.5-routes-admin.md) -- pinned here as literals for
    the cross-cutting HTTP surfaces (ops.scrape, http.crosscut) and the CLI (cli)

Cell drivers (record.sh dispatches on `driver`; absent = the LLM wire builder):
  http   an explicit {method, path, headers, body, auth: ok|broke|noscope|admin|none, listener: data|admin}
  exec   run the binary: {args, env, config: baseline|<mutation>, mode: validate|boot|cli}
Cells may carry `compare: [classes]` when part of their output is inherently random (a generated
signing key) — the differ then judges only those classes; `fresh: true` boots a new busbar first.

Each protocol cell is crossed with the OUTCOME CLASSES the governed path must reproduce
byte-for-byte: the happy path plus every refusal the core pipeline can emit before/around it.

Output: testing/shadow-oracle/cells.json  (stable ids, sorted; the recorder/replayer iterate it).
Usage:  enumerate-cells.py [--write] [--summary]
"""
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
METHOD_INV = ROOT / "qa" / "method-inventory.json"
FIELD_INV = ROOT / "qa" / "field-inventory.json"
OUT = Path(__file__).resolve().parent / "cells.json"

# The outcome classes every plane's governed path must reproduce. Order is the pipeline order the
# refusal is produced at, so a diff names the earliest divergent step.
OUTCOMES = [
    ("ok", "happy path: authenticated, in-scope, under budget, upstream healthy"),
    ("unauthenticated", "no / bad credential -> refused at Authenticate (native 401)"),
    ("out_of_scope", "credential lacks the scope/grant -> refused at Approve (native 403)"),
    ("over_budget", "budget exhausted -> refused at Admit (native 429, names the bucket)"),
    ("malformed", "undecodable request -> refused at decode (native 400)"),
    ("upstream_down", "upstream refuses/times out -> Route failover / native upstream error"),
]
# Outcomes that only make sense for a request the plane actually forwards (not for refusals that
# never reach Route).
STREAMING_OUTCOMES = [("ok_stream", "happy path, streamed response (SSE / frames)")]
# Gemini's second streaming framing: `streamGenerateContent` WITHOUT `?alt=sse` answers a JSON
# array, not SSE. A Gemini client's own framing, so it is enumerated same-dialect only.
ARRAY_STREAM_OUTCOME = ("ok_stream_array", "happy path, streamed as a JSON array (gemini without alt=sse)")


# Refusals are produced BEFORE Route, so they never depend on the egress dialect: enumerate them
# same-proto only (ingress == egress). Forwarded outcomes reach Route and exercise the cross-protocol
# translation the LLM plane exists for: enumerate EVERY ordered (ingress, egress) dialect pair.
PRE_ROUTE = {"unauthenticated", "out_of_scope", "over_budget", "malformed"}


def llm_cells(inv: dict) -> list[dict]:
    """LLM: refusal outcomes per dialect (same-proto); forwarded outcomes (ok, upstream_down, and a
    streamed happy path where the EGRESS dialect streams) for every ingress x egress dialect pair —
    the diagonal is the codec's own round trip, the off-diagonal is cross-protocol translation."""
    dialects = sorted(inv["dialects"]) if isinstance(inv["dialects"], list) else sorted(inv["dialects"].keys())
    streams = {f["dialect"] for f in inv["fields"] if f.get("streaming")}

    def cell(i: str, e: str, oc: str, why: str) -> dict:
        c = {
            "id": f"llm|{i}|{e}|request|{oc}",
            "plane": "llm", "family": "llm.wire", "ingress_dialect": i, "egress_dialect": e,
            "cross_protocol": i != e, "transport": "http", "op": "chat",
            "outcome": oc, "why": why,
        }
        # A 5xx from the upstream parks the lane's breaker; a later cell on that lane would then
        # record "overloaded" instead of its own outcome. `fresh` = the recorder boots a NEW busbar
        # (re-mints, re-primes) before this cell, so every cell is "from a fresh boot, do X".
        if oc == "upstream_down":
            c["fresh"] = True
        return c

    cells = []
    for d in dialects:
        for oc, why in OUTCOMES:
            if oc in PRE_ROUTE:
                cells.append(cell(d, d, oc, why))
    for i in dialects:
        for e in dialects:
            for oc, why in OUTCOMES:
                if oc not in PRE_ROUTE:
                    cells.append(cell(i, e, oc, why))
            if e in streams:
                for oc, why in STREAMING_OUTCOMES:
                    cells.append(cell(i, e, oc, why))
    # Not gated on the inventory's `streaming` flag: the array framing is a gemini path selector
    # (`streamGenerateContent` without `alt=sse`), not a field the inventory lists.
    if "gemini" in dialects:
        cells.append(cell("gemini", "gemini", *ARRAY_STREAM_OUTCOME))
    return cells


def protocol_cells(inv: dict) -> list[dict]:
    """MCP / A2A: every non-N/A inventory cell x every outcome. The inventory cell already carries
    protocol, method, originator, role, transport and obligation; we add the outcome axis."""
    na = {c["id"] for c in inv.get("na_cells", [])} if isinstance(inv.get("na_cells"), list) else set()
    cells = []
    for c in inv["cells"]:
        if c["id"] in na or c.get("obligation") == "n/a":
            continue
        for oc, why in OUTCOMES:
            cells.append({
                "id": f"{c['id']}|{oc}",
                "plane": c["protocol"], "method": c["method"], "originator": c["originator"],
                "role": c["role"], "transport": c["transport"], "obligation": c["obligation"],
                "outcome": oc, "why": why,
            })
    return cells


MIGRATION_CORPUS = ROOT / "tests" / "migration-corpus" / "from-tags"
FIXTURES = Path(__file__).resolve().parent / "fixtures"


def http(id_: str, family: str, method: str, path: str, *, auth: str = "ok", listener: str = "data",
         headers: dict | None = None, body: str | None = None, why: str = "", **extra) -> dict:
    id_ = id_.replace("/", "")  # ids become file names on both sides of the differ
    c = {"id": id_, "plane": "core", "family": family, "driver": "http", "outcome": "ok",
         "request": {"method": method, "path": path, "headers": headers or {}, "body": body,
                     "auth": auth, "listener": listener}, "why": why}
    c.update(extra)
    return c


def exec_(id_: str, family: str, *, args: list[str], mode: str, config: str = "baseline",
          env: dict | None = None, why: str = "", **extra) -> dict:
    id_ = id_.replace("/", "")
    c = {"id": id_, "plane": "core", "family": family, "driver": "exec", "outcome": "ok",
         "exec": {"args": args, "mode": mode, "config": config, "env": env or {}}, "why": why}
    c.update(extra)
    return c


def cli_cells() -> list[dict]:
    """Every first-argument dispatch of 1.5.5 (ops inventory §2.1): exit code + stdout/stderr bytes."""
    F = "cli"
    return [
        exec_("cli|--version", F, args=["--version"], mode="cli", why="prints `busbar <ver>`; exit 0"),
        exec_("cli|-V", F, args=["-V"], mode="cli", why="alias of --version"),
        exec_("cli|--help", F, args=["--help"], mode="cli", why="the verbatim help block; exit 0"),
        exec_("cli|-h", F, args=["-h"], mode="cli", why="alias of --help"),
        exec_("cli|--validate|baseline", F, args=["--validate"], mode="validate", why="ok: config valid — N provider(s) …; exit 0"),
        exec_("cli|--list-plugins", F, args=["--list-plugins"], mode="cli", why="plugins block listing; exit 0"),
        exec_("cli|--migrate-config|missing-path", F, args=["--migrate-config"], mode="cli", why="missing path; exit 2"),
        exec_("cli|--migrate-config|unreadable", F, args=["--migrate-config", "/nonexistent/old.yaml"], mode="cli", why="unreadable; exit 1"),
        exec_("cli|--generate-signing-key", F, args=["--generate-signing-key"], mode="cli",
              compare=["status"], why="random key: only the exit code is a contract"),
        exec_("cli|--print-metadata-blocklist", F, args=["--print-metadata-blocklist"], mode="cli", why="built-in denylist ∪ security.blocked_metadata_hosts"),
        exec_("cli|unknown-flag", F, args=["--definitely-not-a-flag"], mode="cli", why="unrecognized argument; exit 2"),
        exec_("cli|--safe-mode|first-arg", F, args=["--safe-mode"], mode="cli", why="1.5.5: unrecognized as a FIRST argument; exit 2 (PB-23)"),
        exec_("cli|env|BUSBAR_CONFIG-missing", F, args=["--validate"], mode="validate", config="missing",
              why="config path does not exist; [error] …; exit 1"),
        exec_("cli|env|RUST_LOG-crate-filter", F, args=["--validate"], mode="validate", env={"RUST_LOG": "busbar=debug"},
              why="bare tracing::Level only — a crate filter silently falls back (PB-51)"),
    ]


def migrate_cells() -> list[dict]:
    """--migrate-config on every shipped config, then --validate of the migrated result."""
    cells = []
    for f in sorted(MIGRATION_CORPUS.glob("*.yaml")):
        tag = f.name.removesuffix("_config.yaml")
        rel = str(f.relative_to(ROOT))
        cells.append(exec_(f"config.migrate|{tag}|migrate", "config.migrate",
                           args=["--migrate-config", rel], mode="cli", config="none",
                           why="YAML to stdout, banner to stderr, exit 0/1/2 (PB-50)"))
        cells.append(exec_(f"config.migrate|{tag}|validate-migrated", "config.migrate",
                           args=["--validate"], mode="validate", config=f"migrated:{rel}",
                           why="the migrated document under --validate"))
    return cells


def scrape_cells() -> list[dict]:
    F = "ops.scrape"
    return [
        http("ops.scrape|/metrics|key", F, "GET", "/metrics", why="RouteAuth::Key; text/plain; version=0.0.4 (PB-43/70)"),
        http("ops.scrape|/metrics|none", F, "GET", "/metrics", auth="none", why="data-plane key auth refused"),
        # The contract is an ABSENCE: the body is filtered to the ledger/journal/hold/WAL series lines
        # only, so the 1.5.5 golden is an empty body and any such series on a later binary is a diff.
        http("ops.scrape|/metrics|no-ledger-series", F, "GET", "/metrics",
             body_lines=r"^busbar_(ledger|journal|hold|wal)_",
             why="no busbar_ledger_/journal_/hold_/wal_ series on a 1.5.5 config: the scrape keeps only those lines, so the golden is empty (PB-13, PB-15, PB-17, PB-41)"),
        http("ops.scrape|/metrics|admin-listener", F, "GET", "/metrics", auth="admin", listener="admin", why="admin router has no /metrics (PB-76)"),
        http("ops.scrape|/metrics/hooks|key", F, "GET", "/metrics/hooks", why="core axum route; charset=utf-8 (PB-43)"),
        http("ops.scrape|/stats|key", F, "GET", "/stats", why="20 per-lane fields, 'unbounded', variant names (PB-43)"),
        http("ops.scrape|/stats|none", F, "GET", "/stats", auth="none", why="auth chain applies"),
        http("ops.scrape|/healthz|data", F, "GET", "/healthz", auth="none", why="unconditional bypass; 200 ok"),
        http("ops.scrape|/healthz|admin", F, "GET", "/healthz", auth="none", listener="admin", why="same on the admin listener (RT-003)"),
        http("ops.scrape|/v1/models|openai-fp", F, "GET", "/v1/models", why="openai envelope by fingerprint (no x-api-key rung, PB-100)"),
        http("ops.scrape|/v1/models|anthropic-fp", F, "GET", "/v1/models", headers={"anthropic-version": "2023-06-01"}, why="anthropic envelope"),
        http("ops.scrape|/v1/models|x-api-key", F, "GET", "/v1/models", headers={"x-api-key": "irrelevant"}, why="x-api-key is NOT a rung for /v1/models"),
        http("ops.scrape|/v1beta/models", F, "GET", "/v1beta/models", why="gemini listing"),
        http("ops.scrape|/v1/models|none", F, "GET", "/v1/models", auth="none", why="refused"),
    ]


# A body larger than request_body_max_bytes (32 MiB default). Never inlined: the recorder expands the
# marker at request time so cells.json stays reviewable.
BIG_BODY = "@oversize:33MiB"


def crosscut_cells() -> list[dict]:
    F = "http.crosscut"
    return [
        http("http.crosscut|unknown-path|bare", F, "POST", "/definitely/unknown", body="{}", why="catch-all: path-inferred 404 (PB-30)"),
        http("http.crosscut|unknown-path|openai-suffix", F, "POST", "/x/v1/chat/completions", body='{"model":"nope","messages":[]}', why="detects openai; unknown model"),
        http("http.crosscut|unknown-path|anthropic-header", F, "POST", "/whatever", headers={"anthropic-version": "2023-06-01"}, body="{}", why="detects anthropic by header presence"),
        http("http.crosscut|unknown-path|anthropic-beta", F, "POST", "/whatever", headers={"anthropic-beta": "x"}, body="{}", why="anthropic-beta is rung 2 too (PB-30)"),
        http("http.crosscut|/api-prefix|data", F, "GET", "/api/v1/admin/nope", why="frozen admin envelope on the data listener (PB-30)"),
        http("http.crosscut|/api|data", F, "GET", "/api", why="exact /api also forced"),
        http("http.crosscut|admin-unknown|admin", F, "GET", "/api/v1/admin/nope", auth="admin", listener="admin", why="nested not_found envelope (PB-76)"),
        http("http.crosscut|admin-outside-prefix|admin", F, "GET", "/nope", auth="admin", listener="admin", why="outer admin router: empty-bodied 404 (PB-76)"),
        http("http.crosscut|admin-wrong-method|admin", F, "DELETE", "/api/v1/admin/info", auth="admin", listener="admin", why="method_not_allowed envelope"),
        http("http.crosscut|wrong-method|GET-messages", F, "GET", "/v1/messages", why="405 protocol-native (RT-014)"),
        http("http.crosscut|OPTIONS|chat", F, "OPTIONS", "/v1/chat/completions", auth="none", why="no CORS layer ever; OPTIONS => None (PB-100)"),
        http("http.crosscut|HEAD|healthz", F, "HEAD", "/healthz", auth="none", why="HEAD on a GET route"),
        http("http.crosscut|413|openai", F, "POST", "/v1/chat/completions", body=BIG_BODY, why="oversize after auth, dialect-shaped (PB-60)"),
        http("http.crosscut|413|openai-unauth", F, "POST", "/v1/chat/completions", auth="none", body=BIG_BODY, why="unauthenticated oversize: 401 first (PB-60)"),
        http("http.crosscut|413|anthropic", F, "POST", "/v1/messages", headers={"anthropic-version": "2023-06-01"}, body=BIG_BODY, why="anthropic envelope"),
        http("http.crosscut|413|api-prefix", F, "POST", "/api/v1/admin/keys", auth="admin", listener="admin", body=BIG_BODY, why="admin envelope discards status/kind (PB-60)"),
        http("http.crosscut|auth-token|GET-none", F, "GET", "/auth/token", auth="none", why="browser exchange bypass (PB-33)"),
        http("http.crosscut|auth-token|POST-empty", F, "POST", "/auth/token", auth="none", body="{}", why="flat {\"error\":…} envelope (PB-100)"),
        http("http.crosscut|bearer-and-x-api-key", F, "GET", "/stats", headers={"x-api-key": "not-a-key"}, why="carrier precedence: Bearer wins (PB-35)"),
        http("http.crosscut|x-api-key-only|bad", F, "GET", "/stats", auth="none", headers={"x-api-key": "not-a-key"}, why="second carrier, invalid"),
    ]


# admin.ops: for each operation of fixtures/admin-bodies.json a happy cell (with its `pre` setup chain),
# an unauthenticated cell, and where the fixture provides them a bad-body, a not-found, a stale
# If-Match, a malformed If-Match and an idempotent-replay cell. Every cell boots fresh, so the
# `order` of the fixture is turned into per-op PREREQUISITES (the earlier ops on the same resource).
# Every MUTATING op's happy cell (and its idempotent-replay copy) also carries a `request.post`: the
# follow-up GET named in fixtures/admin-readback.json, recorded as `effects.readback` after the write
# — so a 200 that wrote nothing shows up as a diff, not a pass.
ADMIN_BODIES = FIXTURES / "admin-bodies.json"
ADMIN_READBACK = FIXTURES / "admin-readback.json"
BOOT_MUTATIONS = FIXTURES / "boot-mutations.json"
# resource → the ops that must precede an op on it within one boot (create before update/delete)
ADMIN_PRE = {
    "PutGroupsName": ["PostGroups"], "PatchGroupsName": ["PostGroups"], "DeleteGroupsName": ["PostGroups"],
    "GetGroupsName": [], "GetGroupsNameUsage": [],
    "PatchExportNameSettings": ["PutExportName"], "DeleteExportName": ["PutExportName"], "GetExportName": [],
    "PatchIdentityProvidersNameSettings": ["PutIdentityProvidersName"], "DeleteIdentityProvidersName": ["PutIdentityProvidersName"],
    "PostConfigRollback": ["PutConfigSettings"], "DeleteOverlaySection": ["PutConfigSettings"],
    "GetConfigDiff": ["PutConfigSettings"], "GetConfigVersionsV": [],
}


def _path_of(op: dict, variant: dict) -> str:
    path = variant.get("path") or op["path"]
    q = variant.get("query")
    if q and "?" not in path:
        path += "?" + "&".join(f"{k}={v}" for k, v in sorted(q.items()))
    return path


def _req_of(op: dict, variant: dict, *, auth="admin") -> dict:
    return {"method": op["method"], "path": _path_of(op, variant),
            "headers": variant.get("headers") or {}, "auth": auth, "listener": "admin",
            "body": (json.dumps(variant["body"], separators=(",", ":"), sort_keys=True)
                     if isinstance(variant.get("body"), (dict, list)) else variant.get("body"))}


def _readback_post(opid: str, write_path: str) -> list[dict] | None:
    """Turn this op's fixtures/admin-readback.json entry into a `request.post` follow-up GET (or
    None for a `none` entry / an op the file does not mention). See that file for the kind vocabulary
    -- `resource` paths keep their literal `{RESP:/pointer}` placeholder; record.sh fills it in from
    the write's own captured response at record time."""
    if not ADMIN_READBACK.exists():
        return None
    spec = json.loads(ADMIN_READBACK.read_text())["readback"].get(opid)
    if not spec or spec["kind"] == "none":
        return None
    if spec["kind"] == "same":
        path = write_path
    elif spec["kind"] == "parent":
        path = write_path.rsplit("/", 1)[0]
    else:  # fixed | resource: the spec names the path outright
        path = spec["path"]
    return [{"method": "GET", "path": path, "headers": {}, "auth": "admin", "listener": "admin"}]


def admin_cells() -> list[dict]:
    if not ADMIN_BODIES.exists():
        return []
    fx = json.loads(ADMIN_BODIES.read_text())
    ops = fx["ops"]
    stale = fx.get("stale_if_match", {})
    cells = []
    F = "admin.ops"

    def pre_chain(opid: str) -> list[dict]:
        chain = []
        for pid in ADMIN_PRE.get(opid, []):
            pop = ops[pid]
            if pop.get("ok"):
                chain.append(_req_of(pop, pop["ok"]))
        return chain

    for opid, op in sorted(ops.items()):
        base_path = op["path"]
        why = op.get("notes", "")[:160]
        if op.get("restart"):
            # PostRestart ends the process; recorded as its own cell (fresh boot, expect 202 then exit)
            pass
        variant = op.get("variant")
        if op.get("ok"):
            c = http(f"admin.ops|{opid}|ok", F, op["method"], _path_of(op, op["ok"]),
                     auth="admin", listener="admin", headers=op["ok"].get("headers") or {},
                     body=_req_of(op, op["ok"])["body"], why=why, **({"config_variant": variant} if variant else {}))
            if opid == "GetAudit":
                # A deterministic 4-action chain on a FRESH boot, so the audit content comparison pins
                # the four action literals AND the chain's link integrity (each entry's hash seals the
                # one before it) -- not just the page shape a bare GetAudit would otherwise prove.
                c["fresh"] = True
                c["request"]["path"] = "/api/v1/admin/audit?limit=4"
                c["request"]["pre"] = [
                    {"method": "POST", "path": "/api/v1/admin/keys", "listener": "admin", "auth": "admin",
                     "headers": {"Content-Type": "application/json", "Idempotency-Key": "oracle-idem-post-keys-1"},
                     "body": json.dumps({"group": "oracle", "name": "oracle-minted"}, separators=(",", ":"), sort_keys=True)},
                    {"method": "POST", "path": "/api/v1/admin/keys/{KEY_OK}/rotate", "listener": "admin", "auth": "admin",
                     "headers": {"Idempotency-Key": "oracle-idem-audit-chain-rotate"}},
                    {"method": "POST", "path": "/api/v1/admin/keys/{KEY_BROKE}/revoke", "listener": "admin", "auth": "admin",
                     "headers": {}},
                    {"method": "PUT", "path": "/api/v1/admin/config/settings", "listener": "admin", "auth": "admin",
                     "headers": {"Content-Type": "application/json"},
                     "body": json.dumps({"limits": {"request_body_max_bytes": 33554432}}, separators=(",", ":"), sort_keys=True)},
                ]
                c["why"] = ("mint, rotate {KEY_OK}, revoke {KEY_BROKE}, then a config/settings write, all "
                            "on one fresh boot: the four newest audit entries pin the four action literals "
                            "and the chain's own link integrity, not just the page's shape")
            pre = pre_chain(opid) if opid != "GetAudit" else []
            if pre:
                c["request"]["pre"] = pre
            if op.get("mutating"):
                post = _readback_post(opid, c["request"]["path"])
                if post:
                    c["request"]["post"] = post
            cells.append(c)
            if op.get("idempotent"):
                # the SAME read-back: a replayed write must show the same state as the first write did.
                c2 = json.loads(json.dumps(c)); c2["id"] = f"admin.ops|{opid}|idempotent-replay"
                c2["request"]["repeat"] = 2; c2["why"] = "same Idempotency-Key twice: the replay returns the first response (PB-21)"
                cells.append(c2)
            if op.get("if_match") and stale:
                for kind in ("stale", "malformed"):
                    # a stale/malformed If-Match is a REFUSED write (409/400): no read-back, nothing changed
                    c3 = json.loads(json.dumps(c)); c3["id"] = f"admin.ops|{opid}|if-match-{kind}"
                    c3["request"].pop("post", None)
                    c3["request"]["headers"] = {**c3["request"]["headers"], stale.get("header", "If-Match"): stale[kind]}
                    c3["why"] = f"If-Match {kind}: {stale.get(kind + '_expect')} (PB-100)"
                    cells.append(c3)
        else:
            cells.append(http(f"admin.ops|{opid}|ok", F, op["method"], base_path, auth="admin", listener="admin",
                              why="needs fixture: " + why, needs_fixture=True))
        # unauthenticated: same request, no credential
        v = op.get("ok") or {}
        cells.append(http(f"admin.ops|{opid}|unauth", F, op["method"], _path_of(op, v) if v else base_path, auth="none",
                          listener="admin", headers={k: x for k, x in (v.get("headers") or {}).items() if k.lower() != "authorization"},
                          body=_req_of(op, v)["body"] if v else None, why="no credential -> 401 envelope"))
        if op.get("bad_body"):
            cells.append(http(f"admin.ops|{opid}|bad-body", F, op["method"], op["bad_body"].get("path") or (_path_of(op, v) if v else base_path),
                              auth="admin", listener="admin", headers=op["bad_body"].get("headers") or {},
                              body=_req_of(op, op["bad_body"])["body"], why=f"expect {op['bad_body'].get('expect')}"))
        if op.get("not_found"):
            cells.append(http(f"admin.ops|{opid}|not-found", F, op["method"], op["not_found"]["path"], auth="admin",
                              listener="admin", headers=(v.get("headers") or {}), body=_req_of(op, v)["body"] if v else None,
                              why=f"expect {op['not_found'].get('expect')}"))
    return cells


def boot_cells() -> list[dict]:
    """One cell per inventoried boot refusal/warning: the mutated config under --validate (mode both/
    validate) or a real boot (mode boot). A mutation the fixture could not express (op: null) is still
    a cell — the recorder records it as a named gap, never a pass."""
    if not BOOT_MUTATIONS.exists():
        return []
    fx = json.loads(BOOT_MUTATIONS.read_text())
    cells = []
    for m in fx["mutations"]:
        fam = m.get("family", "boot.refusal")
        mode = "boot" if m.get("mode") == "boot" else "validate"
        args = ["--validate"] if mode == "validate" else []
        cells.append(exec_(f"{fam}|{m['id']}|{mode}", fam, args=args, mode=mode,
                           config=f"mutation:{m['id']}",
                           why=f"expect exit {m.get('expect', {}).get('exit')}; stderr ∋ {str(m.get('expect', {}).get('stderr_contains'))[:80]}",
                           needs_fixture=(m.get("op") is None)))
    return cells


def failover_cells() -> list[dict]:
    """The failover walk against pool oracle-fo (openai-chat w3 + anthropic w1, consecutive-1
    breaker), the cross-pool hop (oracle-fb -> oracle-fo) and least_bad (oracle-lb). `mock_control`
    is written to the mock's control file before the request: {"<egress model>": "<verb>"}."""
    F = "route.failover"
    body = lambda pool, stream=False: json.dumps({"model": pool, "messages": [{"role": "user", "content": "ping"}], **({"stream": True} if stream else {})}, separators=(",", ":"), sort_keys=True)
    cells = []
    def fo(id_, pool, ctl, why, stream=False, **extra):
        c = http(f"route.failover|{id_}", F, "POST", "/v1/chat/completions", body=body(pool, stream), why=why, **extra)
        c["mock_control"] = ctl
        return c
    cells += [
        fo("fo|all-up", "oracle-fo", {}, "SWRR over two members, 3:1 (PB-5/57)"),
        fo("fo|primary-down", "oracle-fo", {"m-openai-chat": "down"}, "first attempt 503 -> breaker trips (consecutive 1) -> failover to anthropic; 200 (PB-8/10)"),
        fo("fo|primary-5xx", "oracle-fo", {"m-openai-chat": "5xx"}, "500 disposition -> failover"),
        fo("fo|primary-429", "oracle-fo", {"m-openai-chat": "429"}, "upstream 429 with Retry-After 7: disposition + honor_retry_after floor (PB-80)"),
        fo("fo|all-down", "oracle-fo", {"m-openai-chat": "down", "m-anthropic": "down"}, "every member fails -> on_exhausted default 503 + Retry-After (PB-4)"),
        fo("fo|all-down-stream", "oracle-fo", {"m-openai-chat": "down", "m-anthropic": "down"}, "same, streamed request", stream=True),
        fo("fo|primary-slow", "oracle-fo", {"m-openai-chat": "slow"}, "attempt exceeds upstream_request_timeout? (default 300 s: NOT cut; the mock sleeps 8 s then answers) — records the real 1.5.5 wait", ),
        fo("fo|primary-cut-stream", "oracle-fo", {"m-openai-chat": "cut"}, "transport cut after the first SSE frame: stream_failed, tokens 0, lane unit not refunded (PB-27)", stream=True),
        fo("fo|primary-cut-body", "oracle-fo", {"m-openai-chat": "cut"}, "transport cut mid-body on a buffered response: 502, fee refunded (PB-91)"),
        fo("fb|member-down", "oracle-fb", {"m-cohere": "down"}, "cohere down -> on_exhausted fallback_pool oracle-fo -> served by the hop; scoped draws on the ATTEMPTED pool (PB-47)"),
        fo("fb|all-down", "oracle-fb", {"m-cohere": "down", "m-openai-chat": "down", "m-anthropic": "down"}, "hop exhausted too -> 503"),
        fo("fb|member-401", "oracle-fb", {"m-cohere": "401"}, "cohere answers 401: an auth hard-down on the member; what the caller sees and what the breaker records (PB-83)"),
        fo("fb|member-down-stream-openai", "oracle-fb", {"m-cohere": "down"}, "a STREAM served by the fallback lane (oracle-fo's openai-chat member): the usage delta is the contract — a fallback stream must bill exactly as the hot path does", stream=True, weight=10),
        fo("lb|member-down", "oracle-lb", {"m-gemini": "down"}, "least_bad: one breaker-bypassing attempt against the tripped member (PB-4)"),
        fo("lb|up", "oracle-lb", {}, "least_bad pool healthy"),
        fo("fo|second-request-after-trip", "oracle-fo", {"m-openai-chat": "down"}, "two requests in one boot: the second never tries the tripped member", pre_same=True),
    ]
    # the second-request cell needs a same-boot predecessor: an unrecorded identical request first
    for c in cells:
        if c.pop("pre_same", False):
            c["request"]["pre"] = [{"method": "POST", "path": "/v1/chat/completions", "listener": "data", "auth": "ok",
                                    "headers": {"Content-Type": "application/json"}, "body": body("oracle-fo")}]
    return cells


PLUGIN_DIGESTS = Path(__file__).resolve().parent / "plugin-digests.tsv"


def plugin_cells() -> list[dict]:
    """The PUBLISHED 1.5.5-era plugins (plugin-digests.tsv) under the binary under test:
    `plugins.load|<name>` lists the plugin dir (kind, signature, status per plugin) and, for every
    store, `plugins.store-persist|<name>` boots with it as `store:`, spends, restarts and reads back.
    A 1.5.5 operator's plugin must load in 1.6.0 unchanged (PB-11/37/93)."""
    if not PLUGIN_DIGESTS.exists():
        return []
    names = sorted({ln.split("\t")[0] for ln in PLUGIN_DIGESTS.read_text().splitlines() if ln and not ln.startswith("#")})
    cells = []
    for n in names:
        cells.append({"id": f"plugins.load|{n}", "plane": "core", "family": "plugins", "driver": "script",
                      "script": {"name": "plugin-list.sh", "args": [n]}, "outcome": "ok",
                      "why": "--list-plugins with the published tarball: kind/alias/signature/STATUS line (PB-11)"})
        if n.startswith("store-"):
            needs = n in ("store-postgres", "store-mysql", "store-valkey")  # need a live backend service
            cells.append({"id": f"plugins.store-persist|{n}", "plane": "core", "family": "plugins", "driver": "script",
                          "script": {"name": "store-persist.sh", "args": [n]}, "outcome": "ok",
                          "why": "validate, boot, mint, spend, restart, read back (PB-11/37/93; persistence is the job)",
                          **({"needs_fixture": True} if needs else {})})
    return cells


def billing_cells() -> list[dict]:
    """Money as the user reads it: the key and group usage views after a known sequence of requests
    (all priced 2.5 units each by the rate card: cents-truncation, per-request fee, refund on a
    non-2xx, the `total` window) — PB-16/22/27/91/99."""
    F = "billing"
    chat = lambda auth="ok", model="m-openai-chat": {"method": "POST", "path": "/v1/chat/completions", "listener": "data", "auth": auth,
                                                     "headers": {"Content-Type": "application/json"},
                                                     "body": json.dumps({"model": model, "messages": [{"role": "user", "content": "ping"}]}, separators=(",", ":"))}
    cells = []
    def usage(id_, pre, why, path="/api/v1/admin/keys/{KEY_OK}/usage", auth="admin"):
        c = http(f"billing|{id_}", F, "GET", path, auth=auth, listener="admin", why=why)
        c["request"]["pre"] = pre
        return c
    cells += [
        usage("key-usage|fresh", [], "a fresh key: zero everything; the exact field set and literals"),
        usage("key-usage|after-1", [chat()], "1 request: requests 1, tokens 18, spend_cents 250 (2.5 units)"),
        usage("key-usage|after-3", [chat(), chat(), chat()], "3 requests: 3 / 54 / 750 — no truncation drift across rows"),
        usage("key-usage|after-cross-protocol", [chat(model="m-anthropic"), chat(model="m-gemini")], "two lanes: per-lane rows folded into one view"),
        usage("key-usage|after-upstream-down", [{**chat(), "mock_control": {"m-openai-chat": "down"}}], "a 503: requests +1, billable refunded, spend 0 (PB-16/26/27)"),
        usage("group-usage|after-2", [chat(), chat()], "the group view", path="/api/v1/admin/groups/oracle/usage"),
        usage("group-usage|broke-after-prime", [], "the primed broke group: 1 request already spent", path="/api/v1/admin/groups/broke/usage"),
        usage("admin-usage|after-2", [chat(), chat()], "GET /admin/usage (all keys, today)", path="/api/v1/admin/usage"),
        usage("admin-usage|past-day", [chat()], "a past UTC day bucket: empty and byte-stable", path="/api/v1/admin/usage?day=2020-01-01"),
        usage("key-usage|noscope-after-403", [chat(auth="noscope")], "a 403 at Approve charges nothing", path="/api/v1/admin/keys/{KEY_NOSCOPE}/usage"),
        usage("key-usage|broke-after-429", [chat(auth="broke")], "a 429 at Admit charges nothing more", path="/api/v1/admin/keys/{KEY_BROKE}/usage"),
    ]
    return cells


def hooks_cells() -> list[dict]:
    """The published headroom gate (prompt: rw, on_error: nothing) attached to pool oracle-hooked:
    the request is rewritten (compressed) before egress; the response, the usage and the hook
    scrape are the contract (PB-6/46/84/95/98; hook ABI 1)."""
    F = "hooks"; V = "hooks"
    body = lambda stream=False: json.dumps({"model": "oracle-hooked", "messages": [{"role": "user", "content": "ping " * 40}], **({"stream": True} if stream else {})}, separators=(",", ":"), sort_keys=True)
    return [
        http("hooks|hooked-pool|ok", F, "POST", "/v1/chat/completions", body=body(), why="gate + rewrite in 1.5.5 order; served 200", config_variant=V),
        http("hooks|hooked-pool|ok_stream", F, "POST", "/v1/chat/completions", body=body(True), why="streamed through the gate", config_variant=V),
        http("hooks|hooked-pool|unauth", F, "POST", "/v1/chat/completions", auth="none", body=body(), why="refused before any hook", config_variant=V),
        http("hooks|metrics-hooks", F, "GET", "/metrics/hooks", why="the hook's own scrape exposition (PB-43)", config_variant=V),
        http("hooks|admin-list", F, "GET", "/api/v1/admin/hooks", auth="admin", listener="admin", why="registry with the loaded hook, incl. the 1.5.5 legacy `at` field alongside `phase`/`fires_at` (A15)", config_variant=V),
        http("hooks|unhooked-pool|ok", F, "POST", "/v1/chat/completions", body=json.dumps({"model": "m-openai-chat", "messages": [{"role": "user", "content": "ping"}]}), why="a pool without the hook is untouched", config_variant=V),
        # A15 — 1.5.5 spellings HEAD 1.6.0 dropped and the owner rule restored: a hook def's
        # `plugin:` alias for `module:` (read-only back-compat), and the settings PUT `persist:`
        # control key (boolean-validated, accepted, then ignored). Both must round-trip on the
        # golden 1.5.5 binary AND on HEAD post-fix.
        # POST /hooks returns 201 with the registered hook VIEW itself (the same `HookView` GET
        # serves) — a single self-contained cell proves both the `plugin:` alias is accepted AND
        # that it resolves to `module: busbar-webrequest` on readback, with no cross-cell ordering
        # dependency.
        http("hooks|register|plugin-alias", F, "POST", "/api/v1/admin/hooks", auth="admin", listener="admin",
             headers={"Content-Type": "application/json"},
             body=json.dumps({"name": "oracle-plugin-alias", "config": {"kind": "tap", "plugin": "busbar-webrequest"}}, separators=(",", ":"), sort_keys=True),
             why="1.5.5 `hooks.<h>.plugin` back-compat alias for `module:` — must still register, and the 201 body's `module` must resolve to `busbar-webrequest` (A15)", config_variant=V),
        http("hooks|config-settings-put|persist-true", F, "PUT", "/api/v1/admin/config/settings", auth="admin", listener="admin",
             headers={"Content-Type": "application/json"},
             body=json.dumps({"persist": True}, separators=(",", ":"), sort_keys=True),
             why="1.5.5 `persist:` boolean control key — accepted (boolean-validated) then ignored, never an unknown-field 400 (A15)", config_variant=V),
        http("hooks|config-settings-put|persist-non-boolean", F, "PUT", "/api/v1/admin/config/settings", auth="admin", listener="admin",
             headers={"Content-Type": "application/json"},
             body=json.dumps({"persist": "yes"}, separators=(",", ":"), sort_keys=True),
             why="a non-boolean `persist:` is refused naming `persist`+`boolean`, not `unknown field` (A15)", config_variant=V),
        # A16 — the hook payload's `message_count` on the normalized IR: an OpenAI chat body may embed
        # a `system`-role turn inside `messages`. 1.5.5 counted the raw wire array length (including
        # that turn); the IR folds it out of `messages` into `system`. This cell exercises the hooked
        # pool end to end with such a body so a `message_count` regression that changes the hook's
        # decide/rewrite outcome (and therefore the response byte shape) surfaces as a diff — the
        # literal wire integer busbar sends the plugin is not independently observable through this
        # black-box published plugin, so the numeric parity is additionally pinned at the unit level
        # (`cargo test -p busbar-core hooks::wire`, `IrFacts::shape().turn_count`).
        http("hooks|hooked-pool|embedded-system-turn", F, "POST", "/v1/chat/completions",
             body=json.dumps({"model": "oracle-hooked", "messages": [
                 {"role": "system", "content": "be terse"},
                 {"role": "user", "content": "ping " * 40},
             ]}, separators=(",", ":"), sort_keys=True),
             why="an embedded system-role turn folded out of `messages` by the IR — message_count parity (A16)", config_variant=V),
    ]


def concurrent(id_: str, family: str, method: str, path: str, n: int, *, auth: str = "ok", listener: str = "data",
               headers: dict | None = None, body: str | None = None, why: str = "", **extra) -> dict:
    """A `driver: concurrent` cell: N parallel copies of the same request (record.sh fires them all
    at once and records the sorted multiset of statuses + the usage/metrics delta — see record.sh's
    `record_concurrent_cell`), never a single response."""
    id_ = id_.replace("/", "")
    c = {"id": id_, "plane": "core", "family": family, "driver": "concurrent", "outcome": "ok",
         "request": {"method": method, "path": path, "headers": headers or {}, "body": body,
                     "auth": auth, "listener": listener},
         "concurrent": {"n": n}, "why": why}
    c.update(extra)
    return c


def concurrency_cells() -> list[dict]:
    """Inbound/lane concurrency has no cell without a threaded mock and a `concurrent` driver: N
    parallel copies of the same request, judged on the sorted multiset of statuses they come back
    with plus the usage delta. Every cell boots fresh — in-flight permits must never leak from an
    earlier cell into this one's count."""
    F = "concurrency"
    ok_body = json.dumps({"model": "m-openai-chat", "messages": [{"role": "user", "content": "ping"}]},
                          separators=(",", ":"), sort_keys=True)
    lc1_body = json.dumps({"model": "oracle-lc1", "messages": [{"role": "user", "content": "ping"}]},
                           separators=(",", ":"), sort_keys=True)
    return [
        concurrent("concurrency|ok|n8", F, "POST", "/v1/chat/completions", 8, body=ok_body, fresh=True,
                   why="8 parallel requests against an UNBOUNDED lane: all 200, usage = 8x — "
                       "concurrency alone must never perturb billing"),
        # `mock_control: slow` holds every admitted request open for the mock's whole sleep (~8s):
        # without it the mock answers so fast that N "parallel" curls (forked one at a time by the
        # shell, microseconds apart) mostly slip through serially instead of ever genuinely
        # overlapping — the shed/AtCapacity arm below needs real, sustained in-flight overlap to fire.
        concurrent("concurrency|inbound-shed|n8", F, "POST", "/v1/chat/completions", 8, body=ok_body, fresh=True,
                   config_variant="inbound-concurrency-2", mock_control={"*": "slow"},
                   why="limits.max_inbound_concurrent: 2 sheds the excess immediately (never queued) "
                       "with the static overloaded 503 body + Retry-After: 1 — 2 admitted, 6 shed"),
        concurrent("concurrency|lane-atcapacity|n4", F, "POST", "/v1/chat/completions", 4, body=lc1_body, fresh=True,
                   mock_control={"*": "slow"},
                   why="pool oracle-lc1's one member has models.<m>.max_concurrent: 1: 1 admitted, "
                       "the other 3 hit AtCapacity and are skipped within the pick, falling through "
                       "to the pool's default on_exhausted 503 (Retry-After: the 2s AT_CAPACITY floor "
                       "— no breaker cooldown is involved here, so it never beats that floor)"),
    ]


def queue_cells() -> list[dict]:
    """`on_exhausted: { queue: { max_ms } }` (pool oracle-q, one member, max_concurrent: 1): a
    bounded wait for the permit to free rather than an immediate shed, and the bounded-wait-expires
    arm when the member can never free it in time."""
    F = "queue"
    q_body = json.dumps({"model": "oracle-q", "messages": [{"role": "user", "content": "ping"}]},
                         separators=(",", ":"), sort_keys=True)
    return [
        concurrent("queue|serve|n3", F, "POST", "/v1/chat/completions", 3, body=q_body, fresh=True,
                   why="on_exhausted: queue{max_ms: 4000}: 1 admitted immediately, the other 2 queue "
                       "on the freed permit and are served once the first request completes — all "
                       "200; busbar_pool_queued is the park-depth gauge for this"),
        concurrent("queue|timeout|n2", F, "POST", "/v1/chat/completions", 2, body=q_body, fresh=True,
                   config_variant="queue-timeout", mock_control={"m-queue-lane": "slow"},
                   why="queue.max_ms shrunk to 50ms against a `slow` member that never frees its "
                       "permit in time: the bounded wait expires and the queued request falls "
                       "through to the pool's on_exhausted 503 + Retry-After, same shape as an "
                       "immediate shed"),
    ]


def cooldown_cells() -> list[dict]:
    """Trip pool oracle-cd's one member (mock `down`, base_cooldown_secs 1, consecutive_n 1), settle
    the mock, wait past the jittered cooldown, and send the same request again: served 200. Fully
    self-contained (scripts/cooldown-trip.sh boots its own busbar on its own ports), because the
    sleep-past-cooldown step needs precise timing no shared-boot bookkeeping here provides."""
    return [{
        "id": "cooldown|trip-then-serve", "plane": "core", "family": "cooldown", "driver": "script",
        "script": {"name": "cooldown-trip.sh"}, "outcome": "ok",
        "why": ("base_cooldown_secs 1: a tripped member is refused (503, nothing billed), then once "
                "the jittered cooldown elapses the SAME request is served (200, billed) — the "
                "breaker's own trip-then-recover cycle. Proven on the CUMULATIVE counters "
                "busbar_breaker_trips_total / busbar_upstream_failures_total, which survive the "
                "scrape-time busbar_lane_state gauge settling back to its starting value (0 -> 2 -> "
                "0) by the time this cell's one before/after snapshot is taken, plus the "
                "requests-vs-billable_requests split in the usage delta."),
    }]


def crosscut_traps_cells() -> list[dict]:
    """`crosscut.traps`: five cells that each pin ONE value the normalizer would otherwise strip or
    blank by default (`keep` on the cell — see normalize.py's `--keep`), because for these five the
    value itself, not just its presence/shape, is the parity contract a byte-diff would otherwise
    silently hide. Each is a real request against the same oracle config every other core cell uses."""
    F = "crosscut.traps"
    chat = lambda model: json.dumps({"model": model, "messages": [{"role": "user", "content": "ping"}]},
                                     separators=(",", ":"), sort_keys=True)
    cells = []
    cells.append(http(
        "crosscut.traps|x-request-id-present", F, "POST", "/v1/chat/completions", body=chat("m-openai-chat"),
        keep={"headers": ["x-request-id"]},
        why="the generated x-request-id is present on a DATA-plane response, not only on admin/error "
            "envelopes: keep the header (id-normalized) so a binary that stops setting it on the happy "
            "path is a diff, not a silent pass through the normal hdr.date strip"))
    fo_body = chat("oracle-fo")
    trap = http("crosscut.traps|exhausted-retry-after-floor", F, "POST", "/v1/chat/completions", body=fo_body,
                 keep={"headers": ["retry-after"]},
                 why="every member of pool oracle-fo is driven down (mock `down` verb, same technique as "
                     "route.failover|fo|all-down): the on_exhausted 503's Retry-After is pinned instead of "
                     "blanked to <RETRY>, so the report can show its actual value and a regression that "
                     "floors it below 2 seconds (the breaker's own base_cooldown_secs is 15s, jittered) is "
                     "a visible diff, not hidden inside the usual retry-after normalization (PB-4)")
    trap["mock_control"] = {"m-openai-chat": "down", "m-anthropic": "down"}
    cells.append(trap)
    cells.append(http(
        "crosscut.traps|openapi-info-version", F, "GET", "/api/v1/admin/openapi.json",
        auth="admin", listener="admin", keep={"json_keys": ["info.version"]},
        why="the served OpenAPI document's own info.version literal (1.5.4 on 1.5.5, stale per the "
            "routes inventory) is pinned instead of being folded into <VERSION> by the generic "
            "ver.string rule, so a later binary that quietly bumps or fixes this frozen literal shows "
            "up as a diff either way"))
    quantile_cell = http(
        "crosscut.traps|request-duration-quantiles", F, "GET", "/metrics",
        keep={"text_regex": r'^busbar_request_duration_seconds\{[^}]*quantile='},
        why="three chat requests warm the summary, then /metrics is scraped: the QUANTILE LABEL SET "
            "busbar_request_duration_seconds publishes (which quantiles exist at all) is a contract "
            "even though each sampled duration is not -- keep those lines with the numeric value "
            "blanked to <DUR>, instead of the default metrics.timing rule dropping the whole sample")
    quantile_cell["request"]["pre"] = [
        {"method": "POST", "path": "/v1/chat/completions", "listener": "data", "auth": "ok",
         "headers": {"Content-Type": "application/json"}, "body": chat("m-openai-chat")}
        for _ in range(3)
    ]
    cells.append(quantile_cell)
    cells.append(http(
        # NOTE: the sibling admin.ops|GetPlugins|ok cell uses `?type=hook` (a pre-existing typo in
        # fixtures/admin-bodies.json, not owned here) and gets a 400 for it -- this trap uses the
        # binary's actual accepted value (`hooks`) so it exercises a real 200 with real items.
        "crosscut.traps|plugin-digests", F, "GET", "/api/v1/admin/plugins?type=hooks",
        auth="admin", listener="admin", config_variant="hooks", keep={"json_keys": ["items.digest"]},
        why="GET /api/v1/admin/plugins (hooks variant, the published headroom + webrequest plugins "
            "loaded): each item's digest is content-derived and pinned instead of being left to the "
            "generic scrubbing rules, so a later binary that reports a plugin's tarball as unchanged "
            "while its actual bytes moved is a diff"))
    return cells


def auth_lifecycle_cells() -> list[dict]:
    """`auth.lifecycle`: the three key-revoke/rotate/expiry scripts already committed under scripts/,
    each a self-contained boot on its own ports (mirrors plugins.store-persist|<name>'s own-boot
    script cell) proving the DATA-plane consequence of an admin lifecycle action, not just the shape
    of the admin response that triggered it."""
    F = "auth.lifecycle"
    return [
        {"id": "auth.lifecycle|key-revoke", "plane": "core", "family": F, "driver": "script",
         "script": {"name": "key-revoke.sh"}, "outcome": "ok", "weight": 10,
         "why": "revoke actually stops the data plane, not just the admin response: mint, spend (200), "
                "revoke, spend again with the same token -> the ingress-native 401, and the usage delta "
                "shows the revoked spend billed nothing"},
        {"id": "auth.lifecycle|key-rotate", "plane": "core", "family": F, "driver": "script",
         "script": {"name": "key-rotate.sh"}, "outcome": "ok", "weight": 10,
         "why": "rotate cuts the OLD token over immediately (no grace period) and the NEW token is live "
                "at once on the same node: mint, spend with the old token (200), rotate, spend with the "
                "old token again (401, no grace), spend with the new token (200); usage shows exactly "
                "the two served spends billed"},
        {"id": "auth.lifecycle|key-expiry", "plane": "core", "family": F, "driver": "script",
         "script": {"name": "key-expiry.sh"}, "outcome": "ok", "weight": 10,
         "why": "minting a key with expires_at in the past (Unix epoch + 1): 1.5.5 never enforces a "
                "stored key-level expiry on the request path, only a signed token's own exp claim, so "
                "the admin API's own expires_at-must-be-future validation makes this expiry path "
                "unreachable through the admin API (400 at mint, spend never attempted) — recorded as "
                "the real outcome rather than assumed from the design doc"},
    ]


def teller_cells() -> list[dict]:
    """`teller`: H2 -- one named cell per Teller step (ARCHITECTURE.md #2.2), llm plane, each its own
    self-contained boot (script driver, mirrors auth.lifecycle's own-boot shape) so a step's cell can
    assert the ORDER around it (what happened before/after) rather than just one response's shape.
    1.5.5 carries no "Teller" vocabulary, but it already realises the order these cells name -- every
    cell here is recorded against, and must PASS on, the published 1.5.5 golden."""
    F = "teller"
    return [
        {"id": "teller|authenticate-refusal", "plane": "llm", "family": F, "driver": "script",
         "script": {"name": "teller-authenticate-refusal.sh"}, "outcome": "ok", "weight": 10,
         "why": "step 1 AUTHENTICATE: a bad credential is refused before step 2 VERIFY is ever "
                "reached -- native 401, zero upstream egress recorded, zero usage drawn"},
        {"id": "teller|verify-refusal", "plane": "llm", "family": F, "driver": "script",
         "script": {"name": "teller-verify-refusal.sh"}, "outcome": "ok", "weight": 10,
         "why": "step 2 VERIFY: a credential whose allowed_pools excludes the target pool is refused "
                "before step 4 ADMIT ever draws a bucket -- native 403, zero egress, zero usage delta"},
        {"id": "teller|admit-refusal", "plane": "llm", "family": F, "driver": "script",
         "script": {"name": "teller-admit-refusal.sh"}, "outcome": "ok", "weight": 10,
         "why": "step 4 ADMIT: a principal already past authenticate/verify/approve but over budget "
                "is refused before step 5 ROUTE ever dials -- native 429, zero further egress, zero "
                "further usage/spend delta on the refused call"},
        {"id": "teller|route-failover", "plane": "llm", "family": F, "driver": "script",
         "script": {"name": "teller-route-failover.sh"}, "outcome": "ok", "weight": 10,
         "why": "step 5 ROUTE: the first lane in a pool is down, the walk fails over to the next "
                "verified destination within the same unit -- one served terminal, one egress on the "
                "live lane, exactly one usage posting even though two lanes were attempted"},
        {"id": "teller|meter-row", "plane": "llm", "family": F, "driver": "script",
         "script": {"name": "teller-meter-row.sh"}, "outcome": "ok", "weight": 10,
         "why": "step 6 METER: a single served request settles to a usage delta of exactly one "
                "request, with the priced token/spend figures matching the mock's fixed response, "
                "never a partial or doubled posting"},
        {"id": "teller|audit-record", "plane": "llm", "family": F, "driver": "script",
         "script": {"name": "teller-audit-record.sh"}, "outcome": "ok", "weight": 10,
         "why": "step 7 AUDIT: a governed mutation seals its own audit record -- the chain gains "
                "exactly one entry naming the right action and outcome, first entry's prev_hash empty"},
        {"id": "teller|exit-terminal", "plane": "llm", "family": F, "driver": "script",
         "script": {"name": "teller-exit-terminal.sh"}, "outcome": "ok", "weight": 10,
         "why": "exit: a unit relaying multiple response frames (a streamed answer) still settles to "
                "exactly one terminal and one usage posting -- no post per frame, no late double-post"},
    ]


def neutrality_cells() -> list[dict]:
    """`neutrality`: the oracle's own baseline config is already 1.5.5-shaped (no mcp:/agents:/
    streams: section — see oracle-config.sh), so these cells pin the operator-visible surfaces that
    must stay IDENTICAL when a binary with every plane compiled in boots it: the boot banner, the
    /metrics series set, every deny_unknown_fields section's own accepted-key list, the route set,
    and an idle boot's in-flight accounting. A later binary that starts a plane, mounts a route, or
    emits a series just because it CAN, without the operator asking for it, is a diff here."""
    F = "neutrality"
    cells = []
    # (a) the boot banner: RUST_LOG=info pinned explicitly (not the recorder's default `warn`) so the
    # golden and candidate are compared at the same verbosity regardless of any default-filter drift;
    # `body_lines` keeps only lines the tracing formatter tagged INFO/WARN/ERROR, in emission order —
    # a line that only shows at DEBUG (Bootstrap/Migration/Policy/keyset) must stay invisible here.
    cells.append(exec_(
        "neutrality|boot-lines", F, args=[], mode="boot", config="baseline", env={"RUST_LOG": "info"},
        body_lines=r"\b(INFO|WARN|ERROR)\b",
        why="the exact ordered set of boot log lines at INFO and above on a pure 1.5.5-shaped config "
            "(no mcp/agents/streams section) — every 1.6.0-additive plane stays silent and out of order"))
    # (b) /metrics: the published series NAMES + TYPES (the `# HELP` / `# TYPE` preamble lines,
    # sample values already dropped by metrics.shape) plus an explicit absence check for any plane
    # series, so a plane compiled in but never configured cannot register even an empty series.
    cells.append(http(
        "neutrality|metrics-series", F, "GET", "/metrics", body_lines=r"^# (HELP|TYPE) ",
        why="the /metrics series NAME + TYPE set on a pure 1.5.5-shaped config: no busbar_plane_* or "
            "ledger series may appear just because the binary can compile them in"))
    cells.append(http(
        "neutrality|metrics-no-plane-series", F, "GET", "/metrics",
        body_lines=r"^busbar_(plane|ledger|journal|hold|wal)_",
        why="an ABSENCE contract like ops.scrape's own ledger check, extended to the plane-prefixed "
            "series: the golden is an empty body, and any surviving line on a later binary is a diff"))
    # (c) unknown-key `expected one of` lists: the top-level struct plus every NAMED-MAP section that
    # actually appears in a 1.5.5-shaped config, fed one bogus sibling key each — added to
    # fixtures/boot-mutations.json under family "neutrality" (ids NEUT-U-*) so boot_cells() below
    # already turns each into its own `neutrality|NEUT-U-<section>|validate` cell; nothing to add here.
    # (d) the route set on a plane-neutral config: the operational routes plus a 404 on a path shaped
    # like an unconfigured plane's own mount — proves the route table gained nothing it was not asked
    # for, not merely that the configured routes still answer.
    cells.append(http("neutrality|routes|stats", F, "GET", "/stats",
                       why="the pool/lane topology route answers on a plane-neutral config exactly as the "
                           "operational-routes rule in ARCHITECTURE.md describes"))
    cells.append(http("neutrality|routes|healthz", F, "GET", "/healthz", auth="none",
                       why="unconditional bypass, unaffected by which planes are compiled in"))
    cells.append(http("neutrality|routes|v1-models", F, "GET", "/v1/models",
                       why="the openai-envelope model listing on a plane-neutral config"))
    cells.append(http("neutrality|routes|admin-openapi-paths", F, "GET", "/api/v1/admin/openapi.json",
                       auth="admin", listener="admin", keep={"json_keys": ["paths"]},
                       why="the served path list: absent mcp:/agents:/streams: sections, the document "
                           "must list only the 1.5.5 admin surface — the `paths` object is kept raw "
                           "(no version/id scrubbing under it) so an added path is a visible diff"))
    cells.append(http("neutrality|routes|mcp-shaped-404", F, "GET", "/mcp",
                       why="no mcp: block is configured: the MCP plane's own mount path falls through "
                           "to the ordinary path-inferred 404 like any other unmatched path"))
    cells.append(http("neutrality|routes|a2a-shaped-404", F, "GET", "/.well-known/agent-card.json",
                       why="no agents: block is configured: the A2A well-known agent-card path is unmounted"))
    cells.append(http("neutrality|routes|voice-shaped-404", F, "GET", "/v1/realtime",
                       why="no streams: block is configured: the voice plane's realtime-shaped path is unmounted"))
    # (e) /stats in-flight accounting at rest: an explicit FRESH boot (never sharing state with an
    # earlier cell) so every lane's inflight/free_slots fields are pinned at their idle value — the
    # absence of any reserved headroom a session-transport plane would otherwise draw against.
    stats_idle = http("neutrality|stats-idle-zero", F, "GET", "/stats",
                       why="on an idle fresh boot every lane's in-flight fields read their zero/unbounded "
                           "rest state: no session-transport plane is claimed, so nothing is pre-reserved")
    stats_idle["fresh"] = True
    cells.append(stats_idle)
    return cells


def main() -> int:
    minv = json.loads(METHOD_INV.read_text())
    finv = json.loads(FIELD_INV.read_text())
    cells = sorted(llm_cells(finv) + protocol_cells(minv) + cli_cells() + migrate_cells()
                   + scrape_cells() + crosscut_cells() + admin_cells() + boot_cells() + failover_cells()
                   + plugin_cells() + billing_cells() + hooks_cells()
                   + concurrency_cells() + queue_cells() + cooldown_cells()
                   + crosscut_traps_cells() + auth_lifecycle_cells() + teller_cells() + neutrality_cells(),
                   key=lambda c: c["id"])
    ids = [c["id"] for c in cells]
    assert len(ids) == len(set(ids)), "cell ids must be unique"
    doc = {
        "_comment": [
            "GENERATED by testing/shadow-oracle/enumerate-cells.py. Do not edit by hand.",
            "Regenerate: testing/shadow-oracle/enumerate-cells.py --write",
            "One cell = one recorded (request, response, effects) triple the shadow oracle replays.",
        ],
        "derived_from": {"method_inventory": str(METHOD_INV.relative_to(ROOT)),
                          "field_inventory": str(FIELD_INV.relative_to(ROOT))},
        "outcomes": [{"outcome": o, "why": w} for o, w in OUTCOMES + STREAMING_OUTCOMES + [ARRAY_STREAM_OUTCOME]],
        "counts": {
            "total": len(cells),
            "by_plane": {p: sum(1 for c in cells if c["plane"] == p) for p in sorted({c["plane"] for c in cells})},
            "by_family": {f: sum(1 for c in cells if c.get("family", c["plane"]) == f)
                          for f in sorted({c.get("family", c["plane"]) for c in cells})},
        },
        "cells": cells,
    }
    if "--summary" in sys.argv or "--write" not in sys.argv:
        print(json.dumps(doc["counts"], indent=2))
    if "--write" in sys.argv:
        OUT.write_text(json.dumps(doc, indent=2) + "\n")
        print(f"wrote {OUT.relative_to(ROOT)} ({len(cells)} cells)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
