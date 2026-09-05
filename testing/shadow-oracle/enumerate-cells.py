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
ADMIN_BODIES = FIXTURES / "admin-bodies.json"
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
            pre = pre_chain(opid)
            if pre:
                c["request"]["pre"] = pre
            cells.append(c)
            if op.get("idempotent"):
                c2 = json.loads(json.dumps(c)); c2["id"] = f"admin.ops|{opid}|idempotent-replay"
                c2["request"]["repeat"] = 2; c2["why"] = "same Idempotency-Key twice: the replay returns the first response (PB-21)"
                cells.append(c2)
            if op.get("if_match") and stale:
                for kind in ("stale", "malformed"):
                    c3 = json.loads(json.dumps(c)); c3["id"] = f"admin.ops|{opid}|if-match-{kind}"
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
        http("hooks|admin-list", F, "GET", "/api/v1/admin/hooks", auth="admin", listener="admin", why="registry with the loaded hook", config_variant=V),
        http("hooks|unhooked-pool|ok", F, "POST", "/v1/chat/completions", body=json.dumps({"model": "m-openai-chat", "messages": [{"role": "user", "content": "ping"}]}), why="a pool without the hook is untouched", config_variant=V),
    ]


def main() -> int:
    minv = json.loads(METHOD_INV.read_text())
    finv = json.loads(FIELD_INV.read_text())
    cells = sorted(llm_cells(finv) + protocol_cells(minv) + cli_cells() + migrate_cells()
                   + scrape_cells() + crosscut_cells() + admin_cells() + boot_cells() + failover_cells()
                   + plugin_cells() + billing_cells() + hooks_cells(),
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
