#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""busbar's OWN oracle cell list — the DATA half of `busbar-oracle cells`, never the engine.

The oracle records the current binary's exact behavior (bytes + effects) per cell and replays it
against any later binary. Its cell list must be a function of what busbar claims to support, so a
new method, dialect or transport becomes a new cell automatically (an uncovered cell is RED), and
no one can forget one.

WHY THIS IS A PYTHON MODULE AND NOT A FROZEN JSON FILE. 1380 of the 2316 cells are DERIVED by
looping over qa/method-inventory.json, 138 by globbing tests/migration-corpus/from-tags/*.yaml and
240 by branching over fixtures/admin-bodies.json. Freezing the result to JSON would destroy the one
invariant this file exists to enforce — that a new method IS a new cell, with nobody in the loop.

WHAT LIVES HERE AND WHAT DOES NOT. Everything here is a fact about BUSBAR: the outcome vocabulary,
the fixture paths, the literal tables, the three cell constructors (which hardcode busbar's
`plane: "core"` and its auth/listener vocabulary), and the 22 builders. Nothing here knows how the
generator RUNS — no argument parsing, no byte-compare, no floor check, no write. That half is the
product-agnostic engine, `busbar-oracle cells` (enumerate-cells.py in GetBusbar/busbar-oracle).

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
Cells may carry `compare: [classes]` when part of their output is inherently random — the differ
then judges only those classes; `fresh: true` boots a new busbar first. `compare` is POLICED, in
diff-cells.py's check_compare_policy(): it is a whitelist, so what it drops is everything it does
not name, and it may only drop classes OUTSIDE MONEY_CLASSES and never effects.files/effects.script;
the cell must carry a `why`; and the dropped classes are printed on the cell's report row as
`narrowed: [...]` so a narrow PASS never reads as a whole one. If output is merely non-deterministic,
normalize it in normalize.py (which is how the signing key stopped needing a `compare` at all) —
reach for `compare` only when there is nothing left to normalize.

A cell may also carry `bindings: [PB-N, ...]`: the Appendix B parity rows it proves. That list is
READ BY A PROGRAM — the design-bindings gate scans each cell for its `PB-N` tokens and derives
the binding's oracle checks from what it finds — so it is a field, not an aside in the cell's
`why`. The distinction is not cosmetic: as a parenthetical in prose (`(PB-43/70)`) it was
unqueryable, it constrained how the sentence could be written, and the `/`-joined spelling meant
the derivation silently saw only the first row of the pair. As data it is exact, and `why` goes
back to being one plain-English line about what the cell pins.

Each protocol cell is crossed with the OUTCOME CLASSES the governed path must reproduce
byte-for-byte: the happy path plus every refusal the core pipeline can emit before/around it.

-- THE CONTRACT WITH THE ENGINE --------------------------------------------------------------
The engine imports this file by path ($BUSBAR_ORACLE_DATA/cells/__init__.py), calls `bind()`, then
reads the exports below and calls the builders in order. It knows no builder's name, no fixture's
name and no inventory's name; every one of those is a busbar fact and stays on this side.

  bind(root, data)      set ROOT (the product repo root) and DATA (this directory), and derive every
                        fixture/inventory path and DERIVED_FROM from them. MUST be called first.
  ROOT, DATA: Path      set by bind(); the builders read them, nothing infers them.
  COMMENT: list[str]    the `_comment` lines of the generated cells.json header. Busbar's own text,
                        so it lives here — including the two lines that still name
                        `testing/shadow-oracle/enumerate-cells.py`, kept byte-for-byte because
                        cells.json's bytes are the contract and a header rewording is a diff.
  DERIVED_FROM: dict    the `derived_from` block: the inventories, product-root-relative.
  OUTCOME_ROWS: list    the `outcomes` block, already flattened to {"outcome":…, "why":…}.
  BUILDERS: list        ordered (name, callable); each callable takes nothing and returns list[dict].
  SHRINK_PROBE: callable() -> (list[dict], set[str])
                        the engine's --selftest hazard: repoint ONE family's fixture at a path that
                        cannot exist, call its real builder, and hand back what it yielded (it must
                        be []) together with the family names that builder owns. This is how the
                        floor check is proven to discriminate without the engine naming a busbar
                        builder or a busbar fixture.

Output: testing/shadow-oracle/cells.json  (stable ids, sorted; the recorder/replayer iterate it).
Regenerate: bin/oracle cells --write   (--check, --summary, --selftest, --accept-family-shrink).
"""
import json
from pathlib import Path

# Set by bind(). Never derived from __file__: this module is data the engine loads by path, so its
# own position says nothing about where the product it describes lives.
ROOT: Path = None      # the product repo root (busbar)
DATA: Path = None      # the product's oracle data dir (testing/shadow-oracle)


def bind(root: Path, data: Path) -> None:
    """Bind this module to a product checkout. The engine calls this before any builder runs."""
    global ROOT, DATA, METHOD_INV, FIELD_INV, MIGRATION_CORPUS, FIXTURES
    global ADMIN_BODIES, ADMIN_READBACK, BOOT_MUTATIONS, PLUGIN_DIGESTS, DERIVED_FROM
    ROOT = Path(root)
    DATA = Path(data)
    METHOD_INV = ROOT / "qa" / "method-inventory.json"
    FIELD_INV = ROOT / "qa" / "field-inventory.json"
    MIGRATION_CORPUS = ROOT / "tests" / "migration-corpus" / "from-tags"
    FIXTURES = DATA / "fixtures"
    ADMIN_BODIES = FIXTURES / "admin-bodies.json"
    ADMIN_READBACK = FIXTURES / "admin-readback.json"
    BOOT_MUTATIONS = FIXTURES / "boot-mutations.json"
    PLUGIN_DIGESTS = DATA / "plugin-digests.tsv"
    DERIVED_FROM = {"method_inventory": str(METHOD_INV.relative_to(ROOT)),
                    "field_inventory": str(FIELD_INV.relative_to(ROOT))}


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
# The mid-stream failure: the upstream sent N good events and THEN an in-band error (or died). The
# response has already begun, so the refusal cannot be a status code — it has to be translated into
# the door's own stream dialect, and the tokens already delivered have to be billed or refunded.
STREAM_UPSTREAM_ERROR_OUTCOME = (
    "stream_upstream_error",
    "the upstream fails PART WAY THROUGH a stream: N good events, then an in-band error event")

# TWO SHAPES THE HAPPY-PATH FIXTURES DO NOT CARRY. `ok` sends a bare `ping` and the mock answers with
# bare text, so two whole surfaces are unrecorded: an ANSWER that annotates its text with a source,
# and a REQUEST whose content array mixes a cache marker with a native attachment. Both are ordinary
# 200s — nothing about them is an error path — which is exactly why a golden built from `ping` never
# sees them, and why a codec defect in either is invisible to the differ.
RESPONSES_CITATION_OUTCOME = (
    "ok_citation",
    "happy path whose ANSWER carries a URL citation: the Responses annotation the published "
    "UrlCitationBody FLATTENS onto the annotation object, which the `ok` fixture's bare-text answer "
    "never exercises")
GEMINI_TOOL_USE_TOKENS_OUTCOME = (
    "ok_tool_use_tokens",
    "happy path whose ANSWER reports `usageMetadata.toolUsePromptTokenCount`: the server-side "
    "tool-use token term Vertex reports BESIDE `promptTokenCount` (measured 32 against an 18-token "
    "prompt on a real capture), which the `ping` fixture's tool-less answer never produces and "
    "which is therefore the one money term no recorded cell can see")
BEDROCK_CACHEPOINT_DOCUMENT_OUTCOME = (
    "ok_cachepoint_document",
    "happy path whose REQUEST puts a `cachePoint` BEFORE a native `document` block: a wire slot that "
    "yields no IR block, ahead of a block the reader parks by wire position — the index-space "
    "disagreement the `ping` fixture's single text block cannot produce")


# Refusals are produced BEFORE Route, so they never depend on the egress dialect: enumerate them
# same-proto only (ingress == egress). Forwarded outcomes reach Route and exercise the cross-protocol
# translation the LLM plane exists for: enumerate EVERY ordered (ingress, egress) dialect pair.
PRE_ROUTE = {"unauthenticated", "out_of_scope", "over_budget", "malformed"}

# The group BUDGET arm of Admit, as distinct from `over_budget` above (which is the group's
# `requests` cap — checked FIRST, so a bucket that also carries a requests cap can never surface its
# own budget exhaustion). Driven by a sibling group whose ONLY limit is a `budget` total a single
# priming request already exceeds: `governance::state` checks `requests` before `budget`, so
# omitting the requests cap is what makes the block land on `metric: "budget"` (KIND_INSUFFICIENT_QUOTA)
# rather than `metric: "requests"` (KIND_RATE_LIMIT) — the two refusals share a 429 status but the
# Anthropic writer projects them into DIFFERENT wire types (`rate_limit_error` vs `billing_error`;
# crates/busbar-llm-codec/src/anthropic/writer.rs), so a golden that never exercises the budget arm
# can never catch a regression there. LLM-only: no other family's oracle config has this group.
OVER_BUDGET_TOTAL = (
    "over_budget_total",
    "group BUDGET total already exhausted, no per-day request cap on the bucket -> refused at "
    "Admit (native 429, metric: budget, names the bucket) -- distinct from `over_budget`'s "
    "requests-cap refusal; the Anthropic-dialect projection is `billing_error`, not `rate_limit_error`",
)


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
        cells.append(cell(d, d, *OVER_BUDGET_TOTAL))
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
    # The stream that FAILS after it has already started. Every other upstream_down cell refuses
    # before a byte is sent, so the whole mid-stream arm — what the door emits after N good frames,
    # whether the connection is closed or an in-band error frame is translated into the door's own
    # dialect, and (money) whether the tokens already delivered are billed or refunded — is
    # unrecorded. One cell per BACKEND on its own door (the diagonal): the backend decides what the
    # error looks like on the wire, the door decides what the client is told, and the diagonal
    # covers all six of each. SKIP-able until the recorder drives mock-upstream.py's `stream-error`
    # verb (added alongside this cell); the golden is recorded from the published 1.5.5 binary by
    # the integrator, so nothing is recorded here.
    # gemini is not in the inventory's `streams` set (its streaming is the path-selected
    # streamGenerateContent framing, not a `streaming` field), but it streams, and a mid-stream
    # failure is exactly as unrecorded there — so it gets the cell too: all six backends.
    for d in dialects:
        if d not in streams and d != "gemini":
            continue
        c = cell(d, d, *STREAM_UPSTREAM_ERROR_OUTCOME)
        c["needs_fixture"] = True
        c["mock_control"] = {"stream-error": True}
        cells.append(c)
    # THE TWO SHAPES THE HAPPY-PATH FIXTURES DO NOT COVER. Same SKIP-able posture as the mid-stream
    # failure above: definitions only, `needs_fixture` until the integrator records them from the
    # published 1.5.5 binary, so each reads as a NAMED golden gap rather than a silent pass.
    #
    # THE CITATION, on the DIAGONAL (responses -> responses). The annotation is a property of the
    # ANSWER, so the egress dialect is what decides its shape; the diagonal is the striking case
    # because a same-dialect hop READS BACK bytes it has just written, so a reader that only knows
    # the nested Chat spelling drops an annotation its own writer produced in the flat one. Driven by
    # the mock's `citation` verb, which answers with the published flat `UrlCitationBody`.
    if "responses" in dialects:
        c = cell("responses", "responses", *RESPONSES_CITATION_OUTCOME)
        c["needs_fixture"] = True
        c["mock_control"] = {"citation": True}
        cells.append(c)
    # THE cachePoint-BEFORE-A-DOCUMENT REQUEST. Bedrock-shaped both ends: `cachePoint` and the native
    # `document` block are Converse's own vocabulary, so only the bedrock DOOR can receive one, and
    # only the bedrock EGRESS can emit one. Nothing about the answer matters here — the whole cell is
    # what busbar SENDS UPSTREAM, which the recorder captures alongside the response. No mock verb:
    # the fixture is the request body, built by build-request.py.
    if "bedrock" in dialects:
        c = cell("bedrock", "bedrock", *BEDROCK_CACHEPOINT_DOCUMENT_OUTCOME)
        c["needs_fixture"] = True
        cells.append(c)
    # THE TOOL-USE TOKEN TERM, on the DIAGONAL (gemini -> gemini). Google reports
    # `usageMetadata.toolUsePromptTokenCount` as a FOURTH ADDITIVE term beside `promptTokenCount`,
    # not as a slice of it -- measured, on real Vertex bytes, at 32 against an 18-token prompt
    # (crates/busbar-llm-codec/src/tests/proto/golden/vendor/, and
    # docs/design/gemini-usage-metadata-spec-discrepancy.md). 1.5.5 read it as a slice and dropped
    # it from the bill, under-counting every server-tool Gemini turn by exactly that term; 1.6.0
    # bills it in the input tier. NOT ONE RECORDED CELL SEES THAT: the mock's happy-path answer
    # carries no tool-use term at all, so the whole money surface is invisible to the differ, which
    # is precisely how a 14% under-count survived a full golden. The diagonal is the striking case
    # because a same-dialect hop reads back bytes it has just written, so it pins the wire shape
    # (the term BESIDE the prompt count, `totalTokenCount` reconciling) and the ledger row together.
    # Same SKIP-able posture as the citation and cachePoint cells above — but WITH NO mock_control,
    # and that absence is the point. This cell used to declare `{"tool-use": true}`, a verb the
    # pinned mock does not implement; the mock's fallback for a control it cannot resolve is a
    # HEALTHY 200, so the cell would have recorded the tool-less happy path while claiming to pin the
    # tool-use token term. Rather than invent a verb here, the control is dropped and the cell stays
    # `needs_fixture`, exactly like the bedrock cachePoint cell above whose fixture is also the only
    # thing it is waiting on. The gap is NAMED in accepted-gaps.json ("needs a tool-use verb in the
    # pinned mock; product decision on the six-dialect tool-use response shape"): recording it needs
    # both a mock that answers with `usageMetadata.toolUsePromptTokenCount` AND that product
    # decision, neither of which the oracle may make for itself.
    if "gemini" in dialects:
        c = cell("gemini", "gemini", *GEMINI_TOOL_USE_TOKENS_OUTCOME)
        c["needs_fixture"] = True
        cells.append(c)
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


# MIGRATION_CORPUS, FIXTURES and the fixture paths below are BOUND BY bind(), never derived from
# this file's own position: the engine is a separate tool and only the product knows where its
# data lives. See the module docstring.


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
    """Every first-argument dispatch of 1.5.5 (the ops inventory's CLI-dispatch rows): exit code + stdout/stderr bytes."""
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
        # NO `compare` HERE. It carried `compare: ["status"]` — "random key: only the exit code is a
        # contract" — and that was wrong twice over. (1) The key is not random by the time the differ
        # sees it: normalize.py's `audit.hash` rule already rewrites any hex run >= 32 to `<HASH>`,
        # so the golden's body for this cell is the literal `<HASH>\n` and compares exactly. (2) The
        # rest of the cell was never random at all, and status-only threw all of it away: the
        # operator guidance block this verb prints on stderr (the wiring instructions, and the
        # promise that the key itself is NOT echoed there so a CI log stays secret-free), the file
        # set the run left behind — a build that WRITES the key to disk instead of only printing it
        # would be a secret leak visible in `effects.files` and in nothing else — the egress, the
        # readback and the normalizer rules that fired. A `compare` list on the one verb that mints
        # a secret is the last place to be generous.
        exec_("cli|--generate-signing-key", F, args=["--generate-signing-key"], mode="cli",
              why="prints one ed25519 key (normalized to <HASH>) on stdout and the wiring guidance on stderr; exit 0"),
        exec_("cli|--print-metadata-blocklist", F, args=["--print-metadata-blocklist"], mode="cli", why="built-in denylist ∪ security.blocked_metadata_hosts"),
        exec_("cli|unknown-flag", F, args=["--definitely-not-a-flag"], mode="cli", why="unrecognized argument; exit 2"),
        exec_("cli|--safe-mode|first-arg", F, args=["--safe-mode"], mode="cli", why="1.5.5: unrecognized as a FIRST argument; exit 2", bindings=["PB-23"]),
        exec_("cli|env|BUSBAR_CONFIG-missing", F, args=["--validate"], mode="validate", config="missing",
              why="config path does not exist; [error] …; exit 1"),
        exec_("cli|env|RUST_LOG-crate-filter", F, args=["--validate"], mode="validate", env={"RUST_LOG": "busbar=debug"},
              why="bare tracing::Level only — a crate filter silently falls back", bindings=["PB-51"]),
    ]


def migrate_cells() -> list[dict]:
    """--migrate-config on every shipped config, then --validate of the migrated result."""
    cells = []
    for f in sorted(MIGRATION_CORPUS.glob("*.yaml")):
        tag = f.name.removesuffix("_config.yaml")
        rel = str(f.relative_to(ROOT))
        cells.append(exec_(f"config.migrate|{tag}|migrate", "config.migrate",
                           args=["--migrate-config", rel], mode="cli", config="none",
                           why="YAML to stdout, banner to stderr, exit 0/1/2", bindings=["PB-50"]))
        cells.append(exec_(f"config.migrate|{tag}|validate-migrated", "config.migrate",
                           args=["--validate"], mode="validate", config=f"migrated:{rel}",
                           why="the migrated document under --validate"))
    return cells


def scrape_cells() -> list[dict]:
    F = "ops.scrape"
    return [
        http("ops.scrape|/metrics|key", F, "GET", "/metrics", why="RouteAuth::Key; text/plain; version=0.0.4", bindings=["PB-43", "PB-70"]),
        http("ops.scrape|/metrics|none", F, "GET", "/metrics", auth="none", why="data-plane key auth refused"),
        # The contract is an ABSENCE: the body is filtered to the ledger/journal/hold/WAL series lines
        # only, so the 1.5.5 golden is an empty body and any such series on a later binary is a diff.
        http("ops.scrape|/metrics|no-ledger-series", F, "GET", "/metrics",
             body_lines=r"^busbar_(ledger|journal|hold|wal)_",
             why="no busbar_ledger_/journal_/hold_/wal_ series on a 1.5.5 config: the scrape keeps only those lines, so the golden is empty", bindings=["PB-13", "PB-15", "PB-17", "PB-41"]),
        http("ops.scrape|/metrics|admin-listener", F, "GET", "/metrics", auth="admin", listener="admin", why="admin router has no /metrics", bindings=["PB-76"]),
        http("ops.scrape|/metrics/hooks|key", F, "GET", "/metrics/hooks", why="core axum route; charset=utf-8", bindings=["PB-43"]),
        http("ops.scrape|/stats|key", F, "GET", "/stats", why="20 per-lane fields, 'unbounded', variant names", bindings=["PB-43"]),
        http("ops.scrape|/stats|none", F, "GET", "/stats", auth="none", why="auth chain applies"),
        http("ops.scrape|/healthz|data", F, "GET", "/healthz", auth="none", why="unconditional bypass; 200 ok"),
        http("ops.scrape|/healthz|admin", F, "GET", "/healthz", auth="none", listener="admin", why="same on the admin listener (the admin-listener parity rule)", inventory=["RT-003"]),
        http("ops.scrape|/v1/models|openai-fp", F, "GET", "/v1/models", why="openai envelope by fingerprint (no x-api-key rung)", bindings=["PB-100"]),
        http("ops.scrape|/v1/models|anthropic-fp", F, "GET", "/v1/models", headers={"anthropic-version": "2023-06-01"}, why="anthropic envelope"),
        http("ops.scrape|/v1/models|x-api-key", F, "GET", "/v1/models", headers={"x-api-key": "irrelevant"}, why="x-api-key is NOT a rung for /v1/models"),
        http("ops.scrape|/v1beta/models", F, "GET", "/v1beta/models", why="gemini listing"),
        http("ops.scrape|/v1/models|none", F, "GET", "/v1/models", auth="none", why="refused"),
        # A RUNG THAT DOES NOT EXIST, PINNED AS ABSENT. `/v1/models` (list) is served; the OpenAI
        # models resource also defines RETRIEVE, `GET /v1/models/{id}`, and 1.5.5 does not serve it:
        # the path matches no route on the data listener, so the answer is a 405 from the `/v1/models`
        # route's own method/path fallback, not a model-shaped 404. Without this cell nothing in the
        # corpus mentions the retrieve rung at all, and "the models surface is covered" would be a
        # claim resting on the LIST cells alone — so a later binary could start serving retrieve (or
        # start answering it 404, or 200 with a leaked model view) and every models cell would still
        # be green. The id is a model the config really defines, so a 405 here is the ROUTE refusing
        # the verb, never "that model does not exist".
        http("ops.scrape|/v1/models/id|retrieve", F, "GET", "/v1/models/m-openai-chat",
             why="1.5.5 has no retrieve rung on the models resource: GET /v1/models/{id} is 405, not a "
                 "model view — recorded so the llm plane's model rung can never claim it silently"),
    ]


# A body larger than request_body_max_bytes (32 MiB default). Never inlined: the recorder expands the
# marker at request time so cells.json stays reviewable.
BIG_BODY = "@oversize:33MiB"


def crosscut_cells() -> list[dict]:
    F = "http.crosscut"
    return [
        http("http.crosscut|unknown-path|bare", F, "POST", "/definitely/unknown", body="{}", why="catch-all: path-inferred 404", bindings=["PB-30"]),
        http("http.crosscut|unknown-path|openai-suffix", F, "POST", "/x/v1/chat/completions", body='{"model":"nope","messages":[]}', why="detects openai; unknown model"),
        http("http.crosscut|unknown-path|anthropic-header", F, "POST", "/whatever", headers={"anthropic-version": "2023-06-01"}, body="{}", why="detects anthropic by header presence"),
        http("http.crosscut|unknown-path|anthropic-beta", F, "POST", "/whatever", headers={"anthropic-beta": "x"}, body="{}", why="anthropic-beta is rung 2 too", bindings=["PB-30"]),
        http("http.crosscut|/api-prefix|data", F, "GET", "/api/v1/admin/nope", why="frozen admin envelope on the data listener", bindings=["PB-30"]),
        http("http.crosscut|/api|data", F, "GET", "/api", why="exact /api also forced"),
        http("http.crosscut|admin-unknown|admin", F, "GET", "/api/v1/admin/nope", auth="admin", listener="admin", why="nested not_found envelope", bindings=["PB-76"]),
        http("http.crosscut|admin-outside-prefix|admin", F, "GET", "/nope", auth="admin", listener="admin", why="outer admin router: empty-bodied 404", bindings=["PB-76"]),
        http("http.crosscut|admin-wrong-method|admin", F, "DELETE", "/api/v1/admin/info", auth="admin", listener="admin", why="method_not_allowed envelope"),
        http("http.crosscut|wrong-method|GET-messages", F, "GET", "/v1/messages", why="405 protocol-native (the protocol-native-status-code rule)", inventory=["RT-014"]),
        http("http.crosscut|OPTIONS|chat", F, "OPTIONS", "/v1/chat/completions", auth="none", why="no CORS layer ever; OPTIONS => None", bindings=["PB-100"]),
        http("http.crosscut|HEAD|healthz", F, "HEAD", "/healthz", auth="none", why="HEAD on a GET route"),
        http("http.crosscut|413|openai", F, "POST", "/v1/chat/completions", body=BIG_BODY, why="oversize after auth, dialect-shaped", bindings=["PB-60"]),
        http("http.crosscut|413|openai-unauth", F, "POST", "/v1/chat/completions", auth="none", body=BIG_BODY, why="unauthenticated oversize: 401 first", bindings=["PB-60"]),
        http("http.crosscut|413|anthropic", F, "POST", "/v1/messages", headers={"anthropic-version": "2023-06-01"}, body=BIG_BODY, why="anthropic envelope"),
        http("http.crosscut|413|api-prefix", F, "POST", "/api/v1/admin/keys", auth="admin", listener="admin", body=BIG_BODY, why="admin envelope discards status/kind", bindings=["PB-60"]),
        # The oversize refusal is produced BEFORE any plane sees the body, so its envelope is decided
        # by the door's own dialect detection. Three doors had no 413 cell at all, which is exactly
        # where a 1.6.0 plane that mounts its own body-limit layer would change the answer unseen.
        # SKIP-able (`needs_fixture`) until the recorder's config mounts the mcp:/agents: blocks:
        # on a 1.5.5 config those paths are unmounted and the cell would record the path-inferred
        # 404, not the 413 it is here to pin.
        http("http.crosscut|413|mcp-streamable-http", F, "POST", "/mcp", body=BIG_BODY,
             headers={"Content-Type": "application/json", "Accept": "application/json, text/event-stream"},
             needs_fixture=True,
             why="oversize on the MCP streamable-http mount: which envelope answers before the plane "
                 "is reached (JSON-RPC error vs the path-inferred dialect envelope) — needs a recorder "
                 "config that mounts the mcp: block"),
        http("http.crosscut|413|a2a-jsonrpc", F, "POST", "/a2a", body=BIG_BODY,
             headers={"Content-Type": "application/json"}, needs_fixture=True,
             why="oversize on the A2A JSON-RPC mount (busbar-a2a-codec MOUNT_PATH) — needs a recorder "
                 "config that mounts the agents: block"),
        # This one needs no new fixture — it is recordable on a 1.5.5 config today, and the golden
        # will owe it at the integrator's next re-record from the published binary. Until then it is
        # simply a cell the golden has no row for, i.e. a named gap, never a silent pass.
        http("http.crosscut|413|gemini-path", F, "POST", "/v1beta/models/m-gemini:generateContent",
             body=BIG_BODY,
             why="oversize on the gemini path: the gemini door detects by PATH, not by header or "
                 "body, so it is the one dialect whose 413 envelope the openai/anthropic cells above "
                 "cannot stand in for"),
        http("http.crosscut|auth-token|GET-none", F, "GET", "/auth/token", auth="none", why="browser exchange bypass", bindings=["PB-33"]),
        http("http.crosscut|auth-token|POST-empty", F, "POST", "/auth/token", auth="none", body="{}", why="flat {\"error\":…} envelope", bindings=["PB-100"]),
        http("http.crosscut|bearer-and-x-api-key", F, "GET", "/stats", headers={"x-api-key": "not-a-key"}, why="carrier precedence: Bearer wins", bindings=["PB-35"]),
        http("http.crosscut|x-api-key-only|bad", F, "GET", "/stats", auth="none", headers={"x-api-key": "not-a-key"}, why="second carrier, invalid"),
    ]


# admin.ops: for each operation of fixtures/admin-bodies.json a happy cell (with its `pre` setup chain),
# an unauthenticated cell, and where the fixture provides them a bad-body, a not-found, a stale
# If-Match, a malformed If-Match and an idempotent-replay cell. Every cell boots fresh, so the
# `order` of the fixture is turned into per-op PREREQUISITES (the earlier ops on the same resource).
# Every MUTATING op's happy cell (and its idempotent-replay copy) also carries a `request.post`: the
# follow-up GET named in fixtures/admin-readback.json, recorded as `effects.readback` after the write
# — so a 200 that wrote nothing shows up as a diff, not a pass.
# A path id far past the 64-character bound every `/keys/{id}` handler is documented to apply
# (`reject_overlong_id` -> 400 "id must be <= 64 characters"). 200 characters after the `vk_` prefix:
# long enough that no length bound between 1 and 200 can pass it, short enough to stay inside every
# URL-length limit in the stack, so a refusal here is the LENGTH GUARD and never a truncation
# somewhere else. Fixed bytes, so the cell is byte-stable across recordings.
OVERLONG_KEY_ID = "vk_" + "0" * 200
# ADMIN_BODIES / ADMIN_READBACK / BOOT_MUTATIONS: bound by bind().
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
        # The inventory rows this operation is pinned against, as data. Same reason `bindings` is a
        # field: inventory-coverage.py asks "does any cell cite this row id?", so a row id belongs
        # where a program can see it rather than inside a truncated note.
        inv = {"inventory": op["inventory"]} if op.get("inventory") else {}
        if op.get("restart"):
            # PostRestart ends the process; recorded as its own cell (fresh boot, expect 202 then exit)
            pass
        variant = op.get("variant")
        if op.get("ok"):
            c = http(f"admin.ops|{opid}|ok", F, op["method"], _path_of(op, op["ok"]),
                     auth="admin", listener="admin", headers=op["ok"].get("headers") or {},
                     body=_req_of(op, op["ok"])["body"], why=why, **inv,
                     **({"config_variant": variant} if variant else {}))
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
                c2["request"]["repeat"] = 2; c2["bindings"] = ["PB-21"]
                c2["why"] = "same Idempotency-Key twice: the replay returns the first response"
                cells.append(c2)
            if op.get("if_match") and stale:
                for kind in ("stale", "malformed"):
                    # a stale/malformed If-Match is a REFUSED write (409/400): no read-back, nothing changed
                    c3 = json.loads(json.dumps(c)); c3["id"] = f"admin.ops|{opid}|if-match-{kind}"
                    c3["request"].pop("post", None)
                    c3["request"]["headers"] = {**c3["request"]["headers"], stale.get("header", "If-Match"): stale[kind]}
                    c3["why"] = f"If-Match {kind}: {stale.get(kind + '_expect')}"
                    c3["bindings"] = ["PB-100"]
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
        # UNBOUNDED CALLER-SUPPLIED IDENTIFIER — the defect class this variant exists to pin. Every
        # `/keys/{id}` operation takes an opaque id straight off the URL and carries it into a store
        # lookup and into the audit `resource` string; two of them (rotate's idempotency cache) also
        # RETAIN it. The bound is `reject_overlong_id` (400, "id must be <= 64 characters"), and the
        # only way to know a handler still has it is to send an id past it, on the SAME otherwise
        # well-formed request the not-found cell sends, and record the refusal. A handler that lost
        # the guard does not fail loudly — it falls through to the not-found path and answers 404,
        # which reads like a perfectly ordinary refusal unless a cell is watching the five siblings
        # beside it. Six operations, six cells, no gaps: the guard is a per-handler call, so five
        # cells prove nothing about the sixth (that is exactly how the rotate gap survived).
        if "/keys/{id}" in op["path"]:
            cells.append(http(f"admin.ops|{opid}|overlong-id", F, op["method"],
                              op["path"].replace("{id}", OVERLONG_KEY_ID), auth="admin", listener="admin",
                              headers=(v.get("headers") or {}), body=_req_of(op, v)["body"] if v else None,
                              why="an unbounded caller-supplied identifier: a 203-character id on the "
                                  "`{id}` path segment. RECORDED TRUTH (published 1.5.5): five of the "
                                  "six `/keys/{id}` handlers refuse it 400 `invalid_request` / \"id "
                                  "must be <= 64 characters\" before the store lookup; "
                                  "PostKeysIdRotate — the one handler that never calls the bound — "
                                  "falls through to 404 `not_found` / \"key not found\", which is "
                                  "indistinguishable from an ordinary miss. On every one of the six "
                                  "the audit row is still written with the FULL id in `resource`, so "
                                  "the 400 bounds the lookup and the rotate idempotency cache key, "
                                  "not the audit string. See accepted-differences.json K-1"))

    # Three cells added for the ADMIN row of qa/teller-steps.json (the H2 Teller-step matrix): a fifth
    # plane, mapped onto the existing admin.ops family rather than a new one.
    #
    # verify/approve: the operator admin credential presented at the DATA listener. `chain: [keys]`
    # only recognizes a signed virtual key, so the raw admin secret is Denied before any budget bucket
    # is drawn -- the credential cannot reach a destination it was never scoped to reach. This is the
    # closest genuine proof the harness can produce today: a role-bound external admin identity
    # provider (the seam that would let a real insufficient-SCOPE 403 exist, as opposed to a wrong-
    # destination refusal) is not wired up here -- the harness only proves the auth-oidc plugin loads
    # (plugins.load|auth-oidc), not a working token-issuing flow -- so approve stays mapped to the same
    # cell rather than gaining an independent one.
    cells.append(http("admin.ops|admin-token|wrong-destination", F, "POST", "/v1/chat/completions",
                       auth="admin", listener="data", headers={"Content-Type": "application/json"},
                       body=json.dumps({"model": "m-openai-chat", "messages": [{"role": "user", "content": "ping"}]},
                                       separators=(",", ":")),
                       why="the admin operator credential is not a valid signed vkey on the data-plane "
                           "chain (keys); refused before Admit ever draws a budget bucket"))

    # admit: the Config rate class is limited to 10 mutating calls/min per bucket. PostConfigReload
    # carries no If-Match and no side effect beyond re-reading the same config.yaml, so it can be
    # hammered in one fresh boot without any other cell's state getting in the way. `repeat: 11`
    # records only the LAST response -- the 11th call in this boot's Config-class window.
    reload_cell = http("admin.ops|PostConfigReload|rate-limit", F, "POST", "/api/v1/admin/config/reload",
                        auth="admin", listener="admin",
                        why="the 11th Config-class mutation inside one boot's 60s window is refused "
                            "(429) before the reload itself runs -- CONFIG_CLASS_RULES, not the crate's "
                            "own Crud placeholder")
    reload_cell["request"]["repeat"] = 11
    cells.append(reload_cell)

    # meter: one mutating admin op (creating a group) posts no billing/usage delta at all, even though
    # the oracle's providers carry a non-zero per-request fee (the `billing` family's own cells price
    # every LLM request at 2.5 units). GET /api/v1/admin/usage after the ONE admin mutation, on an
    # otherwise-untouched fresh boot, is still the all-zero shape.
    usage_cell = http("admin.ops|GetUsage|no-usage-after-mutation", F, "GET", "/api/v1/admin/usage",
                       auth="admin", listener="admin",
                       why="admin operations are never billed: one PostGroups mutation leaves "
                           "/api/v1/admin/usage at its fresh-boot zero shape")
    usage_cell["request"]["pre"] = [{
        "method": "POST", "path": "/api/v1/admin/groups", "listener": "admin", "auth": "admin",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(ops["PostGroups"]["ok"]["body"], separators=(",", ":"), sort_keys=True),
    }]
    cells.append(usage_cell)
    return cells


# A10b (2026-09-05): boot rows whose precondition a single-exec mutation cannot produce — each needs
# a durable governance store already carrying state from a PRIOR boot (or a running process an admin
# call reaches) that the mutation's ONE config/env/args edit has no way to leave behind. Mapped by
# BOOT id to the script (in scripts/) that boots twice / reloads and captures the second outcome; see
# each script's own header for the exact mechanism and, for BOOT-173, why it is deliberately absent.
BOOT_SCRIPT_CELLS = {
    "BOOT-172": ("durable-governance-precondition.sh", ["budget-hydration"]),
    "BOOT-174": ("durable-governance-precondition.sh", ["dangling-group"]),
    "BOOT-175": ("durable-governance-precondition.sh", ["governance-init"]),
    "BOOT-W13": ("durable-governance-precondition.sh", ["inert-keys"]),
    "BOOT-W24": ("plugins-fetch-reload-miss.sh", []),
}


def boot_cells() -> list[dict]:
    """One cell per inventoried boot refusal/warning: the mutated config under --validate (mode both/
    validate) or a real boot (mode boot). A mutation the fixture could not express (op: null) is still
    a cell — the recorder records it as a named gap, never a pass. A row in BOOT_SCRIPT_CELLS instead
    gets a `driver: script` cell (see its comment) — the fixture exists, it just is not an
    apply-mutation.py op."""
    if not BOOT_MUTATIONS.exists():
        return []
    fx = json.loads(BOOT_MUTATIONS.read_text())
    cells = []
    for m in fx["mutations"]:
        fam = m.get("family", "boot.refusal")
        mode = "boot" if m.get("mode") == "boot" else "validate"
        args = ["--validate"] if mode == "validate" else []
        why = f"expect exit {m.get('expect', {}).get('exit')}; stderr ∋ {str(m.get('expect', {}).get('stderr_contains'))[:80]}"
        script = BOOT_SCRIPT_CELLS.get(m["id"])
        if script is not None:
            sname, sargs = script
            cells.append({"id": f"{fam}|{m['id']}|{mode}".replace("/", ""), "plane": "core",
                          "family": fam, "driver": "script", "outcome": "ok",
                          "script": {"name": sname, "args": sargs}, "why": why})
            continue
        cells.append(exec_(f"{fam}|{m['id']}|{mode}", fam, args=args, mode=mode,
                           config=f"mutation:{m['id']}",
                           why=why,
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
        fo("fo|all-up", "oracle-fo", {}, "SWRR over two members, 3:1", bindings=["PB-5", "PB-57"]),
        fo("fo|primary-down", "oracle-fo", {"m-openai-chat": "down"}, "first attempt 503 -> breaker trips (consecutive 1) -> failover to anthropic; 200", bindings=["PB-8", "PB-10"]),
        fo("fo|primary-5xx", "oracle-fo", {"m-openai-chat": "5xx"}, "500 disposition -> failover"),
        fo("fo|primary-429", "oracle-fo", {"m-openai-chat": "429"}, "upstream 429 with Retry-After 7: disposition + honor_retry_after floor", bindings=["PB-80"]),
        fo("fo|all-down", "oracle-fo", {"m-openai-chat": "down", "m-anthropic": "down"}, "every member fails -> on_exhausted default 503 + Retry-After", bindings=["PB-4"]),
        fo("fo|all-down-stream", "oracle-fo", {"m-openai-chat": "down", "m-anthropic": "down"}, "same, streamed request", stream=True),
        fo("fo|primary-slow", "oracle-fo", {"m-openai-chat": "slow"}, "attempt exceeds upstream_request_timeout? (default 300 s: NOT cut; the mock sleeps 8 s then answers) — records the real 1.5.5 wait", ),
        fo("fo|primary-cut-stream", "oracle-fo", {"m-openai-chat": "cut"}, "transport cut after the first SSE frame: stream_failed, tokens 0, lane unit not refunded", stream=True, bindings=["PB-27"]),
        fo("fo|primary-cut-body", "oracle-fo", {"m-openai-chat": "cut"}, "transport cut mid-body on a buffered response: 502, fee refunded", bindings=["PB-91"]),
        fo("fb|member-down", "oracle-fb", {"m-cohere": "down"}, "cohere down -> on_exhausted fallback_pool oracle-fo -> served by the hop; scoped draws on the ATTEMPTED pool", bindings=["PB-47"]),
        fo("fb|all-down", "oracle-fb", {"m-cohere": "down", "m-openai-chat": "down", "m-anthropic": "down"}, "hop exhausted too -> 503"),
        fo("fb|member-401", "oracle-fb", {"m-cohere": "401"}, "cohere answers 401: an auth hard-down on the member; what the caller sees and what the breaker records", bindings=["PB-83"]),
        fo("fb|member-down-stream-openai", "oracle-fb", {"m-cohere": "down"}, "a STREAM served by the fallback lane (oracle-fo's openai-chat member): the usage delta is the contract — a fallback stream must bill exactly as the hot path does", stream=True, weight=10),
        fo("lb|member-down", "oracle-lb", {"m-gemini": "down"}, "least_bad: one breaker-bypassing attempt against the tripped member", bindings=["PB-4"]),
        fo("lb|up", "oracle-lb", {}, "least_bad pool healthy"),
        fo("fo|second-request-after-trip", "oracle-fo", {"m-openai-chat": "down"}, "two requests in one boot: the second never tries the tripped member", pre_same=True),
    ]
    # the second-request cell needs a same-boot predecessor: an unrecorded identical request first
    for c in cells:
        if c.pop("pre_same", False):
            c["request"]["pre"] = [{"method": "POST", "path": "/v1/chat/completions", "listener": "data", "auth": "ok",
                                    "headers": {"Content-Type": "application/json"}, "body": body("oracle-fo")}]
    return cells


# PLUGIN_DIGESTS: bound by bind().

# store plugin -> the env var whose value is the connection URL for its backend. store-persist.sh
# reads the SAME map to build the plugin's `settings: { url: ... }`, so the cell's skip condition and
# the fixture it would use can never name different variables.
STORE_FIXTURE_ENV = {
    "store-postgres": "BUSBAR_TEST_POSTGRES_URL",
    "store-mysql": "BUSBAR_TEST_MYSQL_URL",
    "store-valkey": "VALKEY_URL",
}


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
                      "why": "--list-plugins with the published tarball: kind/alias/signature/STATUS line",
                      "bindings": ["PB-11"]})
        if n.startswith("store-"):
            # A store with a NETWORK backend cannot be recorded from the tree alone: it needs a live
            # service. Naming the env var that carries its URL (rather than a bare `true`) is what
            # lets the same cell be a named gap on a box that has no such service AND a real
            # recording on one that does — see record.sh, which skips only when the named var is
            # unset. The var is a STATIC property of the cell, so cells.json stays byte-identical
            # whether or not the service happens to be up when it is regenerated.
            needs = STORE_FIXTURE_ENV.get(n)  # None => recordable from the tree (sqlite)
            cells.append({"id": f"plugins.store-persist|{n}", "plane": "core", "family": "plugins", "driver": "script",
                          "script": {"name": "store-persist.sh", "args": [n]}, "outcome": "ok",
                          "why": "validate, boot, mint, spend, restart, read back (persistence is the job)",
                          "bindings": ["PB-11", "PB-37", "PB-93"],
                          **({"needs_fixture": needs} if needs else {})})
    return cells


# The oracle config's rate card at ONE HUNDRED TIMES its booted rates (oracle-config.sh prices every
# model at input 100000 / output 200000 micro-units per token and sets no per-request fee), plus a
# per_request_fee the boot config does not have at all.
#
# THE FIGURES ARE THE DISCRIMINATOR, so they are chosen to make the three hypotheses arithmetically
# distinct rather than merely "different". The mock answers every request with the same 11 in / 7 out,
# so one request costs 11*100000 + 7*200000 = 2,500,000 micros under the BOOT card and
# 11*10,000,000 + 7*20,000,000 + a 3-cent fee (30,000 micros) = 250,030,000 under the WRITTEN one.
# Four requests reach /admin/usage in this cell (two the recorder primes at boot, one before the PUT,
# one after):
#
#   read-time derivation, whole ledger repriced  -> total 1,000,120,000  (4 x 250,030,000)
#   priced per row at charge time                -> total   257,530,000  (3 x 2,500,000 + 250,030,000)
#   restart-to-apply, card never applied         -> total    10,000,000  (4 x 2,500,000)
#
# Two rows at the same price could not tell those apart; these totals share no leading digits.
#
# UNITS, since they are not the same field to field: `rate_card`'s *_utok are MICRO-units per token,
# `spend_micros` is micro-units, and `per_request_fee` is an i64 in CENTS — 1 cent = 10,000 micros,
# 1 cost unit = 100 cents = 1,000,000 micros. Recorded, not assumed: a first pass set the fee to
# 7,000,000 meaning "7 units" and it landed as 70,000,000,000 micros per request, which put the
# `oracle` group (budget 1,000,000/day) over its cap and got the SECOND chat request refused 429 —
# the cell then had three rows instead of four and proved nothing about the epoch. 3 cents keeps
# every request inside the budget, so all four rows are present to be priced.
#
# COMPLETE ON PURPOSE, not for tidiness: 1.5.5 refuses a partial card outright — "rate_card is
# AUTHORITATIVE and COMPLETE: you either price nothing or price everything" — with a 400, and a
# rate-card cell whose write was refused would record the boot card twice and call that a finding.
PRICED_MODELS = ["m-anthropic", "m-openai-chat", "m-openai-responses", "m-gemini", "m-bedrock",
                 "m-cohere", "m-lane-c1", "m-queue-lane", "m-cd-lane"]
HUNDREDFOLD_RATE_CARD = {m: {"input_utok": 10000000, "output_utok": 20000000} for m in PRICED_MODELS}
NEW_PER_REQUEST_FEE = 3


def billing_cells() -> list[dict]:
    """Money as the user reads it: the key and group usage views after a known sequence of requests
    (all priced 2.5 units each by the rate card: cents-truncation, per-request fee, refund on a
    non-2xx, the `total` window) — PB-16/22/27/91/99."""
    F = "billing"
    chat = lambda auth="ok", model="m-openai-chat": {"method": "POST", "path": "/v1/chat/completions", "listener": "data", "auth": auth,
                                                     "headers": {"Content-Type": "application/json"},
                                                     "body": json.dumps({"model": model, "messages": [{"role": "user", "content": "ping"}]}, separators=(",", ":"))}
    cells = []
    def usage(id_, pre, why, path="/api/v1/admin/keys/{KEY_OK}/usage", auth="admin", **extra):
        c = http(f"billing|{id_}", F, "GET", path, auth=auth, listener="admin", why=why, **extra)
        c["request"]["pre"] = pre
        return c
    cells += [
        usage("key-usage|fresh", [], "a fresh key: zero everything; the exact field set and literals"),
        usage("key-usage|after-1", [chat()], "1 request: requests 1, tokens 18, spend_cents 250 (2.5 units)"),
        usage("key-usage|after-3", [chat(), chat(), chat()], "3 requests: 3 / 54 / 750 — no truncation drift across rows"),
        usage("key-usage|after-cross-protocol", [chat(model="m-anthropic"), chat(model="m-gemini")], "two lanes: per-lane rows folded into one view"),
        usage("key-usage|after-upstream-down", [{**chat(), "mock_control": {"m-openai-chat": "down"}}], "a 503: requests +1, billable refunded, spend 0", bindings=["PB-16", "PB-26", "PB-27"]),
        usage("group-usage|after-2", [chat(), chat()], "the group view", path="/api/v1/admin/groups/oracle/usage"),
        usage("group-usage|broke-after-prime", [], "the primed broke group: 1 request already spent", path="/api/v1/admin/groups/broke/usage"),
        usage("admin-usage|after-2", [chat(), chat()], "GET /admin/usage (all keys, today)", path="/api/v1/admin/usage"),
        usage("admin-usage|past-day", [chat()], "a past UTC day bucket: empty and byte-stable", path="/api/v1/admin/usage?day=2020-01-01"),
        usage("key-usage|noscope-after-403", [chat(auth="noscope")], "a 403 at Approve charges nothing", path="/api/v1/admin/keys/{KEY_NOSCOPE}/usage"),
        usage("key-usage|broke-after-429", [chat(auth="broke")], "a 429 at Admit charges nothing more", path="/api/v1/admin/keys/{KEY_BROKE}/usage"),
    ]
    # The one billing arm no scripted cell drives: a request PINNED to window M whose charge lands on
    # a cell a concurrent admission has already rolled to M+1. 1.5.5 resolved the charge on
    # `window > cell.window_start` but the refund on `cell.window_start == window`, so the two halves
    # of one request could land on different cells and a failed straddling request kept its flat fee
    # for the life of that window — leaving the derived spend a budget cap reads one fee too high.
    # This is the ONLY cell register entry M-1 is allowed to forgive, which is why it exists by name
    # even before the recorder can drive it: an acceptance whose scope is "some future cell" is an
    # acceptance nobody can audit.
    refund = usage("key-usage|refund-across-window",
                   [{**chat(), "mock_control": {"m-openai-chat": "down"}}],
                   "a request that straddles the window roll: its flat per-request fee must be "
                   "refunded from the SAME cell the charge landed on, so the view reads spend 0 and "
                   "not one fee too high (M-1)")
    refund["needs_fixture"] = True
    cells.append(refund)

    # THE RATE-CARD EPOCH — which requests a card written mid-window prices. One boot, one sequence:
    # a request, `PUT /config/settings` with a complete 100x card + a new per_request_fee (200), a
    # second request, then `GET /admin/usage`. See HUNDREDFOLD_RATE_CARD above for the three
    # hypotheses and the three totals that separate them.
    #
    # WHAT 1.5.5 ACTUALLY DOES (recorded from the published binary, 48e2800c): the whole ledger is
    # priced off the card in force at READ time. Every row — the request after the write, the request
    # BEFORE it, and the two the recorder primed at boot — comes back at the new rate. Not an epoch
    # boundary, not a restart. That matches what the code says (`admin/v1/service.rs` derives spend
    # per read; `contract/mod.rs` calls spend_micros "a MUTABLE ESTIMATE"; rate_card is not in
    # `reload_to_apply_fields`) and what docs/admin-api.md promises ("a rate correction re-prices
    # history on the next read"). The cell's value is holding the binary to it byte for byte, and
    # naming the consequence: an invoice already read off this endpoint stops being reproducible
    # from it the moment a rate is corrected.
    #
    # THE ASSUMPTION THIS REPLACES, and why it looked true: an earlier pass drove a PARTIAL card (one
    # model), read both requests at the boot rate, and concluded restart-to-apply. It was not. 1.5.5
    # refuses a partial card with a 400 — "rate_card is AUTHORITATIVE and COMPLETE: you either price
    # nothing or price everything" — so the write never landed and the boot card was still the only
    # card there had ever been. A `pre` need only be ANSWERED, not 2xx (record.sh's
    # run_pre_request), so that refusal was invisible: the cell would have recorded a REFUSED WRITE
    # as a pricing epoch. Hence the complete card, and hence figures that move far enough that "the
    # write landed" is legible in the total itself.
    #
    # ONE APPLY PATH, NOT TWO. `PUT /api/v1/admin/config/settings` is the only route that can write
    # `rate_card`: the root-settings sections are single-valued, and the named-map overlay route
    # (`admin/v1/json/named_map.rs`, whose no-disk-base / locked-overlay arms answer 400) serves
    # `export`/`hooks`/`identity-providers`-shaped NAMED maps, of which rate_card is not one — the
    # 1.5.5 verb table has no per-section config route for it. So there is no second apply path for
    # this cell to record; the closest neighbour is `POST /config/apply` (a whole-document apply),
    # a different operation with its own admin.ops cells.
    #
    # `config_variant: rate-card-epoch` IS THE CLEAN-UP, and it is load-bearing. The 200 writes a
    # runtime overlay beside config.yaml, and record.sh rewrites the config (the only thing that
    # deletes that overlay) ONLY when a cell's variant differs from the one on disk. Left in place,
    # the next baseline boot inherits the 100x card, its per-boot priming request for the `broke` /
    # `broke-quota` keys — whose groups carry a 1-cent/day budget — is refused at Admit, boot_busbar
    # fails, and THE FOLLOWING CELL is red for a reason that has nothing to do with it (observed:
    # ops.scrape|/v1/models/{id}|retrieve, the cell that happens to sort next). An unrecognized
    # variant writes the baseline config byte for byte (see oracle-config.sh), so this costs the
    # cell nothing and hands the next one a clean tree.
    epoch = usage("rate-card|epoch-mid-window",
                  [chat(),
                   {"method": "PUT", "path": "/api/v1/admin/config/settings", "listener": "admin",
                    "auth": "admin", "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"rate_card": HUNDREDFOLD_RATE_CARD,
                                        "per_request_fee": NEW_PER_REQUEST_FEE},
                                       separators=(",", ":"), sort_keys=True)},
                   chat()],
                  "RECORDED TRUTH (published 1.5.5, binary 48e2800c). Three hypotheses, three "
                  "totals: read-time derivation over the whole ledger = 1000120000; priced per row "
                  "at charge time = 257530000; restart-to-apply = 10000000. RECORDED: 1000120000 — "
                  "4 requests at 250030000 each. A complete `rate_card` (+ per_request_fee) written "
                  "through PUT /api/v1/admin/config/settings mid-window is LIVE and RETROACTIVE: "
                  "/admin/usage prices the entire ledger off the card in force at READ time, so the "
                  "request before the write, the request after it, and the recorder's two boot "
                  "priming requests all come back at the new rate. No restart, no epoch boundary, no "
                  "row left at the old price. The money class this pins is the retroactivity itself "
                  "— a rate correction silently re-prices history, so an invoice already read off "
                  "this endpoint is not reproducible from it afterwards. (An earlier pass concluded "
                  "restart-to-apply by driving a PARTIAL card, which 1.5.5 refuses 400 as "
                  "incomplete; the write never landed and a `pre` need only be answered, not 2xx, "
                  "so the refusal was invisible. This card is complete and the write is a 200.)",
                  path="/api/v1/admin/usage", config_variant="rate-card-epoch")
    cells.append(epoch)
    return cells


def rate_card_history_cells() -> list[dict]:
    """THE RATE-CARD HISTORY: the cells the rate-card-history design lists for the oracle, pinning the money-as-a-lookup binding.

    Seven cells recorded from the PUBLISHED 1.5.5 BINARY FIRST, so that when M6 lands the divergence
    has a judge that predates it. Six of the seven name a 1.6.0 surface that DOES NOT EXIST in 1.5.5
    (`/api/v1/admin/ledger/*`, `?as_of=`, `?currency=`, a card with a native currency, an append-only
    history) — and that is the point. A cell whose golden is 1.5.5's REFUSAL is the only thing that
    can later prove the 1.6.0 surface is additive rather than a silent change of an answer somebody
    already depends on: without the recorded 404/405/400, "this endpoint is new" is an assertion, and
    afterwards it is a diff. So each of these records what 1.5.5 ACTUALLY answers to the 1.6.0 call,
    never what the design wishes it answered, and the `why` below states the recorded figure.

    CONFIG_VARIANT ON EVERY CELL THAT CAN WRITE — and, deliberately, on the ones that cannot either.
    `PUT /config/settings` writes a runtime overlay beside config.yaml, and record.sh clears it only
    when a cell's variant differs from the one on disk (see oracle-config.sh: an unrecognized variant
    writes the BASELINE config byte for byte, which is the whole mechanism). The epoch cell learned
    this the expensive way — its 100x card leaked into the NEXT cell's boot, whose priming request
    for the 1-cent/day `broke` group was then refused at Admit, and an unrelated cell went red. Every
    cell here therefore declares its own variant, including the three whose 1.5.5 answer is a refusal
    that writes nothing: a cell that is a 404 today may be a 200 the day the surface lands, and the
    isolation must already be in place when that happens rather than be remembered then.

    `billing|rate-card|history-mid-window` IS THE SCRIPT CELL, and it is the one that must be. Its
    finding is not one response but the RELATION between three `/usage` reads taken at three points
    of one window, and record.sh's `pre` requests are UNRECORDED by construction (run_pre_request
    checks only that busbar answered). An http cell could record the last read and would then have
    to assert the first two in prose. The script driver records all three as bytes. It also gets the
    isolation (d) asks for in a strictly stronger form than a variant: record.sh stops the recording
    busbar, restores the baseline config, and hands the script its own empty tree — so the overlay
    its PUTs write lives and dies inside the cell.
    """
    LF, CF = "ledger", "config"
    chat = lambda: {"method": "POST", "path": "/v1/chat/completions", "listener": "data", "auth": "ok",
                    "headers": {"Content-Type": "application/json"},
                    "body": json.dumps({"model": "m-openai-chat", "messages": [{"role": "user", "content": "ping"}]},
                                       separators=(",", ":"))}
    put_settings = lambda doc, variant=None: {
        "method": "PUT", "path": "/api/v1/admin/config/settings", "listener": "admin", "auth": "admin",
        "headers": {"Content-Type": "application/json"},
        "body": json.dumps(doc, separators=(",", ":"), sort_keys=True)}
    j = lambda doc: json.dumps(doc, separators=(",", ":"), sort_keys=True)

    cells = []

    # 1. THE JUDGE. Two complete cards written into ONE window with a request either side of each,
    #    and `/usage` read after EVERY write. 1.5.5's read-time derivation means each read reprices
    #    the WHOLE window at whatever card is current at that instant, so the same three requests
    #    have three different histories depending only on when you looked. Under the dated history
    #    the same sequence answers with each row at the card it was earned under, and only the LAST
    #    read moves — which is why this cell and the recorded `epoch-mid-window` are the entire
    #    scope of the PB-103 breaking registration.
    cells.append({
        "id": "billing|rate-card|history-mid-window", "plane": "core", "family": "billing",
        "driver": "script", "script": {"name": "rate-card-history.sh"}, "outcome": "ok",
        "weight": 10, "bindings": ["PB-103"],
        "why": "TWO complete rate cards written into ONE window (10x, then 100x + a 3-cent "
               "per_request_fee), with a chat before the first, between the two and after the "
               "second, and GET /api/v1/admin/usage read after EACH write. RECORDED TRUTH "
               "(published 1.5.5, binary 48e2800c): both PUTs are 200, all three chats are 200, and "
               "the three reads total 25,000,000 / 500,060,000 / 750,090,000 micro-units — every "
               "read prices the ENTIRE window at the card in force at READ time. The arithmetic "
               "says so unambiguously: chat1 ALONE reads back at 25,000,000 (one request at CARD A) "
               "when it was earned at 2,500,000 under the boot card, and by the final read all "
               "three requests sit at 250,030,000 each. Priced-at-charge would have given 2,500,000 "
               "/ 27,500,000 / 277,530,000 — no leading digit in common — so the reading is "
               "measured, not inferred. THE CONSEQUENCE, which is the finding: the first request is "
               "reported at THREE different prices over the life of ONE window, so an invoice read "
               "off this endpoint stops being reproducible from it the moment a rate is corrected, "
               "and the number depends only on when you looked. This is the cell the 1.6.0 "
               "divergence is judged on (the money-as-a-lookup binding): under the dated rate-card history the two "
               "pre-edit requests keep the boot and 10x cards, the final answer becomes "
               "277,530,000, and ONLY the final read moves — the two earlier reads were already the "
               "honest figure at their own instant and stay byte-identical. The script driver, not "
               "`pre`, because a `pre` request's response is never recorded (record.sh "
               "run_pre_request checks only that busbar ANSWERED) and this cell's finding is the "
               "relation between the three reads, not any one of them."})

    # 2. `as_of` — the read-time snapshot selector 1.6.0 adds to every ledger read. On 1.5.5 the
    #    RESPONSE already carries an `as_of` field (it is in the epoch cell's golden), so the
    #    question the cell settles is what the binary does with `as_of` as a REQUEST parameter:
    #    honoured, refused, or silently dropped. Recorded, not assumed — "unknown params are
    #    ignored" is exactly the kind of belief a cell exists to replace.
    cells.append(http("ledger|rate-history|as-of", LF, "GET",
                      "/api/v1/admin/usage?as_of=1", auth="admin", listener="admin",
                      config_variant="rate-card-as-of", bindings=["PB-103"],
                      why="a mid-window 100x card, then GET /admin/usage?as_of=1 — the snapshot "
                          "selector 1.6.0 gives every ledger read, sent to the binary that has no "
                          "history to select from. RECORDED (published 1.5.5): 200, and the "
                          "parameter is SILENTLY IGNORED. The body is the current-card reprice "
                          "`billing|rate-card|epoch-mid-window` records — total 1,000,120,000, all "
                          "four rows at the newest card — and the response's OWN `as_of` field "
                          "comes back 0, not the 1 that was asked for. So 1.5.5 neither honours the "
                          "snapshot nor refuses the request: it answers a DIFFERENT question under "
                          "a name that promises a snapshot, and reports an `as_of` that "
                          "contradicts the one in the URL. A caller who guesses this parameter "
                          "today gets a confident wrong answer. Under 1.6.0 the same URL returns "
                          "the snapshot it names — a changed number under unchanged request bytes, "
                          "which is exactly why the additive registration has to name this cell "
                          "instead of resting on the ledger endpoints being new."))
    cells[-1]["request"]["pre"] = [chat(), put_settings({"rate_card": HUNDREDFOLD_RATE_CARD,
                                                         "per_request_fee": NEW_PER_REQUEST_FEE}), chat()]

    # 3/4. THE AMEND VERB. 1.6.0's back-dating path is an operator-SIGNED admin write; 1.5.5 has no
    #    such route at all. Both the signed and the unsigned call are recorded, because the pair is
    #    the evidence that the refusal is about the ROUTE and not about the signature: if 1.5.5
    #    answered the two differently, the verb would already exist in some form and the 1.6.0
    #    surface would not be additive.
    amend_body = j({"effective_from": 1, "rate_card": HUNDREDFOLD_RATE_CARD,
                    "window": {"day": "2020-01-01"}, "reason": "oracle: back-date the window"})
    cells.append(http("ledger|amend|adjusting-entries", LF, "POST",
                      "/api/v1/admin/ledger/amend-rate-history", auth="admin", listener="admin",
                      headers={"Content-Type": "application/json",
                               "X-Busbar-Signature": "ed25519:oracle-operator-signature"},
                      body=amend_body, config_variant="rate-card-amend", bindings=["PB-103"],
                      why="POST /api/v1/admin/ledger/amend-rate-history, SIGNED, against the binary "
                          "that has no ledger route table. RECORDED (published 1.5.5): 404 with "
                          "code `not_found` and message \"resource not found\" — the ROUTER's "
                          "generic miss, NOT a 405 from a path that exists for another method, and "
                          "the `X-Busbar-Signature` header is never read (it cannot be: nothing "
                          "routes). That distinction is the point of recording it rather than "
                          "assuming it: a 405 would have meant the path already exists in some "
                          "form. The refusal is the proof the 1.6.0 verb is ADDITIVE — no 1.5.5 "
                          "operator can be relying on an answer here, because there is no answer "
                          "here — and it is recorded before the verb is built, so the claim is a "
                          "diff rather than an assertion."))
    cells.append(http("ledger|amend|refused-unsigned", LF, "POST",
                      "/api/v1/admin/ledger/amend-rate-history", auth="admin", listener="admin",
                      headers={"Content-Type": "application/json"}, body=amend_body,
                      config_variant="rate-card-amend-unsigned", bindings=["PB-103"],
                      why="the same amend call with NO operator signature. RECORDED (published "
                          "1.5.5): 404 `not_found` / \"resource not found\", BYTE-IDENTICAL to the "
                          "signed sibling — which is the whole value of the pair. 1.5.5 is refusing "
                          "the ROUTE and knows nothing about signatures, so the two calls cannot be "
                          "told apart; had they differed, the premise that this verb is new would "
                          "be false and the additive registration would be wrong. Under 1.6.0 the "
                          "two separate — signed proceeds and journals a repricing record, unsigned "
                          "is refused AND journalled — and this cell is the recorded baseline that "
                          "separation is measured against."))

    # 5. NATIVE CURRENCY. The native-currency rule forbids a pivot: a card prices a lane in the currency it is billed
    #    in, with no cross-rate anywhere. 1.5.5's `currency` is a fixed LABEL on the response
    #    ("USD" in every billing golden) and its rate_card entries have no currency at all — so the
    #    open question is whether an entry carrying one is refused as an unknown field or accepted
    #    and ignored. "Accepted and ignored" would be the dangerous answer (a card that says BHD
    #    and bills USD), which is why the cell records the WRITE's own response.
    cells.append(http("ledger|currency|native", LF, "PUT", "/api/v1/admin/config/settings",
                      auth="admin", listener="admin",
                      headers={"Content-Type": "application/json"},
                      body=j({"rate_card": {m: {"input_utok": 10000000, "output_utok": 20000000,
                                                "currency": ("JPY" if m == "m-openai-chat" else "USD")}
                                            for m in PRICED_MODELS}}),
                      config_variant="rate-card-currency", bindings=["PB-103"],
                      why="a complete card that prices ONE lane in a second currency natively "
                          "(m-openai-chat in JPY, the rest USD) — the shape the native-currency rule requires and the "
                          "shape 1.5.5 has no field for. RECORDED (published 1.5.5): 400 "
                          "`invalid_request`, \"malformed config settings body: unknown field "
                          "`currency`, expected one of `input_utok`, `output_utok`, "
                          "`cache_read_utok`, `cache_write_utok`\" — 1.5.5 REFUSES the key rather "
                          "than accepting and dropping it, and names the four it does know. That is "
                          "the good answer and it is worth pinning as bytes, because the "
                          "alternative was a card that says JPY while /usage keeps labelling the "
                          "money USD: a mislabelled invoice no cell would have caught. Since the "
                          "field is refused today, 1.6.0 accepting it is purely ADDITIVE — the "
                          "known-key list IS the contract, and this cell is what proves `currency` "
                          "was outside it before the history landed. Fixing the wording also holds "
                          "a 1.6.0 build that accepts `currency` to refusing every OTHER "
                          "misspelling the same way."))

    # 6. MINOR-UNIT ROUNDING. The minor-unit rule divides by 10^(9-exp) ONCE per row, truncating. Before that can
    #    be a per-currency exponent it has to be true of the currency 1.5.5 already has, so this
    #    cell drives rates far below USD's minor unit (1 micro-unit per token against the mock's
    #    11 in / 7 out = 18 micros for a whole request, where one cent is 10,000) and records where
    #    the truncation actually lands: on the row, on the total, or not at all.
    cells.append(http("ledger|currency|minor-unit-rounding", LF, "GET", "/api/v1/admin/usage",
                      auth="admin", listener="admin",
                      config_variant="rate-card-minor-unit", bindings=["PB-103"],
                      why="a complete card priced at ONE micro-unit per token — a whole request "
                          "costs 11+7 = 18 micro-units against a USD minor unit of 10,000 — then "
                          "GET /admin/usage. RECORDED (published 1.5.5): every per-key row is "
                          "spend_micros 18, and the per-model row and the total are 54, an EXACT "
                          "sum of three exact rows. So on this endpoint 1.5.5 does NOT project to a "
                          "minor unit at all: `spend_micros` is carried at full micro-unit "
                          "precision and nothing is truncated to cents anywhere in the view — the "
                          "cents truncation lives on the paths that REPORT cents, not here. That is "
                          "the baseline the minor-unit rule must be compatible with, and it makes the compatible "
                          "reading precise: 'divide by 10^(9-exp) ONCE per row, truncating' has to "
                          "leave THIS endpoint's figures alone, or the identity test's statement 2 "
                          "— exact against the published 1.5.5 binary for a single-entry history — "
                          "fails on any window worth less than a cent, which is every window on a "
                          "quiet day. Recorded on the currency 1.5.5 already has, so the "
                          "zero-exponent (JPY) and three-exponent (BHD) arms 1.6.0 adds have a USD "
                          "baseline that is a measurement rather than a belief."))
    cells[-1]["request"]["pre"] = [put_settings({"rate_card": {m: {"input_utok": 1, "output_utok": 1}
                                                               for m in PRICED_MODELS}}), chat()]

    # 7. APPEND, NOT REPLACE. The append-not-replace rule makes a config PUT append a dated entry to the history instead of
    #    overwriting the card. The 1.5.5 behaviour it has to be compatible with is the refusal that
    #    the epoch cell's own history turns on: a PARTIAL card is a 400, "rate_card is AUTHORITATIVE
    #    and COMPLETE". That refusal is load-bearing for the whole design — it is why "the card" is
    #    always a complete document and therefore why appending one is well-defined — and until now
    #    it was quoted from the source rather than recorded from the binary.
    cells.append(http("config|rate-card|append-not-replace", CF, "PUT",
                      "/api/v1/admin/config/settings", auth="admin", listener="admin",
                      headers={"Content-Type": "application/json"},
                      body=j({"rate_card": {"m-openai-chat": {"input_utok": 10000000,
                                                              "output_utok": 20000000}}}),
                      config_variant="rate-card-partial", bindings=["PB-103"],
                      why="a PARTIAL rate card (one model of the nine) through "
                          "PUT /config/settings. RECORDED (published 1.5.5): 400 `invalid_request` "
                          "— \"config validation failed: rate_card is present but 8 configured "
                          "models have no rate entry (rate_card is AUTHORITATIVE and COMPLETE: you "
                          "either price nothing or price everything)\", followed by all eight "
                          "missing models named one per line with a paste-ready zero-rate stub. The "
                          "sentence used to be quoted from the source; it is now bytes, INCLUDING "
                          "the remediation block, so a later binary that keeps the refusal but "
                          "drops the list of what is missing is a diff. This is the refusal an "
                          "earlier pass at the epoch cell tripped over WITHOUT seeing it (a `pre` "
                          "need only be ANSWERED, not 2xx, so a refused write was recorded as a "
                          "pricing epoch), and it is the precondition for the append-not-replace rule: a config PUT can "
                          "APPEND a dated entry to the history precisely because the thing it "
                          "carries is always a WHOLE card, never a patch. Under 1.6.0 this stays a "
                          "400 and the accepted sibling appends instead of overwriting — which is "
                          "what /ledger/rate-history shows, and what makes 'append, not replace' a "
                          "property of a well-defined object rather than a slogan."))
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
        http("hooks|metrics-hooks", F, "GET", "/metrics/hooks", why="the hook's own scrape exposition", config_variant=V, bindings=["PB-43"]),
        http("hooks|admin-list", F, "GET", "/api/v1/admin/hooks", auth="admin", listener="admin", why="registry with the loaded hook, incl. the 1.5.5 legacy `at` field alongside `phase`/`fires_at` (the legacy-hook-spelling rule)", config_variant=V),
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
             why="1.5.5 `hooks.<h>.plugin` back-compat alias for `module:` — must still register, and the 201 body's `module` must resolve to `busbar-webrequest` (the legacy-hook-spelling rule)", config_variant=V),
        http("hooks|config-settings-put|persist-true", F, "PUT", "/api/v1/admin/config/settings", auth="admin", listener="admin",
             headers={"Content-Type": "application/json"},
             body=json.dumps({"persist": True}, separators=(",", ":"), sort_keys=True),
             why="1.5.5 `persist:` boolean control key — accepted (boolean-validated) then ignored, never an unknown-field 400 (the legacy-hook-spelling rule)", config_variant=V),
        http("hooks|config-settings-put|persist-non-boolean", F, "PUT", "/api/v1/admin/config/settings", auth="admin", listener="admin",
             headers={"Content-Type": "application/json"},
             body=json.dumps({"persist": "yes"}, separators=(",", ":"), sort_keys=True),
             why="a non-boolean `persist:` is refused naming `persist`+`boolean`, not `unknown field` (the legacy-hook-spelling rule)", config_variant=V),
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
             why="an embedded system-role turn folded out of `messages` by the IR — message_count parity (the folded-system-turn parity rule)", config_variant=V),
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
    the mock, prove the refusal while still inside the cooldown, then wait past the LONGEST cooldown
    the jitter can draw and send the same request again: served 200. Fully self-contained
    (scripts/cooldown-trip.sh boots its own busbar on its own ports), because both waits are taken
    against the wall-clock second the trip landed in — timing no shared-boot bookkeeping provides."""
    return [{
        "id": "cooldown|trip-then-serve", "plane": "core", "family": "cooldown", "driver": "script",
        "script": {"name": "cooldown-trip.sh"}, "outcome": "ok",
        "why": ("base_cooldown_secs 1 with a consecutive-1 trip: the failing member is tripped (503, "
                "nothing billed), the SAME request is still refused 503 while the cooldown runs even "
                "though the upstream is healthy again, and once the cooldown is past it is served "
                "(200, billed) — the breaker's own trip-then-recover cycle, both arms. The first "
                "trip computes off streak 1, so the draw is a whole second in [1, 3] (base << 1 = 2, "
                "+/-1s jitter, clamped): the script issues the trip just after a second boundary, "
                "refuses at +0.3s (inside every possible draw) and serves at +4.5s (past every "
                "possible draw), so neither arm can land in the jitter window. Proven on the "
                "CUMULATIVE counters busbar_breaker_trips_total / busbar_upstream_failures_total, "
                "which survive the scrape-time busbar_lane_state gauge settling back to its starting "
                "value (0 -> 2 -> 0) by the time this cell's one before/after snapshot is taken, "
                "plus the requests-vs-billable_requests split in the usage delta."),
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
                 keep={"headers_min": {"retry-after": 2}},
                 why="every member of pool oracle-fo is driven down (mock `down` verb, same technique as "
                     "route.failover|fo|all-down): the on_exhausted 503's Retry-After is pinned instead of "
                     "blanked to <RETRY>, so the report can show its actual value and a regression that "
                     "floors it below 2 seconds (the breaker's own base_cooldown_secs is 15s, jittered) is "
                     "a visible diff, not hidden inside the usual retry-after normalization",
                 bindings=["PB-4"])
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
                "the real outcome rather than assumed from the plan"},
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


def documented_cells() -> list[dict]:
    """`documented`: PB-71's documented-vs-actual family. One cell per TESTABLE claim in
    docs/design/inventory/1.5.5-ops-observability.md §8 (27 README rows :1047-1073, 29 CHANGELOG
    rows :1087-1115); the claim text (and its doc citation) is in the cell's `why`. The two rows
    ARCHITECTURE.md names CONTRADICTED (README:272, CHANGELOG:134-137) get a cell that pins the
    CODE's actual behaviour — `why` says the doc is wrong and cites the doc line, per PB-71's
    "code-wins" rule. Claims that are pure prose (external benchmarks, Kubernetes/Docker manifest
    literals busbar itself never observes, CI-pipeline-only behaviour, or a bare pointer to another
    §'s own detailed cross-check) are NOT cells here — they are named gaps in
    qa/documented-claims.json with `status: "prose"` and a one-line reason, never silently dropped.
    """
    F = "documented"
    chat = lambda model: json.dumps({"model": model, "messages": [{"role": "user", "content": "ping"}]},
                                     separators=(",", ":"), sort_keys=True)
    cells = []

    # ── README documented-behaviour rows (27 rows; 15 testable rows -> 6 cells here, 1 CONTRADICTED, 12 prose) ────────
    cells.append(http("documented|readme|six-protocols|openai-chat", F, "POST", "/v1/chat/completions",
                       body=chat("m-openai-chat"),
                       why="README:22 'Six wire protocols, first class on both sides' + README:85-88 "
                           "base_url=http://localhost:8080/v1, model = pool name — the OpenAI-chat "
                           "route actually serves (main.rs:233-244, :236)"))
    cells.append(http("documented|readme|six-protocols|openai-responses", F, "POST", "/v1/responses",
                       body=json.dumps({"model": "m-openai-responses", "input": "ping"}, separators=(",", ":"), sort_keys=True),
                       why="README:22 six protocols + README:103 client.responses.create(model=\"fast\") "
                           "— the Responses route actually serves (main.rs:238)"))
    cells.append(http("documented|readme|six-protocols|anthropic", F, "POST", "/v1/messages",
                       headers={"anthropic-version": "2023-06-01"},
                       body=json.dumps({"model": "m-anthropic", "max_tokens": 64, "messages": [{"role": "user", "content": "ping"}]}, separators=(",", ":"), sort_keys=True),
                       why="README:22 six protocols + README:97-99 pool name in the base URL "
                           "(http://localhost:8080/fast) — the Anthropic route actually serves (main.rs:234)"))
    cells.append(http("documented|readme|six-protocols|gemini", F, "POST", "/v1beta/models/m-gemini:generateContent",
                       body=json.dumps({"contents": [{"role": "user", "parts": [{"text": "ping"}]}]}, separators=(",", ":"), sort_keys=True),
                       why="README:22 six protocols + README:108-110 base_url=http://localhost:8080 "
                           "— the Gemini route actually serves (main.rs:239-240)"))
    cells.append(http("documented|readme|six-protocols|cohere", F, "POST", "/v2/chat",
                       body=chat("m-cohere"),
                       why="README:22 six protocols + README:113-115 Cohere v2 client.chat(model=\"fast\") "
                           "— the Cohere route actually serves (main.rs:237)"))
    # bedrock (README:117-121, :22) is deliberately NOT a cell here: its ingress is SigV4-signed,
    # which the plain http driver cannot express (no sigv4 signer in this family's reuse set); the
    # route itself is already exhaustively pinned by the llm.wire family's own `llm|bedrock|*` cells
    # (which DO carry a sigv4 signer) — see qa/documented-claims.json.
    cells.append(exec_("documented|readme|env-launch", F, args=["--version"], mode="cli",
                        env={}, why="README:182 `BUSBAR_CONFIG=./config.yaml ./busbar &` — plain "
                                    "`--version` under the same BUSBAR_CONFIG-driven launch path "
                                    "(main.rs:120, :224) exits 0"))
    cells.append(exec_("documented|readme|validate-ci", F, args=["--validate"], mode="validate",
                        why="README:194 '`busbar --validate` parses your config and every provider "
                            "reference and exits non-zero on anything wrong, with no server, no "
                            "network and no state' (main.rs:193, :205-208, :258-263)"))
    cells.append(http("documented|readme|healthz-probes", F, "GET", "/healthz", auth="none",
                       why="README:247-248 readinessProbe and livenessProbe both httpGet "
                           "{path: /healthz, port: http} — one path serves both (main.rs, "
                           "endpoints.rs:269-283, plugin_routes.rs:21,53)"))
    cells.append(exec_("documented|readme|export-standards", F, args=["--validate"], mode="validate",
                        why="README:280 'observability over open standards: Prometheus, OTLP and a "
                            "per-request audit webhook' — the oracle's own baseline config runs a "
                            "prometheus export sink clean through --validate; OTLP/webhook module "
                            "existence is separately pinned by PB-74's EXPORT_MODULES freeze"))
    cells.append(exec_("documented|readme|migrate-config-freeze", F, args=["--validate"], mode="validate",
                        config="mutation:BOOT-P41",
                        why="README:282 'config.yaml … changes always ship with `busbar "
                            "--migrate-config` and a loud fail-closed boot' — a 1.x-shaped config "
                            "(legacy `providers.<name>.api_key_env`) fails closed naming the migrator "
                            "(config/migrate.rs:277-289)"))
    cells.append({"id": "documented|readme|config-locked", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-overlay-refused.sh", "args": ["locked"]}, "outcome": "ok", "weight": 10,
                  "why": "README:217 `config: { locked: true }` for GitOps/read-only root "
                         "(config/overlay.rs:34,:48-49) — boots clean and refuses a live "
                         "PUT /api/v1/admin/config/settings with the fixed no-writable-overlay message"})
    cells.append({"id": "documented|readme|tls-mtls", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-tls.sh"}, "outcome": "ok", "weight": 10,
                  "why": "README:280 'native TLS and mTLS with no reverse proxy in front' "
                         "(config/mod.rs:472; tls::serve mTLS arm main.rs:1111-1125) — a self-signed "
                         "cert + `tls: {cert, key}` boots and serves /healthz over HTTPS directly, "
                         "and the same port refuses plain HTTP once TLS is configured"})
    cells.append({"id": "documented|readme|docker-defaults", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-docker-defaults.sh"}, "outcome": "ok", "weight": 10,
                  "why": "README:188-192 `docker run --rm -p 8080:8080 -e ANTHROPIC_KEY -e "
                         "BUSBAR_ADMIN_TOKEN getbusbar/busbar` — the EXACT shipped docker/config.yaml "
                         "(listen port rewritten off 8080 only) boots and answers /healthz + "
                         "/v1/models with only those two env vars set (Dockerfile:33, "
                         "docker/config.yaml:22,30)"})
    # THE OTHER HALF OF THE SHIPPED IMAGE'S STORY. docker-defaults above proves the image boots on
    # its own default config; this proves the DURABLE recipe the Dockerfile's own header hands
    # operators -- "Governance (optional) needs a writable volume for the SQLite file, e.g.
    # -v busbar-data:/var/lib/busbar with store.settings.db_path" plus "drop a signed plugin tarball
    # into /etc/busbar/plugins", the image shipping with ZERO plugins. Four moving parts (a
    # FROM-scratch image with no shell, a tarball the loader must accept, an ABSOLUTE plugins.dir,
    # and a volume that outlives the container) that nothing in this tree had ever run together --
    # and the reported operator failure was precisely there. The fixture var names the image for the
    # same reason store-persist.sh will not invent a backend URL: a cell that ran cannot then have
    # driven an image other than the one it named.
    cells.append({"id": "documented|dockerfile|store-persists-across-the-container", "plane": "core", "family": F,
                  "driver": "script", "script": {"name": "store-persist-image.sh"}, "outcome": "ok", "weight": 10,
                  "why": "CONTRADICTED (code wins, PB-71): Dockerfile:12-13,26-27 documents a durable store in "
                         "the published image — a signed plugin tarball dropped into /etc/busbar/plugins plus a "
                         "writable volume for the SQLite file. Measured against 1.5.5 the recipe cannot be "
                         "followed: the image is FROM scratch and its busbar is a dynamically-linked ELF, so a "
                         "cdylib plugin cannot be dlopen'd at all (memfd `dlopen failed`; the private-staging "
                         "fallback then has no /tmp, and `dlopen failed` again when given one). busbar is right "
                         "throughout — the store refuses to open and boot is refused loudly, exit 1, reason "
                         "named, never a silent fall back to RAM. This cell pins the trajectory: the pre-flight "
                         "`--list-plugins` verdict the operator reads (LOADS), both refusal causes separately, "
                         "and the mint/kill/read-back path it takes the day the image can load a plugin",
                  "bindings": ["PB-11", "PB-37", "PB-93"],
                  "needs_fixture": "BUSBAR_TEST_BUSBAR_IMAGE"})
    # CONTRADICTED (README:272, code-wins per PB-71): pins the ACTUAL behaviour.
    cells.append({"id": "documented|readme|contradicted-overlay-boots", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-overlay-refused.sh", "args": ["overlay-unwritable"]}, "outcome": "ok", "weight": 10,
                  "why": "CONTRADICTED: README:272 says '`config: { locked: true }` is what lets the "
                         "root filesystem be read-only … Busbar refuses to boot without one "
                         "[a writable overlay path]'. The doc is wrong — 1.5.4 code boots, serves "
                         "traffic normally, WARNs 'config is READ-ONLY (the overlay backend is not "
                         "writable)', and refuses only admin-API config MUTATIONS, never the boot "
                         "itself (main.rs:856-865; config/overlay.rs:44-53; CHANGELOG.md:40-46). "
                         "This cell pins the code's actual behaviour as the parity target."})

    # ── CHANGELOG documented-behaviour rows (29 rows; 19 testable rows -> 6 cells (one script covers 3 rows) + 2 more "
    # scripts + simple http/exec cells, 1 CONTRADICTED, 10 prose) ─────────────────────────────────
    cells.append({"id": "documented|changelog|docker-boots-and-mutation-refused", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-overlay-refused.sh", "args": ["overlay-unwritable"]}, "outcome": "ok", "weight": 10,
                  "why": "CHANGELOG:36-38 (1.5.4) 'The Docker image starts again' (previously exited 1 "
                         "before binding a port on an unwritable overlay) + CHANGELOG:40-46 'Busbar "
                         "boots, serves traffic, warns clearly … and refuses admin-API config changes "
                         "outright' — both confirmed by the same boot+mutation-attempt facts as the "
                         "README:272 CONTRADICTED cell above (main.rs:856-865)"})
    cells.append({"id": "documented|changelog|validate-checks", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-validate-checks.sh"}, "outcome": "ok", "weight": 10,
                  "why": "four independent CHANGELOG claims, each its own `busbar --validate` check: "
                         "CHANGELOG:81-87 (1.5.3) unresolvable env:/file: secret ref exits 1; "
                         "CHANGELOG:110-112 (1.5.3) `admin_insecure` retired for `admin_require_mtls` "
                         "(inverted meaning); CHANGELOG:196-197 (1.5.2) `auth.chain: [keys]` with no "
                         "way to ever mint an admin token now refuses to start; CHANGELOG:185-186 "
                         "(1.5.3) a config file named with no directory component boots clean in a "
                         "writable directory"})
    cells.append({"id": "documented|changelog|admin-restart", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-admin-restart.sh"}, "outcome": "ok", "weight": 10,
                  "why": "CHANGELOG:309-310 (1.5.0) 'POST /api/v1/admin/restart applies the settings "
                         "that need a restart … without shell access' — a PUT "
                         "advanced.response_headers.server_timing stages in the overlay (the response "
                         "itself says so), POST /restart drains and exits the process, and a fresh "
                         "launch against the same config+overlay serves /healthz WITH the "
                         "Server-Timing header the pre-restart PUT staged (admin/restart.rs:4-18; "
                         "admin/v1/json/handlers.rs:2386-2439)"})
    cells.append(http("documented|changelog|headers-off-default", F, "GET", "/healthz", auth="none",
                       why="CHANGELOG:107-109 (1.5.3) 'Response headers are off by default … "
                           "`observability.emit_server_timing` no longer exists.' — the oracle's "
                           "baseline config never sets advanced.response_headers, so no Server-Timing "
                           "header rides an ordinary response (main.rs:798-807, :3885-3897)"))
    cells.append(http("documented|changelog|stats-reasons", F, "GET", "/stats",
                       why="CHANGELOG:218-219 (1.5.1) '/stats and /metrics report why a lane cannot "
                           "take a request … and how many requests are parked.' (endpoints.rs:89-135)"))
    cells.append(http("documented|changelog|lane-available-metric", F, "GET", "/metrics",
                       body_lines=r"^busbar_lane_(available|at_capacity)",
                       why="CHANGELOG:229 (1.5.1) '`busbar_lane_at_capacity` is replaced by "
                           "`busbar_lane_available`.' — the golden shows `busbar_lane_available` "
                           "series lines and NO `busbar_lane_at_capacity` line at all (metrics.rs:260; "
                           "negative assertion metrics.rs:1446-1447)"))
    retry_trap = http("documented|changelog|retry-after-floor", F, "POST", "/v1/chat/completions",
                       body=chat("oracle-fo"), keep={"headers_min": {"retry-after": 2}},
                       why="CHANGELOG:235 (1.5.1) '`Retry-After` on an exhaustion 503 always said one "
                           "second under saturation, rather than the real cooldown.' — every member of "
                           "pool oracle-fo driven down; the on_exhausted 503's Retry-After is pinned "
                           "(>= 2s, the breaker's own 15s base_cooldown_secs jittered), never the old "
                           "1-second floor (endpoints.rs:477-481)")
    retry_trap["mock_control"] = {"m-openai-chat": "down", "m-anthropic": "down"}
    cells.append(retry_trap)
    cells.append(exec_("documented|changelog|worker-threads-zero", F, args=["--validate"], mode="validate",
                        config="mutation:BOOT-W34",
                        why="CHANGELOG:190 (1.5.3) '`advanced.worker_threads: 0` was silently ignored "
                            "instead of reported.' — now a boot WARN names the ignored value "
                            "(main.rs:612-621)"))
    cells.append(exec_("documented|changelog|no-keygen-at-boot", F, args=[], mode="boot",
                        config="mutation:BOOT-075",
                        why="CHANGELOG:210-214 (1.5.1) 'Busbar no longer generates a signing key at "
                            "boot. … 1.5.0 wrote this file itself beside your config, which boot-looped "
                            "on a read-only mount.' — a missing `auth.signing_key` now REFUSES to "
                            "start (fail-closed) rather than silently writing one (main.rs:2255-2258)"))
    cells.append(exec_("documented|changelog|legacy-config-refused", F, args=["--validate"], mode="validate",
                        config="mutation:BOOT-P41",
                        why="CHANGELOG:247-250 (1.5.0) 'The config file changed shape and a 1.x config "
                            "refuses to start. Run `busbar --migrate-config <old.yaml> > config.yaml` … "
                            "then run `busbar --validate`.' — same legacy-marker fail-closed fixture as "
                            "the README:282 migrate-config-freeze cell (main.rs:1619-1631)"))
    cells.append(http("documented|changelog|no-per-key-gauge", F, "GET", "/metrics",
                       body_lines=r"^busbar_key_budget_remaining_cents",
                       why="CHANGELOG:258-259 (1.5.0) 'The per-key `busbar_key_budget_remaining_cents` "
                           "gauge is gone with them, so use the bucket gauges.' — the golden is an "
                           "empty body; any such series on a later binary is a diff (metrics.rs:1179 "
                           "negative assertion)"))
    cells.append(exec_("documented|changelog|validate-list-plugins", F, args=["--list-plugins"], mode="cli",
                        why="CHANGELOG:313-314 (1.5.0) '`busbar --validate` covers the whole new "
                            "surface with paste-ready fixes, and `busbar --list-plugins` prints the "
                            "plugin inventory without loading plugin code.' (main.rs:264-364, :366-452)"))
    spend_cell = http("documented|changelog|spend-metrics-labelled", F, "GET", "/metrics",
                       body_lines=r"^busbar_(spend_cents|budget_remaining_cents|tokens)_",
                       why="CHANGELOG:315-316 (1.5.0) 'Spend, budget-remaining and token metrics are "
                           "labelled by group and window, and key labels set at mint time echo onto "
                           "per-key series.' — after one served spend, the label set on these series "
                           "carries group=/window= (metrics.rs:233-243, :767-800)")
    spend_cell["request"]["pre"] = [
        {"method": "POST", "path": "/v1/chat/completions", "listener": "data", "auth": "ok",
         "headers": {"Content-Type": "application/json"}, "body": chat("m-openai-chat")}
    ]
    cells.append(spend_cell)
    # CONTRADICTED (CHANGELOG:134-137, code-wins per PB-71): pins the ACTUAL precedence.
    cells.append({"id": "documented|changelog|contradicted-providers-env-wins", "plane": "core", "family": F, "driver": "script",
                  "script": {"name": "documented-providers-env-wins.sh"}, "outcome": "ok", "weight": 10,
                  "why": "PARTIALLY CONTRADICTED: CHANGELOG:134-137 (1.5.3) says of the deprecated "
                         "env vars '… and the config key wins if you set both.' For BUSBAR_PROVIDERS "
                         "specifically the doc is wrong — the ENV VAR wins over `providers_file:` "
                         "(main.rs:1645-1647 in the 1.5.5 tag). Two providers catalogs, config.yaml "
                         "declares `providers_file:` for one, BUSBAR_PROVIDERS names the other; "
                         "`--validate`'s own success line echoes back which path it actually resolved "
                         "(the ops-observability env-set inventory) — the golden names the env-set file, pinning the "
                         "code's actual precedence as the parity target."})
    return cells
def hazard_cells() -> list[dict]:
    """`hazard`: what a 1.6.0 binary must NOT do to a config that names no data directory and no
    peers — which is every config a 1.5.5 operator ever wrote.

    The durable-ledger design says an unset data directory means no probe and no files: the journal
    is memory-buffered, the keyset is sealed in the store, the WAL and the local keyset exist ONLY
    when a data directory is written, and the record-rate / keyset-reference warnings fire only when
    a data directory or peers is written. Every one of those is an ABSENCE, and an absence is the
    one thing a passing unit test proves least: the code path that would create the file simply is
    not reached, so nothing is asserted about it.

    So these are RECORDED, not asserted. Both cells run the same script — boot on such a config,
    send ONE chat request, shut down cleanly — and report state the binary could only have changed
    by doing something the config never asked for. Recorded on the published 1.5.5 FIRST: that run
    is what defines the exact file set, so the cell says "no MORE and no FEWER files than 1.5.5
    leaves", not "the file set someone wrote down once"."""
    F = "hazard"
    return [
        {"id": "hazard|no-data-dir|files", "plane": "core", "family": F, "driver": "script",
         "script": {"name": "hazard-no-data-dir.sh", "args": ["files"]}, "outcome": "ok", "weight": 10,
         "why": "boot on a config with no data directory and no peers, serve one chat request, shut "
                "down: the process's working directory and the config's OWN directory must hold "
                "exactly the files 1.5.5 leaves — no WAL, no keyset, no journal, no probe file"},
        {"id": "hazard|no-data-dir|logs", "plane": "core", "family": F, "driver": "script",
         "script": {"name": "hazard-no-data-dir.sh", "args": ["logs"]}, "outcome": "ok", "weight": 10,
         "why": "the same boot's whole log carries NO line naming a data directory, a WAL, peers or "
                "a fleet: the golden is an empty line set, so any such line on a later binary is a "
                "diff rather than a judgement call about whether the wording is alarming"},
    ]


# -- THE EXPORTS THE ENGINE READS ---------------------------------------------------------------
# The two `_comment` lines still name testing/shadow-oracle/enumerate-cells.py. That is deliberate:
# cells.json's BYTES are the contract the recorder, the replayer and every parity report agree on,
# and rewording a header line is a diff on 2316 cells that says nothing about busbar. They are
# busbar's own text, so this is where they belong; the wording moves when someone means it to.
COMMENT = [
    "GENERATED by testing/shadow-oracle/enumerate-cells.py. Do not edit by hand.",
    "Regenerate: testing/shadow-oracle/enumerate-cells.py --write",
    "One cell = one recorded (request, response, effects) triple the shadow oracle replays.",
]

# The `outcomes` block, flattened. Order is the pipeline order the refusal is produced at.
OUTCOME_ROWS = [{"outcome": o, "why": w} for o, w in OUTCOMES + STREAMING_OUTCOMES
                + [ARRAY_STREAM_OUTCOME, STREAM_UPSTREAM_ERROR_OUTCOME,
                   RESPONSES_CITATION_OUTCOME, BEDROCK_CACHEPOINT_DOCUMENT_OUTCOME]]

# `derived_from`, filled in by bind() (it is product-root-relative, and only bind() knows the root).
DERIVED_FROM: dict = {}


# The two inventory-driven builders read their OWN inventories, so the engine never learns a busbar
# file name and `derived_from` stays entirely on this side.
def llm_wire_cells() -> list[dict]:
    return llm_cells(json.loads(FIELD_INV.read_text()))


def protocol_wire_cells() -> list[dict]:
    return protocol_cells(json.loads(METHOD_INV.read_text()))


# The 22 builders, in order. The engine calls them all and sorts the union by id.
BUILDERS = [
    ("llm.wire", llm_wire_cells),
    ("protocol", protocol_wire_cells),
    ("cli", cli_cells),
    ("config.migrate", migrate_cells),
    ("ops.scrape", scrape_cells),
    ("http.crosscut", crosscut_cells),
    ("admin.ops", admin_cells),
    ("boot", boot_cells),
    ("route.failover", failover_cells),
    ("plugins", plugin_cells),
    ("billing", billing_cells),
    ("rate-card-history", rate_card_history_cells),
    ("hooks", hooks_cells),
    ("concurrency", concurrency_cells),
    ("queue", queue_cells),
    ("cooldown", cooldown_cells),
    ("crosscut.traps", crosscut_traps_cells),
    ("auth.lifecycle", auth_lifecycle_cells),
    ("teller", teller_cells),
    ("neutrality", neutrality_cells),
    ("documented", documented_cells),
    ("hazard", hazard_cells),
]


def shrink_probe() -> tuple[list[dict], set[str]]:
    """THE HAZARD, REPRODUCED ON DEMAND -- the engine's --selftest calls this.

    Every builder above opens with `if not <FIXTURE>.exists(): return []`, which is a sane guard
    against a crash and a terrible one against a mistake: a renamed fixture makes a whole family
    vanish, the generator exits 0, and cells.json — which IS the owed set — quietly loses it. So the
    floor check has to be proven to REFUSE that, on a real loss rather than a simulated one.

    admin.ops is the family used, because it is the largest fixture-gated one and its loss is the
    exact accident this guards against. Returns what the real builder yields with its fixture
    repointed at a path that cannot exist (which must be []) and the family names it owns, so the
    engine can ask the floor about them without knowing either.
    """
    global ADMIN_BODIES
    saved, ADMIN_BODIES = ADMIN_BODIES, DATA / "no-such-fixture-selftest.json"
    try:
        return admin_cells(), {"admin.ops"}
    finally:
        ADMIN_BODIES = saved


SHRINK_PROBE = shrink_probe
