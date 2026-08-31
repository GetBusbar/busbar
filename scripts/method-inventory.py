#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
#
# DERIVE the MCP and A2A method inventory, and the method x direction x transport MATRIX, from
# sources that enumerate mechanically. Then WRITE it to qa/method-inventory.json, which
# crates/busbar/tests/method_coverage.rs turns into a build failure for any cell that is neither
# implemented nor explicitly waived.
#
# WHY THIS FILE EXISTS AT ALL, AND WHY THE LIST IS NOT TYPED OUT BY HAND.
# The owner's ruling for 1.6.0 is "i want full alphabet coverage not just A-J. I want A-Z". A
# hand-written method list is precisely how coverage ends at J with nobody noticing: the author
# writes down the methods they were thinking about, the ones they were not thinking about are
# absent, and an absent row looks exactly like a row that was considered and found not to apply.
# So the inventory is READ OUT OF THE SPECIFICATION AUTHORS' OWN ARTEFACTS:
#
#   MCP   rmcp 3.1.2, `src/model.rs`. rmcp is the MCP maintainers' Rust SDK for revision
#         2026-07-28. Two things are read: every `const_string!(XMethod = "wire/name")`, which is
#         the complete set of wire method names the SDK knows; and the four `ts_union!` blocks
#         (ClientRequest / ServerRequest / ClientNotification / ServerNotification), which say who
#         ORIGINATES each one. A method that exists is in the const set. A method whose const is
#         in no union is reported as an ORPHAN and must be classified explicitly below -- it is
#         never silently dropped, because "declared but not routed" is exactly the kind of method
#         a union-only derivation loses.
#
#   A2A   a2a-pb 0.2.0, `proto/a2a.proto`. Per A2A SPEC 1.4 the proto is "the single authoritative
#         normative definition"; the `service A2AService` block's rpc list IS the method list, and
#         each rpc's `google.api.http` option IS the HTTP+JSON binding. Nothing is transcribed.
#
# WHAT IS NOT MECHANICAL, AND HOW IT IS KEPT HONEST.
# Three facts cannot be read out of either artefact, and each is written down here with a citation
# and a CROSS-CHECK that fails if the derived list moves underneath it:
#
#   1. A2A JSON-RPC 0.3-era method names (`message/send`, ...). The proto only carries the rpc
#      name. LEGACY_JSONRPC_0_3 below must cover EXACTLY the derived rpc set -- add an rpc
#      upstream and this script refuses to run until the alias is supplied.
#   2. Surfaces the specifications define that are NOT rpcs or JSON-RPC methods but that a
#      customer nonetheless invokes: the A2A well-known Agent Card, A2A push delivery, and the
#      MCP streamable-HTTP session verbs. Each is listed in EXTRA_SURFACES with the requirement
#      IDs in testing/ that exercise it, so the claim "the suites already test this" is checkable.
#   3. Which cells are N/A. An N/A cell carries a REASON string and the test asserts the reason is
#      non-empty. An unexplained absent cell is the failure mode this whole file exists to prevent.
#
# USAGE
#   scripts/method-inventory.py --write     regenerate qa/method-inventory.json
#   scripts/method-inventory.py --check     fail if the committed file is stale (CI)
#   scripts/method-inventory.py --selftest  prove the derivation cannot be lied to
#
# The SDK sources are located in the cargo registry. They are NOT vendored in this tree yet (the
# pins land in step 1 of the 1.6.0 sequence), so --write and --check require `cargo fetch` to have
# run and REFUSE rather than skip when the sources are absent. The Rust gate needs none of this:
# it reads the committed JSON.

import argparse
import glob
import json
import os
import re
import sys

RMCP_VERSION = "3.1.2"
A2A_PB_VERSION = "0.2.0"

# MCP revision the pinned rmcp implements, and the A2A spec tag the pinned proto is cut from.
MCP_REVISION = "2026-07-28"
A2A_SPEC_TAG = "v1.0.1"

MCP_TRANSPORTS = ("streamable-http", "stdio")
A2A_TRANSPORTS = ("jsonrpc", "http+json", "grpc")
ROLES = ("server", "client")  # busbar is asked / busbar asks. It is BOTH, on BOTH protocols.

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
OUT = os.path.join(REPO, "qa", "method-inventory.json")

# ---------------------------------------------------------------------------
# The three non-mechanical tables. Each is cross-checked against the derived
# list, so none of them can quietly fall behind the specification.
# ---------------------------------------------------------------------------

# rmcp declares this constant but routes it through no union, so a derivation that reads only the
# unions loses it. SEP-1036 out-of-band elicitation responses: the response travels client ->
# server, so the originator is the client.
MCP_ORPHAN_ORIGINATOR = {
    "notifications/elicitation/response": (
        "client",
        "notification",
        "rmcp declares ElicitationResponseNotificationMethod but lists it in no ts_union!; "
        "SEP-1036 sends the elicitation response from client to server",
    ),
}

# A2A SPEC 9.1 "Method Naming" makes the JSON-RPC method name the PascalCase rpc name. SPEC 9.3's
# Base Request Structure still shows the 0.3-era "category/action" placeholder, and SPEC 3.6.2
# requires an agent to read a missing A2A-Version header AS 0.3 -- so the 0.3 names remain a live
# surface, not history. testing/a2a-harness/a2aht/spec.py records the same divergence under
# AMBIGUITIES["JSONRPC_METHOD_NAMING_EXAMPLE"]. The mapping is not derivable from the proto
# (SubscribeToTask -> tasks/resubscribe is not a transform of anything), so it is written out and
# then cross-checked for exact coverage of the derived rpc set.
LEGACY_JSONRPC_0_3 = {
    "SendMessage": "message/send",
    "SendStreamingMessage": "message/stream",
    "GetTask": "tasks/get",
    "ListTasks": "tasks/list",
    "CancelTask": "tasks/cancel",
    "SubscribeToTask": "tasks/resubscribe",
    "CreateTaskPushNotificationConfig": "tasks/pushNotificationConfig/set",
    "GetTaskPushNotificationConfig": "tasks/pushNotificationConfig/get",
    "ListTaskPushNotificationConfigs": "tasks/pushNotificationConfig/list",
    "DeleteTaskPushNotificationConfig": "tasks/pushNotificationConfig/delete",
    "GetExtendedAgentCard": "agent/getAuthenticatedExtendedCard",
}

# Surfaces the suites in testing/ exercise that are in NEITHER the rmcp method constants nor the
# proto service block. Each names the requirement IDs that already test it, which is what makes
# "the conformance suites cover this" a checkable claim rather than an assertion.
EXTRA_SURFACES = [
    {
        "protocol": "a2a",
        "method": "GET /.well-known/agent-card.json",
        "originator": "client",
        "kind": "http-resource",
        "why_not_derived": (
            "A2A SPEC 8.2 and the IANA registration in SPEC 14.3 define the Agent Card as an HTTP "
            "resource. It is not an rpc in service A2AService, so a proto-only derivation misses "
            "it entirely -- and it is the FIRST thing every A2A client fetches."
        ),
        "exercised_by": [
            "a2a-tck CARD-DISC-001",
            "a2a-tck CARD-STRUCT-001",
            "a2a-tck CARD-PROTO-001/002",
            "a2a-tck CARD-CACHE-001/002/003",
            "a2a-tck CARD-SIGN-001..004",
            "a2a-tck CARD-EXT-001/002",
        ],
        "na": {
            "grpc": "The card is an HTTP resource at a well-known path, not an rpc; gRPC has no "
            "well-known-path concept and the proto service block does not declare it. A gRPC-only "
            "peer discovers busbar via the same HTTP fetch."
        },
    },
    {
        "protocol": "a2a",
        "method": "PushNotificationDelivery",
        "originator": "server",
        "kind": "webhook",
        "why_not_derived": (
            "Delivering a push notification is the agent POSTing a Task to the client's webhook "
            "URL. It is an obligation of the server role with no rpc, no JSON-RPC method and no "
            "gRPC form -- so it is invisible to the service block even though three TCK MUSTs "
            "judge it."
        ),
        "exercised_by": [
            "a2a-tck PUSH-DELIVER-001",
            "a2a-tck PUSH-DELIVER-002",
            "a2a-tck PUSH-DELIVER-003",
        ],
        "na": {
            "jsonrpc": "Delivery is an outbound HTTP POST to the client's webhook. There is no "
            "JSON-RPC request for it; the JSON-RPC binding only carries the CONFIG methods.",
            "grpc": "Same: the proto declares the config messages, never a delivery rpc.",
        },
    },
    {
        "protocol": "mcp",
        "method": "GET /mcp (open SSE stream)",
        "originator": "client",
        "kind": "http-verb",
        "why_not_derived": (
            "Opening the server-to-client SSE stream, and resuming it with Last-Event-ID, is a "
            "streamable-HTTP transport obligation with no JSON-RPC method name, so an "
            "rmcp-model-only derivation cannot see it. Without it NO server-originated request "
            "or notification can reach the client over HTTP."
        ),
        "exercised_by": [
            "mcp-conformance (official) server-sse-multiple-streams",
            "mcp-conformance (official) server-stateless",
        ],
        "na": {
            "stdio": "stdio has no session envelope and no second channel: the stream IS the "
            "process's stdout, opened once at spawn."
        },
    },
    {
        "protocol": "mcp",
        "method": "DELETE /mcp (terminate session)",
        "originator": "client",
        "kind": "http-verb",
        "why_not_derived": (
            "Explicit session termination is a streamable-HTTP verb, not a JSON-RPC method. It is "
            "the only way a client can tell a gateway to drop server-side state it is being "
            "billed for."
        ),
        "exercised_by": [
            "mcp-conformance (official) server-stateless",
            "mcp-conformance (in-house battery) SEAM session clauses",
        ],
        "na": {
            "stdio": "A stdio session ends when the process does; there is no session id to "
            "delete."
        },
    },
]


def die(msg):
    print(f"method-inventory: {msg}", file=sys.stderr)
    sys.exit(2)


# ---------------------------------------------------------------------------
# MCP, out of rmcp's own model.rs
# ---------------------------------------------------------------------------

CONST_RE = re.compile(r'const_string!\(\s*(\w+)\s*=\s*"([^"]*)"\s*,?\s*\)', re.S)
ALIAS_RE = re.compile(r"pub type (\w+)\s*=\s*\w+\s*<\s*(\w+Method)\b", re.S)
UNION_RE = re.compile(r"ts_union!\(\s*export type (\w+)\s*=\s*(.*?)\);", re.S)

MCP_UNIONS = {
    "ClientRequest": ("client", "request"),
    "ServerRequest": ("server", "request"),
    "ClientNotification": ("client", "notification"),
    "ServerNotification": ("server", "notification"),
}


def derive_mcp(model_src):
    """Return [(method, originator, kind, source)] from rmcp's model.rs."""
    consts = {n: v for n, v in CONST_RE.findall(model_src) if n.endswith("Method")}
    if len(consts) < 30:
        die(f"only {len(consts)} method constants found in rmcp model.rs -- refusing to "
            "generate a vacuous inventory")
    aliases = dict(ALIAS_RE.findall(model_src))
    unions = {
        name: [v.strip().rstrip(";") for v in body.split("|") if v.strip()]
        for name, body in UNION_RE.findall(model_src)
    }

    rows = []
    seen_consts = set()
    for union, (originator, kind) in MCP_UNIONS.items():
        if union not in unions:
            die(f"rmcp no longer declares ts_union! {union}; the derivation is out of date")
        for variant in unions[union]:
            variant = variant.replace("box ", "").strip()
            if variant.startswith("Custom"):
                # CustomRequest/CustomNotification are the escape hatch for methods the SDK does
                # not model. They are not methods and must not become rows.
                continue
            const = aliases.get(variant)
            if const is None:
                die(f"{union} variant {variant} has no `pub type` binding a method constant; "
                    "the parser is stale, not the SDK")
            wire = consts.get(const)
            if wire is None:
                die(f"{variant} binds {const}, which is not a method constant")
            seen_consts.add(const)
            rows.append((wire, originator, kind, f"rmcp {RMCP_VERSION} {union}::{variant}"))

    # Anything declared but not routed. Never dropped: classified here or the run fails.
    for const, wire in sorted(consts.items()):
        if const in seen_consts:
            continue
        entry = MCP_ORPHAN_ORIGINATOR.get(wire)
        if entry is None:
            die(f"rmcp declares method constant {const} = {wire!r} but lists it in no "
                "ts_union!, and MCP_ORPHAN_ORIGINATOR does not classify it. Classify it with a "
                "citation -- do not delete this check.")
        originator, kind, note = entry
        rows.append((wire, originator, kind, f"rmcp {RMCP_VERSION} const {const} ({note})"))

    # Two distinct obligations share the name `ping` (client->server and server->client). The row
    # key is (method, originator) precisely so neither disappears into the other.
    keyed = {}
    for wire, originator, kind, source in rows:
        keyed.setdefault((wire, originator), (kind, source))
    return keyed


# ---------------------------------------------------------------------------
# A2A, out of a2a-pb's vendored a2a.proto
# ---------------------------------------------------------------------------

SERVICE_RE = re.compile(r"service\s+A2AService\s*\{(.*?)\n\}", re.S)
RPC_RE = re.compile(
    r"rpc\s+(\w+)\s*\(\s*(?:stream\s+)?[\w.]+\s*\)\s*returns\s*\(\s*(stream\s+)?[\w.]+\s*\)\s*\{(.*?)\n  \}",
    re.S,
)
HTTP_RE = re.compile(r"(get|post|put|patch|delete)\s*:\s*\"([^\"]+)\"")


def derive_a2a(proto_src):
    m = SERVICE_RE.search(proto_src)
    if not m:
        die("a2a.proto has no `service A2AService` block")
    body = m.group(1)
    rpcs = {}
    for name, streaming, opts in RPC_RE.findall(body):
        bindings = [
            {"verb": verb.upper(), "path": path}
            for verb, path in HTTP_RE.findall(opts)
            # Skip the {tenant}-prefixed additional_bindings: same method, same obligation,
            # a deployment-shape prefix. The primary binding is the one a cell is about.
            if "{tenant}" not in path
        ]
        if not bindings:
            die(f"rpc {name} carries no google.api.http binding; the HTTP+JSON column would be "
                "a guess")
        rpcs[name] = {
            "server_streaming": bool(streaming),
            "http": bindings[0],
        }
    if len(rpcs) < 8:
        die(f"only {len(rpcs)} rpcs parsed out of service A2AService -- refusing to generate a "
            "vacuous inventory")

    # The alias table must cover EXACTLY the derived set. This is the check that makes the one
    # hand-written A2A table safe: a new rpc upstream stops the build here.
    missing = sorted(set(rpcs) - set(LEGACY_JSONRPC_0_3))
    extra = sorted(set(LEGACY_JSONRPC_0_3) - set(rpcs))
    if missing:
        die(f"LEGACY_JSONRPC_0_3 has no 0.3 name for {missing}; supply it with a spec citation")
    if extra:
        die(f"LEGACY_JSONRPC_0_3 names {extra}, which the proto no longer declares; remove the "
            "stale alias")
    return rpcs


# ---------------------------------------------------------------------------
# The matrix
# ---------------------------------------------------------------------------

def cell_id(protocol, transport, role, originator, method):
    return f"{protocol}|{transport}|{role}|{originator}|{method}"


def obligation(role, originator):
    """What the cell actually demands of busbar. A method 'implemented' in one direction is
    still a missing letter, and these two words are the difference."""
    return "handle" if role != originator else "issue"


def build(mcp_rows, a2a_rpcs):
    methods = []

    for (wire, originator), (kind, source) in sorted(mcp_rows.items()):
        methods.append({
            "protocol": "mcp",
            "method": wire,
            "originator": originator,
            "kind": kind,
            "derived_from": source,
            "transports": list(MCP_TRANSPORTS),
            "na": {},
        })

    for name in sorted(a2a_rpcs):
        info = a2a_rpcs[name]
        methods.append({
            "protocol": "a2a",
            "method": name,
            "originator": "client",
            "kind": "rpc",
            "derived_from": f"a2a-pb {A2A_PB_VERSION} proto/a2a.proto service A2AService",
            "transports": list(A2A_TRANSPORTS),
            "server_streaming": info["server_streaming"],
            "wire_names": {
                # SPEC 9.1 vs SPEC 9.3; both are live because SPEC 3.6.2 makes a version-less
                # request a 0.3 request. A gateway that serves only one of these serves half its
                # callers.
                "jsonrpc_1_0": name,
                "jsonrpc_0_3": LEGACY_JSONRPC_0_3[name],
                "http+json": f"{info['http']['verb']} {info['http']['path']}",
                "grpc": f"/a2a.v1.A2AService/{name}",
            },
            "na": {},
        })

    for extra in EXTRA_SURFACES:
        methods.append({
            "protocol": extra["protocol"],
            "method": extra["method"],
            "originator": extra["originator"],
            "kind": extra["kind"],
            "derived_from": "not derivable: " + extra["why_not_derived"],
            "exercised_by": extra["exercised_by"],
            "transports": list(
                MCP_TRANSPORTS if extra["protocol"] == "mcp" else A2A_TRANSPORTS
            ),
            "na": extra["na"],
        })

    cells = []
    for m in methods:
        for transport in m["transports"]:
            for role in ROLES:
                cid = cell_id(m["protocol"], transport, role, m["originator"], m["method"])
                cell = {
                    "id": cid,
                    "protocol": m["protocol"],
                    "method": m["method"],
                    "originator": m["originator"],
                    "role": role,
                    "transport": transport,
                    "obligation": obligation(role, m["originator"]),
                }
                if transport in m["na"]:
                    cell["na_reason"] = m["na"][transport]
                cells.append(cell)

    cells.sort(key=lambda c: c["id"])
    return {
        "_comment": [
            "GENERATED by scripts/method-inventory.py. Do not edit by hand.",
            "Regenerate:  scripts/method-inventory.py --write",
            "",
            "This is the ENUMERATED method inventory for MCP and A2A, expanded into the",
            "method x direction x transport matrix. crates/busbar/tests/method_coverage.rs",
            "reads it and FAILS the build for any cell that is neither implemented nor",
            "explicitly waived in qa/method-coverage.status.",
            "",
            "A cell with an na_reason is not owed an implementation. A cell WITHOUT one is,",
            "and its absence from the status file is a MISSING -- which is a build failure,",
            "not a silence.",
        ],
        "mcp_revision": MCP_REVISION,
        "a2a_spec_tag": A2A_SPEC_TAG,
        "derived_from": {
            "mcp": f"rmcp {RMCP_VERSION} src/model.rs",
            "a2a": f"a2a-pb {A2A_PB_VERSION} proto/a2a.proto",
        },
        "roles": list(ROLES),
        "methods": methods,
        "cells": cells,
        "counts": {
            "mcp_methods": sum(1 for m in methods if m["protocol"] == "mcp"),
            "a2a_methods": sum(1 for m in methods if m["protocol"] == "a2a"),
            "cells": len(cells),
            "na_cells": sum(1 for c in cells if "na_reason" in c),
        },
    }


# ---------------------------------------------------------------------------
# Sources
# ---------------------------------------------------------------------------

def find_source(pattern, what):
    home = os.environ.get("CARGO_HOME") or os.path.expanduser("~/.cargo")
    hits = sorted(glob.glob(os.path.join(home, "registry", "src", "*", pattern)))
    if not hits:
        die(f"cannot find {what} under {home}/registry/src/*/{pattern}. Run `cargo fetch` for a "
            "crate depending on it. This REFUSES rather than skipping: an inventory derived from "
            "an absent source would be an inventory of nothing.")
    return hits[-1]


def render():
    rmcp = find_source(f"rmcp-{RMCP_VERSION}/src/model.rs", f"rmcp {RMCP_VERSION}")
    proto = find_source(f"a2a-pb-{A2A_PB_VERSION}/proto/a2a.proto", f"a2a-pb {A2A_PB_VERSION}")
    with open(rmcp, encoding="utf-8") as fh:
        mcp_rows = derive_mcp(fh.read())
    with open(proto, encoding="utf-8") as fh:
        a2a_rpcs = derive_a2a(fh.read())
    doc = build(mcp_rows, a2a_rpcs)
    return json.dumps(doc, indent=2, sort_keys=False) + "\n"


# ---------------------------------------------------------------------------
# Self-test: the derivation must be unable to lose a method quietly.
# ---------------------------------------------------------------------------

def selftest():
    rmcp = find_source(f"rmcp-{RMCP_VERSION}/src/model.rs", f"rmcp {RMCP_VERSION}")
    proto = find_source(f"a2a-pb-{A2A_PB_VERSION}/proto/a2a.proto", f"a2a-pb {A2A_PB_VERSION}")
    model = open(rmcp, encoding="utf-8").read()
    protosrc = open(proto, encoding="utf-8").read()

    ok = True

    def check(name, fn, expect_die):
        nonlocal ok
        try:
            fn()
            died = False
        except SystemExit:
            died = True
        if died != expect_die:
            ok = False
            print(f"  FAIL {name}: expected {'refusal' if expect_die else 'success'}", flush=True)
        else:
            print(f"  ok   {name}", flush=True)

    print("method-inventory SELF-TEST (the derivation cannot be lied to)", flush=True)

    # 1. Baseline: the real sources parse.
    check("real sources parse", lambda: derive_mcp(model), False)
    check("real proto parses", lambda: derive_a2a(protosrc), False)

    # 2. Deleting a method from a union must NOT silently shrink the answer -- the constant is
    #    then an unclassified orphan and the run must refuse.
    doctored = model.replace("    | CallToolRequest\n", "", 1)
    if doctored == model:
        ok = False
        print("  FAIL doctoring: could not remove CallToolRequest from ClientRequest")
    check("a method dropped from a union is refused, not lost", lambda: derive_mcp(doctored), True)

    # 3. An rpc added to the proto with no 0.3 alias must stop the run.
    added = protosrc.replace(
        "  // Sends a message to an agent.",
        '  rpc FrobnicateTask(GetTaskRequest) returns (Task) {\n'
        '    option (google.api.http) = {\n      get: "/tasks/{id=*}:frob"\n    };\n  }\n'
        "  // Sends a message to an agent.",
        1,
    )
    check("a new rpc with no 0.3 alias is refused", lambda: derive_a2a(added), True)

    # 4. A vacuous parse (empty source) must refuse rather than emit an empty inventory.
    check("empty rmcp source refuses", lambda: derive_mcp(""), True)
    check("empty proto refuses", lambda: derive_a2a(""), True)

    # 5. Every N/A cell carries a reason. An unexplained absent cell is the failure mode this
    #    whole file exists to prevent.
    doc = build(derive_mcp(model), derive_a2a(protosrc))
    bad = [c["id"] for c in doc["cells"] if "na_reason" in c and not c["na_reason"].strip()]
    if bad:
        ok = False
        print(f"  FAIL N/A cells without a reason: {bad}")
    else:
        print("  ok   every N/A cell carries a reason")

    # 6. Both roles exist for every method. A method implemented in one direction is still a
    #    missing letter, and the matrix has to be able to say so.
    roles_seen = {}
    for c in doc["cells"]:
        roles_seen.setdefault((c["protocol"], c["method"], c["transport"]), set()).add(c["role"])
    lopsided = [k for k, v in roles_seen.items() if v != set(ROLES)]
    if lopsided:
        ok = False
        print(f"  FAIL methods present in only one direction: {lopsided[:5]}")
    else:
        print("  ok   every method has both a server-role and a client-role cell")

    print("SELF-TEST " + ("PASS" if ok else "FAIL"))
    return 0 if ok else 1


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    g = ap.add_mutually_exclusive_group(required=True)
    g.add_argument("--write", action="store_true", help="regenerate qa/method-inventory.json")
    g.add_argument("--check", action="store_true", help="fail if the committed file is stale")
    g.add_argument("--selftest", action="store_true", help="prove the derivation cannot be lied to")
    args = ap.parse_args()

    if args.selftest:
        return selftest()

    fresh = render()
    if args.write:
        os.makedirs(os.path.dirname(OUT), exist_ok=True)
        with open(OUT, "w", encoding="utf-8") as fh:
            fh.write(fresh)
        doc = json.loads(fresh)
        c = doc["counts"]
        print(f"wrote {OUT}: {c['mcp_methods']} MCP methods, {c['a2a_methods']} A2A methods, "
              f"{c['cells']} cells ({c['na_cells']} N/A)")
        return 0

    if not os.path.exists(OUT):
        die(f"{OUT} does not exist. Generate it with scripts/method-inventory.py --write")
    with open(OUT, encoding="utf-8") as fh:
        committed = fh.read()
    if committed != fresh:
        die("qa/method-inventory.json is STALE against the pinned SDK sources. The specification "
            "moved and the matrix did not. Regenerate with `scripts/method-inventory.py --write` "
            "and read the diff -- a new row is a new obligation.")
    print("qa/method-inventory.json matches a fresh derivation")
    return 0


if __name__ == "__main__":
    sys.exit(main())
