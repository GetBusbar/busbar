#!/usr/bin/env python3
# kind-isolation dep-wall gate — busbar 1.6.0 DECISIONS #40(a)
#
# LAW (DECISIONS.md #40, amends/relies on #33, #38, #39):
#   "dep-wall — a plugin crate's entire workspace dependency closure = `busbar-contract`
#    and nothing else; a RED-provable `kind-isolation` CI gate runs `cargo metadata` on
#    every `busbar-<kind>-*` crate and asserts closure ∩ {kernel, core-*, any secret impl,
#    any other plugin} = ∅ (you cannot `use` what you cannot name)."
#   Cites: #33 (plugin infra = sdk+loader), #38 (busbar-contract is the ONE ABI crate),
#          #39 (every plugin = 1 repo = 1 crate; planes = 4).
#
# WHAT THIS ENFORCES
#   For every PLUGIN crate in the roster below, compute the transitive dependency closure
#   from `cargo metadata` (normal + build edges; dev-dependencies excluded — they do not
#   ship in the plugin artifact). Any *in-workspace* `busbar-*` crate in that closure that
#   is NOT in ALLOWED_DEPS is a VIOLATION, reported with the offending edge path from the
#   plugin down to the leaked crate.
#
# RED-PROVABLE
#   Green only when every roster plugin's closure ⊆ ALLOWED_DEPS ∪ {external non-busbar}.
#   Add a forbidden edge to any plugin's Cargo.toml and this gate goes RED. Today it is
#   EXPECTED-RED (planes/codecs/transports still pull busbar-substrate & friends) — that is
#   the point: the gate is report-only until the #34 rename + #19/#37 core-dissolve wave
#   lands, then it flips blocking (see docs/design/1.6.0-kind-isolation-gate.md).
#
# ROSTER
#   The roster + allowed set finalize with the #34 rename wave and the #39 plugin-repo
#   split. Until then the in-tree roster is maintained HERE (or via --roster FILE). Edit
#   the two lists below; nothing else needs to change.

import argparse
import json
import subprocess
import sys
from collections import deque

# --------------------------------------------------------------------------------------
# ROSTER (editable) — the in-tree PLUGIN crates as they exist TODAY (pre-rename wave #34).
# A crate belongs here if it is a plugin INSTANCE (a kind impl / cdylib / plane / transport
# / codec that folds into a plane), NOT kernel/core/contract/plugin-infra scaffolding.
# --------------------------------------------------------------------------------------
DEFAULT_ROSTER = [
    # --- plane kind: the #39 target adapters (planes = 4) ---
    "busbar-plane-llm",
    "busbar-plane-mcp",
    "busbar-plane-a2a",
    "busbar-plane-streaming",
    # --- plane kind: transitional adapter crates still present pre-fold (#39 folds these) ---
    "busbar-plane-voice",
    "busbar-plane-mcp-host",
    "busbar-plane-a2a-host",
    # --- plane kind: the fat engine crates being DELETED (#19/#20/#21) — still plugins today ---
    "busbar-llm",
    "busbar-mcp",
    "busbar-a2a",
    "busbar-voice",
    # --- codec crates: fold INTO the plane crate at #39; separate crates today ---
    "busbar-llm-codec",
    "busbar-mcp-codec",
    "busbar-a2a-codec",
    "busbar-voice-codec",
    # --- transport kind: the 7 carriers (#3) ---
    "busbar-transport-http",
    "busbar-transport-ws",
    "busbar-transport-stdio",
    "busbar-transport-tcp",
    "busbar-transport-tls",
    "busbar-transport-sse",
    "busbar-transport-grpc",
    # --- store kind instances ---
    "busbar-store-memory",
    "busbar-store-example-plugin",
    # --- secret kind instances ---
    "busbar-secret-example-plugin",
    # --- auth kind instances ---
    "busbar-auth-static-plugin",
    # --- hook kind instances ---
    "busbar-hook-test-plugin",
    "busbar-hooks-ranking",
    # --- export kind instances ---
    "busbar-export-example-plugin",
    # --- plane cdylib example (drop-in plane) ---
    "busbar-plugin-example-plane",
]

# --------------------------------------------------------------------------------------
# ALLOWED_DEPS (editable) — the ONLY in-workspace busbar-* crates a plugin may name.
# DECISIONS #40(a): closure = `busbar-contract` and nothing else. (#38: busbar-contract is
# the ONE ABI crate.) Everything else busbar-* in the closure is a VIOLATION.
# NOTE (OPEN, flagged in the doc): #2/#33 say plugins self-register via busbar-plugin-sdk,
# which would need to join this set post-fold; #40(a) as written names only busbar-contract.
# The gate defaults to the #40(a) literal; add "busbar-plugin-sdk" here if the owner rules.
# --------------------------------------------------------------------------------------
DEFAULT_ALLOWED = [
    "busbar-contract",
]

# Crates that are NOT plugins and NOT allowed deps — naming any of these is the headline
# violation class the law calls out: {kernel, core-*, substrate, api, other plugin}.
# (Informational: used only to classify/label offenders in the report.)
FORBIDDEN_PREFIXES_LABELS = [
    ("busbar-kernel", "kernel"),
    ("busbar-core", "core-*"),
    ("busbar-substrate", "substrate"),
    ("busbar-unit-", "unit/kernel-workflow"),
    ("busbar-api", "api"),
    ("busbar-admin", "core/admin"),
    ("busbar-oauth2", "core/oauth2"),
    ("busbar-caps", "core/caps"),
    ("busbar-grammar", "core/grammar"),
    ("busbar-timing", "core/timing"),
    ("busbar-secret-ref", "secret machinery"),
]


def classify(name):
    for prefix, label in FORBIDDEN_PREFIXES_LABELS:
        if name == prefix or name.startswith(prefix):
            return label
    return "other-plugin/non-contract"


def load_metadata():
    out = subprocess.run(
        ["cargo", "metadata", "--format-version", "1"],
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(out.stdout)


def build_graph(meta):
    """Return (id2name, ws_busbar_ids, adjacency).

    adjacency[id] = list of (dep_id) for in-workspace busbar-* deps reachable over
    non-dev edges (kind null == normal, "build" == build-dep; dev-only edges dropped).
    External crates.io deps never point back into path busbar crates, so restricting the
    traversal to the workspace-busbar subgraph loses no reachable busbar crate.
    """
    id2name = {p["id"]: p["name"] for p in meta["packages"]}
    ws = set(meta["workspace_members"])
    ws_busbar = {i for i in ws if id2name[i].startswith("busbar")}

    adjacency = {i: [] for i in ws_busbar}
    for node in meta["resolve"]["nodes"]:
        nid = node["id"]
        if nid not in ws_busbar:
            continue
        for dep in node["deps"]:
            kinds = [dk.get("kind") for dk in dep.get("dep_kinds", [])]
            # ship edge = at least one non-dev (normal/build) edge
            if not any(k is None or k == "build" for k in kinds):
                continue
            pkg = dep["pkg"]
            if pkg in ws_busbar and pkg != nid:
                adjacency[nid].append(pkg)
    return id2name, ws_busbar, adjacency


def closure_paths(start_id, adjacency, id2name):
    """BFS from start_id over the busbar subgraph. Returns {reached_id: [name path]}."""
    parent = {start_id: None}
    q = deque([start_id])
    while q:
        cur = q.popleft()
        for nxt in adjacency.get(cur, []):
            if nxt not in parent:
                parent[nxt] = cur
                q.append(nxt)
    paths = {}
    for reached in parent:
        if reached == start_id:
            continue
        chain = []
        node = reached
        while node is not None:
            chain.append(id2name[node])
            node = parent[node]
        chain.reverse()
        paths[reached] = chain
    return paths


def main():
    ap = argparse.ArgumentParser(description="busbar kind-isolation dep-wall gate (#40a)")
    ap.add_argument("--roster", help="file with one plugin crate name per line (overrides default)")
    ap.add_argument("--allow", action="append", default=[],
                    help="extra allowed in-workspace busbar-* dep (repeatable)")
    ap.add_argument("--report-only", action="store_true",
                    help="always exit 0 (CI report-only mode until the rename wave lands)")
    ap.add_argument("--json", action="store_true", help="emit machine-readable JSON")
    args = ap.parse_args()

    roster = list(DEFAULT_ROSTER)
    if args.roster:
        with open(args.roster) as fh:
            roster = [ln.strip() for ln in fh if ln.strip() and not ln.startswith("#")]
    allowed = set(DEFAULT_ALLOWED) | set(args.allow)

    meta = load_metadata()
    id2name, ws_busbar, adjacency = build_graph(meta)
    name2id = {id2name[i]: i for i in ws_busbar}

    results = []       # (plugin, [violation dicts])
    missing = []       # roster names not present in this workspace
    for plugin in roster:
        pid = name2id.get(plugin)
        if pid is None:
            missing.append(plugin)
            continue
        paths = closure_paths(pid, adjacency, id2name)
        viols = []
        for reached_id, chain in paths.items():
            name = id2name[reached_id]
            if name in allowed:
                continue
            viols.append({"crate": name, "class": classify(name), "path": chain})
        viols.sort(key=lambda v: (v["class"], v["crate"]))
        results.append((plugin, viols))

    total_viol_edges = sum(len(v) for _, v in results)
    plugins_red = [p for p, v in results if v]

    if args.json:
        print(json.dumps({
            "allowed": sorted(allowed),
            "missing_from_workspace": missing,
            "plugins_checked": len(results),
            "plugins_with_violations": len(plugins_red),
            "total_violation_edges": total_viol_edges,
            "results": [{"plugin": p, "violations": v} for p, v in results],
        }, indent=2))
    else:
        print("== busbar kind-isolation dep-wall (DECISIONS #40a) ==")
        print(f"allowed in-workspace deps: {', '.join(sorted(allowed))}")
        if missing:
            print(f"WARNING roster crates not in this workspace: {', '.join(missing)}")
        print(f"plugins checked: {len(results)}  |  with violations: {len(plugins_red)}  "
              f"|  total offending edges: {total_viol_edges}")
        print("")
        for plugin, viols in results:
            if not viols:
                print(f"  OK   {plugin}: closure clean (⊆ {', '.join(sorted(allowed))} + external)")
                continue
            print(f"  RED  {plugin}: {len(viols)} forbidden busbar-* dep(s)")
            for v in viols:
                print(f"         - {v['crate']}  [{v['class']}]")
                print(f"             edge: {'  ->  '.join(v['path'])}")

    if total_viol_edges and not args.report_only:
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
