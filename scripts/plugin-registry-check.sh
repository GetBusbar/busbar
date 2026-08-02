#!/usr/bin/env bash
# THE REGISTRY GATE: keeps plugins.yaml (the single source of truth for first-party plugins) and
# its consumers honest. RED when a registry entry lacks coverage somewhere, or when a plugin-shaped
# org repo exists that the registry doesn't know about. See plugins.yaml's own header for the
# design; this gate is what turns "remembered in five places" into "enforced from one".
#
# Checks, in order:
#   1. Registry shape: required fields, valid kinds/gates, unique repo/alias/crate.
#   2. qa-gate.yml derives its sibling checkouts from the registry (its clone loop calls this
#      script's --list mode) — per-plugin hand-written checkout steps are gone by design, so the
#      check is "the registry-driven step exists", not "a literal step per plugin exists".
#   3. release-check.sh coverage per entry's `gate` kind:
#        suite  — the registry-driven loop exists (calls --list) AND the entry's `service` has a
#                 handler arm in release-check.sh (a new service value needs a new container spec).
#        binary/smoke — an explicit phase touching the entry's sibling path (../<dir>) exists.
#   4. [network, skipped with --offline] every entry has a published GitHub release on its
#      version_line WITH >0 assets (a tag+release with no assets is a phantom, not a release).
#   5. [network, skipped with --offline] reverse sweep: org repos matching plugin naming
#      (store-*, *-hook, auth-*, or kind-named like hashicorp-*) must be in the registry or in
#      excluded_repos.
#
# Usage: scripts/plugin-registry-check.sh [--offline]
#        scripts/plugin-registry-check.sh --list
#
# --list is the machine-readable registry feed the other consumers iterate (release-check.sh's
# suite loop, qa-gate.yml's clone loop): one tab-separated line per plugin —
#   repo <TAB> dir <TAB> alias <TAB> kind <TAB> service <TAB> release_gate <TAB> gate <TAB> checkout_ref
# where dir is checkout_dir (falling back to repo) and checkout_ref is "-" when unset. Shape
# validation (check 1) still runs first, so a malformed registry fails every consumer loudly.
set -euo pipefail
cd "$(dirname "$0")/.."

MODE="${1:-}"

python3 - "$MODE" <<'PYEOF'
import json, re, subprocess, sys

mode = sys.argv[1]
offline = mode == "--offline"
list_mode = mode == "--list"
fail = []

# ── Parse plugins.yaml. PyYAML when present; otherwise a minimal parser for this file's known,
# deliberately-simple shape (flat list of flat mappings + one string list) so the gate has zero
# hard dependencies beyond python3 itself.
text = open("plugins.yaml", encoding="utf-8").read()
try:
    import yaml  # type: ignore
    doc = yaml.safe_load(text)
except ModuleNotFoundError:
    doc = {"excluded_repos": [], "plugins": []}
    cur = None
    section = None
    for raw in text.splitlines():
        line = raw.split("#", 1)[0].rstrip()
        if not line.strip():
            continue
        if line == "excluded_repos:":
            section = "excluded"
            continue
        if line == "plugins:":
            section = "plugins"
            continue
        if section == "excluded" and line.strip().startswith("- "):
            doc["excluded_repos"].append(line.strip()[2:].strip())
        elif section == "plugins":
            m = re.match(r"^  - (\w+):\s*(.*)$", line)
            if m:
                cur = {m.group(1): m.group(2).strip().strip('"')}
                doc["plugins"].append(cur)
                continue
            m = re.match(r"^    (\w+):\s*(.*)$", line)
            if m and cur is not None:
                cur[m.group(1)] = m.group(2).strip().strip('"')

plugins = doc.get("plugins") or []
excluded = set(doc.get("excluded_repos") or [])

# ── 1. Shape.
REQUIRED = ["repo", "kind", "alias", "crate", "version_line", "service", "release_gate", "gate"]
KINDS = {"store", "auth", "hook", "secret"}
GATES = {"suite", "binary", "smoke"}
seen = {"repo": set(), "alias": set(), "crate": set()}
for p in plugins:
    missing = [f for f in REQUIRED if f not in p or not str(p[f]).strip()]
    if missing:
        fail.append(f"registry entry {p.get('repo', p)}: missing fields {missing}")
        continue
    if p["kind"] not in KINDS:
        fail.append(f"{p['repo']}: kind '{p['kind']}' not one of {sorted(KINDS)}")
    if p["gate"] not in GATES:
        fail.append(f"{p['repo']}: gate '{p['gate']}' not one of {sorted(GATES)}")
    for k in seen:
        if p[k] in seen[k]:
            fail.append(f"duplicate {k} '{p[k]}' in registry")
        seen[k].add(p[k])
if not plugins:
    fail.append("plugins.yaml parsed to an empty plugin list")

# ── --list: shape-validated machine-readable feed for the iterating consumers, then stop.
if list_mode:
    if fail:
        print("PLUGIN REGISTRY GATE: RED (--list refused on a malformed registry)", file=sys.stderr)
        for f in fail:
            print(f"  - {f}", file=sys.stderr)
        sys.exit(1)
    for p in plugins:
        print("\t".join([
            p["repo"],
            p.get("checkout_dir") or p["repo"],
            p["alias"],
            p["kind"],
            p["service"],
            p["release_gate"],
            p["gate"],
            p.get("checkout_ref") or "-",
        ]))
    sys.exit(0)

# ── 2. qa-gate.yml derives its checkouts from the registry (no hand-written per-plugin steps).
devgate = open(".github/workflows/qa-gate.yml", encoding="utf-8").read()
if "plugin-registry-check.sh --list" not in devgate:
    fail.append("qa-gate.yml does not clone siblings via the registry "
                "(expected a step iterating `scripts/plugin-registry-check.sh --list`)")

# ── 3. release-check.sh coverage, per each entry's declared gate kind.
relcheck = open("scripts/release-check.sh", encoding="utf-8").read()
suite_loop_present = "plugin-registry-check.sh --list" in relcheck
for p in plugins:
    d = p.get("checkout_dir") or p["repo"]
    if p.get("gate") == "suite":
        if not suite_loop_present:
            fail.append(f"release-check.sh has no registry-driven suite loop "
                        f"(expected it to iterate `plugin-registry-check.sh --list`) — {p['repo']} uncovered")
        svc = p["service"]
        if svc != "none" and not re.search(rf"^\s*{re.escape(svc)}\)", relcheck, re.M):
            fail.append(f"release-check.sh's suite loop has no container-spec arm for service "
                        f"'{svc}' ({p['repo']}) — add one to its service case block")
    else:
        if f"../{d}" not in relcheck:
            fail.append(f"release-check.sh has no explicit phase touching ../{d} "
                        f"({p['repo']}, gate: {p.get('gate')})")

# ── 4 + 5. Network checks via `gh` (GITHUB_TOKEN in CI).
if not offline:
    def gh(path):
        r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
        return json.loads(r.stdout) if r.returncode == 0 else None

    for p in plugins:
        rel = gh(f"repos/GetBusbar/{p['repo']}/releases/latest")
        if rel is None:
            fail.append(f"{p['repo']}: no published release at all")
            continue
        tag = str(rel.get("tag_name", ""))
        if not tag.lstrip("v").startswith(p["version_line"] + "."):
            fail.append(f"{p['repo']}: latest release {tag} is not on version line {p['version_line']}.x")
        if not rel.get("assets"):
            fail.append(f"{p['repo']}: release {tag} has ZERO assets — a phantom release, not a release")

    repos = gh("orgs/GetBusbar/repos?per_page=100") or []
    known = {p["repo"] for p in plugins} | excluded
    pat = re.compile(r"^(store-.*|.*-hook|auth-.*|hashicorp-.*|secret-.*)$")
    for r in repos:
        name = r["name"]
        if pat.match(name) and name not in known:
            fail.append(f"org repo '{name}' matches plugin naming but is not in plugins.yaml "
                        f"(register it or add to excluded_repos with a reason)")

if fail:
    print("PLUGIN REGISTRY GATE: RED")
    for f in fail:
        print(f"  - {f}")
    sys.exit(1)
mode_desc = "offline (structure only)" if offline else "full (structure + releases + org sweep)"
print(f"PLUGIN REGISTRY GATE: green — {len(plugins)} plugins, mode: {mode_desc}")
PYEOF
