#!/usr/bin/env bash
# THE REGISTRY GATE: keeps plugins.yaml (the single source of truth for first-party plugins) and
# its consumers honest. RED when a registry entry lacks coverage somewhere, or when a plugin-shaped
# org repo exists that the registry doesn't know about. See plugins.yaml's own header for the
# design; this gate is what turns "remembered in five places" into "enforced from one".
#
# Checks, in order:
#   1. Registry shape: required fields, valid kinds, unique repo/alias/crate.
#   2. dev-gate.yml checks out every entry (by repo name or checkout_dir legacy name).
#   3. release-check.sh has a phase touching every entry's sibling path (../<dir>).
#   4. [network, skipped with --offline] every entry has a published GitHub release on its
#      version_line WITH >0 assets (a tag+release with no assets is a phantom, not a release).
#   5. [network, skipped with --offline] reverse sweep: org repos matching plugin naming
#      (store-*, *-hook, auth-*, or kind-named like hashicorp-*) must be in the registry or in
#      excluded_repos.
#
# Usage: scripts/plugin-registry-check.sh [--offline]
set -euo pipefail
cd "$(dirname "$0")/.."

OFFLINE="${1:-}"

python3 - "$OFFLINE" <<'PYEOF'
import json, re, subprocess, sys

offline = sys.argv[1] == "--offline"
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
REQUIRED = ["repo", "kind", "alias", "crate", "version_line", "service", "release_gate"]
KINDS = {"store", "auth", "hook", "secret"}
seen = {"repo": set(), "alias": set(), "crate": set()}
for p in plugins:
    missing = [f for f in REQUIRED if f not in p or not str(p[f]).strip()]
    if missing:
        fail.append(f"registry entry {p.get('repo', p)}: missing fields {missing}")
        continue
    if p["kind"] not in KINDS:
        fail.append(f"{p['repo']}: kind '{p['kind']}' not one of {sorted(KINDS)}")
    for k in seen:
        if p[k] in seen[k]:
            fail.append(f"duplicate {k} '{p[k]}' in registry")
        seen[k].add(p[k])
if not plugins:
    fail.append("plugins.yaml parsed to an empty plugin list")

# ── 2. dev-gate.yml checkouts.
devgate = open(".github/workflows/dev-gate.yml", encoding="utf-8").read()
for p in plugins:
    names = {p["repo"], p.get("checkout_dir") or p["repo"]}
    if not any(f"repository: GetBusbar/{n}" in devgate for n in names):
        fail.append(f"dev-gate.yml has no checkout for {p['repo']} (accepted names: {sorted(names)})")

# ── 3. release-check.sh phases.
relcheck = open("scripts/release-check.sh", encoding="utf-8").read()
for p in plugins:
    d = p.get("checkout_dir") or p["repo"]
    if f"../{d}" not in relcheck:
        fail.append(f"release-check.sh has no phase touching ../{d} ({p['repo']})")

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
mode = "offline (structure only)" if offline else "full (structure + releases + org sweep)"
print(f"PLUGIN REGISTRY GATE: green — {len(plugins)} plugins, mode: {mode}")
PYEOF
