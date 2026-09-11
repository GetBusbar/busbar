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

# ── --selftest ───────────────────────────────────────────────────────────────────────────────────
# Drives check 5 (the reverse org sweep) against a STUBBED `gh`, because the case that matters is
# the one where `gh` fails: an expired token used to make the sweep return None, `or []` turned that
# into an empty list, the loop body never ran, and the gate printed green having swept nothing.
# The sweep is the only check that can see a plugin-shaped repo nobody registered, so its silence
# is the one silence with no second signal behind it.
#
# Each case asserts on the check-5 line specifically, not on the exit code: the stub cannot know
# each plugin's version_line, so check 4 is noisy under it and is not what these cases are about.
if [ "$MODE" = "--selftest" ]; then
  tmp="$(mktemp -d)"; trap 'rm -rf "$tmp"' EXIT
  rc=0
  mk_stub() {  # mk_stub <orgs-behaviour-script>
    mkdir -p "$tmp/bin"
    { printf '#!/usr/bin/env bash\ncase "$2" in\n  */releases/latest) echo %s ;;\n  orgs/*)\n' \
        "'{\"tag_name\":\"v0.0.0\",\"assets\":[{\"name\":\"a\"}]}'"
      printf '%s\n' "$1"
      printf '    ;;\nesac\n'
    } > "$tmp/bin/gh"
    chmod +x "$tmp/bin/gh"
  }
  probe() {  # probe <label> <want-present|want-absent> <pattern>
    local out; out="$(PATH="$tmp/bin:$PATH" "$0" 2>&1 || true)"
    if [ "$2" = want-present ]; then
      if printf '%s' "$out" | grep -qF "$3"; then printf '  [ok]     %s\n' "$1"
      else printf '  [FAILED] %s (no line matching: %s)\n' "$1" "$3"; rc=1; fi
    else
      if printf '%s' "$out" | grep -qF "$3"; then printf '  [FAILED] %s (unexpected line: %s)\n' "$1" "$3"; rc=1
      else printf '  [ok]     %s\n' "$1"; fi
    fi
  }
  echo "plugin-registry-check selftest (check 5, the reverse org sweep)"

  # CASE 1: gh cannot answer at all — an expired token, no read:org, a rate limit.
  mk_stub '    echo "gh: Bad credentials (HTTP 401)" >&2; exit 1'
  probe "an expired/failing gh token REDS the org sweep instead of sweeping nothing" \
    want-present "the reverse org sweep (check 5) COULD NOT RUN"

  # CASE 2: gh answers, with nothing. An empty answer from an API is not an empty org.
  mk_stub '    echo "[]"'
  probe "an empty org listing REDS the sweep rather than passing it vacuously" \
    want-present "the reverse org sweep (check 5) saw only 0 org repo(s)"

  # CASE 3: a real-shaped listing containing an unregistered plugin-shaped repo — the sweep's whole
  # purpose. This is the half that proves the guards above did not just disable the check.
  mk_stub '    python3 -c "import json;print(json.dumps([{\"name\":\"r\"+str(i)} for i in range(40)]+[{\"name\":\"store-bogus\"}]))"'
  probe "a plausible listing still catches an unregistered plugin-shaped repo" \
    want-present "org repo 'store-bogus' matches plugin naming"

  # CASE 4: the same listing without the stray repo must not manufacture a finding.
  mk_stub '    python3 -c "import json;print(json.dumps([{\"name\":\"r\"+str(i)} for i in range(40)]))"'
  probe "a clean listing produces no sweep finding" want-absent "matches plugin naming but is not in plugins.yaml"

  echo
  [ "$rc" = 0 ] && { echo "plugin-registry-check selftest: the org sweep fails loud and still finds strays"; exit 0; }
  # ── CHECK 2, FAIL-INJECTED. A COMMENT MENTIONING THE LOOP IS NOT THE LOOP ──────────────────────
  # Check 2 asserted only that the string `plugin-registry-check.sh --list` appeared SOMEWHERE in
  # the qa-gate surface, and scripts/qa-gate-run.sh's header documents that loop in prose. Deleting
  # the real invocation from cmd_siblings therefore left the gate green on the strength of the
  # sentence describing what had just been removed -- the sibling fan-out would have cloned nothing
  # while this gate reported it registry-driven. Proven by OBSERVATION against a throwaway tree in
  # which the invocation is deleted and only the comment remains, with the unmutated tree as the
  # control so the case cannot pass by having broken check 2 outright.
  echo
  echo "plugin-registry-check selftest (check 2, the registry-driven sibling loop)"
  c2="$tmp/c2"
  mkdir -p "$c2/scripts" "$c2/.github/workflows"
  cp plugins.yaml "$c2/plugins.yaml"
  cp scripts/plugin-registry-check.sh scripts/release-check.sh "$c2/scripts/"
  [ -f scripts/release-check-1.5.2.sh ] && cp scripts/release-check-1.5.2.sh "$c2/scripts/"
  [ -f .github/workflows/qa-gate.yml ] && cp .github/workflows/qa-gate.yml "$c2/.github/workflows/"

  # Capture, never `producer | grep -q`. Under `pipefail` grep -q exits on its first match, the
  # producer takes SIGPIPE, and the pipeline reports failure whether or not the text was there --
  # which inverts both arms of this case. (Same trap plugin-ci-refs.sh's selftest documents.)
  c2_says() {  # c2_says <needle>  -> 0 when the gate's output contains it
    local out; out="$( (cd "$c2" && ./scripts/plugin-registry-check.sh --offline) 2>&1 || true)"
    case "$out" in *"$1"*) return 0 ;; *) return 1 ;; esac
  }
  C2_NEEDLE='does not clone siblings via the registry'

  # CONTROL: the unmutated copy must still pass check 2, so a RED below is the mutation talking.
  cp scripts/qa-gate-run.sh "$c2/scripts/qa-gate-run.sh"
  if c2_says "$C2_NEEDLE"; then
    printf '  [FAILED] %s\n' "control: the UNMUTATED tree failed check 2 (the check is broken, not the subject)"; rc=1
  else
    printf '  [ok]     %s\n' "control: the unmutated tree passes check 2"
  fi

  # MUTATION: delete the real invocation, keep every comment that mentions it.
  python3 - "$c2/scripts/qa-gate-run.sh" <<'MUT'
import re, sys
p = sys.argv[1]
out = []
for ln in open(p, encoding="utf-8"):
    if "plugin-registry-check.sh --list" in ln and not ln.lstrip().startswith("#"):
        ln = re.sub(r'\./scripts/plugin-registry-check\.sh --list', 'echo', ln)
    out.append(ln)
open(p, "w", encoding="utf-8").write("".join(out))
MUT
  if c2_says "$C2_NEEDLE"; then
    printf '  [ok]     %s\n' "deleting the loop but keeping the comment that describes it is RED"
  else
    printf '  [FAILED] %s\n' "check 2 passed with the registry-driven loop DELETED — a comment satisfied it"; rc=1
  fi

  echo
  [ "$rc" = 0 ] && { echo "plugin-registry-check selftest: the org sweep fails loud and still finds strays, and a comment cannot stand in for the registry loop"; exit 0; }
  echo "plugin-registry-check selftest: FAILED"; exit 1
fi

python3 - "$MODE" <<'PYEOF'
import json, os, re, subprocess, sys

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

# ── 2. the qa gate derives its checkouts from the registry (no hand-written per-plugin steps).
#
# The loop itself now lives in scripts/qa-gate-run.sh, not inline in the YAML: qa-gate.yml is a thin
# dispatcher that checks out the triggering SHA and invokes that script from it, so gate logic is
# versioned with the code it gates instead of frozen on the default branch (`workflow_run` always
# loads the workflow file from the default branch). This check follows the code rather than the
# filename: the loop must exist in one of the two files, and it must not be satisfied by a mere
# comment mentioning the string, so the whole qa-gate surface is scanned as one unit.
#
# A COMMENT MENTIONING THE LOOP IS NOT THE LOOP. This scanned the raw file text, and
# scripts/qa-gate-run.sh's own header documents the registry-driven checkout in prose -- the exact
# string `plugin-registry-check.sh --list` appears there as commentary. So deleting the real
# invocation from cmd_siblings left this check GREEN on the strength of the sentence describing the
# thing that had just been removed: the gate would have reported a registry-driven sibling fan-out
# while every plugin sibling silently went un-cloned. The comment two paragraphs up already claimed
# this could not happen. Strip whole-line comments before scanning so the claim is true.
def _code(path):
    """A file's contents with whole-line comments removed."""
    if not os.path.exists(path):
        return ""
    return "".join(ln for ln in open(path, encoding="utf-8")
                   if not ln.lstrip().startswith(("#", "//")))


devgate = _code(".github/workflows/qa-gate.yml") + _code("scripts/qa-gate-run.sh")
if "plugin-registry-check.sh --list" not in devgate:
    fail.append("the qa gate does not clone siblings via the registry (expected qa-gate.yml or "
                "scripts/qa-gate-run.sh to iterate `scripts/plugin-registry-check.sh --list`)")

# ── 3. release-check.sh coverage, per each entry's declared gate kind.
# Comment-stripped for the same reason check 2 is: release-check.sh's own prose names both the
# registry loop and several `../<dir>` sibling paths, so a phase deleted from the code would still
# have been "found" in the sentence that described it.
relcheck = _code("scripts/release-check.sh")
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

# ── 3c. `release_gate: required` MEANS THE SAME THING FOR EVERY GATE SHAPE.
# plugins.yaml documents the column as "release-check.sh hard-fails if the sibling checkout is
# missing", but only the Phase 2 SUITE loop ever read it (its `$P_RELGATE` arm). A `gate: binary` or
# `gate: smoke` entry could therefore be marked `required` and still be loud-SKIPPED into a green
# gate — a field that means one thing in the registry and another in the runner, which is worse than
# no field at all, because flipping it looks like it did something. Measured: store-sqlite, the one
# store busbar's own Dockerfile recommends by name.
#
# The suite loop is covered by its own `$P_RELGATE` read; every other shape must consult the single
# reader, `registry_release_gate <repo>`, by NAME — so the honouring cannot be deleted while this
# check goes on reporting coverage. Comment-stripped, for the reason check 2 gives.
relgate_reader_present = "registry_release_gate()" in relcheck
suite_relgate_read = "P_RELGATE" in relcheck
for p in plugins:
    if p.get("release_gate") != "required":
        continue
    if p.get("gate") == "suite":
        if not suite_relgate_read:
            fail.append(f"{p['repo']} is release_gate: required but release-check.sh's suite loop "
                        "no longer reads the release_gate column ($P_RELGATE) — a missing sibling "
                        "would be skipped into a green gate")
        continue
    if not relgate_reader_present:
        fail.append("release-check.sh has no `registry_release_gate()` reader, so a "
                    f"release_gate: required non-suite entry ({p['repo']}, gate: {p.get('gate')}) "
                    "cannot be honoured — its missing sibling would loud-skip into a green gate")
    elif not re.search(rf"registry_release_gate\s+{re.escape(p['repo'])}\b", relcheck):
        fail.append(f"{p['repo']} is release_gate: required (gate: {p.get('gate')}) but "
                    f"release-check.sh never asks `registry_release_gate {p['repo']}` — its phase "
                    "would loud-skip a missing sibling checkout instead of failing the gate")

# ── 3b. 1.5.2 token-exchange coverage: every kind:auth plugin must have a token-exchange flow case.
# Mirrors how check 3 reds a plugin lacking a gate phase — a kind:auth plugin with NO arm in the
# registry-driven token-exchange matrix (release-check-1.5.2.sh's `auth_plugin_flows()`) is RED, so a
# new auth plugin cannot ship an untested /auth/token surface. The matrix lives in the 1.5.2 feature
# gate, which release-check.sh invokes; the check scans BOTH files (concatenated) so it stays true
# whether the loop lives in release-check.sh or the sourced 1.5.2 script.
tokenx = ""
for _f in ("scripts/release-check.sh", "scripts/release-check-1.5.2.sh"):
    tokenx += "\n" + _code(_f)  # comment-stripped: see check 2
tokenx_loop_present = "plugin-registry-check.sh --list" in tokenx and "auth_plugin_flows" in tokenx
for p in plugins:
    if p["kind"] != "auth":
        continue
    if not tokenx_loop_present:
        fail.append("the 1.5.2 token-exchange gate has no registry-driven kind:auth loop "
                    "(expected release-check(-1.5.2).sh to iterate `plugin-registry-check.sh --list` "
                    f"with an `auth_plugin_flows()` capability map) — {p['repo']} uncovered")
        continue
    # A per-alias arm in auth_plugin_flows() — the same shape check 3 uses for a suite `service` arm.
    if not re.search(rf"^\s*{re.escape(p['alias'])}\)", tokenx, re.M):
        fail.append(f"kind:auth plugin {p['repo']} (alias {p['alias']}) has no token-exchange flow "
                    f"case — add an `{p['alias']})` arm to auth_plugin_flows() declaring which "
                    f"/auth/token direction(s) it supports (post/get/form)")

# ── 4 + 5. Network checks via `gh` (GITHUB_TOKEN in CI).
if not offline:
    # WHY THIS RETURNS A REASON AND NOT `None`.
    #
    # It used to be `return json.loads(r.stdout) if r.returncode == 0 else None`, and the org sweep
    # below was `repos = gh("orgs/GetBusbar/repos?per_page=100") or []`. Every way `gh` can fail —
    # an expired GITHUB_TOKEN, a token without `read:org`, a secondary rate limit, gh not on PATH,
    # DNS — produced None, `or []` turned that into an empty list, the `for r in repos:` body never
    # ran, and check 5 printed GREEN having swept nothing. That is the whole failure this gate
    # exists to prevent, in the gate itself: the reverse sweep is the ONLY check that can see a
    # plugin-shaped repo nobody registered, and an unregistered repo is invisible by construction —
    # there is no other signal that would have gone red. An empty answer from an API is never
    # evidence of an empty org.
    #
    # So: the call reports WHY it failed, and both callers below treat "could not ask" as RED with
    # that reason attached, distinct from "asked, and the answer was no".
    def gh(path):
        """-> (data, error). Exactly one is non-None."""
        try:
            r = subprocess.run(["gh", "api", path], capture_output=True, text=True)
        except FileNotFoundError:
            return None, "the `gh` CLI is not on PATH"
        if r.returncode != 0:
            why = (r.stderr or r.stdout or "").strip().replace("\n", " ")[:300]
            return None, f"`gh api {path}` exited {r.returncode}: {why or '<no output>'}"
        try:
            return json.loads(r.stdout), None
        except json.JSONDecodeError as e:
            return None, f"`gh api {path}` returned output that is not JSON ({e})"

    for p in plugins:
        # Pre-release entry (a new plugin whose FIRST release is cut together with the core version it
        # targets): registered here so the dev-gate/token-exchange loops cover it, but it has no
        # published release yet BY DESIGN. The org-repo scan below still requires it registered; only
        # this published-release arm is deferred. Flip `released: true` (or drop the key) at the cut.
        if str(p.get("released", "true")).strip().lower() == "false":
            continue
        rel, err = gh(f"repos/GetBusbar/{p['repo']}/releases/latest")
        if rel is None:
            # 404 really is "no published release at all"; anything else is "we could not ask",
            # and the two need different fixes. Conflating them sent people looking for a missing
            # release when the actual fault was a token.
            if "HTTP 404" in (err or "") or "Not Found" in (err or ""):
                fail.append(f"{p['repo']}: no published release at all")
            else:
                fail.append(f"{p['repo']}: could not determine whether a release exists — {err}")
            continue
        tag = str(rel.get("tag_name", ""))
        if not tag.lstrip("v").startswith(p["version_line"] + "."):
            fail.append(f"{p['repo']}: latest release {tag} is not on version line {p['version_line']}.x")
        if not rel.get("assets"):
            fail.append(f"{p['repo']}: release {tag} has ZERO assets — a phantom release, not a release")

    # THE FLOOR IS DERIVED, NOT TYPED. Every repo in plugins.yaml — registered or explicitly
    # excluded — is a repo this registry ASSERTS exists in GetBusbar. A sweep that comes back with
    # fewer repos than that has not seen repos we already know are there, so it is answering for
    # something narrower than the org and cannot rule out the unregistered repo it is looking for.
    # Derived means it tracks the registry: adding a plugin raises the floor by one, automatically.
    ORG_REPO_FLOOR = len(plugins) + len(excluded)

    repos, err = gh("orgs/GetBusbar/repos?per_page=100")
    if repos is None:
        fail.append("the reverse org sweep (check 5) COULD NOT RUN — " + str(err) + ". This is RED, "
                    "not a pass: the sweep is the only check that can see a plugin-shaped repo "
                    "nobody registered, so a sweep that inspected zero repos has ruled nothing out. "
                    "Fix: give this run a GITHUB_TOKEN with read:org, or run --offline, which skips "
                    "checks 4 and 5 by NAME rather than by accident.")
    elif not isinstance(repos, list) or len(repos) < ORG_REPO_FLOOR:
        fail.append(f"the reverse org sweep (check 5) saw only {len(repos) if isinstance(repos, list) else 0} "
                    f"org repo(s); the floor is {ORG_REPO_FLOOR}. GetBusbar has many more than that, so a "
                    "list this short means the query answered for something other than the org (a token "
                    "scoped to one repo, a paginated first page that came back empty). A sweep over an "
                    "implausibly small set cannot rule out an unregistered plugin repo.")
    else:
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
