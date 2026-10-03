#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
"""THE PLUGIN GATES every first-party plugin repo is judged by. .github/workflows/plugin-ci.yml runs
them at the busbar commit the plugin pins (.busbar-ref), so the CI logic and the contract move
together. Pure functions over what cargo, nm and the two lockfiles say; every gate prints one line per
finding and exits 1 on any. `selftest` plants a RED for every gate and runs before a verdict is trusted.

  plugin-gates.py depwall <metadata.json> <repo>
  plugin-gates.py netban <metadata.json> <deps.toml> <repo>
  plugin-gates.py cdeps <metadata.json> <deps.toml>
  plugin-gates.py imports <undefined-symbols.txt> <needed-libs.txt> <deps.toml> <repo>
  plugin-gates.py parity <plugin Cargo.lock> <busbar Cargo.lock>
  plugin-gates.py bothways <conformance --list output>
  plugin-gates.py declares <busbar-root> <kind> <declares.json>
  plugin-gates.py selftest

The policy is .github/fleet/deps.toml at the pin: the socket/TLS ban (BUSBAR-1.6.0.md line 3980) and
the C-dependency allow-list. Cargo.lock parity with busbar's lock is RED (PLUGIN-TEMPLATE ruling 3b).
declares.json's contract_abi is the top of the loader's supported_abi(kind) at the pin, min = max
(THE DESIGN §11.8); busbar-release's `plugin sync` renders it. The pin itself is
scripts/fleet/pin-check.sh's.
"""

import json
import os
import re
import sys
import tempfile
import tomllib

BUSBAR_GIT = "https://github.com/GetBusbar/busbar"
KINDS = ("store", "secret", "auth", "hook", "export", "plane", "transport")
FIRST_PARTY_PLUGIN = re.compile(r"^busbar-(%s)-[a-z0-9-]+$" % "|".join(KINDS))
CORE = re.compile(r"^busbar-(kernel|core)(-.*)?$")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


# ── the shipped closure ──────────────────────────────────────────────────────────────────────────


def closure(meta):
    """Package ids reachable from the workspace members over NORMAL and BUILD edges (a
    dev-dependency is a test's, not the shipped image's), members excluded."""
    nodes = {n["id"]: n for n in meta["resolve"]["nodes"]}
    members = set(meta["workspace_members"])
    seen, queue = set(), list(members)
    while queue:
        cur = queue.pop()
        for d in nodes.get(cur, {}).get("deps", []):
            kinds = {k.get("kind") for k in d.get("dep_kinds", [])}
            if kinds & {None, "build"} and d["pkg"] not in seen:
                seen.add(d["pkg"])
                queue.append(d["pkg"])
    return seen - members, nodes, {p["id"]: p for p in meta["packages"]}


def depwall(meta, repo):
    """Part 2 #40 (a): a plugin's busbar closure is busbar-contract and nothing else; no kernel or
    core crate, and no other plugin."""
    ids, _, pkgs = closure(meta)
    members = {pkgs[m]["name"] for m in meta["workspace_members"]}
    out = []
    for i in sorted(ids, key=lambda x: pkgs[x]["name"]):
        p = pkgs[i]
        name, src = p["name"], p.get("source") or ""
        if src.startswith("git+" + BUSBAR_GIT) and name != "busbar-contract":
            out.append(f"DEPWALL {name} {p['version']} from busbar is in the shipped closure (only busbar-contract may be)")
        elif CORE.match(name):
            out.append(f"DEPWALL {name} {p['version']} is a kernel/core crate in the shipped closure")
        elif FIRST_PARTY_PLUGIN.match(name) and name not in members and not name.startswith(repo):
            out.append(f"DEPWALL {name} {p['version']} is another plugin in the shipped closure")
    return out


def netban(meta, deps, repo):
    """BUSBAR-1.6.0.md line 3980: no plugin opens its own socket, dials, binds or does TLS."""
    net = deps["net-ban"]
    ids, nodes, pkgs = closure(meta)
    carrier = repo in net.get("carriers", [])
    socket_only = {"socket2", "tokio/net", "mio/net"}
    out = []
    for i in sorted(ids, key=lambda x: pkgs[x]["name"]):
        name = pkgs[i]["name"]
        if name in net["crates"] and not (carrier and name in socket_only):
            out.append(f"NETBAN {name} {pkgs[i]['version']} is in the shipped closure ({net.get('spec', 'line 3980')})")
        feats = set(nodes[i].get("features", []))
        for f in net["features"]:
            crate, feat = f.split("/", 1)
            if crate == name and feat in feats and not (carrier and f in socket_only):
                out.append(f"NETBAN {name}/{feat} is enabled in the shipped closure ({net.get('spec', 'line 3980')})")
    return out


def _req_ok(version, req):
    """Does `version` satisfy `req`: `=x.y.z` exact, else a caret requirement (`0.17`, `1.1`)."""
    v = [int(x) for x in re.findall(r"\d+", version.split("+")[0].split("-")[0])[:3]]
    if req.startswith("="):
        return version.split("+")[0] == req[1:].strip()
    r = [int(x) for x in req.strip().lstrip("^").split(".")]
    if v[: len(r)] < r:
        return False
    first = next((k for k, x in enumerate(r) if x != 0), len(r) - 1)
    return v[: first + 1] == r[: first + 1]


def cdeps(meta, deps):
    """Ruling 3d: a native library in the shipped closure is on the allow-list, at its version, with
    its bundling features on."""
    allow = {e["crate"]: e for e in deps.get("c-deps", {}).get("allow", [])}
    ids, nodes, pkgs = closure(meta)
    out = []
    for i in sorted(ids, key=lambda x: pkgs[x]["name"]):
        p = pkgs[i]
        if not p.get("links"):
            continue
        e = allow.get(p["name"])
        if e is None:
            out.append(f"CDEP {p['name']} {p['version']} links native `{p['links']}` and is not on the C allow-list")
            continue
        if not _req_ok(p["version"], e["version"]):
            out.append(f"CDEP {p['name']} {p['version']} is not the allowed version {e['version']}")
        missing = set(e.get("features", [])) - set(nodes[i].get("features", []))
        if missing:
            out.append(f"CDEP {p['name']} is not bundled: features {sorted(missing)} are off")
    return out


def imports(undefined, needed, deps, repo):
    """The post-LTO import scan: the built cdylib imports no socket or TLS symbol, and links no
    TLS library."""
    net = deps["net-ban"]
    carrier = repo in net.get("carriers", [])
    banned = set(net["imports"])
    out = []
    for sym in sorted({s.split("@")[0].strip() for s in undefined if s.strip()}):
        if sym in banned and not (carrier and not sym.startswith("SSL_")):
            out.append(f"IMPORT the built cdylib imports `{sym}` ({net.get('spec', 'line 3980')})")
    for lib in sorted({x.strip() for x in needed if x.strip()}):
        if re.match(r"lib(ssl|crypto|gnutls|nss3)\b", lib):
            out.append(f"IMPORT the built cdylib links `{lib}` ({net.get('spec', 'line 3980')})")
    return out


def _lock_versions(text):
    d = tomllib.loads(text)
    out = {}
    for p in d.get("package", []):
        src = p.get("source", "")
        if src.startswith("registry+"):
            out.setdefault(p["name"], set()).add(p["version"])
    return out


def parity(plugin_lock, busbar_lock):
    """Ruling 3b, RED: every crates.io package both locks hold is at a version busbar's lock holds."""
    mine, theirs = _lock_versions(plugin_lock), _lock_versions(busbar_lock)
    out = []
    for name in sorted(mine.keys() & theirs.keys()):
        for v in sorted(mine[name] - theirs[name]):
            out.append(f"PARITY {name} {v}: busbar's lock at the pin holds {', '.join(sorted(theirs[name]))}")
    return out


BOTH_WAYS = "the_linked_and_the_dropped_in_"


def bothways(listing):
    """The conformance target holds the both-ways arm and at least one RED arm."""
    names = [l.split(":")[0].strip() for l in listing if l.rstrip().endswith(": test")]
    names = [n.rsplit("::", 1)[-1] for n in names]
    out = []
    if not any(n.startswith(BOTH_WAYS) for n in names):
        out.append(f"BOTHWAYS no `{BOTH_WAYS}*` test in the conformance target (linked door vs built cdylib, one transcript)")
    if not any(not n.startswith(BOTH_WAYS) for n in names):
        out.append("BOTHWAYS no RED arm in the conformance target (a test proving the comparison can fail)")
    return out



# ── declares.json ────────────────────────────────────────────────────────────────────────────────


def _const_value(src, name):
    m = re.search(r"const\s+%s\s*:\s*u\d+\s*=\s*(\d+)\s*;" % re.escape(name), src)
    return int(m.group(1)) if m else None


def kind_abi(root, kind):
    """The current contract-ABI version of `kind` in the busbar tree at `root`: the top of the
    loader's supported_abi(kind), resolved through busbar-contract's constants."""
    reg = None
    for p in ("crates/plugin-loader/src/registry.rs", "crates/busbar-plugin-loader/src/registry.rs"):
        if os.path.exists(os.path.join(root, p)):
            reg = re.sub(r"//[^\n]*", "", _read(os.path.join(root, p)))
            break
    if reg is None:
        raise ValueError("no plugin-loader registry.rs in the busbar tree")
    m = re.search(r'"%s"\s*=>\s*&\[(.*?)\]' % re.escape(kind), reg, re.S)
    if not m:
        raise ValueError(f"supported_abi has no arm for kind `{kind}`")
    top = [x.strip() for x in m.group(1).split(",") if x.strip()][-1]
    if top.isdigit():
        return int(top)
    parts = top.split("::")
    if len(parts) == 1:
        v = _const_value(reg, top)
        if v is None:
            raise ValueError(f"`{top}` is not a numeric const in registry.rs")
        return v
    base = os.path.join(root, "crates/busbar-contract/src", *parts[1:-1])
    for p in (os.path.join(base, "mod.rs"), base + ".rs"):
        if os.path.exists(p):
            v = _const_value(_read(p), parts[-1])
            if v is not None:
                return v
    raise ValueError(f"cannot resolve `{top}` in busbar-contract")


def declares(root, kind, text):
    """declares.json states the kind's current contract ABI at the pin, min = max."""
    want = kind_abi(root, kind)
    try:
        got = json.loads(text).get("contract_abi")
    except ValueError as e:
        return [f"DECLARES declares.json is not JSON: {e}"]
    if got != {"min": want, "max": want}:
        return [f"DECLARES contract_abi is {got}; busbar at the pin speaks {kind} v{want} (min = max = {want}). "
                f"Re-render it with busbar-release plugin sync."]
    return []


# ── selftest: every gate RED on its planted defect, GREEN on the clean case ─────────────────────────

CRATES = "registry+https://github.com/rust-lang/crates.io-index"
BUSBAR_SRC = "git+https://github.com/GetBusbar/busbar?rev=x#x"
POLICY = {
    "net-ban": {"spec": "line 3980", "crates": ["rustls", "socket2"], "features": ["tokio/net"],
                "imports": ["socket", "connect"], "carriers": []},
    "c-deps": {"allow": [{"crate": "libsqlite3-sys", "version": "=0.38.1", "features": ["bundled"], "reason": "r"}]},
}


def _meta(packages, edges):
    nodes = {p[0]: {"id": p[0], "deps": [], "features": p[5] if len(p) > 5 else []} for p in packages}
    for a, b, k in edges:
        nodes[a]["deps"].append({"pkg": b, "dep_kinds": [{"kind": k}]})
    return {"workspace_members": ["m"],
            "packages": [{"id": p[0], "name": p[1], "version": p[2], "source": p[3],
                          "links": p[4] if len(p) > 4 else None} for p in packages],
            "resolve": {"nodes": list(nodes.values())}}


def selftest():
    fails = []

    def case(name, got, want_red):
        if bool(got) != want_red:
            fails.append(f"{name}: expected {'RED' if want_red else 'GREEN'}, got {got}")

    m = ("m", "busbar-store-x", "1.0.0", None)
    case("depwall green", depwall(_meta([m, ("c", "busbar-contract", "1", BUSBAR_SRC), ("l", "busbar-plugin-loader", "1", BUSBAR_SRC)],
                                        [("m", "c", None), ("m", "l", "dev")]), "busbar-store-x"), False)
    case("depwall kernel", depwall(_meta([m, ("k", "busbar-kernel", "1", BUSBAR_SRC)], [("m", "k", None)]), "busbar-store-x"), True)
    case("netban dev-only", netban(_meta([m, ("r", "rustls", "0.23.1", CRATES)], [("m", "r", "dev")]), POLICY, "r"), False)
    case("netban rustls", netban(_meta([m, ("r", "rustls", "0.23.1", CRATES)], [("m", "r", None)]), POLICY, "r"), True)
    case("netban tokio/net", netban(_meta([m, ("t", "tokio", "1.0.0", CRATES, None, ["net"])], [("m", "t", None)]), POLICY, "r"), True)
    case("cdeps bundled", cdeps(_meta([m, ("s", "libsqlite3-sys", "0.38.1", CRATES, "sqlite3", ["bundled"])], [("m", "s", None)]), POLICY), False)
    case("cdeps unbundled", cdeps(_meta([m, ("s", "libsqlite3-sys", "0.38.1", CRATES, "sqlite3", [])], [("m", "s", None)]), POLICY), True)
    case("cdeps unlisted", cdeps(_meta([m, ("z", "aws-lc-sys", "0.3.0", CRATES, "aws_lc")], [("m", "z", "build")]), POLICY), True)
    case("imports clean", imports(["malloc@GLIBC_2.2.5"], ["libc.so.6"], POLICY, "r"), False)
    case("imports socket", imports(["connect@GLIBC_2.2.5"], [], POLICY, "r"), True)
    case("imports libssl", imports([], ["libssl.so.3"], POLICY, "r"), True)
    lock = lambda v: f'version = 4\n[[package]]\nname = "serde"\nversion = "{v}"\nsource = "{CRATES}"\n'
    case("parity equal", parity(lock("1.0.1"), lock("1.0.1")), False)
    case("parity drift", parity(lock("1.0.2"), lock("1.0.1")), True)
    both = ["the_linked_and_the_dropped_in_x: test", "a_wrong_kind_is_refused: test"]
    case("bothways both arms", bothways(both), False)
    case("bothways no RED arm", bothways(both[:1]), True)
    case("bothways no equality arm", bothways(both[1:]), True)
    with tempfile.TemporaryDirectory() as d:
        os.makedirs(os.path.join(d, "crates/plugin-loader/src"))
        os.makedirs(os.path.join(d, "crates/busbar-contract/src/abi/cold"))
        with open(os.path.join(d, "crates/plugin-loader/src/registry.rs"), "w", encoding="utf-8") as f:
            f.write('match kind {\n    // a, comment\n    "store" => &[FLOOR, busbar_contract::abi::cold::ABI_VERSION],\n    "auth" => &[1, 3],\n}\n')
        with open(os.path.join(d, "crates/busbar-contract/src/abi/cold/mod.rs"), "w", encoding="utf-8") as f:
            f.write("pub const ABI_VERSION: u32 = 4;\n")
        case("declares current", declares(d, "store", '{"contract_abi": {"min": 4, "max": 4}}'), False)
        case("declares stale", declares(d, "store", '{"contract_abi": {"min": 3, "max": 3}}'), True)
        case("declares literal", declares(d, "auth", '{"contract_abi": {"min": 3, "max": 3}}'), False)
    for f in fails:
        print(f"SELFTEST {f}")
    print(f"plugin-gates selftest: {len(fails)} failure(s)")
    return 1 if fails else 0


def main(argv):
    if not argv:
        sys.exit(__doc__)
    cmd, args = argv[0], argv[1:]
    if cmd == "selftest":
        return selftest()
    load = lambda p: json.loads(_read(p))
    toml = lambda p: tomllib.loads(_read(p))
    if cmd == "depwall":
        out = depwall(load(args[0]), args[1])
    elif cmd == "netban":
        out = netban(load(args[0]), toml(args[1]), args[2])
    elif cmd == "cdeps":
        out = cdeps(load(args[0]), toml(args[1]))
    elif cmd == "imports":
        out = imports(_read(args[0]).splitlines(), _read(args[1]).splitlines(), toml(args[2]), args[3])
    elif cmd == "parity":
        out = parity(_read(args[0]), _read(args[1]))
    elif cmd == "bothways":
        out = bothways(_read(args[0]).splitlines())
    elif cmd == "declares":
        out = declares(args[0], args[1], _read(args[2]))
    else:
        sys.exit(f"plugin-gates.py: unknown gate `{cmd}`")
    for line in out:
        print(line)
    print(f"{cmd}: {len(out)} finding(s)")
    return 1 if out else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
