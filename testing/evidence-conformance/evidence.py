#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""THE EVIDENCE RIGS: `evidence-audit-trail`, `evidence-rbac` and `evidence-tls`.

    python3 -I testing/evidence-conformance/evidence.py audit|rbac|tls

Three `evidence-only` suites (conformance/registry.toml): busbar supplies audit EVIDENCE, never a
certificate of its own. Each is judged here in three legs, all of which always run, into one verdict
at $CONFORMANCE_OUT/verdict.json (testing/conformance/run.sh holds it to the schema):

  control   a known-good peer the rig did not get from busbar MUST pass the rig's judge,
  negative  a deliberately broken peer MUST be graded red by that same judge, for the right reason,
  subject   busbar, the SHIPPED binary (dist/default, `cargo build --locked`) built from this
            checkout and booted on loopback with a config generated here, MUST pass the judge.

`pass` only when all three held; anything else is `fail` (armed) with every reason named.

audit  The judge is an INDEPENDENT verifier of busbar's audit chain (chain.py + ed25519.py), written
       from docs/audit-chain-digest-v4.md alone: no busbar code, library or constant. Control: the
       page's own worked example and a chain the rig seals itself. Negative: that chain tampered
       with, a record deleted, two reordered, the tail truncated, the signatures re-keyed. Subject:
       the chain a booted busbar seals for its admin traffic, read through `/audit/range`,
       `/audit/head` and `/audit/keys`, must verify, AND the same four mutations of it (tamper,
       delete, reorder, truncate) must each be refused.
rbac   The judge is a scope-refusal MATRIX over every admin operation the node's own OpenAPI document
       lists, the scope each needs derived from the published rule (docs/admin-api.md: every GET,
       POST /config/validate and POST /plugins/inspect is `read-only`, everything else `full`) and
       cross-checked against the document's `x-busbar-required-scope`. Principals: none, garbage, a
       token from a foreign key, an expired one, a wrong audience, a data-plane virtual key (all
       401), an unbound role (refused), a `read-only` role, a role `full` capped by its provider's
       `max_admin_scope: read-only`, a role granted one verb by `verbs:` (each 403 on what it lacks,
       admitted on what it holds), and `full` (admitted everywhere). Plus the data plane: `/stats`
       refuses no credential, an admin credential and a revoked key, and admits a live key; and the
       planes are separate (an admin path on the data listener and a data path on the admin listener
       are 404). Roles come from busbar's real OIDC module (GetBusbar/busbar-auth-oidc at the rev
       dist/default/Cargo.lock pins), dropped in as a plugin, verifying RS256 JWTs the rig signs with
       its own key and serves as a JWKS over TLS. Every request carries a fresh `sub`, so no two share
       a rate bucket. Control: a reference admin server written here that enforces the published rule.
       Negative: the same server with scope enforcement broken.
tls    The judge is a client-certificate probe: a certless client and a client from a rogue CA must be
       refused, a client from the configured CA admitted. Control: Python's own OpenSSL server
       requiring client certificates. Negative: the same server with the requirement made optional.
       Subject: busbar's data listener (`tls.client_ca`) and admin listener (`admin_tls.client_ca`),
       both. And the testssl subject: the `tls` suite's verdict from this same conformance run must be
       `pass` (run here, through testing/tls-conformance/tls.sh, when this suite runs alone).

Everything is generated at run time: the PKI (pki.py, no openssl), every key, port and config.
Needs cargo, git and python3 (no docker, but the `tls` suite this one reads needs it).
"""
import http.client
import importlib.util
import json
import os
import secrets
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
import time
import http.server
import re

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = os.path.dirname(os.path.dirname(HERE))


def _load(name):
    spec = importlib.util.spec_from_file_location(f"evidence_{name}", os.path.join(HERE, f"{name}.py"))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


chain = _load("chain")
pki = _load("pki")

SUITES = {
    "audit": ("evidence-audit-trail",
              "Audit trail: hash-chained, Ed25519-signed, tamper-evident action log",
              "an independent verifier (from docs/audit-chain-digest-v4.md alone) over /audit/range: the "
              "live chain verifies; tampered, deleted, reordered and truncated records are each refused"),
    "rbac": ("evidence-rbac",
             "Scope-based RBAC: least-privilege admin scopes, per-verb grants, admin/data-plane separation",
             "every admin operation in the node's OpenAPI document against principals lacking its scope "
             "(refused) and holding it (admitted), plus the data plane's key gate and plane separation"),
    "tls": ("evidence-tls",
            "TLS / mutual TLS: native termination, client-certificate enforcement, admin plane isolation",
            "the testssl subject (the tls suite) plus certless and rogue-CA clients refused on an mTLS data "
            "listener and on admin_tls with client_ca, a CA-issued client admitted"),
}


class Refused(Exception):
    pass


def say(*parts):
    print("evidence:", *parts, file=sys.stderr, flush=True)


def free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def tail(path, n=12):
    try:
        with open(path, errors="replace") as f:
            return " | ".join(line.rstrip() for line in f.readlines()[-n:])
    except OSError:
        return "(no log)"


def run(argv, log, cwd=None, env=None):
    with open(log, "ab") as out:
        out.write(("\n$ " + " ".join(argv) + "\n").encode())
        out.flush()
        return subprocess.call(argv, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT)


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# THE SUBJECT: the shipped binary (dist/default), from this checkout
# ─────────────────────────────────────────────────────────────────────────────────────────────────

def target_dir():
    # dist/default is its own workspace: its build gets a directory of its own under this repo's
    # target, so it never relinks over the root workspace's `busbar` (another suite builds that one).
    return os.path.join(os.environ.get("CARGO_TARGET_DIR") or os.path.join(REPO, "target"), "dist-default")


def build_subject(log, *, oidc=False):
    manifest = os.path.join(REPO, "dist", "default", "Cargo.toml")
    tgt = target_dir()
    builds = [["cargo", "build", "--locked", "--manifest-path", manifest, "--target-dir", tgt, "--bin", "busbar"]]
    if oidc:
        builds += [["cargo", "build", "--locked", "--manifest-path", manifest, "--target-dir", tgt,
                    "-p", "busbar-auth-oidc-plugin"],
                   ["cargo", "build", "--locked", "--target-dir", os.path.join(tgt, "root"),
                    "-p", "busbar-plugin-loader", "--features", "pack", "--bin", "busbar-plugin-pack"]]
    for argv in builds:
        rc = run(argv, log, cwd=REPO)
        if rc != 0:
            raise Refused(f"`{' '.join(argv[:3])} … {' '.join(argv[-4:])}` exited {rc}: {tail(log, 6)}")
    debug = os.path.join(tgt, "debug")
    out = {"busbar": os.path.join(debug, "busbar")}
    if oidc:
        lib = "libbusbar_auth_oidc_plugin." + ("dylib" if sys.platform == "darwin" else "so")
        out["oidc"] = os.path.join(debug, lib)
        out["pack"] = os.path.join(tgt, "root", "debug", "busbar-plugin-pack")
        out["oidc_version"] = oidc_pin()
    return out


def oidc_pin():
    """The OIDC module's version as dist/default/Cargo.lock pins it."""
    with open(os.path.join(REPO, "dist", "default", "Cargo.lock")) as f:
        lock = f.read()
    m = re.search(r'name = "busbar-auth-oidc-plugin"\nversion = "([^"]+)"\nsource = "([^"]+)"', lock)
    if not m:
        raise Refused("dist/default/Cargo.lock pins no busbar-auth-oidc-plugin")
    return m.group(1)


class Busbar:
    """One booted busbar: config written here, both listeners on loopback ports of this run's own."""

    def __init__(self, binary, work, name, cfg):
        self.dir = os.path.join(work, name)
        os.makedirs(self.dir, exist_ok=True)
        self.log = os.path.join(self.dir, "busbar.log")
        self.cfg = cfg
        conf = os.path.join(self.dir, "config.yaml")
        prov = os.path.join(self.dir, "providers.yaml")
        with open(prov, "w") as f:
            f.write("{}\n")
        cfg["providers_file"] = prov
        with open(conf, "w") as f:
            f.write(json.dumps(cfg, indent=2) + "\n")  # JSON is YAML
        env = {k: v for k, v in os.environ.items()
               if k not in ("NOTIFY_SOCKET", "INVOCATION_ID", "BUSBAR_ADMIN_TOKEN", "LISTEN_FDS", "LISTEN_PID")}
        env["BUSBAR_CONFIG"] = conf
        self.proc = subprocess.Popen([binary], cwd=self.dir, env=env, stdin=subprocess.DEVNULL,
                                     stdout=open(self.log, "wb"), stderr=subprocess.STDOUT,
                                     start_new_session=True)
        self.data = int(cfg["listen"].rsplit(":", 1)[1])
        self.admin = int(cfg["admin_listen"].rsplit(":", 1)[1])

    def wait(self, probe, secs=120):
        deadline = time.time() + secs
        last = None
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise Refused(f"busbar exited during boot ({self.proc.returncode}): {tail(self.log)}")
            try:
                return probe()
            except (OSError, http.client.HTTPException) as e:
                last = e
                time.sleep(0.5)
        raise Refused(f"busbar never answered within {secs}s ({last}): {tail(self.log)}")

    def stop(self):
        if self.proc.poll() is None:
            try:
                os.killpg(self.proc.pid, signal.SIGTERM)
                self.proc.wait(15)
            except (subprocess.TimeoutExpired, ProcessLookupError):
                try:
                    os.killpg(self.proc.pid, signal.SIGKILL)
                except ProcessLookupError:
                    pass


def request(port, method, path, *, headers=None, body=None, ctx=None, timeout=15):
    """(status, parsed-or-raw body). TLS when `ctx` is given."""
    if ctx is None:
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=timeout)
    else:
        c = http.client.HTTPSConnection("127.0.0.1", port, context=ctx, timeout=timeout)
    try:
        data = None if body is None else (body if isinstance(body, bytes) else json.dumps(body).encode())
        h = dict(headers or {})
        if data is not None:
            h.setdefault("content-type", "application/json")
        c.request(method, path, body=data, headers=h)
        r = c.getresponse()
        raw = r.read()
        try:
            return r.status, json.loads(raw)
        except ValueError:
            return r.status, raw
    finally:
        c.close()


def base_config(data, admin, **extra):
    cfg = {
        "listen": f"127.0.0.1:{data}",
        "admin_listen": f"127.0.0.1:{admin}",
        "store": {"module": "memory"},
        "providers": {},
        "models": {},
        "auth": {"chain": [], "admin_auth": []},
    }
    cfg.update(extra)
    return cfg


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# evidence-audit-trail
# ─────────────────────────────────────────────────────────────────────────────────────────────────

def worked_example():
    """The three bodies of docs/audit-chain-digest-v4.md section 7: range, head, keys."""
    with open(os.path.join(REPO, "docs", "audit-chain-digest-v4.md")) as f:
        page = f.read()
    sec = page.split("## 7. A worked example", 1)[1]
    blocks = re.findall(r"```json\n(.*?)```", sec, re.S)
    if len(blocks) < 3:
        raise Refused("docs/audit-chain-digest-v4.md section 7 does not carry its three bodies")
    return tuple(json.loads(b) for b in blocks[:3])


def rig_records():
    """Six records of the rig's own, every repeated group and a multi-byte text among them."""
    base = {k: ("" if kind == "text" else 0) for k, kind in (f for f in chain.FIELDS if len(f) == 2)}
    base.update(lines_count=0, lines=[], hooks_count=0, hooks=[], children_count=0, children=[],
                subject_tag="principal", subject_value="rig", outcome="Completed", finish="Stop",
                origin_kind="client", emission_delta="0")
    out = []
    for n in range(6):
        r = dict(base, unit_key=100 + n, incarnation=1, op_class=f"rig.op.{n}", wall=1_790_000_000 + n,
                 mono=10 * n, node=3)
        if n == 1:
            r.update(lines=[{"class": "tokens.in", "quantity": 12, "source": "Reported", "estimated": 0},
                            {"class": "tokens.out", "quantity": 7, "source": "Estimated", "estimated": 1}],
                     lines_count=2, emission_delta="-7")
        if n == 2:
            r.update(hooks=[{"hook": "gate|bar", "head": "veto", "failed": 1}], hooks_count=1,
                     destination="https://upstream.invalid/v1")
        if n == 3:
            r.update(children=[7, 8, 9], children_count=3, op_class="tool.call — ünicode")
        out.append(r)
    return out


def mutations(body, head):
    """(name, range body, head body, the finding class that must appear) per mutation of a chain."""
    recs = body["records"]
    if len(recs) < 4:
        raise Refused(f"a chain of {len(recs)} records is too short to mutate (4 needed)")
    import copy
    out = []
    b = copy.deepcopy(body)
    victim = b["records"][2]
    victim["op_class"] = victim["op_class"] + "-tampered"
    out.append(("tamper (a field edited, digest kept)", b, head, "digest mismatch"))
    b = copy.deepcopy(body)
    victim = b["records"][2]
    victim["op_class"] = victim["op_class"] + "-tampered"
    victim["hash"] = chain.digest(victim)
    out.append(("tamper (a field edited and re-hashed)", b, head, "signature does not verify"))
    b = copy.deepcopy(body)
    del b["records"][2]
    out.append(("delete (a middle record)", b, head, "not contiguous"))
    b = copy.deepcopy(body)
    b["records"][1], b["records"][2] = b["records"][2], b["records"][1]
    out.append(("reorder (two records swapped)", b, head, "not contiguous"))
    b = copy.deepcopy(body)
    del b["records"][-1]
    out.append(("truncate (the newest record dropped)", b, head, "missing from its end"))
    return out


def judge_chain(label, body, keys, head, want_to=None):
    found = chain.verify(body, keys, head, want_from=1, want_to=want_to)
    return [f"{label}: {f}" for f in found]


def judge_mutations(label, body, keys, head, want_to=None):
    why = []
    for name, b, h, must in mutations(body, head):
        found = chain.verify(b, keys, h, want_from=1, want_to=want_to)
        if not found:
            why.append(f"{label}: {name} was NOT refused")
        elif not any(must in f for f in found):
            why.append(f"{label}: {name} was refused, but not for `{must}`: {found[:2]}")
        else:
            say(f"{label}: {name}: refused ({next(f for f in found if must in f)})")
    return why


def suite_audit(work, log):
    why = []
    # control
    say("=== leg 1: control (the published worked example and a chain the rig sealed)")
    rng, head, keys = worked_example()
    why += judge_chain("control: the published worked example", rng, keys, head)
    seed = secrets.token_bytes(32)
    body, keys2, head2 = chain.seal(rig_records(), seed)
    why += judge_chain("control: the rig's sealed chain", body, keys2, head2)
    # negative
    say("=== leg 2: negative control (the rig's chain tampered, deleted, reordered, truncated, re-keyed)")
    why += judge_mutations("negative", body, keys2, head2)
    other, _, _ = chain.seal([], secrets.token_bytes(32))
    _, foreign_keys, _ = chain.seal(rig_records()[:1], secrets.token_bytes(32))
    if not chain.verify(body, foreign_keys, head2):
        why.append("negative: the chain checked against a key set that does not hold its key was NOT refused")
    # subject
    say("=== leg 3: subject (busbar's own chain through /audit/range)")
    bins = build_subject(log)
    data, admin = free_port(), free_port()
    b = Busbar(bins["busbar"], work, "audit", base_config(data, admin))
    try:
        A = "/api/v1/admin"
        b.wait(lambda: request(admin, "GET", A + "/audit/head"))
        # admin traffic of several kinds, each sealed as a unit: reads, a refused write, a 404
        for path in ("/hooks", "/keys", "/groups", "/audit/keys", "/config/settings", "/no-such-path"):
            request(admin, "GET", A + path)
        request(admin, "POST", A + "/keys", body={"name": "audit-probe"})
        request(admin, "POST", A + "/config/validate", body={"config": {}, "providers": {}})
        st, h = request(admin, "GET", A + "/audit/head")
        if st != 200 or not isinstance(h, dict) or not h.get("head"):
            raise Refused(f"/audit/head answered {st}: {str(h)[:200]}")
        top = h["head"]["seq"]
        st, r = request(admin, "GET", A + f"/audit/range?from=1&to={top}")
        st2, k = request(admin, "GET", A + "/audit/keys")
        if st != 200 or st2 != 200:
            raise Refused(f"/audit/range answered {st}, /audit/keys {st2}")
        with open(os.path.join(work, "subject-range.json"), "w") as f:
            json.dump({"head": h, "range": r, "keys": k}, f, indent=1)
        say(f"subject: {len(r.get('records', []))} records to seq {top}")
        if top < 6:
            why.append(f"subject: the node sealed only {top} records for 9 admin requests")
        why += judge_chain("subject", r, k, h, want_to=top)
        why += judge_mutations("subject", r, k, h, want_to=top)
        # a window: it starts where it was asked to, links within itself, and carries its anchor
        if top >= 4:
            st, wnd = request(admin, "GET", A + f"/audit/range?from=2&to={top - 1}")
            found = chain.verify(wnd, k, h, want_from=2, want_to=top - 1)
            if st != 200 or found:
                why.append(f"subject: the window 2..{top - 1} ({st}) did not verify: {found[:2]}")
            anchor = (wnd or {}).get("anchor") if isinstance(wnd, dict) else None
            pk = {x["key_id"]: bytes.fromhex(x["public_key"]) for x in k.get("keys", [])}
            if not anchor or anchor.get("seq", 1 << 64) > top - 1 or not chain.ed25519.verify_strict(
                    pk.get(anchor.get("key_id"), b""), chain.signing_input(anchor.get("hash", "")),
                    bytes.fromhex(anchor.get("signature", "") or "")):
                why.append(f"subject: the window's anchor is not a signed head at or before its end: {anchor}")
        # a range past the head is shorter, not an error
        st, past = request(admin, "GET", A + f"/audit/range?from=1&to={top + 1000}")
        if st != 200 or not isinstance(past, dict) or len(past.get("records", [])) < top:
            why.append(f"subject: a range past the head answered {st} with "
                       f"{len(past.get('records', [])) if isinstance(past, dict) else '?'} records")
    finally:
        b.stop()
    return why


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# evidence-rbac
# ─────────────────────────────────────────────────────────────────────────────────────────────────

ADMIN = "/api/v1/admin"
READ_POSTS = {"/config/validate", "/plugins/inspect"}


def published_scope(method, path):
    """docs/admin-api.md: every GET, POST /config/validate and POST /plugins/inspect is read-only."""
    rel = path[len(ADMIN):] if path.startswith(ADMIN) else path
    if method == "GET" or (method == "POST" and rel in READ_POSTS):
        return "read-only"
    return "full"


def operations(doc):
    """[(method, path template, annotated scope, verb name)] for every admin operation in `doc`."""
    out = []
    for path, item in sorted(doc.get("paths", {}).items()):
        if not path.startswith(ADMIN):
            continue
        for method, op in sorted(item.items()):
            if method.upper() not in ("GET", "POST", "PUT", "PATCH", "DELETE"):
                continue
            out.append((method.upper(), path, op.get("x-busbar-required-scope"), op.get("operationId")))
    return out


def concrete(path):
    return re.sub(r"\{[^}]+\}", "rbac-probe", path)


class Issuer:
    """The rig's own OIDC issuer: an RS256 key, its JWKS over TLS on a loopback port, signed tokens."""

    def __init__(self, pkidir, ca, name="rig"):
        self.key = pki.RsaKey()
        self.kid = f"{name}-{secrets.token_hex(4)}"
        jwks = json.dumps({"keys": [self.key.jwk(self.kid)]}).encode()
        leaf = pki.Cert("localhost", issuer=ca, server=True, dns=["localhost"], ips=["127.0.0.1"])
        crt, key = leaf.write(pkidir, f"jwks-{name}", chain=True)
        self.hits = 0
        issuer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                issuer.hits += 1
                self.send_response(200 if self.path == "/jwks" else 404)
                self.send_header("content-type", "application/json")
                payload = jwks if self.path == "/jwks" else b"{}"
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(crt, key)
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        self.url = f"https://127.0.0.1:{self.port}/jwks"
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def token(self, iss, aud, roles, *, exp_in=600, key=None):
        now = int(time.time())
        claims = {"iss": iss, "aud": aud, "sub": f"rbac-{secrets.token_hex(6)}", "iat": now, "nbf": now - 5,
                  "exp": now + exp_in, "roles": roles}
        return pki.jwt(key or self.key, self.kid, claims)

    def stop(self):
        self.server.shutdown()


ISS = "https://rig-issuer.invalid"
AUD = "busbar-rbac"


def principals(iss_obj, rogue_key, verb_names, capped=False):
    """name -> (a function minting one fresh header set, expectation function(scope, verb) -> want).
    want is 'admit', 'forbid' (403), 'deny' (401) or 'refuse' (either). `capped`: the principals of a
    node whose provider leaves `max_admin_scope` at its default, `read-only`."""
    def bearer(tok):
        return {"authorization": f"Bearer {tok}"}

    def tok(roles, aud=AUD, **kw):
        return lambda: bearer(iss_obj.token(ISS, aud, roles, **kw))

    if capped:
        return {
            "an unbound role": (tok(["rbac-nobody"]), lambda s, v: "refuse"),
            "a full role capped read-only by its provider": (
                tok(["rbac-full"]), lambda s, v: "admit" if s == "read-only" else "forbid"),
            "a role granted two verbs, capped read-only by its provider": (
                tok(["rbac-verbs"]), lambda s, v: "admit" if v in verb_names and s == "read-only" else "forbid"),
        }
    return {
        "no credential": (lambda: {}, lambda s, v: "deny"),
        "a garbage bearer": (lambda: bearer("not-a-token." + secrets.token_hex(8)), lambda s, v: "deny"),
        "a token signed by a foreign key": (tok(["rbac-full"], key=rogue_key), lambda s, v: "deny"),
        "an expired token": (tok(["rbac-full"], exp_in=-3600), lambda s, v: "deny"),
        "a token for another audience": (lambda: bearer(iss_obj.token(ISS, "someone-else", ["rbac-full"])),
                                         lambda s, v: "deny"),
        "an unbound role": (tok(["rbac-nobody"]), lambda s, v: "refuse"),
        "a read-only role": (tok(["rbac-reader"]), lambda s, v: "admit" if s == "read-only" else "forbid"),
        "a role granted two verbs": (tok(["rbac-verbs"]),
                                     lambda s, v: "admit" if v in verb_names else "forbid"),
        "a full role": (tok(["rbac-full"]), lambda s, v: "admit"),
    }


def classify(status, body):
    if status == 401:
        return "deny"
    if status == 403:
        return "forbid"
    if status == 429:
        return "rate-limited"
    return "admit"


def matrix(port, ops, prins, ctx=None, extra_headers=None):
    """Every (principal, operation) cell: the findings, and the count of cells judged."""
    why, n = [], 0
    for pname, (mint, expect) in prins.items():
        for method, path, scope, verb in ops:
            want = expect(scope, verb)
            h = mint()
            h.update(extra_headers or {})
            body = None if method in ("GET", "DELETE") else {}
            try:
                st, b = request(port, method, concrete(path), headers=h, body=body, ctx=ctx)
            except (OSError, http.client.HTTPException) as e:
                why.append(f"{pname} {method} {path}: no answer ({e})")
                continue
            n += 1
            got = classify(st, b)
            ok = got == want or (want == "refuse" and got in ("deny", "forbid"))
            if want == "forbid" and got == "forbid":
                code = b.get("error", {}).get("code") if isinstance(b, dict) else None
                if code != "forbidden":
                    ok = False
                    got = f"403 with code {code!r}"
            if not ok:
                why.append(f"{pname} {method} {path}: wanted {want}, got {got} ({st} {str(b)[:120]})")
    return why, n


class ReferenceAdmin:
    """The control's known-good peer: an admin surface that enforces the PUBLISHED rule, verifying
    RS256 tokens against the rig issuer's key itself. `broken` turns scope enforcement off for the
    negative control (a read-only principal is admitted to mutations, and an expired token passes)."""

    def __init__(self, ops, issuer, broken=False, capped=False):
        bindings = {"rbac-reader": "read-only", "rbac-full": "full"}
        n, e = issuer.key.n, issuer.key.e
        ref = self

        def principal(headers):
            auth = headers.get("authorization", "")
            if not auth.startswith("Bearer "):
                return None
            try:
                h64, c64, s64 = auth[7:].split(".")
                import base64

                def d(x):
                    return base64.urlsafe_b64decode(x + "=" * (-len(x) % 4))
                sig = int.from_bytes(d(s64), "big")
                em = pow(sig, e, n).to_bytes((n.bit_length() + 7) // 8, "big")
                import hashlib
                want = hashlib.sha256(f"{h64}.{c64}".encode()).digest()
                if not em.endswith(want) or not em.startswith(b"\x00\x01\xff"):
                    return None
                claims = json.loads(d(c64))
            except (ValueError, TypeError):
                return None
            if claims.get("iss") != ISS or claims.get("aud") != AUD:
                return None
            if claims.get("exp", 0) < time.time() and not broken:
                return None
            roles = claims.get("roles", [])
            scope = None
            for r in roles:
                s = bindings.get(r)
                if s == "full" or (s and scope is None):
                    scope = s
            verbs = set(ref.verbs) if "rbac-verbs" in roles else set()
            if capped:
                scope = "read-only" if scope else None
                verbs = {v for v in verbs if table_scope.get(v) == "read-only"}
            return {"scope": scope, "verbs": verbs}

        table = {(m, re.sub(r"\{[^}]+\}", "rbac-probe", p)): (s, v) for m, p, s, v in ops}
        table_scope = {v: s for m, p, s, v in ops}

        class H(http.server.BaseHTTPRequestHandler):
            def _do(self):
                n_ = int(self.headers.get("content-length") or 0)
                if n_:
                    self.rfile.read(n_)
                key = (self.command, self.path.split("?")[0])
                if key not in table:
                    return self._send(404, "not_found")
                scope, verb = table[key]
                p = principal({k.lower(): v for k, v in self.headers.items()})
                if p is None:
                    return self._send(401, "unauthorized")
                held = p["scope"] == "full" or (p["scope"] == "read-only" and scope == "read-only") \
                    or verb in p["verbs"]
                if broken:
                    held = p["scope"] is not None or bool(p["verbs"])
                if not held:
                    return self._send(403, "forbidden")
                return self._send(200 if self.command == "GET" else 400, "ok")

            def _send(self, st, code):
                body = json.dumps({"error": {"code": code, "message": code}}).encode()
                self.send_response(st)
                self.send_header("content-type", "application/json")
                self.send_header("content-length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _do

            def log_message(self, *a):
                pass

        self.verbs = []
        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


# The control's operation set: the published table's shape, one of each kind.
REFERENCE_OPS = [
    ("GET", ADMIN + "/keys", "read-only", "get_keys"),
    ("POST", ADMIN + "/keys", "full", "post_keys"),
    ("GET", ADMIN + "/audit/range", "read-only", "get_audit_range"),
    ("POST", ADMIN + "/config/validate", "read-only", "post_config_validate"),
    ("DELETE", ADMIN + "/groups/{name}", "full", "delete_groups_by_name"),
    ("PUT", ADMIN + "/admin-auth", "full", "put_admin_auth"),
]


def pack_oidc(bins, work, log):
    plugins = os.path.join(work, "plugins")
    os.makedirs(plugins, exist_ok=True)
    rc = run([bins["pack"], "pack", "--lib", bins["oidc"], "--name", "oidc", "--alias", "oidc", "--kind", "auth",
              "--version", bins["oidc_version"], "--publisher", "busbar-evidence-rbac",
              "--out", os.path.join(plugins, "oidc.tar.gz"), "--allow-unsigned"], log)
    if rc != 0:
        raise Refused(f"the OIDC module could not be packed (exit {rc}): {tail(log, 6)}")
    return plugins


def rbac_config(data, admin, plugins, issuer, ca_pem, signing_key_file, verb_names, ceiling):
    def idp(aud, ceiling):
        d = {"module": "oidc", "settings": {"issuer": ISS, "audience": aud, "jwks_url": issuer.url,
                                            "role_claim": "roles", "ca_cert_pem": ca_pem}}
        if ceiling:
            d["max_admin_scope"] = ceiling
        return d
    bind = {"rbac-reader": {"admin_scope": "read-only"}, "rbac-full": {"admin_scope": "full"},
            "rbac-verbs": {"verbs": sorted(verb_names)}}
    return base_config(
        data, admin,
        **{"identity-providers": {"rig": idp(AUD, ceiling)},
           "plugins": {"enabled": True, "dir": plugins, "trust": {"allow_unsigned": True}},
           "advanced": {"allow_destinations": ["127.0.0.1"]},
           "auth": {"chain": ["keys"] if ceiling == "full" else [], "admin_auth": ["rig"],
                    "signing_key": {"file": signing_key_file}, "role_bindings": {"rig": bind}}})


def suite_rbac(work, log):
    why = []
    pkidir = os.path.join(work, "pki")
    os.makedirs(pkidir, exist_ok=True)
    ca = pki.Cert("evidence-rbac CA", ca=True)
    ca_file, _ = ca.write(pkidir, "ca")
    issuer = Issuer(pkidir, ca)
    rogue = pki.RsaKey()
    try:
        # control and negative: the reference admin surface, correct and broken
        ref_verbs = {"get_keys", "delete_groups_by_name"}
        for leg, broken in (("control", False), ("negative", True)):
            say(f"=== leg {1 if leg == 'control' else 2}: {leg} (the reference admin surface"
                f"{', scope enforcement broken' if broken else ''})")
            found, n = [], 0
            for capped in (False, True):
                ref = ReferenceAdmin(REFERENCE_OPS, issuer, broken=broken, capped=capped)
                ref.verbs = sorted(ref_verbs)
                try:
                    f_, n_ = matrix(ref.port, REFERENCE_OPS, principals(issuer, rogue, ref_verbs, capped))
                finally:
                    ref.stop()
                found, n = found + f_, n + n_
            say(f"{leg}: {n} cells, {len(found)} findings")
            if not broken and found:
                why += [f"control: {f}" for f in found[:10]]
            if broken:
                if not found:
                    why.append("negative: the broken reference surface passed the matrix")
                elif not any("wanted forbid, got admit" in f for f in found) \
                        or not any("expired" in f and "wanted deny" in f for f in found):
                    why.append(f"negative: refused, but not for the broken scope and expiry checks: {found[:3]}")

        # subject
        say("=== leg 3: subject (busbar, its OIDC module dropped in)")
        bins = build_subject(log, oidc=True)
        plugins = pack_oidc(bins, work, log)
        skf = os.path.join(work, "signing.key")
        with open(skf, "w") as f:
            f.write(secrets.token_hex(32))
        with open(ca_file) as f:
            ca_pem = f.read()
        data, admin = free_port(), free_port()
        # the verbs role's grant: one read verb and one mutation, by the closed table's names
        verb_names = {"get_keys", "post_keys"}
        b = Busbar(bins["busbar"], work, "rbac",
                   rbac_config(data, admin, plugins, issuer, ca_pem, skf, verb_names, "full"))
        try:
            full = principals(issuer, rogue, verb_names)["a full role"][0]
            b.wait(lambda: request(admin, "GET", ADMIN + "/audit/head", headers=full()))
            st, doc = request(admin, "GET", ADMIN + "/openapi.json", headers=full())
            if st != 200 or not isinstance(doc, dict):
                raise Refused(f"the node's OpenAPI document answered {st}: {str(doc)[:200]}")
            ops = operations(doc)
            if len(ops) < 40:
                raise Refused(f"the node's OpenAPI document lists only {len(ops)} admin operations")
            names = {o[3] for o in ops}
            # the verb table's snake-case names, as the document spells its operations
            snake = {o[3]: re.sub(r"(?<!^)(?=[A-Z])", "_", o[3] or "").lower() for o in ops}
            judged = []
            for m, p, s, v in ops:
                rule = published_scope(m, p)
                if s != rule:
                    why.append(f"subject: {m} {p} is annotated {s!r}, the published rule says {rule!r}")
                judged.append((m, p, rule, snake[v]))
            ops = judged
            missing = [v for v in verb_names if v not in {o[3] for o in ops}]
            if missing:
                raise Refused(f"the verbs role names {missing}, which the document's operations do not ({sorted(names)[:5]}…)")
            # the dangerous mutations last: the full role's pass runs them for real (with probe bodies)
            last = ("/restart", "/chain-break")
            ops.sort(key=lambda o: any(o[1].endswith(x) for x in last))
            say(f"subject: {len(ops)} admin operations")
            prins = principals(issuer, rogue, verb_names)
            # a data-plane virtual key, minted by the full role, presented to the admin plane
            st, minted = request(admin, "POST", ADMIN + "/keys", headers=full(), body={"name": "rbac-data"})
            if st != 201 or not isinstance(minted, dict) or not minted.get("token"):
                raise Refused(f"POST /keys answered {st}: {str(minted)[:200]}")
            vkey = minted["token"]
            prins = dict(list(prins.items())[:-1]) | {
                "a data-plane virtual key": (lambda: {"authorization": f"Bearer {vkey}"}, lambda s, v: "deny"),
                "a full role": prins["a full role"]}
            found, n = matrix(admin, ops, prins)
            say(f"subject: {n} admin cells, {len(found)} findings")
            why += [f"subject: {f}" for f in found]
            # the data plane: /stats is the key-gated route every build serves
            cells = [
                ("no credential", {}, 401),
                ("an admin full-role token", full(), 401),
                ("a live virtual key", {"authorization": f"Bearer {vkey}"}, 200),
            ]
            for name, h, want in cells:
                st, body = request(data, "GET", "/stats", headers=h)
                if st != want:
                    why.append(f"subject: data plane GET /stats with {name}: wanted {want}, got {st} {str(body)[:120]}")
            # the planes are separate listeners: the data route is not on the admin listener (whatever
            # credential asks), the admin surface is not on the data listener
            for name, h in (("a live virtual key", {"authorization": f"Bearer {vkey}"}), ("the full role", full())):
                st, body = request(admin, "GET", "/stats", headers=h)
                if st == 200:
                    why.append(f"subject: the data route /stats is served on the admin listener to {name}")
                elif st not in (401, 404):
                    why.append(f"subject: the data route /stats on the admin listener answered {name} {st}")
                say(f"subject: GET /stats on the admin listener with {name}: {st}")
            st, body = request(admin, "POST", ADMIN + f"/keys/{minted.get('id')}/revoke", headers=full(), body={})
            if st >= 300:
                why.append(f"subject: revoking the virtual key answered {st} {str(body)[:120]}")
            else:
                st, body = request(data, "GET", "/stats", headers={"authorization": f"Bearer {vkey}"})
                if st != 401:
                    why.append(f"subject: data plane GET /stats with a revoked key: wanted 401, got {st}")
            st, _ = request(data, "GET", ADMIN + "/keys", headers=full())
            if st != 404:
                why.append(f"subject: an admin path on the data listener answered {st}, not 404")
            if issuer.hits == 0:
                why.append("subject: busbar never fetched the issuer's JWKS, so no role token was verified")
        finally:
            b.stop()
        # the ceiling: the same provider with `max_admin_scope` left at its default, `read-only`
        data, admin = free_port(), free_port()
        b = Busbar(bins["busbar"], work, "rbac-capped",
                   rbac_config(data, admin, plugins, issuer, ca_pem, skf, verb_names, None))
        try:
            capped = principals(issuer, rogue, verb_names, capped=True)
            reader = capped["a full role capped read-only by its provider"][0]
            b.wait(lambda: request(admin, "GET", ADMIN + "/audit/head", headers=reader()))
            found, n = matrix(admin, ops, capped)
            say(f"subject (provider ceiling read-only): {n} admin cells, {len(found)} findings")
            why += [f"subject (provider ceiling read-only): {f}" for f in found]
        finally:
            b.stop()
    finally:
        issuer.stop()
    return why


# ─────────────────────────────────────────────────────────────────────────────────────────────────
# evidence-tls
# ─────────────────────────────────────────────────────────────────────────────────────────────────

def probe(port, ca_file, client=None, path="/healthz"):
    """'admitted' when an HTTP response came back over TLS; 'refused' with the reason otherwise."""
    ctx = ssl.create_default_context(cafile=ca_file)
    ctx.set_alpn_protocols(["http/1.1"])
    if client:
        ctx.load_cert_chain(*client)
    try:
        with socket.create_connection(("127.0.0.1", port), timeout=10) as raw:
            with ctx.wrap_socket(raw, server_hostname="localhost") as s:
                s.sendall(f"GET {path} HTTP/1.1\r\nhost: localhost\r\nconnection: close\r\n\r\n".encode())
                head = s.recv(64)
                if head.startswith(b"HTTP/1."):
                    return "admitted", head.split(b"\r\n")[0].decode(errors="replace")
                return "refused", f"no HTTP response ({head[:20]!r})"
    except (ssl.SSLError, OSError) as e:
        return "refused", f"{type(e).__name__}: {e}"


def judge_mtls(label, port, ca_file, good, rogue, path="/healthz"):
    why = []
    for name, client, want in (("a certless client", None, "refused"),
                               ("a client from a rogue CA", rogue, "refused"),
                               ("a client from the configured CA", good, "admitted")):
        got, detail = probe(port, ca_file, client, path)
        say(f"{label}: {name}: {got} ({detail})")
        if got != want:
            why.append(f"{label}: {name} was {got}, must be {want} ({detail})")
    return why


class OpenSslServer:
    """The control's peer: Python's OpenSSL server, client certificates REQUIRED (or, broken, OPTIONAL)."""

    def __init__(self, leaf, ca_file, required=True):
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(*leaf)
        ctx.load_verify_locations(ca_file)
        ctx.verify_mode = ssl.CERT_REQUIRED if required else ssl.CERT_OPTIONAL

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("content-length", "3")
                self.end_headers()
                self.wfile.write(b"ok\n")

            def log_message(self, *a):
                pass

        class S(http.server.ThreadingHTTPServer):
            def get_request(self):
                sock, addr = self.socket.accept()
                return ctx.wrap_socket(sock, server_side=True), addr

            def handle_error(self, request, client_address):
                pass

        self.server = S(("127.0.0.1", 0), H)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


def testssl_leg(work, log):
    """The tls suite's verdict from this conformance run, or from running it here."""
    out = os.environ.get("CONFORMANCE_OUT", "")
    sibling = os.path.join(os.path.dirname(out), "tls", "verdict.json") if out else ""
    if sibling and os.path.isfile(sibling):
        src = f"this run's tls suite ({sibling})"
    else:
        d = os.path.join(work, "tls")
        os.makedirs(d, exist_ok=True)
        rc = run(["bash", os.path.join(REPO, "testing", "tls-conformance", "tls.sh")], log,
                 cwd=REPO, env=dict(os.environ, CONFORMANCE_OUT=d, CONFORMANCE_SUITE="tls"))
        sibling, src = os.path.join(d, "verdict.json"), f"testing/tls-conformance/tls.sh, run here (exit {rc})"
    try:
        with open(sibling) as f:
            v = json.load(f)
    except (OSError, ValueError) as e:
        return [f"subject: the testssl subject wrote no verdict ({src}): {e}"]
    say(f"subject: the testssl subject: {v.get('status')} ({src})")
    if v.get("suite") != "tls" or v.get("status") != "pass" or v.get("armed") is not True:
        return [f"subject: the testssl subject is {v.get('status')!r}, not pass ({src}): {v.get('reason', '')[:300]}"]
    return []


def suite_tls(work, log):
    why = []
    pkidir = os.path.join(work, "pki")
    os.makedirs(pkidir, exist_ok=True)
    ca = pki.Cert("evidence-tls CA", ca=True)
    rogue_ca = pki.Cert("evidence-tls rogue CA", ca=True)
    ca_file, _ = ca.write(pkidir, "ca")
    leaf = pki.Cert("localhost", issuer=ca, server=True, dns=["localhost"], ips=["127.0.0.1"]).write(pkidir, "leaf", chain=True)
    admin_leaf = pki.Cert("localhost", issuer=ca, server=True, dns=["localhost"], ips=["127.0.0.1"]).write(pkidir, "admin-leaf", chain=True)
    good = pki.Cert("evidence client", issuer=ca, client=True).write(pkidir, "client")
    rogue = pki.Cert("evidence client", issuer=rogue_ca, client=True).write(pkidir, "rogue-client")

    say("=== leg 1: control (OpenSSL server, client certificates required)")
    s = OpenSslServer(leaf, ca_file, required=True)
    try:
        why += judge_mtls("control", s.port, ca_file, good, rogue)
    finally:
        s.stop()
    say("=== leg 2: negative control (OpenSSL server, client certificates optional)")
    s = OpenSslServer(leaf, ca_file, required=False)
    try:
        found = judge_mtls("negative", s.port, ca_file, good, rogue)
        if not found:
            why.append("negative: an OpenSSL server that admits certless clients passed the probe")
        elif not any("certless client was admitted" in f for f in found):
            why.append(f"negative: refused, but not for admitting a certless client: {found}")
    finally:
        s.stop()

    say("=== leg 3: subject (busbar: tls.client_ca on the data listener, admin_tls.client_ca on admin)")
    bins = build_subject(log)
    data, admin = free_port(), free_port()
    cfg = base_config(data, admin,
                      tls={"cert": {"file": leaf[0]}, "key": {"file": leaf[1]}, "client_ca": {"file": ca_file}},
                      admin_tls={"cert": {"file": admin_leaf[0]}, "key": {"file": admin_leaf[1]},
                                 "client_ca": {"file": ca_file}})
    b = Busbar(bins["busbar"], work, "tls", cfg)
    try:
        def up():
            got, detail = probe(data, ca_file, good)
            if got != "admitted":
                raise OSError(detail)
        b.wait(up)
        why += judge_mtls("subject data listener", data, ca_file, good, rogue)
        why += judge_mtls("subject admin listener", admin, ca_file, good, rogue, path="/api/v1/admin/audit/head")
    finally:
        b.stop()
    why += testssl_leg(work, log)
    return why


# ─────────────────────────────────────────────────────────────────────────────────────────────────

def main():
    which = sys.argv[1] if len(sys.argv) > 1 else ""
    if which not in SUITES:
        print(f"usage: evidence.py {'|'.join(SUITES)}", file=sys.stderr)
        return 2
    suite, standard, plan = SUITES[which]
    out = os.environ.get("CONFORMANCE_OUT") or tempfile.mkdtemp(prefix="evidence-out.")
    os.makedirs(out, exist_ok=True)
    work = tempfile.mkdtemp(prefix=f"evidence-{which}.")
    log = os.path.join(out, "build.log")
    why = []
    try:
        why = {"audit": suite_audit, "rbac": suite_rbac, "tls": suite_tls}[which](work, log)
    except Refused as e:
        why = [str(e)]
    except Exception as e:  # a rig fault is a fail, named, never a pass
        import traceback
        traceback.print_exc()
        why = [f"the rig failed: {type(e).__name__}: {e}"]
    finally:
        for d in ("busbar.log",):
            for root, _, files in os.walk(work):
                if d in files:
                    shutil.copy(os.path.join(root, d), os.path.join(out, os.path.basename(root) + "-" + d))
        for f in ("subject-range.json",):
            if os.path.exists(os.path.join(work, f)):
                shutil.copy(os.path.join(work, f), out)
        shutil.rmtree(work, ignore_errors=True)
    v = {"suite": suite, "status": "fail" if why else "pass", "armed": True, "standard": standard, "plan": plan,
         "spec_version": "busbar dist/default from this checkout"}
    if why:
        v["reason"] = "; ".join(why)[:4000]
    with open(os.path.join(out, "verdict.json"), "w") as f:
        json.dump(v, f, indent=2)
        f.write("\n")
    print(json.dumps(v))
    for w in why:
        say("FINDING:", w)
    return 1 if why else 0


if __name__ == "__main__":
    sys.exit(main())
