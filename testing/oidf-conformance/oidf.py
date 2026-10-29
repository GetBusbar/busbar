#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""THE OIDF RIG: `oidf-oauth2` and `fapi2`, judged by the OpenID Foundation conformance suite.

The suite is SELF-HOSTED at a pinned release (its own published images, pinned by digest) and driven
headless by its own runner, `scripts/run-test-plan.py`, from the release's own source. The subject is
busbar built from this checkout, booted as an OAuth 2.0 authorization server (`oauth_as:`) on a TLS
listener, in the FAPI 2.0 Security Profile posture (`oauth_as.fapi2: true`).

THE PLAN. The suite at the pin has NO plain-OAuth2 server plan: `openid=plain_oauth` is a variant of
the FAPI 2.0 Security Profile Final OP plan (`fapi2-security-profile-final-test-plan`), and it is
the only OIDF plan that judges an authorization server that is not an OpenID provider. So both
registry ids name that plan under one variant (plain_oauth + private_key_jwt + DPoP + plain_fapi),
as the 2026-10-02 ruling recorded for the deleted xtask rig: the plan runs ONCE per conformance run
and both verdicts are written from that run (the second id reads the first's record).

THE THREE LEGS, all in one run:

  control   The suite's own RP-against-OP self-test, verbatim the private_key_jwt + DPoP +
            plain_fapi job its own CI runs (CONTROL_ARG): OP-plan modules driven against the
            suite's MOCK authorization server, with the suite's own configs. The suite at the pin
            has no published third-party reference AS it runs against offline (its CI's peers are
            hosted services that need credentials), so the suite judging itself is the known-good
            peer: it proves the instrument (images, network, runner, export parsing) is sound.
  negative  busbar misconfigured: the same plan's modules against a busbar booted WITHOUT the FAPI
            2.0 posture (`fapi2: false`: no PAR, no DPoP, no private_key_jwt advertised). The named
            modules in NEGATIVE_MUST_FAIL must finish FAILED.
  subject   busbar in the FAPI 2.0 posture, the WHOLE plan.

THE VERDICT: `pass` only when the control passed, the negative control failed exactly where it must,
and every module of the subject's plan FINISHED with result PASSED (a SKIPPED module only with the
suite's own reason, which `reason` carries). REVIEW (a module awaiting a human's sign-off on its
screenshot) and WARNING are NOT a pass (orchestrator ruling 2026-10-26), with ONE exception: a
REVIEW module the owner signed off in the committed `signoff.json` counts as passed, and only while
the error page this run's browser captured for it hashes to the page the owner signed (a changed
page is back to awaiting review; the owner ruling of 2026-10-27). FAILED, INTERRUPTED,
UNKNOWN or an unfinished module is `fail`, named. `reason` opens with
`<passed>/<total> pass (<n> owner-reviewed: <modules>), <n> awaiting review: <modules>`. Every module that did not pass has its
suite log, its screenshots and its test id kept under `$CONFORMANCE_OUT/review/` for that sign-off.
The results are read from the suite's own plan export (`--export-dir`), held to the plan's own
module list.

THE RESOURCE OWNER. busbar's authorization server authenticates the resource owner on its consent
screen (`{issuer}/consent`, `RouteAuth::Admin`: the operator, through the admin chain). The suite's
headless browser (HtmlUnit, inside the suite server) reaches it because the subject's generated
config runs the documented open admin posture (`auth.admin_auth: []`, dev only, loopback only); the
browser presses Approve (Deny for user-rejects-authentication). This lives ONLY in the generated
subject config here and changes no product default.

THE PROTECTED RESOURCE the suite calls with the issued token is busbar's own `GET /stats`
(`RouteAuth::Key`): the kernel's DPoP door verifies the proof through the AS plane, and the data
chain verifies the token with busbar's real OIDC module (GetBusbar/busbar-auth-oidc at the rev
busbar ships, dist/default/Cargo.lock, its busbar-contract patched to THIS checkout, packed unsigned) trusting the AS's
JWKS, which a loopback stub serves on its own port (a node's own ports are off-limits to its
connector).

Everything is generated at run time: the TLS PKI, the AS signing key and both PS256 client keys
(openssl inside the pinned suite image), every port, every config.

Usage (from the repo root): python3 -I testing/oidf-conformance/oidf.py
Environment: CONFORMANCE_SUITE (oidf-oauth2 | fapi2), CONFORMANCE_OUT, BUSBAR_CHECKOUT,
CARGO_TARGET_DIR (all set by testing/conformance/run.sh).
"""

import base64
import hashlib
import http.server
import json
import os
import re
import secrets
import shutil
import socket
import ssl
import subprocess
import sys
import threading
import time
import urllib.request
import zipfile

# ---------------------------------------------------------------------------------------------------
# PINS
# ---------------------------------------------------------------------------------------------------

SUITE_REPO = "https://gitlab.com/openid/conformance-suite.git"
SUITE_TAG = "release-v5.3.3"
SUITE_COMMIT = "7d420f716e49d44f8a6b04f0a3e240ad6d68ab55"
# The suite's own published images at that release (registry.gitlab.com/openid/conformance-suite,
# tag release-v5.3.3), pinned by their index digests.
SERVER_IMAGE = ("registry.gitlab.com/openid/conformance-suite"
                "@sha256:377ab51f011d821c4b6f7729053e85adf062d691e51a3615f40507fd900a2436")
NGINX_IMAGE = ("registry.gitlab.com/openid/conformance-suite/nginx"
               "@sha256:d80183af68cb51c72c86b498780d94d6192cbc6adcc70a7d28ac6a01eff0d0db")
# mongo:6.0.13, the version the suite's own compose files name.
MONGO_IMAGE = "mongo@sha256:b415b12f638e2685d06c58ab7fb5943577c50fadec6d9340ef67d21aeac72070"
# python:3.13-alpine, for the suite's runner (it needs httpx and pyparsing, pinned below).
PYTHON_IMAGE = "python@sha256:bf12ecc0bea3f171d55145dd02c78b5eeb09f30ee2ac9cc2b4c9e4e8f5e30741"

# The runner's dependencies (scripts/requirements.txt names httpx and pyparsing unpinned): the full
# closure pip resolved for them, each wheel pinned by its PyPI sha256.
WHEELS = [
    ("https://files.pythonhosted.org/packages/12/b8/4bd346e22b28902df4d651910f5242c28d84e4a5c2435ca5c3f797ed7e2e/anyio-4.15.1-py3-none-any.whl",
     "6152fdbbf9a77fdec97731721bebf7c4c44f7c29b424b0065826173efc7ed101"),
    ("https://files.pythonhosted.org/packages/32/d1/a3652fe2c19134d0d15922177821d863cbd7e842d53a21bbe7e8e3a1b5ac/certifi-2026.10.23-py3-none-any.whl",
     "e9b54de76e530bb6cf0ccd036787103acb58fd42ba930ea8bf948ddbaa2f61d1"),
    ("https://files.pythonhosted.org/packages/04/4b/29cac41a4d98d144bf5f6d33995617b185d14b22401f75ca86f384e87ff1/h11-0.16.0-py3-none-any.whl",
     "63cf8bbe7522de3bf65932fda1d9c2772064ffb3dae62d55932da54b31cb6c86"),
    ("https://files.pythonhosted.org/packages/7e/f5/f66802a942d491edb555dd61e3a9961140fd64c90bce1eafd741609d334d/httpcore-1.0.9-py3-none-any.whl",
     "2d400746a40668fc9dec9810239072b40b4484b640a8c38fd654a024c7a1bf55"),
    ("https://files.pythonhosted.org/packages/2a/39/e50c7c3a983047577ee07d2a9e53faf5a69493943ec3f6a384bdc792deb2/httpx-0.28.1-py3-none-any.whl",
     "d909fcccc110f8c7faf814ca82a9a4d816bc5a6dbfea25d6591d6985b8ba59ad"),
    ("https://files.pythonhosted.org/packages/58/a2/bb081bab032533a855d44de1d56f8e8426114ff1ba5d1f07a438a0a654f8/idna-3.20-py3-none-any.whl",
     "ab7ae7122974553370f0bdb919e1a960b2cd1bc1ef0276416d896db81c14582c"),
    ("https://files.pythonhosted.org/packages/38/bb/d215ee7c73b61497b28a5503f9f53523f294fcc936762b7caf90e0c1c2b5/pyparsing-3.3.3-py3-none-any.whl",
     "ece8c00a69cf01b45d0b1dedabb469c90d8caf996d4fda40f147627a122849a4"),
    ("https://files.pythonhosted.org/packages/49/d3/b8441a820a491ddfc024b0b0cf0393375b75ea13866d9c66727e54c2fc80/typing_extensions-4.16.0-py3-none-any.whl",
     "481caa481374e813c1b176ada14e97f1f67a4539ce9cfeb3f350d78d6370c2e8"),
]

# ---------------------------------------------------------------------------------------------------
# THE PLAN
# ---------------------------------------------------------------------------------------------------

OP_PLAN = "fapi2-security-profile-final-test-plan"
# FAPI2SPFinalTestPlan fixes fapi_request_method=unsigned and fapi_response_mode=plain_response
# itself; naming either here makes the suite refuse to create the plan.
OP_VARIANT = "[openid=plain_oauth][client_auth_type=private_key_jwt][sender_constrain=dpop][fapi_profile=plain_fapi]"
PLAN = OP_PLAN + OP_VARIANT

# The control: the suite's mock authorization server (a FAPI 2.0 client test plan) driven by the OP
# plan's own modules, with the suite's own RP-against-OP configs: VERBATIM the private_key_jwt + DPoP
# + plain_fapi job of the suite's own CI at the pin (.gitlab-ci/run-tests.sh). It is the message-
# signing flavour because the suite's CI runs no plain-OAuth authorization-code self-test: under
# fapi2-security-profile-final-client-test-plan[plain_fapi] the mock refuses the OP modules' own
# authorization request (EnsureAuthorizationRequestContainsOnlyExpectedParamsWhenUsingPAR), which is
# why the suite's CI pairs that plan only with fapi_client_credentials_grant.
CONTROL_OP_MODULES = [
    "fapi2-security-profile-final-discovery-end-point-verification",
    "fapi2-security-profile-final-ensure-request-object-with-multiple-aud-succeeds",
]
CONTROL_ARG = (
    "fapi2-message-signing-final-client-test-plan[client_auth_type=private_key_jwt]"
    "[fapi_request_method=signed_non_repudiation][fapi_client_type=oidc][sender_constrain=dpop]"
    "[fapi_profile=plain_fapi][fapi_response_mode=plain_response]"
    ":fapi2-security-profile-final-client-test-happy-path"
    "{fapi2-message-signing-final-test-plan[openid=openid_connect][client_auth_type=private_key_jwt]"
    "[fapi_request_method=signed_non_repudiation][sender_constrain=dpop][fapi_profile=plain_fapi]"
    "[fapi_response_mode=plain_response]:" + ",".join(CONTROL_OP_MODULES) + "}"
    "scripts/test-configs-rp-against-op/fapi-op-test-config-no-mtls.json"
)
CONTROL_RP_CONFIG = "scripts/test-configs-rp-against-op/fapi-rp-test-config.json"

# The negative control's modules, each of which MUST finish FAILED against busbar without the FAPI
# 2.0 posture: the discovery document advertises no PAR endpoint and no DPoP algorithms, and the
# happy flow cannot push its request.
NEGATIVE_MUST_FAIL = [
    "fapi2-security-profile-final-discovery-end-point-verification",
    "fapi2-security-profile-final-happy-flow",
]

# What the CONTROL (the suite judging its own mock) may finish with. The subject is held stricter
# (`decide`): PASSED only.
GOOD = ("PASSED", "WARNING", "REVIEW", "SKIPPED")

STANDARD = {
    "oidf-oauth2": "OpenID Foundation OAuth2 conformance suite",
    "fapi2": "FAPI 2.0 Security Profile",
}

SUITE_BASE = "https://localhost.emobix.co.uk:8443/"
SUBJECT_HOST = "busbar.oidf.test"
ALIAS = "busbar-oidf"
SCOPE = "conformance"
RESOURCE_PATH = "/stats"
IDP = "fapi-as"
AS_KID = "busbar-oidf-as"

PLAN_TIMEOUT = int(os.environ.get("OIDF_PLAN_TIMEOUT", "3600"))


class Refused(Exception):
    """A leg could not be run. `instrument` says whose fault: the rig's tools (not-run) or busbar's (fail)."""

    def __init__(self, why, instrument=False):
        super().__init__(why)
        self.instrument = instrument


def say(*parts):
    print("oidf:", *parts, file=sys.stderr, flush=True)


# ---------------------------------------------------------------------------------------------------
# PROCESSES
# ---------------------------------------------------------------------------------------------------

def run(argv, log, cwd=None, env=None, timeout=None, stdin=None):
    """Run `argv`, appending its output to `log`; its exit code (124 on timeout)."""
    with open(log, "ab") as out:
        out.write(("\n$ " + " ".join(argv) + "\n").encode())
        out.flush()
        try:
            p = subprocess.run(argv, cwd=cwd, env=env, stdout=out, stderr=subprocess.STDOUT,
                               stdin=stdin if stdin is not None else subprocess.DEVNULL,
                               timeout=timeout)
            return p.returncode
        except subprocess.TimeoutExpired:
            out.write(b"\n[oidf rig: timed out]\n")
            return 124
        except FileNotFoundError as e:
            out.write(f"\n[oidf rig: {e}]\n".encode())
            return 127


def capture(argv, cwd=None, env=None):
    p = subprocess.run(argv, cwd=cwd, env=env, capture_output=True, text=True)
    return p.returncode, p.stdout, p.stderr


def tail(path, n=12):
    try:
        with open(path, errors="replace") as f:
            lines = [l.rstrip() for l in f if l.strip()]
    except OSError:
        return ""
    return " | ".join(lines[-n:])


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def sha256_file(path):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        for chunk in iter(lambda: f.read(1 << 20), b""):
            h.update(chunk)
    return h.hexdigest()


# ---------------------------------------------------------------------------------------------------
# THE INSTRUMENT: the suite's source (runner + its own configs) and the runner's wheels
# ---------------------------------------------------------------------------------------------------

def suite_source(cache, log):
    path = os.path.join(cache, f"conformance-suite-{SUITE_TAG}")
    rc, head, _ = capture(["git", "-C", path, "rev-parse", "HEAD"])
    if rc == 0 and head.strip() == SUITE_COMMIT:
        return path
    shutil.rmtree(path, ignore_errors=True)
    rc = run(["git", "clone", "-q", "--depth", "1", "--branch", SUITE_TAG, SUITE_REPO, path], log)
    _, head, _ = capture(["git", "-C", path, "rev-parse", "HEAD"])
    if rc != 0 or head.strip() != SUITE_COMMIT:
        raise Refused(f"the suite source {SUITE_TAG} could not be fetched at {SUITE_COMMIT} "
                      f"(got {head.strip() or 'nothing'})", instrument=True)
    return path


def wheels(cache):
    d = os.path.join(cache, "wheels")
    os.makedirs(d, exist_ok=True)
    reqs = []
    for url, sha in WHEELS:
        name = url.rsplit("/", 1)[1]
        dest = os.path.join(d, name)
        if not (os.path.isfile(dest) and sha256_file(dest) == sha):
            part = dest + f".part.{os.getpid()}"
            try:
                with urllib.request.urlopen(url, timeout=60) as r, open(part, "wb") as f:
                    shutil.copyfileobj(r, f)
            except OSError as e:
                raise Refused(f"the runner wheel {name} could not be fetched: {e}", instrument=True)
            got = sha256_file(part)
            if got != sha:
                os.unlink(part)
                raise Refused(f"the runner wheel {name} has sha256 {got}, pinned {sha}", instrument=True)
            os.replace(part, dest)
        dist = name.split("-")[0].replace("_", "-")
        version = name.split("-")[1]
        reqs.append(f"{dist}=={version} --hash=sha256:{sha}")
    with open(os.path.join(d, "requirements.txt"), "w") as f:
        f.write("\n".join(reqs) + "\n")
    return d


# ---------------------------------------------------------------------------------------------------
# KEYS AND CERTIFICATES, generated per run with openssl inside the pinned suite image
# ---------------------------------------------------------------------------------------------------

def openssl(pki, log, *args):
    uid = f"{os.getuid()}:{os.getgid()}"
    rc = run(["docker", "run", "--rm", "--user", uid, "-v", f"{pki}:/w", "-w", "/w",
              "--entrypoint", "openssl", SERVER_IMAGE, *args], log)
    if rc != 0:
        raise Refused(f"openssl {args[0]} failed (exit {rc}): {tail(log, 4)}", instrument=True)


def der_tlv(b):
    """One DER TLV: (tag, content, rest)."""
    tag, first = b[0], b[1]
    i = 2
    if first < 0x80:
        n = first
    else:
        k = first & 0x7F
        n = int.from_bytes(b[2:2 + k], "big")
        i = 2 + k
    return tag, b[i:i + n], b[i + n:]


def rsa_jwks(der, kid):
    """A PKCS#8 RSA private key (DER) as the PS256 private JWK the suite signs with, and its public half."""
    _, info, _ = der_tlv(der)               # PrivateKeyInfo, or a bare RSAPrivateKey
    _, _, rest = der_tlv(info)              # version
    if rest[0] == 0x30:                     # PKCS#8: AlgorithmIdentifier, then the key
        _, _, rest = der_tlv(rest)
        _, octets, _ = der_tlv(rest)        # privateKey OCTET STRING
        _, ints, _ = der_tlv(octets)        # RSAPrivateKey SEQUENCE
    else:                                   # PKCS#1 (what openssl 3 writes for -outform DER)
        ints = info
    members = []
    for _ in range(9):                      # version, n, e, d, p, q, dp, dq, qi
        _, v, ints = der_tlv(ints)
        members.append(b64url(v.lstrip(b"\x00") or b"\x00"))
    public = {"kty": "RSA", "alg": "PS256", "use": "sig", "kid": kid, "n": members[1], "e": members[2]}
    private = dict(public)
    for i, name in enumerate(["d", "p", "q", "dp", "dq", "qi"]):
        private[name] = members[3 + i]
    return private, public


def ec_public_jwk(spki_der, kid):
    point = spki_der[-65:]
    if point[0] != 4:
        raise Refused("the AS public key is not an uncompressed P-256 point", instrument=True)
    return {"kty": "EC", "crv": "P-256", "alg": "ES256", "use": "sig", "kid": kid,
            "x": b64url(point[1:33]), "y": b64url(point[33:65])}


def mint(pki, log):
    os.makedirs(pki, exist_ok=True)
    with open(os.path.join(pki, "leaf.ext"), "w") as f:
        f.write(f"subjectAltName=DNS:{SUBJECT_HOST},DNS:localhost,IP:127.0.0.1\n"
                "basicConstraints=critical,CA:FALSE\nkeyUsage=critical,digitalSignature\n"
                "extendedKeyUsage=serverAuth\n")
    ec = ["-newkey", "ec", "-pkeyopt", "ec_paramgen_curve:P-256", "-nodes"]
    openssl(pki, log, "req", "-x509", *ec, "-keyout", "ca.key", "-out", "ca.pem", "-days", "3",
            "-subj", "/CN=busbar oidf throwaway CA", "-addext", "basicConstraints=critical,CA:TRUE",
            "-addext", "keyUsage=critical,keyCertSign,cRLSign")
    openssl(pki, log, "req", *ec, "-keyout", "leaf.key", "-out", "leaf.csr", "-subj", f"/CN={SUBJECT_HOST}")
    openssl(pki, log, "x509", "-req", "-in", "leaf.csr", "-CA", "ca.pem", "-CAkey", "ca.key",
            "-CAcreateserial", "-out", "leaf.pem", "-days", "3", "-extfile", "leaf.ext")
    with open(os.path.join(pki, "chain.pem"), "w") as out:
        for name in ("leaf.pem", "ca.pem"):
            with open(os.path.join(pki, name)) as f:
                out.write(f.read())
    # The AS's ES256 signing key, the way busbar's docs say to make one.
    openssl(pki, log, "genpkey", "-algorithm", "EC", "-pkeyopt", "ec_paramgen_curve:P-256",
            "-outform", "DER", "-out", "as.der")
    # busbar reads a PKCS#8 v1 document; openssl 3 writes SEC1 for an EC key in DER.
    openssl(pki, log, "pkcs8", "-topk8", "-nocrypt", "-inform", "DER", "-in", "as.der", "-outform", "DER",
            "-out", "as.p8")
    openssl(pki, log, "pkey", "-inform", "DER", "-in", "as.der", "-pubout", "-outform", "DER", "-out", "as.pub.der")
    with open(os.path.join(pki, "as.p8"), "rb") as f:
        as_der = f.read()
    with open(os.path.join(pki, "as.key.b64"), "w") as f:
        f.write(base64.b64encode(as_der).decode())
    with open(os.path.join(pki, "as.pub.der"), "rb") as f:
        as_jwks = {"keys": [ec_public_jwk(f.read(), AS_KID)]}
    # The plan's two clients: PS256 (RSA-2048), so the suite can also build its RS256 negative.
    clients = []
    for n in (1, 2):
        openssl(pki, log, "genpkey", "-algorithm", "RSA", "-pkeyopt", "rsa_keygen_bits:2048",
                "-outform", "DER", "-out", f"client{n}.der")
        with open(os.path.join(pki, f"client{n}.der"), "rb") as f:
            private, public = rsa_jwks(f.read(), f"{ALIAS}-client{n}")
        clients.append({"id": f"oidf-suite-client-{n}", "private": private, "public": public})
    return as_jwks, clients


# ---------------------------------------------------------------------------------------------------
# THE SUBJECT: busbar from this checkout, and busbar's OIDC module
# ---------------------------------------------------------------------------------------------------

def cargo_env(target):
    env = dict(os.environ)
    env["CARGO_TARGET_DIR"] = target
    return env


def oidc_pin(checkout):
    """{url, rev, version} of busbar's OIDC module AS SHIPPED: the `busbar-auth-oidc-plugin` row of the
    distribution workspace's lock (dist/default/Cargo.lock; the root workspace is core and names no
    plugin). When release/plugin-pins.tsv (`<repo>\\t<tag>\\t<commit>`) names busbar-auth-oidc, its
    commit must be the lock's rev: the rig never judges a module other than the one released."""
    lock_path = os.path.join(checkout, "dist", "default", "Cargo.lock")
    try:
        with open(lock_path) as f:
            lock = f.read()
    except OSError as e:
        raise Refused(f"dist/default/Cargo.lock could not be read: {e}")
    # Each `[[package]]` table's flat `key = "value"` lines (the runner's python predates tomllib).
    packages = [dict(re.findall(r'^(\w+) = "([^"]*)"$', block, re.M)) for block in lock.split("[[package]]")[1:]]
    pkg = next((p for p in packages if p.get("name") == "busbar-auth-oidc-plugin"), None)
    if not pkg:
        raise Refused("dist/default/Cargo.lock pins no busbar-auth-oidc-plugin")
    m = re.fullmatch(r"git\+(https://[^?#]+)\?rev=([0-9a-f]{40})#([0-9a-f]{40})", pkg.get("source", ""))
    if not m or m.group(2) != m.group(3):
        raise Refused(f"dist/default/Cargo.lock pins busbar-auth-oidc-plugin from {pkg.get('source')!r}, "
                      "not a git rev")
    url, rev = m.group(1), m.group(3)
    pins_path = os.path.join(checkout, "release", "plugin-pins.tsv")
    if os.path.isfile(pins_path):
        with open(pins_path) as f:
            for line in f:
                cols = line.rstrip("\n").split("\t")
                if line.startswith("#") or len(cols) < 3:
                    continue
                if cols[0].rsplit("/", 1)[-1] == "busbar-auth-oidc" and cols[2] != rev:
                    raise Refused(f"release/plugin-pins.tsv ships busbar-auth-oidc {cols[1]} at {cols[2]}, "
                                  f"but dist/default/Cargo.lock pins {rev}")
    return {"url": url, "rev": rev, "version": pkg["version"]}


def subject_builds(checkout):
    """The two builds the subject needs: the binary busbar SHIPS (the distribution workspace,
    dist/default: core plus its compiled-in transports and planes; the root workspace's `busbar` is
    core alone, which has no listener), and the plugin packer from the root workspace."""
    return [
        ["cargo", "build", "--locked", "--manifest-path", os.path.join(checkout, "dist", "default", "Cargo.toml"),
         "--bin", "busbar"],
        ["cargo", "build", "--locked", "-p", "busbar-plugin-loader", "--features", "pack",
         "--bin", "busbar-plugin-pack"],
    ]


def build_subject(checkout, target, work, log):
    env = cargo_env(target)
    for argv in subject_builds(checkout):
        rc = run(argv, log, cwd=checkout, env=env)
        if rc != 0:
            raise Refused(f"`{' '.join(argv)}` exited {rc}: {tail(log, 6)}")
    debug = os.path.join(target, "debug")
    busbar, pack = os.path.join(debug, "busbar"), os.path.join(debug, "busbar-plugin-pack")

    # busbar's OIDC module, from its own repo at the rev busbar SHIPS (oidc_pin), its busbar-contract
    # patched to THIS checkout (what the distribution workspace does for its dev edge), so the module
    # and the subject speak one plugin ABI.
    pin = oidc_pin(checkout)
    version = pin["version"]
    src = os.path.join(work, "busbar-auth-oidc")
    shutil.rmtree(src, ignore_errors=True)
    os.makedirs(src)
    for argv in (["git", "-C", src, "init", "-q"],
                 ["git", "-C", src, "fetch", "-q", "--depth", "1", pin["url"], pin["rev"]],
                 ["git", "-C", src, "checkout", "-q", "--detach", "FETCH_HEAD"]):
        rc = run(argv, log, env=env)
        if rc != 0:
            raise Refused(f"the OIDC module source {pin['url']}@{pin['rev']} could not be fetched "
                          f"(git {argv[3]} exit {rc}): {tail(log, 3)}", instrument=True)
    _, head, _ = capture(["git", "-C", src, "rev-parse", "HEAD"])
    if head.strip() != pin["rev"]:
        raise Refused(f"the OIDC module source is at {head.strip()}, pinned {pin['rev']}", instrument=True)
    contract = os.path.join(checkout, "crates", "busbar-contract")
    patch = f'patch."https://github.com/GetBusbar/busbar".busbar-contract.path="{contract}"'
    plugin_target = os.path.join(target, "oidf-oidc-plugin")
    argv = ["cargo", "build", "--manifest-path", os.path.join(src, "Cargo.toml"), "-p", "busbar-auth-oidc-plugin",
            "--config", patch, "--target-dir", plugin_target]
    rc = run(argv, log, cwd=src, env=env)
    if rc != 0:
        raise Refused(f"the OIDC module did not build (exit {rc}): {tail(log, 6)}")
    lib = os.path.join(plugin_target, "debug",
                       ("libbusbar_auth_oidc_plugin.dylib" if sys.platform == "darwin" else "libbusbar_auth_oidc_plugin.so"))
    plugins = os.path.join(work, "plugins")
    os.makedirs(plugins, exist_ok=True)
    rc = run([pack, "pack", "--lib", lib, "--name", "oidc", "--alias", "oidc", "--kind", "auth",
              "--version", version, "--publisher", "busbar-oidf-conformance",
              "--out", os.path.join(plugins, "oidc.tar.gz"), "--allow-unsigned"], log)
    if rc != 0:
        raise Refused(f"the OIDC module could not be packed (exit {rc}): {tail(log, 6)}")
    return busbar, plugins


class JwksStub:
    """The AS's JWKS on a loopback port of its own, over TLS with the run's leaf (the OIDC module
    fetches a JWKS over https only, trusting the run's CA through `ca_cert_pem`). Never one of the
    subject's ports: a node's connector refuses its own."""

    def __init__(self, jwks, pki):
        body = json.dumps(jwks).encode()
        stub = self
        self.hits = 0

        class H(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                stub.hits += 1
                ok = self.path == "/jwks"
                self.send_response(200 if ok else 404)
                self.send_header("content-type", "application/json")
                payload = body if ok else b"{}"
                self.send_header("content-length", str(len(payload)))
                self.end_headers()
                self.wfile.write(payload)

            def log_message(self, *a):
                pass

        self.server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), H)
        ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        ctx.load_cert_chain(os.path.join(pki, "chain.pem"), os.path.join(pki, "leaf.key"))
        self.server.socket = ctx.wrap_socket(self.server.socket, server_side=True)
        self.port = self.server.server_address[1]
        threading.Thread(target=self.server.serve_forever, daemon=True).start()

    def stop(self):
        self.server.shutdown()


def yaml_of(value):
    """JSON is YAML: busbar reads the generated config as a YAML document."""
    return json.dumps(value, indent=2) + "\n"


def subject_config(*, fapi2, data, admin, issuer, pki, plugins, jwks_url, clients, callback):
    with open(os.path.join(pki, "ca.pem")) as f:
        ca_pem = f.read()
    declared = [{"client_id": c["id"], "redirect_uris": [c["redirect_uri"]], "jwks": {"keys": [c["public"]]}}
                for c in clients]
    return {
        "listen": f"0.0.0.0:{data}",
        "admin_listen": f"127.0.0.1:{admin}",
        "store": {"module": "memory"},
        "providers": {},
        "models": {},
        "tls": {"cert": {"file": os.path.join(pki, "chain.pem")}, "key": {"file": os.path.join(pki, "leaf.key")}},
        "oauth_as": {
            "issuer": issuer,
            "default_grant": [SCOPE],
            "fapi2": fapi2,
            "signing_key": {"file": os.path.join(pki, "as.key.b64")},
            "key_id": AS_KID,
            "clients": declared,
        },
        "identity-providers": {
            IDP: {
                "module": "oidc",
                "settings": {"issuer": issuer, "audience": issuer, "jwks_url": jwks_url, "role_claim": "scope",
                             "ca_cert_pem": ca_pem},
            },
        },
        "plugins": {"enabled": True, "dir": plugins, "trust": {"allow_unsigned": True}},
        "advanced": {"allow_destinations": ["127.0.0.1"]},
        "auth": {"chain": [IDP], "admin_auth": [], "role_bindings": {IDP: {SCOPE: {}}}},
    }


class Subject:
    def __init__(self, busbar, work, name, cfg, data):
        self.dir = os.path.join(work, name)
        os.makedirs(self.dir, exist_ok=True)
        self.log = os.path.join(self.dir, "busbar.log")
        conf = os.path.join(self.dir, "config.yaml")
        prov = os.path.join(self.dir, "providers.yaml")
        with open(conf, "w") as f:
            f.write(yaml_of(cfg))
        with open(prov, "w") as f:
            f.write("{}\n")
        env = dict(os.environ, BUSBAR_CONFIG=conf, BUSBAR_PROVIDERS=prov)
        self.data = data
        out = open(self.log, "wb")
        self.proc = subprocess.Popen([busbar], cwd=self.dir, env=env, stdin=subprocess.DEVNULL,
                                     stdout=out, stderr=subprocess.STDOUT)
        self.ctx = ssl.create_default_context(cafile=cfg["tls"]["cert"]["file"].replace("chain.pem", "ca.pem"))

    def get(self, path):
        import http.client
        c = http.client.HTTPSConnection("127.0.0.1", self.data, context=self.ctx, timeout=10)
        try:
            c.request("GET", path)
            r = c.getresponse()
            return r.status, r.read()
        finally:
            c.close()

    def wait(self, path, secs=90):
        deadline = time.time() + secs
        while time.time() < deadline:
            if self.proc.poll() is not None:
                raise Refused(f"busbar exited during boot ({self.proc.returncode}): {tail(self.log)}")
            try:
                return self.get(path)
            except OSError:
                time.sleep(0.5)
        raise Refused(f"busbar never answered {path} within {secs}s: {tail(self.log)}")

    def stop(self):
        if self.proc.poll() is None:
            self.proc.terminate()
            try:
                self.proc.wait(10)
            except subprocess.TimeoutExpired:
                self.proc.kill()


def boot(busbar, work, name, *, fapi2, pki, plugins, jwks, clients, callback):
    data, admin = free_port(), free_port()
    issuer = f"https://{SUBJECT_HOST}:{data}"
    stub = JwksStub(jwks, pki)
    cfg = subject_config(fapi2=fapi2, data=data, admin=admin, issuer=issuer, pki=pki, plugins=plugins,
                         jwks_url=f"https://127.0.0.1:{stub.port}/jwks", clients=clients, callback=callback)
    s = Subject(busbar, work, name, cfg, data)
    s.stub, s.issuer = stub, issuer
    meta_path = "/.well-known/oauth-authorization-server"
    status, body = s.wait(meta_path)
    if status != 200:
        s.stop()
        raise Refused(f"busbar's authorization-server metadata answered {status}: {body[:200]!r}")
    meta = json.loads(body)
    if meta.get("issuer") != issuer:
        s.stop()
        raise Refused(f"busbar's metadata names issuer {meta.get('issuer')!r}, configured {issuer!r}")
    if fapi2 and "pushed_authorization_request_endpoint" not in meta:
        s.stop()
        raise Refused("busbar's metadata advertises no PAR endpoint: the FAPI 2.0 posture is not on")
    status, body = s.get("/jwks")
    if status != 200 or json.loads(body).get("keys", [{}])[0].get("x") != jwks["keys"][0]["x"]:
        s.stop()
        raise Refused(f"busbar's JWKS ({status}) does not publish the configured signing key")
    return s


# ---------------------------------------------------------------------------------------------------
# THE SUITE: mongo, server, nginx on a compose network of this run's own; the runner joins it
# ---------------------------------------------------------------------------------------------------

def server_entrypoint():
    # The image's own ENTRYPOINT (Dockerfile at the pinned release), preceded by one step: the run's
    # throwaway CA goes into the JVM trust store, because the suite's in-process browser (HtmlUnit),
    # unlike its HTTP client, verifies the authorization server's certificate.
    return ("keytool -importcert -noprompt -cacerts -storepass changeit -alias busbar-oidf-ca "
            "-file /oidf/ca.pem >/dev/null && exec java "
            '-D"fintechlabs.base_url=${BASE_URL}" -D"fintechlabs.base_mtls_url=${BASE_MTLS_URL}" '
            '-D"spring.mongodb.uri=mongodb://${MONGODB_HOST}:27017/test_suite" '
            "-jar /server/fapi-test-suite.jar -Djdk.tls.maxHandshakeMessageSize=65536")


def compose_file(work, pki, suite_src, wheel_dir):
    uid = f"{os.getuid()}:{os.getgid()}"
    doc = {
        "services": {
            "mongodb": {"image": MONGO_IMAGE, "tmpfs": ["/data/db"]},
            "server": {
                "image": SERVER_IMAGE,
                "environment": {
                    "BASE_URL": SUITE_BASE.rstrip("/"),
                    "BASE_MTLS_URL": "https://localhost.emobix.co.uk:8444",
                    "MONGODB_HOST": "mongodb",
                    "SPRING_PROFILES_ACTIVE": "dev",
                },
                "extra_hosts": [f"{SUBJECT_HOST}:host-gateway"],
                "volumes": [f"{os.path.join(pki, 'ca.pem')}:/oidf/ca.pem:ro"],
                "entrypoint": ["/bin/sh", "-c", server_entrypoint().replace("$", "$$")],
                "depends_on": ["mongodb"],
            },
            "nginx": {
                "image": NGINX_IMAGE,
                "depends_on": ["server"],
                # The suite's own outbound requests to its public name reach its front door.
                "networks": {"default": {"aliases": ["localhost.emobix.co.uk"]}},
            },
            "runner": {
                "image": PYTHON_IMAGE,
                "profiles": ["runner"],
                "user": uid,
                "working_dir": "/suite",
                "environment": {
                    "HOME": "/tmp", "PIP_NO_CACHE_DIR": "1", "PYTHONPATH": "/tmp/deps",
                    "CONFORMANCE_SERVER": SUITE_BASE, "CONFORMANCE_DEV_MODE": "1",
                    "DISABLE_SSL_VERIFY": "1", "CI": "1",
                },
                "volumes": [f"{suite_src}:/suite:ro", f"{wheel_dir}:/wheels:ro", f"{work}:/work"],
                "entrypoint": ["/bin/sh", "-c",
                               "pip install -q --disable-pip-version-check --no-index --find-links /wheels "
                               "--require-hashes --target /tmp/deps -r /wheels/requirements.txt "
                               '&& exec python scripts/run-test-plan.py "$$@"', "runner"],
            },
        },
    }
    path = os.path.join(work, "compose.json")
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
    return path


class Suite:
    def __init__(self, work, pki, suite_src, wheel_dir, log):
        self.work, self.log = work, log
        self.project = "oidf" + secrets.token_hex(4)
        self.file = compose_file(work, pki, suite_src, wheel_dir)
        self.up = False

    def compose(self, *args, log=None, timeout=None):
        return run(["docker", "compose", "-p", self.project, "-f", self.file, *args], log or self.log, timeout=timeout)

    def start(self):
        rc = self.compose("up", "-d", "--quiet-pull", "mongodb", "server", "nginx", timeout=900)
        self.up = True
        if rc != 0:
            raise Refused(f"`docker compose up` of the suite failed (exit {rc}): {tail(self.log, 6)}", instrument=True)
        deadline = time.time() + 300
        while time.time() < deadline:
            rc = self.compose("exec", "-T", "server", "curl", "-skf", "-o", "/dev/null",
                              f"{SUITE_BASE}api/runner/available")
            if rc == 0:
                return
            time.sleep(4)
        raise Refused(f"the suite's API never answered within 300s: {tail(self.log, 6)}", instrument=True)

    def reach(self, issuer):
        """The suite's container reaches the subject by its issuer name, over TLS its JVM trusts."""
        rc = self.compose("exec", "-T", "server", "curl", "-sSf", "--max-time", "15", "--cacert", "/oidf/ca.pem",
                          "-o", "/dev/null", f"{issuer}/.well-known/oauth-authorization-server")
        if rc != 0:
            raise Refused(f"the suite's container cannot reach busbar at {issuer} (host-gateway): {tail(self.log, 3)}",
                          instrument=True)
        rc = self.compose("exec", "-T", "server", "keytool", "-list", "-cacerts", "-storepass", "changeit",
                          "-alias", "busbar-oidf-ca")
        if rc != 0:
            raise Refused("the run's CA is not in the suite JVM's trust store", instrument=True)

    def runner(self, leg_dir, args):
        """run-test-plan.py with `args`; (exit code, its output)."""
        os.makedirs(os.path.join(leg_dir, "export"), exist_ok=True)
        rel = os.path.relpath(leg_dir, self.work)
        out = os.path.join(leg_dir, "runner.log")
        rc = self.compose("--profile", "runner", "run", "--rm", "-T", "runner",
                          "--export-dir", f"/work/{rel}/export", "--no-parallel", "--verbose", *args,
                          log=out, timeout=PLAN_TIMEOUT)
        with open(out, errors="replace") as f:
            return rc, f.read()

    def images(self, test_id):
        """The images the suite holds for one module (`GET /api/log/<id>/images`: each entry's `img`
        is the data URI the browser's placeholder fill or an upload recorded)."""
        rc, out, _ = capture(["docker", "compose", "-p", self.project, "-f", self.file, "exec", "-T", "server",
                              "curl", "-sk", f"{SUITE_BASE}api/log/{test_id}/images"])
        try:
            return json.loads(out) if rc == 0 else []
        except ValueError:
            return []

    def down(self):
        if self.up:
            self.compose("logs", "--no-color", "server", log=os.path.join(self.work, "suite-server.log"))
            self.compose("down", "-v", "--remove-orphans", timeout=300)


# ---------------------------------------------------------------------------------------------------
# THE PLAN CONFIGURATION for busbar
# ---------------------------------------------------------------------------------------------------

def plan_config(issuer, description, clients):
    callback = {
        "task": "The AS redirected to the suite's callback",
        "match": f"{SUITE_BASE}test/a/{ALIAS}/callback*",
        "optional": True,
        "commands": [["wait", "id", "submission_complete", 15]],
    }
    # A refused authorization request is an HTML page at /authorize carrying "Authorization error"
    # (busbar-core-oauth2 routes::error_page); the wait fills the module's ExpectXxxErrorPage
    # placeholder. `xpath`, because the suite's browser fills a placeholder only from a real selector.
    error_page = {
        "task": "The AS refused the authorization request with its error page",
        "match": f"{issuer}/authorize*",
        "optional": True,
        "commands": [["wait", "xpath", "//*", 10, "Authorization error", "update-image-placeholder"]],
    }

    def browser(click):
        return [{
            "match": f"{issuer}/*",
            "tasks": [
                {"task": "busbar's consent screen", "match": f"{issuer}/consent*", "optional": True,
                 "commands": [click]},
                error_page,
                callback,
            ],
        }]

    def client(c):
        return {"client_id": c["id"], "scope": SCOPE, "jwks": {"keys": [c["private"]]}}

    return {
        "alias": ALIAS,
        "description": description,
        "server": {"discoveryUrl": f"{issuer}/.well-known/oauth-authorization-server"},
        "client": client(clients[0]),
        "client2": client(clients[1]),
        "resource": {"resourceUrl": f"{issuer}{RESOURCE_PATH}"},
        "browser": browser(["click", "id", "approve"]),
        "override": {
            "fapi2-security-profile-final-user-rejects-authentication": {
                "browser": browser(["click", "id", "deny"]),
            },
            # Nobody approves on the first visit; the repeat showing of the same pushed request
            # carries id="revisit", and only then is Approve pressed (`optional`: absent = no-op).
            "fapi2-security-profile-final-par-ensure-reused-request-uri-prior-to-auth-completion-succeeds": {
                "browser": browser(["click", "xpath", "//*[@id='revisit']/following::button[@id='approve']", "optional"]),
            },
        },
    }


# ---------------------------------------------------------------------------------------------------
# READING THE SUITE'S OWN RESULTS
# ---------------------------------------------------------------------------------------------------

def strip_ansi(s):
    return re.sub(r"\x1b\[[0-9;]*[A-Za-z]", "", s)


def planned_modules(log):
    """Every `[p:i] module` the runner listed under `N modules to test:`, per plan."""
    text = strip_ansi(log)
    plans = []
    stamp = r"(?:\d{4}-\d\d-\d\d \d\d:\d\d:\d\d )?"
    for m in re.finditer(rf"^{stamp}(\d+) modules to test:\n((?:{stamp}  \[\d+:\d+\] \S+\n?)+)", text, re.M):
        mods = re.findall(r"\] (\S+)", m.group(2))
        if len(mods) != int(m.group(1)):
            raise ValueError("the runner's module list does not match its own count")
        plans.append(mods)
    return plans


def exported(export_dir):
    """Every module in the plan export zips in `export_dir` (the suite's `test-log-<module>-<id>.json`:
    `testInfo` and the condition `results`), as [(testInfo, results)]."""
    found = []
    for name in sorted(os.listdir(export_dir)):
        if not name.endswith(".zip"):
            continue
        with zipfile.ZipFile(os.path.join(export_dir, name)) as z:
            for entry in z.namelist():
                if not (entry.startswith("test-log-") and entry.endswith(".json")):
                    continue
                doc = json.loads(z.read(entry))
                found.append((doc["testInfo"], doc.get("results") or []))
    return found


def judge(leg_dir, log):
    """[(module, status, result, why)] for every module the runner listed, read from the export."""
    plans = planned_modules(log)
    if not plans:
        raise ValueError("the runner listed no plan modules (`N modules to test:`)")
    infos = exported(os.path.join(leg_dir, "export"))
    rows = []
    for mods in plans:
        for m in mods:
            match = [x for x in infos if x[0].get("testName") == m]
            if not match:
                rows.append((m, "NO-EXPORT", "", "the plan export carries no result for this module"))
                continue
            info, results = match[0]
            infos.remove(match[0])
            rows.append((m, info.get("status", ""), info.get("result") or "", why(info, results)))
    return rows


def why(info, results):
    """The suite's own words for anything but a clean pass: each condition that did not succeed."""
    seen = []
    for e in results:
        if e.get("result") in ("FAILURE", "WARNING", "REVIEW", "SKIPPED", "INTERRUPTED"):
            line = f"{e.get('result')} {e.get('src', '?')}: {str(e.get('msg', '')).strip()[:160]}"
            if line not in seen:
                seen.append(line)
    if info.get("result") == "SKIPPED" and not seen:
        seen.append("SKIPPED: " + str(info.get("summary", "")).strip()[:160])
    return " / ".join(seen[:4])


# ---------------------------------------------------------------------------------------------------
# THE LEGS
# ---------------------------------------------------------------------------------------------------

def leg_control(suite, work):
    d = os.path.join(work, "control")
    os.makedirs(d, exist_ok=True)
    rc, log = suite.runner(d, [CONTROL_ARG, CONTROL_RP_CONFIG])
    rows = judge(d, log)
    # Held to the subject's rule: every module FINISHED, nothing FAILED. (The runner exits 1 on any
    # WARNING not in an expected-failures file; this rig keeps no such file, and lists warnings.)
    bad = [f"{m} {s}/{r}" for m, s, r, _ in rows if s != "FINISHED" or r not in GOOD]
    return {"leg": "control", "exit": rc, "modules": rows, "ok": not bad, "why": "; ".join(bad)}


def leg_subject(suite, work, name, issuer, clients, modules=None):
    d = os.path.join(work, name)
    os.makedirs(d, exist_ok=True)
    cfg = os.path.join(d, "plan-config.json")
    with open(cfg, "w") as f:
        json.dump(plan_config(issuer, f"busbar {name}", clients), f, indent=2)
    arg = PLAN + (f":{','.join(modules)}" if modules else "")
    rc, log = suite.runner(d, [arg, f"/work/{os.path.relpath(cfg, work)}"])
    rows = judge(d, log)
    # The images the suite holds for every module that did not pass, fetched while it is up: the
    # screenshots a REVIEW is signed off from (keep_review files them).
    shots = {}
    for info, _ in exported(os.path.join(d, "export")):
        if info.get("result") != "PASSED" and info.get("testId"):
            shots[info["testId"]] = suite.images(info["testId"])
    with open(os.path.join(d, "images.json"), "w") as f:
        json.dump(shots, f)
    return rc, rows, review_pages(d)


def review_pages(leg_dir):
    """{module: [sha256 of each page the suite's browser captured for a REVIEW condition]}: what an
    owner sign-off (SIGNOFF) is matched against."""
    pages = {}
    for info, results in exported(os.path.join(leg_dir, "export")):
        if info.get("result") != "REVIEW":
            continue
        pages[info.get("testName", "?")] = sorted(
            hashlib.sha256(e["page_source"].encode()).hexdigest()
            for e in results if e.get("result") == "REVIEW" and isinstance(e.get("page_source"), str))
    return pages


SIGNOFF = os.path.join(os.path.dirname(os.path.abspath(__file__)), "signoff.json")


def signed_off():
    """{module: page_sha256} from the committed owner sign-off file (absent file: none signed)."""
    try:
        with open(SIGNOFF) as f:
            return {e["module"]: e["page_sha256"] for e in json.load(f)["signed"]}
    except OSError:
        return {}


def run_all(work):
    checkout = os.environ.get("BUSBAR_CHECKOUT") or os.getcwd()
    target = os.environ.get("CARGO_TARGET_DIR") or os.path.join(checkout, "target")
    cache = os.path.join(os.environ.get("MODERNCI_CACHE_DIR") or os.path.join(os.path.expanduser("~"), ".cache"),
                         "oidf-conformance")
    os.makedirs(cache, exist_ok=True)
    log = os.path.join(work, "rig.log")
    record = {"plan": PLAN, "suite": f"{SUITE_TAG} ({SUITE_COMMIT[:12]})"}

    for tool in ("docker", "git", "cargo"):
        if not shutil.which(tool):
            raise Refused(f"`{tool}` is not on PATH", instrument=True)
    if run(["docker", "compose", "version"], log) != 0:
        raise Refused("`docker compose` is not available", instrument=True)

    say("fetching the suite's source and the runner's wheels")
    src = suite_source(cache, log)
    wheel_dir = wheels(cache)
    pki = os.path.join(work, "pki")
    say("minting the run's PKI and keys")
    for image in (SERVER_IMAGE, NGINX_IMAGE, MONGO_IMAGE, PYTHON_IMAGE):
        if run(["docker", "pull", "-q", image], log, timeout=900) != 0:
            raise Refused(f"the pinned image {image} could not be pulled", instrument=True)
    as_jwks, clients = mint(pki, log)
    callback = f"{SUITE_BASE}test/a/{ALIAS}/callback"
    clients[0]["redirect_uri"] = callback
    # The happy flow's second-client leg sends exactly this redirect_uri, and busbar matches redirect
    # URIs exactly.
    clients[1]["redirect_uri"] = callback + "?dummy1=lorem&dummy2=ipsum"

    suite = Suite(work, pki, src, wheel_dir, log)
    try:
        say("starting the suite")
        suite.start()
        say("control: the suite's own RP-against-OP self-test")
        record["control"] = leg_control(suite, work)
        say("control:", "ok" if record["control"]["ok"] else "NOT OK " + record["control"]["why"])

        say("building the subject (busbar, busbar-plugin-pack, the OIDC module)")
        try:
            busbar, plugins = build_subject(checkout, target, work, os.path.join(work, "build.log"))
        except Refused as e:
            record["build_error"] = str(e)
            return record

        for name, fapi2, modules in (("subject", True, None), ("negative", False, NEGATIVE_MUST_FAIL)):
            say(f"{name}: booting busbar (fapi2={fapi2})")
            try:
                s = boot(busbar, work, name + "-busbar", fapi2=fapi2, pki=pki, plugins=plugins, jwks=as_jwks,
                         clients=clients, callback=callback)
            except Refused as e:
                record[f"{name}_error"] = str(e)
                continue
            try:
                suite.reach(s.issuer)
                say(f"{name}: running {PLAN}" + (f" modules {modules}" if modules else " (the whole plan)"))
                rc, rows, pages = leg_subject(suite, work, name, s.issuer, clients, modules)
                record[name] = {"exit": rc, "modules": rows, "review_pages": pages}
            except (Refused, ValueError) as e:
                record[f"{name}_error"] = str(e)
            finally:
                s.stop()
                s.stub.stop()
    finally:
        suite.down()
    return record


# ---------------------------------------------------------------------------------------------------
# THE VERDICT
# ---------------------------------------------------------------------------------------------------

def decide(record, signoff=None):
    """(status, armed, reason) from one run's record.

    `pass` only when EVERY module of the subject's plan FINISHED with result PASSED (orchestrator
    ruling 2026-10-26): a REVIEW is a module awaiting a human's sign-off on its screenshot, and a
    WARNING is the suite naming a shortfall, so neither is a pass. A SKIPPED module is a pass only
    with the suite's own reason, which `reason` carries. The reason opens with the count:
    `<passed>/<total> pass (<n> owner-reviewed: <modules>), <n> awaiting review: <modules>`."""
    if "instrument_error" in record:
        return "not-run", False, "the OIDF suite could not be run: " + record["instrument_error"]
    control = record.get("control") or {}
    if not control.get("ok"):
        return "not-run", False, "the control (the suite's own RP-against-OP self-test) did not pass: " + \
            (control.get("why") or "no result")
    if "build_error" in record:
        return "fail", True, "the subject could not be built: " + record["build_error"]
    sub = record.get("subject")
    if not sub:
        return "fail", True, "the subject did not run: " + record.get("subject_error", "no result")
    rows = sub["modules"]
    done = [(m, r, why) for m, s, r, why in rows if s == "FINISHED"]
    passed = [m for m, r, _ in done if r == "PASSED"]
    # A REVIEW is owner-reviewed only when the committed sign-off names the module AND the one page
    # this run captured for it hashes to the signed page. Anything else is awaiting review.
    signoff = signed_off() if signoff is None else signoff
    pages = sub.get("review_pages") or {}
    owner_ok = [m for m, r, _ in done if r == "REVIEW" and m in signoff and pages.get(m) == [signoff[m]]]
    review = [m for m, r, _ in done if r == "REVIEW" and m not in owner_ok]
    warned = [f"{m} ({why})" if why else m for m, r, why in done if r == "WARNING"]
    skipped = [f"{m} ({why})" for m, r, why in done if r == "SKIPPED"]
    red = [f"{m} {s}/{r}" + (f" ({why})" if why else "") for m, s, r, why in rows
           if s != "FINISHED" or r not in ("PASSED", "REVIEW", "WARNING", "SKIPPED")]
    head = f"{len(passed) + len(skipped) + len(owner_ok)}/{len(rows)} pass"
    if owner_ok:
        head += f" ({len(owner_ok)} owner-reviewed: " + ", ".join(owner_ok) + ")"
    if review:
        head += f", {len(review)} awaiting review: " + ", ".join(review)
    notes = [head]
    if warned:
        notes.append(f"{len(warned)} warning: " + "; ".join(warned))
    if red:
        notes.append(f"{len(red)} failed: " + "; ".join(red))
    if skipped:
        notes.append("skipped by the suite: " + "; ".join(skipped))
    status = "fail" if (review or warned or red or not rows) else "pass"
    neg = record.get("negative")
    if not neg:
        status = "fail"
        notes.append("the negative control did not run: " + record.get("negative_error", "no result"))
    else:
        # The suite's own FAILED result, whether it finished the module or interrupted it on the
        # failure (a module whose PAR call fails is interrupted with result FAILED).
        got = {m: (s, r) for m, s, r, _ in neg["modules"]}
        wrong = [f"{m} {'/'.join(got.get(m, ('absent', '')))}"
                 for m in NEGATIVE_MUST_FAIL if got.get(m, ("", ""))[1] != "FAILED"]
        if wrong:
            status = "fail"
            notes.append("the negative control (fapi2: false) did not fail where it must: " + "; ".join(wrong))
        else:
            notes.append("negative control (fapi2: false) failed " + ", ".join(NEGATIVE_MUST_FAIL))
    notes.append("control (suite self-test, " + ", ".join(CONTROL_OP_MODULES) + ") passed")
    if review:
        notes.append("each REVIEW module's suite log and screenshots are kept under review/ in this suite's output")
    return status, True, ". ".join(notes)


def keep_review(work, out):
    """Every subject module whose result is not PASSED (REVIEW first among them): its suite log (the
    export's `test-log-<module>-<id>.json` and `.sig`), every image the suite's browser attached
    (decoded to files), and an index naming the module, its test id and its result, under
    `<out>/review/`. These are what a human signs a REVIEW off from."""
    export = os.path.join(work, "subject", "export")
    dest = os.path.join(out, "review")
    shutil.rmtree(dest, ignore_errors=True)
    if not os.path.isdir(export):
        return
    index = []
    try:
        with open(os.path.join(work, "subject", "images.json")) as f:
            shots = json.load(f)
    except (OSError, ValueError):
        shots = {}
    for name in sorted(os.listdir(export)):
        if not name.endswith(".zip"):
            continue
        with zipfile.ZipFile(os.path.join(export, name)) as z:
            for entry in z.namelist():
                if not (entry.startswith("test-log-") and entry.endswith(".json")):
                    continue
                doc = json.loads(z.read(entry))
                info = doc.get("testInfo", {})
                if info.get("result") == "PASSED":
                    continue
                module, test_id = info.get("testName", "?"), info.get("testId", "?")
                d = os.path.join(dest, module)
                os.makedirs(d, exist_ok=True)
                with open(os.path.join(d, os.path.basename(entry)), "wb") as f:
                    f.write(z.read(entry))
                sig = entry[:-5] + ".sig"
                if sig in z.namelist():
                    with open(os.path.join(d, os.path.basename(sig)), "wb") as f:
                        f.write(z.read(sig))
                images = []
                entries = list(doc.get("results") or []) + list(shots.get(test_id) or [])
                for n, e in enumerate(entries):
                    for key, v in e.items():
                        m = re.match(r"data:image/(\w+);base64,(.*)", v, re.S) if isinstance(v, str) else None
                        if m:
                            img = f"screenshot-{n:04d}-{e.get('src', key)}.{m.group(1)}"
                            with open(os.path.join(d, img), "wb") as f:
                                f.write(base64.b64decode(m.group(2)))
                            images.append(img)
                    # The page the suite's browser captured for a REVIEW (HtmlUnit renders no
                    # pixels; this source is what the placeholder was filled from).
                    if e.get("result") == "REVIEW" and isinstance(e.get("page_source"), str):
                        page = f"review-{n:04d}-{e.get('src', 'page')}.html"
                        with open(os.path.join(d, page), "w") as f:
                            f.write(e["page_source"])
                        images.append(page)
                index.append({"module": module, "test_id": test_id, "status": info.get("status"),
                              "result": info.get("result"), "log": os.path.basename(entry),
                              "evidence": images, "plan_export": name,
                              "review": [e.get("msg") for e in doc.get("results") or [] if e.get("result") == "REVIEW"]})
    if index:
        os.makedirs(dest, exist_ok=True)
        with open(os.path.join(dest, "index.json"), "w") as f:
            json.dump(index, f, indent=2)


def main():
    # The driver (testing/conformance/run.sh) runs each suite inside its `while read` over
    # suites.tsv, so this process's stdin IS the rest of the suite list: any child that reads stdin
    # (git, docker) would eat the next suite's line and it would never run. Nothing here reads stdin.
    devnull = os.open(os.devnull, os.O_RDONLY)
    os.dup2(devnull, 0)
    os.close(devnull)
    suite_id = os.environ.get("CONFORMANCE_SUITE", "fapi2")
    out = os.environ.get("CONFORMANCE_OUT") or os.path.join("target", "conformance", suite_id)
    os.makedirs(out, exist_ok=True)
    # One run serves both ids: it lives beside the per-suite dirs the driver made this invocation.
    work = os.path.abspath(os.path.join(os.path.dirname(os.path.abspath(out)), "oidf-run"))
    head = capture(["git", "rev-parse", "HEAD"])[1].strip()
    rec_path = os.path.join(work, "record.json")
    record = None
    if os.path.isfile(rec_path):
        with open(rec_path) as f:
            prior = json.load(f)
        if prior.get("plan") == PLAN and prior.get("head") == head:
            say(f"reusing this invocation's run of {PLAN}")
            record = prior
    if record is None:
        shutil.rmtree(work, ignore_errors=True)
        os.makedirs(work)
        try:
            record = run_all(work)
        except Refused as e:
            record = {"plan": PLAN, "instrument_error" if e.instrument else "subject_error": str(e)}
        record["head"] = head
        with open(rec_path, "w") as f:
            json.dump(record, f, indent=2)
    status, armed, reason = decide(record)
    keep_review(work, out)
    verdict = {
        "suite": suite_id,
        "status": status,
        "armed": armed,
        "standard": STANDARD.get(suite_id, "OpenID Foundation conformance suite"),
        "plan": PLAN,
        "spec_version": f"OIDF conformance-suite {SUITE_TAG} ({SUITE_COMMIT[:12]}); {OP_PLAN} (FAPI 2.0 Security Profile Final)",
        "reason": reason,
    }
    with open(os.path.join(out, "verdict.json"), "w") as f:
        json.dump(verdict, f, indent=2)
        f.write("\n")
    say(f"{suite_id}: {status}: {reason}")
    return 0 if status == "pass" else 1


if __name__ == "__main__":
    sys.exit(main())
