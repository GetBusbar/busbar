#!/usr/bin/env python3
"""A stub OpenID Connect provider for the auth-plugin functional probe.

The first-party `oidc` auth plugin verifies a caller's bearer token against an issuer's discovery
document + JWKS, then busbar's /auth/token exchange mints a self-scoped busbar key. To exercise that
end to end WITHOUT a real IdP, this fixture is a complete-enough issuer:

  GET /.well-known/openid-configuration  -> discovery pointing jwks_uri back here
  GET /jwks                              -> the RS256 public key as a JWK set
  GET /mint                              -> a freshly signed RS256 id_token for the configured sub
                                            (the probe grabs this and presents it to /auth/token)

A FIXTURE THAT CANNOT SAY NO MAKES THE PROBE VACUOUS (the rule vault-fixture.py and mock-upstream.py
already state, and this one used to break). This issuer served exactly ONE token and it was always
valid, so every credential the probe could present was a credential that SHOULD be accepted — and a
plugin that never fetched the JWKS at all, never checked `exp`, never checked `aud`, and minted a
busbar key for anything with a bearer header, passed probe-auth.sh byte-for-byte. The positive
control alone cannot tell "verified the token" from "waved it through".

So the issuer also mints tokens that MUST be refused, one per property the plugin is supposed to
check, each wrong in exactly one way and correct in every other:

  GET /mint/bad-signature   same header (same kid) and same claims, signed with a SECOND keypair
                            whose public half is NOT in /jwks -> only signature verification refuses
  GET /mint/expired         iat/exp an hour in the past -> only expiry checking refuses
  GET /mint/wrong-audience  aud = a different audience -> only audience checking refuses

The fourth arm needs no endpoint: presenting NO credential at all.

Any other path is 404 — a fixture that answered an unknown /mint/<typo> with a valid token would let
a probe arm silently degrade into the positive control it is supposed to contrast with.

RS256 signing is done by shelling out to `openssl` (present on every GitHub-hosted runner and on
macOS), so the fixture needs no Python crypto package — it stays dependency-free and self-contained,
which is the rule for fleet fixtures. The keypairs are generated once at startup into a temp dir.

Usage: stub-idp.py <port> <self-base-url> <issuer> <audience> <sub> <group-claim-name> <group-value>
"""
import base64
import http.server
import json
import subprocess
import sys
import tempfile
import time
import os

PORT = int(sys.argv[1])
SELF = sys.argv[2].rstrip("/")
ISSUER = sys.argv[3]
AUDIENCE = sys.argv[4]
SUB = sys.argv[5]
GROUP_CLAIM = sys.argv[6]
GROUP_VALUE = sys.argv[7]

TMP = tempfile.mkdtemp(prefix="stub-idp-")
PRIV = os.path.join(TMP, "priv.pem")
# The IMPOSTOR key. Its public half is deliberately never published in /jwks, so a token signed with
# it is well-formed, correctly `kid`-labelled, unexpired and correctly audienced — and verifiable by
# nobody. That is the point: it isolates signature verification from every other check.
PRIV_BAD = os.path.join(TMP, "priv-impostor.pem")
KID = "stub-idp-key-1"

# The arms this issuer can mint, and how each one is wrong. Exactly one property is broken per arm.
MINT_ARMS = ("ok", "bad-signature", "expired", "wrong-audience")


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def gen_key():
    # 2048-bit RSA; traditional PEM so `openssl dgst -sign` reads it directly.
    for path in (PRIV, PRIV_BAD):
        subprocess.run(
            ["openssl", "genrsa", "-out", path, "2048"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def public_numbers():
    # -text prints modulus + publicExponent; parse them into the (n, e) a JWK needs.
    out = subprocess.run(
        ["openssl", "rsa", "-in", PRIV, "-noout", "-modulus"],
        check=True, capture_output=True, text=True,
    ).stdout
    modulus_hex = out.strip().split("=", 1)[1]
    n = bytes.fromhex(modulus_hex)
    # Standard RSA public exponent 65537.
    e = (65537).to_bytes(3, "big")
    return n, e


def jwks():
    # ONLY the real key. Publishing the impostor here would make /mint/bad-signature verifiable and
    # turn that whole arm into a second positive control.
    n, e = public_numbers()
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                      "n": b64url(n), "e": b64url(e)}]}


def sign_jwt(arm="ok"):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    payload = {
        "iss": ISSUER, "aud": AUDIENCE, "sub": SUB,
        "iat": now, "exp": now + 3600, GROUP_CLAIM: [GROUP_VALUE],
    }
    key = PRIV
    if arm == "bad-signature":
        key = PRIV_BAD
    elif arm == "expired":
        # Already expired when it is handed out, and issued before that: a plugin that checks `exp`
        # (or `iat` skew) refuses it, and nothing else about it is wrong.
        payload["iat"] = now - 7200
        payload["exp"] = now - 3600
    elif arm == "wrong-audience":
        payload["aud"] = AUDIENCE + "-not-this-one"
    signing_input = (
        b64url(json.dumps(header, separators=(",", ":")).encode())
        + "."
        + b64url(json.dumps(payload, separators=(",", ":")).encode())
    )
    proc = subprocess.run(
        ["openssl", "dgst", "-sha256", "-sign", key],
        input=signing_input.encode(), capture_output=True, check=True,
    )
    return signing_input + "." + b64url(proc.stdout)


class Handler(http.server.BaseHTTPRequestHandler):
    def _json(self, obj):
        body = json.dumps(obj).encode()
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _text(self, text):
        body = text.encode()
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path.startswith("/.well-known/openid-configuration"):
            self._json({
                "issuer": ISSUER,
                "jwks_uri": SELF + "/jwks",
                "authorization_endpoint": SELF + "/authorize",
                "token_endpoint": SELF + "/token",
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        elif self.path.startswith("/jwks"):
            self._json(jwks())
        elif self.path == "/mint" or self.path.startswith("/mint?"):
            self._text(sign_jwt("ok"))
        elif self.path.split("?", 1)[0].startswith("/mint/"):
            # EXACT arm names only. A prefix match, or a fallback to the happy path, would answer
            # /mint/expierd with a VALID token and the probe would then record "expired refused"
            # about a token that was never expired.
            arm = self.path.split("?", 1)[0][len("/mint/"):]
            if arm in MINT_ARMS:
                self._text(sign_jwt(arm))
            else:
                self.send_response(404)
                self.send_header("Content-Length", "0")
                self.end_headers()
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *_a):
        pass


if __name__ == "__main__":
    gen_key()
    http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler).serve_forever()
