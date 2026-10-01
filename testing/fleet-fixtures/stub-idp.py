#!/usr/bin/env python3
"""A stub OpenID Connect provider for the auth-plugin functional probe.

The first-party `oidc` auth plugin verifies a caller's bearer token against an issuer's discovery
document + JWKS, then busbar's /auth/token exchange mints a self-scoped busbar key. To exercise that
end to end WITHOUT a real IdP, this fixture is a complete-enough issuer:

  GET /.well-known/openid-configuration  -> discovery pointing jwks_uri back here
  GET /jwks                              -> the RS256 public key as a JWK set
  GET /mint                              -> a freshly signed RS256 id_token for the configured sub
                                            (the probe grabs this and presents it to /auth/token)
  GET /mint/bad-signature                -> the same claims signed by a key that is NOT in the JWKS
  GET /mint/expired                      -> a correctly signed token whose exp is in the past
  GET /mint/wrong-audience               -> a correctly signed token for a different audience

Paths match exactly (query string ignored); any other path is a 404. The three bad tokens are the
probe's positive control: a verifier that accepts them is not verifying.

RS256 signing is done by shelling out to `openssl` (present on every GitHub-hosted runner and on
macOS), so the fixture needs no Python crypto package — it stays dependency-free and self-contained,
which is the rule for fleet fixtures. The keypair is generated once at startup into a temp dir.

The server speaks HTTPS: the auth-oidc plugin fetches discovery and the JWKS https-only. It presents a
throwaway self-signed certificate for 127.0.0.1, written to <cert-out> as PEM for the plugin's
`ca_cert_pem` setting.

Usage: stub-idp.py <port> <self-base-url> <issuer> <audience> <sub> <group-claim-name> <group-value> <cert-out>
"""
import base64
import http.server
import json
import subprocess
import sys
import tempfile
import time
import os
import ssl

PORT = int(sys.argv[1])
SELF = sys.argv[2].rstrip("/")
ISSUER = sys.argv[3]
AUDIENCE = sys.argv[4]
SUB = sys.argv[5]
GROUP_CLAIM = sys.argv[6]
GROUP_VALUE = sys.argv[7]
CERT_OUT = sys.argv[8]

TMP = tempfile.mkdtemp(prefix="stub-idp-")
PRIV = os.path.join(TMP, "priv.pem")
WRONG_PRIV = os.path.join(TMP, "wrong.pem")  # signs /mint/bad-signature; never published in the JWKS
KID = "stub-idp-key-1"


def b64url(raw: bytes) -> str:
    return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()


def gen_key():
    # 2048-bit RSA; traditional PEM so `openssl dgst -sign` reads it directly.
    for path in (PRIV, WRONG_PRIV):
        subprocess.run(
            ["openssl", "genrsa", "-out", path, "2048"],
            check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )


def gen_cert():
    key = os.path.join(TMP, "tls.key")
    subprocess.run(
        ["openssl", "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-keyout", key, "-out", CERT_OUT,
         "-days", "2", "-subj", "/CN=127.0.0.1", "-addext", "subjectAltName=IP:127.0.0.1"],
        check=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
    )
    return key


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
    n, e = public_numbers()
    return {"keys": [{"kty": "RSA", "use": "sig", "alg": "RS256", "kid": KID,
                      "n": b64url(n), "e": b64url(e)}]}


def sign_jwt(key=PRIV, aud=None, exp_offset=3600):
    now = int(time.time())
    header = {"alg": "RS256", "typ": "JWT", "kid": KID}
    payload = {
        "iss": ISSUER, "aud": aud or AUDIENCE, "sub": SUB,
        "iat": now, "exp": now + exp_offset, GROUP_CLAIM: [GROUP_VALUE],
    }
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
        path = self.path.split("?", 1)[0]
        if path == "/.well-known/openid-configuration":
            self._json({
                "issuer": ISSUER,
                "jwks_uri": SELF + "/jwks",
                "authorization_endpoint": SELF + "/authorize",
                "token_endpoint": SELF + "/token",
                "response_types_supported": ["id_token"],
                "subject_types_supported": ["public"],
                "id_token_signing_alg_values_supported": ["RS256"],
            })
        elif path == "/jwks":
            self._json(jwks())
        elif path == "/mint":
            self._text(sign_jwt())
        elif path == "/mint/bad-signature":
            self._text(sign_jwt(key=WRONG_PRIV))
        elif path == "/mint/expired":
            self._text(sign_jwt(exp_offset=-3600))
        elif path == "/mint/wrong-audience":
            self._text(sign_jwt(aud=AUDIENCE + "-other"))
        else:
            self.send_response(404)
            self.send_header("Content-Length", "0")
            self.end_headers()

    def log_message(self, *_a):
        pass


if __name__ == "__main__":
    gen_key()
    tls_key = gen_cert()
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.load_cert_chain(CERT_OUT, tls_key)
    server = http.server.ThreadingHTTPServer(("127.0.0.1", PORT), Handler)
    server.socket = ctx.wrap_socket(server.socket, server_side=True)
    server.serve_forever()
