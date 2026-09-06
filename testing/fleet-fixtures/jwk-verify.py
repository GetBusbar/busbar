#!/usr/bin/env python3
"""Verify a JWT's RS256 signature against a JWK set — the fixture selftest's own oracle.

WHY THIS EXISTS. fixture-selftest.sh has to prove that stub-idp.py's /mint/bad-signature really is
unverifiable, and "unverifiable" is not something you can assert by looking at the token: a token
signed by the WRONG key and a token signed by the right one are byte-shaped identically. Comparing
the bad arm's bytes against the good arm's is not the check either — two mints a second apart have
different `iat`, so they differ whatever key signed them, and the comparison would pass on a fixture
that signed both with the same key.

So the selftest does the real thing: rebuild the RSA public key from the `n`/`e` the fixture
PUBLISHES at /jwks, and ask openssl whether the signature verifies under it. That is exactly the
question an OIDC plugin asks, which is the point — the fixture's refusal arms are only meaningful if
the property they claim is the property a verifier would actually test.

Stdlib + openssl only, like every other fixture here: the JWK's (n, e) are DER-encoded into a
SubjectPublicKeyInfo by hand and handed to `openssl dgst -verify`. No crypto package.

Usage: jwk-verify.py <jwks-json-file> <jwt>
  exit 0  signature verifies against a key in the set; prints the decoded payload JSON on stdout
  exit 1  signature does NOT verify (prints the payload anyway, so a caller can still assert claims)
  exit 2  the token is not a well-formed three-part JWT, or the JWKS has no usable RSA key
"""
import base64
import json
import subprocess
import sys
import tempfile
import os


def b64url_decode(s: str) -> bytes:
    return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))


def der_len(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def der_tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + der_len(len(body)) + body


def der_int(raw: bytes) -> bytes:
    # DER INTEGERs are signed: a leading bit of 1 needs a 0x00 pad or the value reads as negative.
    raw = raw.lstrip(b"\x00") or b"\x00"
    if raw[0] & 0x80:
        raw = b"\x00" + raw
    return der_tlv(0x02, raw)


# AlgorithmIdentifier for rsaEncryption (1.2.840.113549.1.1.1) with the explicit NULL parameters
# every RSA SPKI carries. Fixed bytes: there is exactly one correct encoding.
RSA_ALG_ID = bytes.fromhex("300d06092a864886f70d010101" + "0500")


def spki_pem(n: bytes, e: bytes) -> bytes:
    pubkey = der_tlv(0x30, der_int(n) + der_int(e))
    spki = der_tlv(0x30, RSA_ALG_ID + der_tlv(0x03, b"\x00" + pubkey))
    b64 = base64.b64encode(spki).decode()
    lines = "\n".join(b64[i:i + 64] for i in range(0, len(b64), 64))
    return f"-----BEGIN PUBLIC KEY-----\n{lines}\n-----END PUBLIC KEY-----\n".encode()


def main() -> int:
    jwks = json.load(open(sys.argv[1]))
    token = sys.argv[2].strip()
    parts = token.split(".")
    if len(parts) != 3:
        sys.stderr.write(f"not a three-part JWT ({len(parts)} parts)\n")
        return 2
    header = json.loads(b64url_decode(parts[0]))
    payload_raw = b64url_decode(parts[1])
    print(payload_raw.decode())
    sig = b64url_decode(parts[2])
    signing_input = (parts[0] + "." + parts[1]).encode()

    # Match on kid when the header names one — a verifier that tried every key in the set would
    # accept a token whose kid points at a key that is not the one that signed it.
    keys = [k for k in jwks.get("keys", []) if k.get("kty") == "RSA"]
    if header.get("kid"):
        keys = [k for k in keys if k.get("kid") == header["kid"]] or keys
    if not keys:
        sys.stderr.write("the JWK set has no RSA key to verify against\n")
        return 2

    tmp = tempfile.mkdtemp(prefix="jwk-verify-")
    pub, sigf, msgf = (os.path.join(tmp, n) for n in ("pub.pem", "sig.bin", "msg.bin"))
    open(sigf, "wb").write(sig)
    open(msgf, "wb").write(signing_input)
    for k in keys:
        open(pub, "wb").write(spki_pem(b64url_decode(k["n"]), b64url_decode(k["e"])))
        rc = subprocess.run(
            ["openssl", "dgst", "-sha256", "-verify", pub, "-signature", sigf, msgf],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        ).returncode
        if rc == 0:
            return 0
    return 1


if __name__ == "__main__":
    sys.exit(main())
