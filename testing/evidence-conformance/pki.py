# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""RSA, X.509 and JWT minting in plain Python, for the evidence rigs.

The rigs need a throwaway PKI (a CA, a server leaf, client leaves from that CA and from a rogue CA)
and RS256-signed JWTs from an issuer of their own. Python's standard library verifies certificates
but cannot make them, and the rig keeps no host openssl or third-party wheel, so this writes them
from the standards directly: RSA (RFC 8017: key generation, RSASSA-PKCS1-v1_5 with SHA-256), the
DER subset X.509 v3 needs (RFC 5280), and JWS compact serialization (RFC 7515). Nothing here is
busbar's code; everything it makes is checked by someone else's verifier (Python's OpenSSL, rustls'
webpki, the OIDC module), never by this file.
"""
import base64
import datetime
import hashlib
import json
import secrets

# ── RSA ─────────────────────────────────────────────────────────────────────────────────────────────
_SMALL = [p for p in range(3, 2000, 2) if all(p % q for q in range(3, int(p ** 0.5) + 1, 2))]


def _probable_prime(n):
    if n < 2:
        return False
    for p in _SMALL:
        if n % p == 0:
            return n == p
    d, s = n - 1, 0
    while d % 2 == 0:
        d //= 2
        s += 1
    for _ in range(40):
        a = secrets.randbelow(n - 3) + 2
        x = pow(a, d, n)
        if x in (1, n - 1):
            continue
        for _ in range(s - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(bits):
    while True:
        c = secrets.randbits(bits) | (1 << (bits - 1)) | (1 << (bits - 2)) | 1
        if c % 65537 != 1 and _probable_prime(c):
            return c


class RsaKey:
    def __init__(self, bits=2048):
        e = 65537
        while True:
            p, q = _prime(bits // 2), _prime(bits // 2)
            n = p * q
            if p != q and n.bit_length() == bits:
                break
        self.n, self.e, self.p, self.q = n, e, p, q
        self.d = pow(e, -1, (p - 1) * (q - 1))

    def sign(self, msg):
        """RSASSA-PKCS1-v1_5 over SHA-256 (RFC 8017 section 8.2)."""
        k = (self.n.bit_length() + 7) // 8
        t = bytes.fromhex("3031300d060960864801650304020105000420") + hashlib.sha256(msg).digest()
        em = b"\x00\x01" + b"\xff" * (k - len(t) - 3) + b"\x00" + t
        return pow(int.from_bytes(em, "big"), self.d, self.n).to_bytes(k, "big")

    def public_der(self):
        return seq(integer(self.n), integer(self.e))

    def spki(self):
        return seq(seq(oid("1.2.840.113549.1.1.1"), b"\x05\x00"), bitstring(self.public_der()))

    def private_pem(self):
        p, q, d = self.p, self.q, self.d
        der = seq(integer(0), integer(self.n), integer(self.e), integer(d), integer(p), integer(q),
                  integer(d % (p - 1)), integer(d % (q - 1)), integer(pow(q, -1, p)))
        return pem("RSA PRIVATE KEY", der)

    def jwk(self, kid):
        def b(i):
            return b64url(i.to_bytes((i.bit_length() + 7) // 8, "big"))
        return {"kty": "RSA", "kid": kid, "alg": "RS256", "use": "sig", "n": b(self.n), "e": b(self.e)}


# ── DER ─────────────────────────────────────────────────────────────────────────────────────────────
def tlv(tag, body):
    n = len(body)
    if n < 0x80:
        ln = bytes([n])
    else:
        lb = n.to_bytes((n.bit_length() + 7) // 8, "big")
        ln = bytes([0x80 | len(lb)]) + lb
    return bytes([tag]) + ln + body


def seq(*parts):
    return tlv(0x30, b"".join(parts))


def set_of(*parts):
    return tlv(0x31, b"".join(parts))


def integer(i):
    b = i.to_bytes((i.bit_length() + 8) // 8 or 1, "big")
    return tlv(0x02, b)


def oid(dotted):
    a = [int(x) for x in dotted.split(".")]
    out = bytes([40 * a[0] + a[1]])
    for v in a[2:]:
        chunk = [v & 0x7F]
        v >>= 7
        while v:
            chunk.insert(0, 0x80 | (v & 0x7F))
            v >>= 7
        out += bytes(chunk)
    return tlv(0x06, out)


def bitstring(b):
    return tlv(0x03, b"\x00" + b)


def octets(b):
    return tlv(0x04, b)


def utf8(s):
    return tlv(0x0C, s.encode())


def boolean(v):
    return tlv(0x01, b"\xff" if v else b"\x00")


def _time(t):
    return tlv(0x17, t.strftime("%y%m%d%H%M%SZ").encode())


def pem(label, der):
    b = base64.b64encode(der).decode()
    return f"-----BEGIN {label}-----\n" + "\n".join(b[i:i + 64] for i in range(0, len(b), 64)) + f"\n-----END {label}-----\n"


def b64url(b):
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


# ── X.509 ───────────────────────────────────────────────────────────────────────────────────────────
SHA256_RSA = seq(oid("1.2.840.113549.1.1.11"), b"\x05\x00")


def _name(cn):
    return seq(set_of(seq(oid("2.5.4.3"), utf8(cn))))


def _ext(dotted, critical, value):
    return seq(oid(dotted), *( [boolean(True)] if critical else []), octets(value))


class Cert:
    """A certificate and its key. `issuer` None = self-signed (a CA)."""

    def __init__(self, cn, *, issuer=None, ca=False, server=False, client=False, dns=(), ips=()):
        self.key = RsaKey()
        self.cn = cn
        now = datetime.datetime.now(datetime.timezone.utc)
        exts = [_ext("2.5.29.19", True, seq(boolean(True)) if ca else seq())]
        exts.append(_ext("2.5.29.15", True, bitstring(b"\x06") if ca else bitstring(b"\xa0")))
        eku = ([oid("1.3.6.1.5.5.7.3.1")] if server else []) + ([oid("1.3.6.1.5.5.7.3.2")] if client else [])
        if eku:
            exts.append(_ext("2.5.29.37", False, seq(*eku)))
        alt = [tlv(0x82, d.encode()) for d in dns] + [tlv(0x87, bytes(int(x) for x in ip.split("."))) for ip in ips]
        if alt:
            exts.append(_ext("2.5.29.17", False, seq(*alt)))
        exts.append(_ext("2.5.29.14", False, octets(hashlib.sha1(self.key.public_der()).digest())))
        signer = issuer or self
        if issuer is not None:
            exts.append(_ext("2.5.29.35", False, seq(tlv(0x80, hashlib.sha1(issuer.key.public_der()).digest()))))
        tbs = seq(
            tlv(0xA0, integer(2)),
            integer(secrets.randbits(120) | (1 << 119)),
            SHA256_RSA,
            _name(signer.cn),
            seq(_time(now - datetime.timedelta(days=1)), _time(now + datetime.timedelta(days=30))),
            _name(cn),
            self.key.spki(),
            tlv(0xA3, seq(*exts)),
        )
        self.der = seq(tbs, SHA256_RSA, bitstring(signer.key.sign(tbs)))
        self.issuer = issuer

    def pem(self):
        return pem("CERTIFICATE", self.der)

    def chain_pem(self):
        out, c = "", self
        while c is not None:
            out += c.pem()
            c = c.issuer
        return out

    def write(self, directory, name, chain=False):
        """`<name>.pem` (the certificate, or leaf-first chain) and `<name>.key`; their paths."""
        import os
        crt, key = os.path.join(directory, f"{name}.pem"), os.path.join(directory, f"{name}.key")
        with open(crt, "w") as f:
            f.write(self.chain_pem() if chain else self.pem())
        with open(key, "w") as f:
            f.write(self.key.private_pem())
        return crt, key


# ── JWT ─────────────────────────────────────────────────────────────────────────────────────────────
def jwt(key, kid, claims):
    head = b64url(json.dumps({"alg": "RS256", "typ": "JWT", "kid": kid}, separators=(",", ":")).encode())
    body = b64url(json.dumps(claims, separators=(",", ":")).encode())
    sig = key.sign(f"{head}.{body}".encode())
    return f"{head}.{body}.{b64url(sig)}"
