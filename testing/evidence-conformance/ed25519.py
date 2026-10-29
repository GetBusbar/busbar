# SPDX-License-Identifier: Apache-2.0
# Copyright (C) 2026 Busbar Inc and contributors
"""Ed25519 (RFC 8032) in plain Python, for the evidence rigs' INDEPENDENT audit-chain verifier.

Written from RFC 8032 section 5.1 alone: it shares no code, no library and no constant with busbar
(which signs with ed25519-dalek), so a chain this accepts is accepted on the RFC's terms, not on
busbar's word. `verify` is the STRICT rule docs/audit-chain-digest-v4.md section 4 publishes (what
dalek's `verify_strict` applies): canonical point encodings, canonical S (S < L), a small-order public
key or R refused, and the cofactorless equation [S]B = R + [k]A. `sign` exists only so the rig can
seal a known-good chain of its own (the control leg) and test it against RFC 8032's own vectors.
Slow and not constant-time: a verifier of public data, never a key holder in production.
"""
import hashlib

P = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493
D = (-121665 * pow(121666, P - 2, P)) % P
I = pow(2, (P - 1) // 4, P)  # sqrt(-1)


def _inv(x):
    return pow(x, P - 2, P)


def _xrecover(y, sign):
    if y >= P:
        return None
    x2 = (y * y - 1) * _inv(D * y * y + 1) % P
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (P + 3) // 8, P)
    if (x * x - x2) % P != 0:
        x = x * I % P
    if (x * x - x2) % P != 0:
        return None
    if x & 1 != sign:
        x = P - x
    return x


# Extended coordinates (X, Y, Z, T), x = X/Z, y = Y/Z, xy = T/Z.
def _add(p, q):
    a = (p[1] - p[0]) * (q[1] - q[0]) % P
    b = (p[1] + p[0]) * (q[1] + q[0]) % P
    c = 2 * p[3] * q[3] * D % P
    d = 2 * p[2] * q[2] % P
    e, f, g, h = b - a, d - c, d + c, b + a
    return (e * f % P, g * h % P, f * g % P, e * h % P)


def _mul(s, p):
    q = (0, 1, 1, 0)
    while s > 0:
        if s & 1:
            q = _add(q, p)
        p = _add(p, p)
        s >>= 1
    return q


def _encode(p):
    zi = _inv(p[2])
    x, y = p[0] * zi % P, p[1] * zi % P
    return (y | ((x & 1) << 255)).to_bytes(32, "little")


def _decode(b):
    """A point from its 32-byte encoding, or None for a non-canonical or off-curve one."""
    if len(b) != 32:
        return None
    n = int.from_bytes(b, "little")
    y, sign = n & ((1 << 255) - 1), n >> 255
    x = _xrecover(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % P)


_BY = 4 * _inv(5) % P
B = (_xrecover(_BY, 0), _BY, 1, _xrecover(_BY, 0) * _BY % P)
_IDENTITY = _encode((0, 1, 1, 0))


def _small_order(pt):
    return _encode(_mul(8, pt)) == _IDENTITY


def _h(*parts):
    return int.from_bytes(hashlib.sha512(b"".join(parts)).digest(), "little")


def public_key(seed):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    return _encode(_mul(a, B))


def sign(seed, msg):
    h = hashlib.sha512(seed).digest()
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8
    a |= 1 << 254
    pk = _encode(_mul(a, B))
    r = _h(h[32:], msg) % L
    rb = _encode(_mul(r, B))
    s = (r + _h(rb, pk, msg) * a) % L
    return rb + s.to_bytes(32, "little")


def verify_strict(pk, msg, sig):
    """True only when `sig` is a strict RFC 8032 signature by `pk` over `msg`."""
    if len(pk) != 32 or len(sig) != 64:
        return False
    a = _decode(pk)
    r = _decode(sig[:32])
    if a is None or r is None:
        return False
    if _encode(a) != pk or _encode(r) != sig[:32]:
        return False
    if _small_order(a) or _small_order(r):
        return False
    s = int.from_bytes(sig[32:], "little")
    if s >= L:
        return False
    k = _h(sig[:32], pk, msg) % L
    neg_a = ((P - a[0]) % P, a[1], a[2], (P - a[3]) % P)
    return _encode(_add(_mul(s, B), _mul(k, neg_a))) == sig[:32]
