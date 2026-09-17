"""Pure-Python Ed25519 (RFC 8032) — signing and verification with nothing but
the standard library. Vendored identically in Haven and NetWatch so the two
sides never disagree on the scheme and neither grows a native-crypto
dependency.

The point arithmetic is the RFC 8032 Appendix A reference construction
(extended homogeneous coordinates), which is byte-for-byte interoperable with
OpenSSL / libsodium and validated below against the RFC test vectors. It is not
tuned for speed — a verify is a few milliseconds, irrelevant on the daily
licence-refresh path and never on a request path. Do not use it for
high-volume signing.

    pk, sk = keypair()                # sk is the 32-byte seed
    sig = sign(message, sk, pk)       # 64-byte signature (pk optional)
    verify(message, sig, pk)          # -> bool, never raises
"""
from __future__ import annotations

import hashlib
import os

# ── field / group constants ─────────────────────────────────────────────────
p = 2 ** 255 - 19
L = 2 ** 252 + 27742317777372353535851937790883648493


def _sha512(s: bytes) -> bytes:
    return hashlib.sha512(s).digest()


def _sha512_modq(s: bytes) -> int:
    return int.from_bytes(_sha512(s), "little") % L


def _modp_inv(x: int) -> int:
    return pow(x, p - 2, p)


d = -121665 * _modp_inv(121666) % p
_modp_sqrt_m1 = pow(2, (p - 1) // 4, p)


def _recover_x(y: int, sign: int):
    if y >= p:
        return None
    x2 = (y * y - 1) * _modp_inv(d * y * y + 1) % p
    if x2 == 0:
        return None if sign else 0
    x = pow(x2, (p + 3) // 8, p)
    if (x * x - x2) % p != 0:
        x = x * _modp_sqrt_m1 % p
    if (x * x - x2) % p != 0:
        return None
    if (x & 1) != sign:
        x = p - x
    return x


# base point
_g_y = 4 * _modp_inv(5) % p
_g_x = _recover_x(_g_y, 0)
G = (_g_x, _g_y, 1, _g_x * _g_y % p)  # extended coords (X, Y, Z, T)


def _point_add(P, Q):
    A = (P[1] - P[0]) * (Q[1] - Q[0]) % p
    B = (P[1] + P[0]) * (Q[1] + Q[0]) % p
    C = 2 * P[3] * Q[3] * d % p
    D = 2 * P[2] * Q[2] % p
    E, F, Gg, H = B - A, D - C, D + C, B + A
    return (E * F % p, Gg * H % p, F * Gg % p, E * H % p)


def _point_mul(s: int, P):
    Q = (0, 1, 1, 0)  # neutral element
    while s > 0:
        if s & 1:
            Q = _point_add(Q, P)
        P = _point_add(P, P)
        s >>= 1
    return Q


def _point_equal(P, Q) -> bool:
    if (P[0] * Q[2] - Q[0] * P[2]) % p != 0:
        return False
    if (P[1] * Q[2] - Q[1] * P[2]) % p != 0:
        return False
    return True


def _point_compress(P) -> bytes:
    zinv = _modp_inv(P[2])
    x = P[0] * zinv % p
    y = P[1] * zinv % p
    return int.to_bytes(y | ((x & 1) << 255), 32, "little")


def _point_decompress(s: bytes):
    if len(s) != 32:
        return None
    y = int.from_bytes(s, "little")
    sign = y >> 255
    y &= (1 << 255) - 1
    x = _recover_x(y, sign)
    if x is None:
        return None
    return (x, y, 1, x * y % p)


def _secret_expand(secret: bytes):
    if len(secret) != 32:
        raise ValueError("secret seed must be 32 bytes")
    h = _sha512(secret)
    a = int.from_bytes(h[:32], "little")
    a &= (1 << 254) - 8      # clear the low 3 bits and everything at/above bit 254
    a |= (1 << 254)          # set bit 254
    return a, h[32:]


# ── public API ──────────────────────────────────────────────────────────────
def publickey(sk: bytes) -> bytes:
    """Public key (32 bytes) from a 32-byte secret seed."""
    a, _ = _secret_expand(sk)
    return _point_compress(_point_mul(a, G))


def keypair() -> tuple[bytes, bytes]:
    """(public_key, secret_seed), both 32 bytes."""
    sk = os.urandom(32)
    return publickey(sk), sk


def sign(message: bytes, sk: bytes, pk: bytes | None = None) -> bytes:
    """64-byte signature of `message` under 32-byte secret seed `sk`."""
    a, prefix = _secret_expand(sk)
    A = pk if pk is not None else _point_compress(_point_mul(a, G))
    r = _sha512_modq(prefix + message)
    R = _point_mul(r, G)
    Rs = _point_compress(R)
    h = _sha512_modq(Rs + A + message)
    s = (r + h * a) % L
    return Rs + int.to_bytes(s, 32, "little")


def verify(message: bytes, signature: bytes, pk: bytes) -> bool:
    """True iff `signature` is a valid Ed25519 signature of `message` by `pk`.
    Never raises — malformed input is simply an invalid signature."""
    try:
        if len(signature) != 64 or len(pk) != 32:
            return False
        A = _point_decompress(pk)
        if A is None:
            return False
        Rs = signature[:32]
        R = _point_decompress(Rs)
        if R is None:
            return False
        s = int.from_bytes(signature[32:], "little")
        if s >= L:
            return False
        h = _sha512_modq(Rs + pk + message)
        sB = _point_mul(s, G)
        hA = _point_mul(h, A)
        return _point_equal(sB, _point_add(R, hA))
    except Exception:
        return False
