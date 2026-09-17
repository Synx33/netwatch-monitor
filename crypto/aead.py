"""Authenticated encryption for data at rest, standard-library only.

Encrypt-then-MAC: a SHA-256 counter-mode keystream for confidentiality and
HMAC-SHA256 over (nonce || ciphertext) for integrity. Not a NIST primitive, but
an honest, well-understood construction adequate for a locally cached licence
blob keyed to the install's own secret. The key is the install secret (see
config.get_secret_key), so a cache file copied to another machine is useless.

    token = encrypt(plaintext, key)     # bytes
    data  = decrypt(token, key)         # bytes, or None if tampered/wrong key
"""
from __future__ import annotations

import hashlib
import hmac
import os

_NONCE = 16
_TAG = 32


def _keystream(key: bytes, nonce: bytes, n: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < n:
        out += hashlib.sha256(key + nonce + counter.to_bytes(8, "big")).digest()
        counter += 1
    return bytes(out[:n])


def encrypt(plaintext: bytes, key: bytes) -> bytes:
    key = hashlib.sha256(key).digest()          # normalise to 32 bytes
    nonce = os.urandom(_NONCE)
    ks = _keystream(key, nonce, len(plaintext))
    ct = bytes(a ^ b for a, b in zip(plaintext, ks))
    tag = hmac.new(key, nonce + ct, hashlib.sha256).digest()
    return nonce + tag + ct


def decrypt(token: bytes, key: bytes) -> bytes | None:
    try:
        key = hashlib.sha256(key).digest()
        if len(token) < _NONCE + _TAG:
            return None
        nonce, tag, ct = token[:_NONCE], token[_NONCE:_NONCE + _TAG], token[_NONCE + _TAG:]
        expect = hmac.new(key, nonce + ct, hashlib.sha256).digest()
        if not hmac.compare_digest(tag, expect):
            return None
        ks = _keystream(key, nonce, len(ct))
        return bytes(a ^ b for a, b in zip(ct, ks))
    except Exception:
        return None
