"""Licence record signing, verification, and encrypted local cache — pure
functions with no app-config dependency, so both config.py (which reads the
cache to seed identity) and the licensing service (which refreshes it) can use
them without an import cycle.

A licence is a JSON object. Its signature covers the canonical serialisation of
every field except "signature" itself, so the two sides must agree only on that
canonical form (sorted keys, compact separators, UTF-8) — documented in
docs/NETWATCH_INTEGRATION.md.
"""
from __future__ import annotations

import json
from pathlib import Path

from . import aead, ed25519


def canonical(record: dict) -> bytes:
    """The exact bytes that get signed: the record minus its signature,
    JSON with sorted keys and no whitespace, UTF-8."""
    body = {k: v for k, v in record.items() if k != "signature"}
    return json.dumps(body, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=False).encode("utf-8")


def sign_record(record: dict, seed_hex: str, pubkey_hex: str) -> dict:
    """Return a copy of `record` with a hex Ed25519 signature attached.
    (Used by NetWatch and by tests; the private seed never lives in Haven.)"""
    seed = bytes.fromhex(seed_hex)
    pub = bytes.fromhex(pubkey_hex)
    sig = ed25519.sign(canonical(record), seed, pub)
    out = dict(record)
    out["signature"] = sig.hex()
    return out


def verify_signed(record: dict, pubkey_hex: str) -> bool:
    """True iff `record` carries a valid signature by `pubkey_hex`.
    Unsigned or mismatched → False."""
    sig_hex = record.get("signature")
    if not sig_hex:
        return False
    try:
        sig = bytes.fromhex(sig_hex)
        pub = bytes.fromhex(pubkey_hex)
    except ValueError:
        return False
    return ed25519.verify(canonical(record), sig, pub)


def write_cache(path: str | Path, record: dict, key: bytes) -> None:
    token = aead.encrypt(json.dumps(record).encode("utf-8"), key)
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    tmp = p.with_suffix(p.suffix + ".tmp")
    tmp.write_bytes(token)
    tmp.replace(p)   # atomic


def read_cache(path: str | Path, key: bytes) -> dict | None:
    p = Path(path)
    if not p.exists():
        return None
    data = aead.decrypt(p.read_bytes(), key)
    if data is None:
        return None
    try:
        return json.loads(data)
    except Exception:
        return None
