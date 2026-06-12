#!/usr/bin/env python3
"""
clock_fix — orchestration helpers for the NVR clock auto-fix feature.

This module is PURE logic + state + audit. It performs NO network I/O — the
actual ISAPI GET/PUT lives on the device class (devices.HikvisionNVR), which
keeps every authenticated request behind the auth circuit breaker.

What lives here:
  * build_ntp_server_body() / build_time_mode_body() — pure XML builders that
    echo the device's own namespace+version (unit-tested against fixtures).
  * disk-persisted per-device state (keyed by uid = "ip:port"), atomic 0600.
    Load-bearing: the monitor objects are rebuilt every ~5s in the main loop,
    so any in-memory "already attempted / don't retry" flag is destroyed each
    iteration. Persisting to disk is the ONLY thing that makes "never auto-
    retry" real.
  * append-only JSONL audit log of every clock-fix decision and write.

State + audit deliberately live next to the other NetWatch state files (the
project dir) on local fast storage — a fix must not be lost mid-rollout if a
secondary/bulk volume happens to be unavailable.
"""

import json
import os
import time
from pathlib import Path
from datetime import datetime
from xml.sax.saxutils import escape

_HERE = Path(__file__).parent
STATE_PATH = _HERE / 'clock_fix_state.json'
AUDIT_PATH = _HERE / 'clock_fix_audit.jsonl'

# How long after an attempt before this uid may be tried again (single-shot guard).
RETRY_COOLDOWN_SEC = 24 * 3600


# ──────────────────────────────────────────────────────────────────────────
#  PURE XML BUILDERS  (no I/O — unit-tested against captured GET fixtures)
# ──────────────────────────────────────────────────────────────────────────

def _xmlns_attr(ns_uri, version):
    """Reproduce the device's own root attributes. A wrong/missing xmlns is the
    #1 cause of 'statusCode 6 Invalid XML Content', so we echo exactly what the
    device returned on the GET — never a hardcoded namespace."""
    parts = []
    if ns_uri:
        parts.append(f'xmlns="{ns_uri}"')
    if version:
        parts.append(f'version="{version}"')
    return (' ' + ' '.join(parts)) if parts else ''


def build_ntp_server_body(ns_uri, version, slot_id, server, addressing='ipaddress',
                          port=123, interval_min=60):
    """Build the <NTPServer> PUT body for /ISAPI/System/time/ntpServers/<slot_id>.

    addressing: 'ipaddress' -> <ipAddress>, else 'hostname' -> <hostName>.
    interval_min is MINUTES (Hikvision synchronizeInterval unit), not seconds.
    """
    attr = _xmlns_attr(ns_uri, version)
    if addressing == 'hostname':
        addr_el = f'<hostName>{escape(str(server))}</hostName>'
    else:
        addressing = 'ipaddress'
        addr_el = f'<ipAddress>{escape(str(server))}</ipAddress>'
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<NTPServer{attr}>'
        f'<id>{int(slot_id)}</id>'
        f'<addressingFormatType>{addressing}</addressingFormatType>'
        f'{addr_el}'
        f'<portNo>{int(port)}</portNo>'
        f'<synchronizeInterval>{int(interval_min)}</synchronizeInterval>'
        '</NTPServer>'
    )


def build_time_body(ns_uri, version, time_mode, timezone):
    """Build a <Time> PUT body for /ISAPI/System/time with an explicit timeMode
    and timeZone. CRITICAL: NEVER emits a <localTime> element — that would step
    the clock as a direct write, the behaviour the whole feature avoids. Used
    for (a) the NTP flip (mode='NTP'), (b) the timezone/DST fix (mode kept as-is,
    new tz), and (c) the rollback/restore (prior mode + prior tz)."""
    attr = _xmlns_attr(ns_uri, version)
    mode = escape(time_mode) if time_mode else 'NTP'
    tz = escape(timezone) if timezone else ''
    return (
        '<?xml version="1.0" encoding="UTF-8"?>'
        f'<Time{attr}>'
        f'<timeMode>{mode}</timeMode>'
        f'<timeZone>{tz}</timeZone>'
        '</Time>'
    )


def build_time_mode_body(ns_uri, version, timezone):
    """Back-compat shim: flip to NTP, preserve timezone. See build_time_body."""
    return build_time_body(ns_uri, version, 'NTP', timezone)


def strip_dst(timezone):
    """Return the timezone string with any DST clause removed.
    'CST-4:00:00DST01:00:00,M4.1.0/21:00:00,M10.5.0/02:00:00' -> 'CST-4:00:00'.
    Georgia (UTC+4) has no DST, so the bare base is correct. Idempotent."""
    if not timezone:
        return timezone
    i = timezone.find('DST')
    return timezone[:i] if i != -1 else timezone


# ──────────────────────────────────────────────────────────────────────────
#  DISK STATE  (atomic, 0600, keyed by uid "ip:port")
# ──────────────────────────────────────────────────────────────────────────

def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except (FileNotFoundError, json.JSONDecodeError):
        return {}


def save_state(state):
    tmp = str(STATE_PATH) + '.tmp'
    try:
        with open(tmp, 'w') as f:
            json.dump(state, f, indent=2)
        os.replace(tmp, STATE_PATH)
        try:
            os.chmod(STATE_PATH, 0o600)
        except OSError:
            pass
    except OSError as e:
        print(f"[clock_fix] state persist failed: {e}")


def get_uid_state(uid):
    return load_state().get(uid, {})


def update_uid_state(uid, **fields):
    st = load_state()
    cur = st.get(uid, {})
    cur.update(fields)
    st[uid] = cur
    save_state(st)
    return cur


def recently_attempted(uid, now=None):
    """True if this uid was attempted within RETRY_COOLDOWN_SEC — the single-shot
    guard that makes 'never auto-retry' survive the 5s monitor rebuild."""
    now = now if now is not None else time.time()
    last = get_uid_state(uid).get('last_attempt_epoch')
    return last is not None and (now - last) < RETRY_COOLDOWN_SEC


# ──────────────────────────────────────────────────────────────────────────
#  AUDIT LOG  (append-only JSONL)
# ──────────────────────────────────────────────────────────────────────────

def log_event(event):
    """Append one audit record. event is a dict; ts is stamped here."""
    rec = dict(event)
    rec.setdefault('ts', datetime.now().isoformat(timespec='seconds'))
    try:
        with open(AUDIT_PATH, 'a') as f:
            f.write(json.dumps(rec, ensure_ascii=False) + '\n')
        try:
            os.chmod(AUDIT_PATH, 0o600)
        except OSError:
            pass
    except OSError as e:
        print(f"[clock_fix] audit write failed: {e}")


if __name__ == '__main__':
    # Tiny self-test of the pure builders (no I/O, safe to run anywhere).
    b1 = build_ntp_server_body('http://www.std-cgi.com/ver20/XMLSchema', '2.0',
                               1, '10.66.66.1', 'ipaddress', 123, 60)
    b2 = build_time_mode_body('http://www.std-cgi.com/ver20/XMLSchema', '2.0',
                              'CST-4:00:00')
    assert 'localTime' not in b2, 'time body must never contain localTime'
    assert 'std-cgi.com' in b1 and 'std-cgi.com' in b2
    assert '<synchronizeInterval>60</synchronizeInterval>' in b1
    print('clock_fix builders self-test OK')
    print(b1)
    print(b2)
