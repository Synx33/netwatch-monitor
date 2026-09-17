"""Licence issuing service for Haven PMS sites.

Licences are stored as plain JSON (licenses.json) — the raw, unsigned property
fields, one entry per site_id — consistent with the rest of NetWatch's JSON
state. The Ed25519 signature is applied at serve time by GET /api/v1/license/
so any dashboard edit is re-signed automatically.

SECURITY: the private signing key lives ONLY on this NetWatch server, at
LICENSE_SEED_PATH (default ~/.haven-work/netwatch_license_seed.hex). It must be
backed up SEPARATELY from everything else — losing it means re-issuing every
hotel's licence; leaking it lets anyone forge a licence for any hotel. It is
never written to licenses.json, never sent to a client, never logged.
"""
import json
import os
import threading
from datetime import datetime, timedelta, timezone
from pathlib import Path

from crypto import ed25519, licenses

_DIR = Path(__file__).parent
LICENSES_PATH = _DIR / 'licenses.json'
LICENSE_SEED_PATH = Path(os.environ.get(
    'NETWATCH_LICENSE_SEED', str(Path.home() / '.haven-work' / 'netwatch_license_seed.hex')))

# Operator public key — must match the key embedded in Haven (app/config.py).
LICENSE_PUBKEY = os.environ.get(
    'NETWATCH_LICENSE_PUBKEY',
    '67fd38905b71f46c52a4262a66decb363ef640403cf9edbd302dc7542b5629b2')

_lock = threading.Lock()

# the field set of a licence record (everything except site_id + signature),
# with sane defaults, so the dashboard form is the single source of truth.
DEFAULTS = {
    'property_name': '', 'city': '', 'address': '', 'phone': '', 'tax_id': '',
    'currency': 'GEL', 'currency_symbol': '₾', 'vat_rate': 18,
    'max_rooms': 0,
    'modules_enabled': [],                       # subset of MODULES
    'lock_config': {'driver': 'manual', 'prousb_dlscoid': '',
                    'prousb_lockno_format': '{bld:02d}{flr:02d}{rom:02d}',
                    'bonwin_version': '808', 'bonwin_hotelpw': '', 'bonwin_oldpw': ''},
    'grace_days': 30,
    'expires_at': '',                            # ISO date/datetime; '' = derive +1y
}
MODULES = ['locks', 'channel', 'inventory', 'tablet']


def _read_seed():
    return LICENSE_SEED_PATH.read_text().strip()


def _load():
    try:
        with open(LICENSES_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save(data):
    with _lock:
        tmp = str(LICENSES_PATH) + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(data, f, indent=2, ensure_ascii=False)
        os.replace(tmp, LICENSES_PATH)


def list_licenses():
    """All stored licences (raw fields, no signature) keyed by site_id."""
    return _load()


def _coerce(fields):
    """Normalise a form/API payload into a clean record body."""
    rec = json.loads(json.dumps(DEFAULTS))       # deep copy
    for k, v in (fields or {}).items():
        if k in ('site_id', 'signature', 'issued_at'):
            continue
        if k == 'lock_config' and isinstance(v, dict):
            rec['lock_config'].update({kk: vv for kk, vv in v.items()})
        elif k in rec:
            rec[k] = v
    # types
    try:
        rec['vat_rate'] = float(rec['vat_rate'])
    except Exception:
        rec['vat_rate'] = 18
    try:
        rec['max_rooms'] = int(rec['max_rooms'] or 0)
    except Exception:
        rec['max_rooms'] = 0
    try:
        rec['grace_days'] = int(rec['grace_days'] or 30)
    except Exception:
        rec['grace_days'] = 30
    if not isinstance(rec['modules_enabled'], list):
        rec['modules_enabled'] = []
    rec['modules_enabled'] = [m for m in rec['modules_enabled'] if m in MODULES]
    # prousb_dlscoid: keep as int when numeric, so Haven casts cleanly
    d = rec['lock_config'].get('prousb_dlscoid')
    if isinstance(d, str) and d.strip().isdigit():
        rec['lock_config']['prousb_dlscoid'] = int(d.strip())
    return rec


def upsert_license(site_id, fields):
    """Create or replace a site's licence body. Returns the stored body."""
    data = _load()
    rec = _coerce(fields)
    data[site_id] = rec
    _save(data)
    return rec


def delete_license(site_id):
    data = _load()
    if site_id in data:
        del data[site_id]
        _save(data)
        return True
    return False


def signed_license(site_id):
    """Build the full, SIGNED licence record for a site, or None if unknown."""
    data = _load()
    body = data.get(site_id)
    if body is None:
        return None
    now = datetime.now(timezone.utc)
    expires = body.get('expires_at') or (now + timedelta(days=365)).isoformat()
    record = {
        'site_id': site_id,
        'property_name': body.get('property_name', ''),
        'city': body.get('city', ''),
        'address': body.get('address', ''),
        'phone': body.get('phone', ''),
        'tax_id': body.get('tax_id', ''),
        'currency': body.get('currency', 'GEL'),
        'currency_symbol': body.get('currency_symbol', '₾'),
        'vat_rate': body.get('vat_rate', 18),
        'max_rooms': body.get('max_rooms', 0),
        'modules_enabled': body.get('modules_enabled', []),
        'lock_config': body.get('lock_config', {}),
        'issued_at': now.isoformat(),
        'expires_at': expires,
        'grace_days': body.get('grace_days', 30),
    }
    return licenses.sign_record(record, _read_seed(), LICENSE_PUBKEY)


def license_summary(site_id):
    """Light view for the fleet UI: {licensed, property_name, expires_at,
    days_left, modules}. Never signs, never touches the key."""
    body = _load().get(site_id)
    if body is None:
        return {'licensed': False, 'property_name': None, 'expires_at': None,
                'days_left': None, 'modules': []}
    exp = body.get('expires_at')
    days_left = None
    if exp:
        try:
            dt = datetime.fromisoformat(str(exp).replace('Z', '+00:00'))
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            days_left = (dt - datetime.now(timezone.utc)).days
        except Exception:
            pass
    return {'licensed': True, 'property_name': body.get('property_name'),
            'expires_at': exp, 'days_left': days_left,
            'modules': body.get('modules_enabled', [])}
