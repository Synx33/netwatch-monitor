#!/usr/bin/env python3
"""
NetWatch Web UI - manage sites, devices, and view status.
"""
import json
import os
import time
import subprocess
import hashlib
import secrets
import requests
import urllib3
import xml.etree.ElementTree as ET
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import urlparse, parse_qs
from pathlib import Path
from requests.auth import HTTPDigestAuth

CONFIG_PATH = Path(__file__).parent / 'config.json'
STATE_PATH = Path(__file__).parent / 'state.json'
NOTES_PATH = Path(__file__).parent / 'notes.json'
PORT = 7700

# Auth
AUTH_USER = os.environ.get("NETWATCH_USER", "admin")
AUTH_PASS = os.environ.get("NETWATCH_PASS", "change-me")  # set via env var; never hardcode
SESSIONS_PATH = Path(__file__).parent / 'sessions.json'


def _load_sessions():
    try:
        with open(SESSIONS_PATH) as f:
            return json.load(f)
    except Exception:
        return {}


def _save_sessions():
    try:
        tmp = str(SESSIONS_PATH) + '.tmp'
        with open(tmp, 'w') as f:
            json.dump(active_sessions, f)
        os.replace(tmp, SESSIONS_PATH)
        try:
            os.chmod(SESSIONS_PATH, 0o600)
        except Exception:
            pass
    except Exception as e:
        print(f"session persist error: {e}")


active_sessions = _load_sessions()

# Brute-force protection
_login_attempts = {}  # ip -> [timestamp, ...]
_LOGIN_MAX_ATTEMPTS = 5
_LOGIN_LOCKOUT_SECONDS = 300
_global_login_failures = []  # [timestamp, ...] — all IPs combined
_GLOBAL_MAX_FAILURES = 20
_GLOBAL_DELAY = 10  # seconds delay after global threshold

# Password reveal rate limiting
_pw_reveals = {}  # session_token -> [timestamp, ...]
_PW_REVEAL_MAX = 5
_PW_REVEAL_WINDOW = 60  # per minute

# File write locks
import threading
_config_lock = threading.Lock()
_notes_lock = threading.Lock()

SESSION_MAX_AGE = 86400  # 24 hours

def check_auth(handler):
    """Check if request has valid session cookie."""
    cookie = handler.headers.get('Cookie', '')
    for part in cookie.split(';'):
        part = part.strip()
        if part.startswith('session='):
            token = part.split('=', 1)[1]
            if token in active_sessions:
                # Enforce server-side expiry
                if time.time() - active_sessions[token] > SESSION_MAX_AGE:
                    active_sessions.pop(token, None)
                    return False
                return True
    return False

def create_session():
    # Prune expired sessions
    now = time.time()
    expired = [k for k, v in active_sessions.items() if now - v > SESSION_MAX_AGE]
    for k in expired:
        active_sessions.pop(k, None)
    token = secrets.token_hex(32)
    active_sessions[token] = now
    _save_sessions()
    return token

def load_notes():
    try:
        with open(NOTES_PATH) as f:
            return json.load(f)
    except:
        return {}

def save_notes(notes):
    with _notes_lock:
        with open(NOTES_PATH, 'w') as f:
            json.dump(notes, f, indent=2, ensure_ascii=False)

NS = {'ns': 'http://www.isapi.org/ver20/XMLSchema'}

import re
import ipaddress

_BLOCKED_NETWORKS = [
    ipaddress.ip_network('127.0.0.0/8'),
    ipaddress.ip_network('169.254.0.0/16'),
    ipaddress.ip_network('::1/128'),
    ipaddress.ip_network('0.0.0.0/32'),
    ipaddress.ip_network('fc00::/7'),
]

def _validate_ip(ip_str):
    """Validate IP address to prevent command injection and SSRF."""
    if not ip_str or not isinstance(ip_str, str):
        return False
    try:
        addr = ipaddress.ip_address(ip_str)
        for net in _BLOCKED_NETWORKS:
            if addr in net:
                return False
        return True
    except ValueError:
        if re.match(r'^[a-zA-Z0-9][a-zA-Z0-9.\-]{0,253}[a-zA-Z0-9]$', ip_str):
            return True
        return False

def _validate_port(port):
    try:
        p = int(port)
        return 1 <= p <= 65535
    except (ValueError, TypeError):
        return False

def _sanitize_text(text):
    """Sanitize text for HTML output to prevent XSS."""
    if not text:
        return ''
    return str(text).replace('&', '&amp;').replace('<', '&lt;').replace('>', '&gt;').replace('"', '&quot;').replace("'", '&#x27;')

LOG_TYPE_NAMES = {
    'motionStart': 'Motion Detected', 'motionStop': 'Motion Stopped',
    'lineDetectionStart': 'Line Crossing', 'lineDetectionStop': 'Line Crossing Stopped',
    'fieldDetectionStart': 'Intrusion Detected', 'fieldDetectionStop': 'Intrusion Stopped',
    'regionEntranceStart': 'Region Entry', 'regionExitingStart': 'Region Exit',
    'faceSnapStart': 'Face Detected', 'humanRecognitionStart': 'Person Detected',
    'vehicleDetectionStart': 'Vehicle Detected', 'fireDetectionStart': 'Fire Detected',
    'videoLost': 'Video Lost', 'videoException': 'Video Error',
    'hdFull': 'HDD Full', 'hdError': 'HDD Error', 'hdBadBlock': 'HDD Bad Block',
    'highHDTemperature': 'HDD High Temp', 'severeHDFailure': 'HDD Critical Failure',
    'netBroken': 'Network Disconnected', 'ipConflict': 'IP Conflict',
    'ipcDisconnect': 'Camera Disconnected', 'recordError': 'Recording Error',
    'illlegealAccess': 'Illegal Access Attempt', 'raidError': 'RAID Error',
    'localLogin': 'Local Login', 'localLogOut': 'Local Logout',
    'remoteLogin': 'Remote Login', 'remoteLogout': 'Remote Logout',
    'localCfgPara': 'Local Config Change', 'remoteCfgPara': 'Remote Config Change',
    'localFormatDisk': 'HDD Formatted (Local)', 'remoteFormatHd': 'HDD Formatted (Remote)',
    'devicePowerOn': 'Power On', 'devicePowerOff': 'Power Off',
    'hddInfo': 'HDD Info', 'startRec': 'Recording Started', 'stopRec': 'Recording Stopped',
    'hdFormatStart': 'HDD Format Started', 'hdFormatStop': 'HDD Format Complete',
    'runStatusInfo': 'System Status', 'ipcConnect': 'Camera Connected',
}


def _get_ip_info_cache():
    """Build IP→device name cache from ARP table + MAC vendors."""
    cache = {}
    mac_vendors = {}
    try:
        with open(Path(__file__).parent / 'mac_vendors.json') as f:
            mac_vendors = json.load(f)
    except:
        pass

    try:
        import subprocess
        r = subprocess.run(['arp', '-an'], capture_output=True, text=True, timeout=3)
        for line in r.stdout.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[3] != '<incomplete>':
                ip = parts[1].strip('()')
                mac = parts[3].upper()
                prefix = mac[:8].replace(':', '-')
                vendor = mac_vendors.get(prefix, mac_vendors.get(prefix.upper(), ''))
                if vendor:
                    cache[ip] = vendor
                else:
                    cache[ip] = mac
    except:
        pass
    return cache


# Server-side log cache: key = "site:device:date" -> {logs: [...], total_on_device: N, timestamp: T}
_device_log_cache = {}


def _check_nvr_log_count(ip, port, auth, date_from, date_to, meta_id):
    """Quick single request to get total log count without fetching data."""
    import uuid
    search_id = str(uuid.uuid4())
    xml_body = (
        '<?xml version="1.0" encoding="utf-8"?>'
        '<CMSearchDescription>'
        f'<searchID>{search_id}</searchID>'
        f'<metaId>{meta_id}</metaId>'
        '<timeSpanList><timeSpan>'
        f'<startTime>{date_from}T00:00:00Z</startTime>'
        f'<endTime>{date_to}T23:59:59Z</endTime>'
        '</timeSpan></timeSpanList>'
        '<maxResults>1</maxResults>'
        '</CMSearchDescription>'
    )
    try:
        resp = requests.post(
            f"http://{ip}:{port}/ISAPI/ContentMgmt/logSearch",
            data=xml_body.encode('utf-8'),
            auth=auth, headers={"Content-Type": "application/xml"},
            timeout=5, verify=False,
        )
        if resp.status_code == 200:
            root = ET.fromstring(resp.text)
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag == 'totalMatches':
                    return int(elem.text or 0)
    except:
        pass
    return -1


def fetch_device_logs(body):
    """Fetch logs from a Hikvision NVR via ISAPI logSearch, with server-side caching."""
    import uuid
    try:
        config = load_config()
        si = body.get('site', 0)
        di = body.get('device', 0)
        date_from = body.get('date_from', body.get('date', time.strftime('%Y-%m-%d')))
        date_to = body.get('date_to', date_from)
        type_filter = body.get('type', 'all')

        site = config['sites'][si]
        dev = site['devices'][di]
        ip = dev['ip']
        port = dev.get('port', 80)
        username = dev.get('username', 'admin')
        password = dev.get('password', '')

        auth = HTTPDigestAuth(username, password)
        max_logs = body.get('limit', 100)
        total_on_device = 0
        cache_key = f"{si}:{di}:{date_from}:{date_to}"

        # Check cache
        cached = _device_log_cache.get(cache_key)
        if cached:
            # Quick count check — only 1 lightweight request to NVR
            current_count = _check_nvr_log_count(ip, port, auth, date_from, date_to, 'log.std-cgi.com')
            if current_count == cached.get('nvr_total', -1):
                # No new logs — serve from cache instantly
                all_logs = cached['logs']
                total_on_device = cached.get('total_on_device', 0)
                ip_cache = _get_ip_info_cache()
                result = []
                for log in all_logs:
                    meta = log.get('metaId', '')
                    parts = meta.replace('log.hikvision.com/', '').split('/')
                    log_type = parts[0] if parts else ''
                    event_key = parts[1] if len(parts) > 1 else ''
                    channel = parts[2] if len(parts) > 2 else ''
                    if log_type == 'Alarm':
                        continue
                    if type_filter != 'all' and log_type != type_filter:
                        continue
                    event_name = LOG_TYPE_NAMES.get(event_key, event_key)
                    if channel:
                        event_name += f' (CH{channel})'
                    log_ip = log.get('ipAddress', '')
                    ip_label = f"{log_ip} ({ip_cache[log_ip]})" if log_ip and log_ip in ip_cache else log_ip
                    result.append({
                        'time': log.get('StartDateTime', ''), 'type': log_type,
                        'event': event_name, 'user': log.get('userName', ''),
                        'ip': ip_label, 'detail': log.get('additionInformation', ''),
                    })
                result.sort(key=lambda x: x.get('time', ''), reverse=True)
                has_more = len(all_logs) >= max_logs
                return {'logs': result, 'total': len(result), 'total_on_device': total_on_device, 'has_more': has_more, 'cached': True}
            # Count changed — new logs exist, re-fetch everything
        all_logs = []
        position = 0

        # Fetch specific types to avoid downloading hundreds of alarm logs
        if type_filter != 'all':
            meta_ids = [f'log.std-cgi.com/{type_filter}' if type_filter != 'Information' else 'log.std-cgi.com/Infomation']
        else:
            meta_ids = ['log.std-cgi.com/Exception', 'log.std-cgi.com/Operation', 'log.std-cgi.com/Infomation']

        session = requests.Session()
        session.auth = auth
        session.headers.update({"Content-Type": "application/xml"})
        session.verify = False
        base_url = f"http://{ip}:{port}/ISAPI/ContentMgmt/logSearch"

        for meta_id in meta_ids:
            position = 0
            while len(all_logs) < max_logs:
                search_id = str(uuid.uuid4())
                xml_body = (
                    '<?xml version="1.0" encoding="utf-8"?>'
                    '<CMSearchDescription>'
                    f'<searchID>{search_id}</searchID>'
                    f'<metaId>{meta_id}</metaId>'
                    '<timeSpanList><timeSpan>'
                    f'<startTime>{date_from}T00:00:00Z</startTime>'
                    f'<endTime>{date_to}T23:59:59Z</endTime>'
                    '</timeSpan></timeSpanList>'
                    f'<maxResults>64</maxResults>'
                    f'<searchResultPosition>{position}</searchResultPosition>'
                    '</CMSearchDescription>'
                )

                try:
                    resp = session.post(base_url, data=xml_body.encode('utf-8'), timeout=8)
                except:
                    break

                if resp.status_code != 200:
                    break

                root = ET.fromstring(resp.text)
                status = ''
                count = 0
                for elem in root.iter():
                    tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                    if tag == 'responseStatusStrg':
                        status = elem.text or ''
                    if tag == 'totalMatches':
                        total_on_device += int(elem.text or 0)
                    if tag == 'numOfMatches':
                        count = int(elem.text or 0)
                    if tag == 'logDescriptor':
                        log = {}
                        for child in elem:
                            ctag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                            log[ctag] = (child.text or '').strip()
                        all_logs.append(log)

                position += count
                if status != 'MORE' or count == 0:
                    break

        session.close()

        # Save to cache with NVR total for quick change detection
        nvr_total = _check_nvr_log_count(ip, port, auth, date_from, date_to, 'log.std-cgi.com')
        _device_log_cache[cache_key] = {
            'logs': all_logs,
            'total_on_device': total_on_device,
            'nvr_total': nvr_total,
            'timestamp': time.time(),
        }
        # Clean old cache entries (keep last 20)
        if len(_device_log_cache) > 20:
            oldest = sorted(_device_log_cache, key=lambda k: _device_log_cache[k]['timestamp'])
            for k in oldest[:len(_device_log_cache) - 20]:
                del _device_log_cache[k]

        all_logs.sort(key=lambda x: x.get('StartDateTime', ''), reverse=True)

        # Parse and format logs
        ip_cache = _get_ip_info_cache()
        result = []
        for log in all_logs:
            meta = log.get('metaId', '')
            parts = meta.replace('log.hikvision.com/', '').split('/')
            log_type = parts[0] if parts else ''
            event_key = parts[1] if len(parts) > 1 else ''
            channel = parts[2] if len(parts) > 2 else ''

            if log_type == 'Alarm':
                continue

            event_name = LOG_TYPE_NAMES.get(event_key, event_key)
            if channel:
                event_name += f' (CH{channel})'

            log_ip = log.get('ipAddress', '')
            ip_label = log_ip
            if log_ip and log_ip in ip_cache:
                ip_label = f"{log_ip} ({ip_cache[log_ip]})"

            result.append({
                'time': log.get('StartDateTime', ''),
                'type': log_type,
                'event': event_name,
                'user': log.get('userName', ''),
                'ip': ip_label,
                'detail': log.get('additionInformation', ''),
            })

        has_more = len(all_logs) >= max_logs
        return {'logs': result, 'total': len(result), 'total_on_device': total_on_device, 'has_more': has_more}
    except Exception as e:
        return {'error': str(e)}


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(config):
    with _config_lock:
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)
    # Any device in the new config with a filled-in password gets its auth
    # circuit breaker cleared — user presumably fixed the credentials.
    try:
        import sys as _sys
        _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
        from devices import clear_auth_failure
        for site in config.get('sites', []):
            for dev in site.get('devices', []):
                if dev.get('password'):
                    clear_auth_failure(dev.get('ip'))
    except Exception as e:
        print(f"clear_auth_failure during save_config failed: {e}")
    subprocess.run(['sudo', 'systemctl', 'restart', 'netwatch'], capture_output=True, timeout=10)


def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except:
        return {}


def test_device(ip, port, username, password, device_type, snmp_community='public'):
    """Test connection to a device."""
    result = {'ping': False, 'api': False, 'info': {}, 'error': None}

    if not _validate_ip(ip):
        result['error'] = 'Invalid IP address'
        return result
    if not _validate_port(port):
        result['error'] = 'Invalid port'
        return result

    try:
        r = subprocess.run(['ping', '-c', '1', '-W', '2', str(ip)], capture_output=True, timeout=5)
        result['ping'] = r.returncode == 0
    except:
        pass

    if not result['ping']:
        result['error'] = 'Device is not reachable (ping failed)'
        return result

    auth = HTTPDigestAuth(username, password) if username else None

    # Hikvision
    if device_type == 'hikvision_nvr' and username:
        try:
            resp = requests.get(f"http://{ip}:{port}/ISAPI/System/deviceInfo", auth=auth, timeout=5)
            if resp.ok:
                result['api'] = True
                xml = ET.fromstring(resp.text)
                result['info'] = {
                    'model': xml.find('.//ns:model', NS).text if xml.find('.//ns:model', NS) is not None else 'Unknown',
                    'firmware': xml.find('.//ns:firmwareVersion', NS).text if xml.find('.//ns:firmwareVersion', NS) is not None else 'Unknown',
                }
            else:
                result['error'] = f'API returned {resp.status_code} - check credentials'
        except Exception as e:
            result['error'] = str(e)

    # Dahua
    elif device_type == 'dahua_nvr' and username:
        try:
            resp = requests.get(f"http://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo", auth=auth, timeout=5)
            if resp.ok and 'deviceType' in resp.text:
                result['api'] = True
                for line in resp.text.split('\n'):
                    if 'deviceType=' in line:
                        result['info']['model'] = line.split('=')[1].strip()
                    if 'softWareVersion=' in line:
                        result['info']['firmware'] = line.split('=')[1].strip()
            else:
                result['error'] = f'API returned {resp.status_code} - check credentials'
        except Exception as e:
            result['error'] = str(e)

    # Uniview
    elif device_type == 'uniview_nvr' and username:
        try:
            resp = requests.get(f"http://{ip}:{port}/LAPI/V1.0/System/DeviceInfo", auth=auth, timeout=5)
            if resp.ok:
                result['api'] = True
                data = resp.json().get('Response', {}).get('Data', {})
                result['info'] = {'model': data.get('DeviceModel', 'Uniview'), 'firmware': data.get('SoftwareVersion', '')}
            else:
                result['error'] = f'API returned {resp.status_code} - check credentials'
        except Exception as e:
            result['error'] = str(e)

    # Auto-detect NVR
    elif device_type == 'auto_nvr' and username:
        for brand, path, key in [
            ('Hikvision', '/ISAPI/System/deviceInfo', 'DeviceInfo'),
            ('Dahua', '/cgi-bin/magicBox.cgi?action=getSystemInfo', 'deviceType'),
            ('Uniview', '/LAPI/V1.0/System/DeviceInfo', 'DeviceModel'),
        ]:
            try:
                resp = requests.get(f"http://{ip}:{port}{path}", auth=auth, timeout=5)
                if resp.ok and key in resp.text:
                    result['api'] = True
                    result['info'] = {'model': f'Detected: {brand}'}
                    break
            except:
                continue
        if not result['api']:
            result['error'] = 'Could not detect NVR brand - check credentials and port'

    # SNMP devices
    elif device_type in ('switch', 'router', 'access_point'):
        try:
            r = subprocess.run(
                ['snmpget', '-v2c', '-c', snmp_community, '-t', '3', '-r', '1', ip, 'sysDescr.0'],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0 and '=' in r.stdout:
                result['api'] = True
                result['info'] = {'model': r.stdout.split('=')[-1].strip().strip('"')[:80]}
            else:
                result['error'] = 'SNMP not responding - check community string and if SNMP is enabled'
        except Exception as e:
            result['error'] = str(e)

    return result


LOGIN_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="author" content="NetWatch">
    <meta name="owner" content="NetWatch">
    <meta name="copyright" content="NetWatch — source-available. See LICENSE.">
    <!-- NetWatch — source-available network monitoring. See LICENSE. -->
    <title>NetWatch - Login</title>
    <style>
        * { margin:0; padding:0; box-sizing:border-box; }
        body { background:#0a0a1a; color:#e0e0e0; font-family:-apple-system,sans-serif; display:flex; align-items:center; justify-content:center; height:100vh; }
        .login-box { background:#12122a; border:1px solid #1e1e3a; border-radius:10px; padding:32px; width:340px; }
        .login-box h2 { color:#4ecca3; margin-bottom:20px; text-align:center; }
        .form-group { margin-bottom:14px; }
        .form-group label { display:block; font-size:12px; color:#888; margin-bottom:4px; }
        .form-group input { width:100%; padding:10px 12px; background:#1a1a3a; border:1px solid #2a2a5a; border-radius:6px; color:#fff; font-size:14px; }
        .form-group input:focus { outline:none; border-color:#4ecca3; }
        .btn { width:100%; padding:10px; background:#4ecca3; color:#0a0a1a; border:none; border-radius:6px; font-size:14px; font-weight:600; cursor:pointer; margin-top:8px; }
        .btn:hover { opacity:0.9; }
        .error { color:#e94560; font-size:12px; margin-top:8px; text-align:center; display:none; }
    </style>
</head>
<body>
    <div class="login-box">
        <h2>NetWatch</h2>
        <div class="form-group">
            <label>Username</label>
            <input type="text" id="user" autofocus>
        </div>
        <div class="form-group">
            <label>Password</label>
            <input type="password" id="pass" onkeydown="if(event.key==='Enter')login()">
        </div>
        <button class="btn" onclick="login()">Login</button>
        <div class="error" id="error">Wrong username or password</div>
    </div>
    <script>
        function login() {
            var x = new XMLHttpRequest();
            x.open('POST', '/api/login');
            x.setRequestHeader('Content-Type', 'application/json');
            x.onload = function() {
                var d = JSON.parse(x.responseText);
                if (d.ok) { window.location.reload(); }
                else { document.getElementById('error').style.display = 'block'; }
            };
            x.send(JSON.stringify({user: document.getElementById('user').value, pass: document.getElementById('pass').value}));
        }
    </script>
    <div id="cr-dot" onclick="document.getElementById('cr-modal').style.display='flex'"
         style="position:fixed;bottom:8px;right:10px;font-size:16px;color:#4ecca3;cursor:pointer;user-select:none;opacity:0.9;z-index:9998;padding:8px 14px;background:rgba(20,20,48,0.8);border:1px solid #2a2a5a;border-radius:6px;"
         title="About NetWatch">© NetWatch</div>
    <div id="cr-modal" onclick="if(event.target.id==='cr-modal')this.style.display='none'"
         style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:#141430;border:1px solid #2a2a5a;border-radius:10px;padding:22px 26px;max-width:520px;color:#e0e0e0;font-size:13px;line-height:1.55;">
            <div style="font-size:15px;font-weight:600;margin-bottom:10px;color:#4ecca3;">NetWatch</div>
            <div>Copyright &copy; 2026 <b>NetWatch</b>. All rights reserved.</div>
            <div style="margin-top:12px;color:#888;font-size:12px;">
                Proprietary software. No person or entity may use, copy, modify,
                distribute, host, or deploy this software, in whole or in part,
                without permission. See LICENSE.
            </div>
            <div style="text-align:right;margin-top:16px;">
                <button onclick="document.getElementById('cr-modal').style.display='none'"
                        style="padding:6px 14px;background:#2a2a5a;border:none;border-radius:6px;color:#fff;font-size:12px;cursor:pointer;">Close</button>
            </div>
        </div>
    </div>
</body>
</html>"""

PAGE_HTML = """<!DOCTYPE html>
<html>
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <meta name="author" content="NetWatch">
    <meta name="owner" content="NetWatch">
    <meta name="copyright" content="NetWatch — source-available. See LICENSE.">
    <!-- NetWatch — source-available network monitoring. See LICENSE. -->
    <title>NetWatch</title>
    <style>
        * { margin: 0; padding: 0; box-sizing: border-box; }
        body { background: #0a0a1a; color: #e0e0e0; font-family: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif; }
        .header { background: #12122a; padding: 16px 24px; display: flex; align-items: center; justify-content: space-between; border-bottom: 1px solid #1e1e3a; }
        .header h1 { font-size: 20px; color: #4ecca3; }
        .header .status { font-size: 12px; color: #888; }
        .container { max-width: 1200px; margin: 0 auto; padding: 20px; }

        .tabs { display: flex; gap: 0; margin-bottom: 20px; }
        .tab { padding: 10px 20px; background: #12122a; border: 1px solid #1e1e3a; cursor: pointer; color: #888; font-size: 14px; }
        .tab:first-child { border-radius: 6px 0 0 6px; }
        .tab:last-child { border-radius: 0 6px 6px 0; }
        .tab.active { background: #4ecca3; color: #0a0a1a; border-color: #4ecca3; font-weight: 600; }

        .panel { display: none; }
        .panel.active { display: block; }

        /* Status Panel */
        .site-card { background: #12122a; border-radius: 8px; border: 1px solid #1e1e3a; margin-bottom: 16px; overflow: hidden; }
        .site-header { padding: 14px 18px; background: #16163a; display: flex; justify-content: space-between; align-items: center; }
        .site-name { font-size: 16px; font-weight: 600; color: #fff; }
        .site-status { font-size: 12px; padding: 3px 10px; border-radius: 12px; }
        .site-status.ok { background: #1a3a2a; color: #4ecca3; }
        .site-status.alert { background: #3a1a1a; color: #e94560; }
        .device-list { padding: 8px; }
        .device-row { display: flex; align-items: center; padding: 10px 14px; border-radius: 6px; margin: 4px 0; }
        .device-row:hover { background: #1a1a3a; }
        .device-dot { width: 10px; height: 10px; border-radius: 50%; margin-right: 12px; flex-shrink: 0; }
        .device-dot.online { background: #4ecca3; box-shadow: 0 0 6px #4ecca3; }
        .device-dot.offline { background: #e94560; box-shadow: 0 0 6px #e94560; }
        .device-info { flex: 1; }
        .device-name { font-size: 14px; color: #fff; }
        .device-ip { font-size: 11px; color: #666; margin-top: 2px; }
        .device-detail { font-size: 11px; color: #888; text-align: right; }
        .cam-list { margin-top: 6px; display: flex; gap: 4px; flex-wrap: wrap; }
        .cam-dot { width: 8px; height: 8px; border-radius: 50%; }
        .cam-dot.on { background: #4ecca3; }
        .cam-dot.off { background: #e94560; }

        /* Manage Panel */
        .btn { padding: 8px 16px; border: none; border-radius: 6px; cursor: pointer; font-size: 13px; font-weight: 600; }
        .btn-primary { background: #4ecca3; color: #0a0a1a; }
        .btn-danger { background: #e94560; color: #fff; }
        .btn-secondary { background: #2a2a4a; color: #ccc; }
        .btn:hover { opacity: 0.9; }

        .form-group { margin-bottom: 12px; }
        .form-group label { display: block; font-size: 12px; color: #888; margin-bottom: 4px; }
        .form-group input, .form-group select { width: 100%; padding: 8px 12px; background: #1a1a3a; border: 1px solid #2a2a5a; border-radius: 6px; color: #fff; font-size: 13px; }
        .form-group input:focus, .form-group select:focus { outline: none; border-color: #4ecca3; }

        .modal-overlay { display: none; position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7); z-index: 100; align-items: center; justify-content: center; }
        .modal-overlay.show { display: flex; }
        .modal { background: #12122a; border-radius: 10px; border: 1px solid #2a2a5a; padding: 24px; width: 90%; max-width: 500px; }
        .modal h3 { color: #4ecca3; margin-bottom: 16px; }
        .modal-actions { display: flex; gap: 8px; margin-top: 16px; justify-content: flex-end; }

        .site-manage { background: #12122a; border-radius: 8px; border: 1px solid #1e1e3a; margin-bottom: 12px; padding: 16px; }
        .site-manage-header { display: flex; justify-content: space-between; align-items: center; margin-bottom: 12px; }
        .site-manage-header h3 { color: #fff; font-size: 15px; }
        .device-manage-row { display: flex; align-items: center; justify-content: space-between; padding: 8px 12px; background: #1a1a3a; border-radius: 6px; margin: 6px 0; }
        .device-manage-info { flex: 1; }
        .device-manage-name { color: #fff; font-size: 13px; }
        .device-manage-type { color: #666; font-size: 11px; }

        .test-result { margin-top: 12px; padding: 10px; border-radius: 6px; font-size: 12px; }
        .test-result.success { background: #1a3a2a; color: #4ecca3; }
        .test-result.error { background: #3a1a1a; color: #e94560; }

        .empty { text-align: center; color: #666; padding: 40px; font-size: 14px; }

        /* Device Logs */
        .dl-row { display:flex; align-items:flex-start; padding:10px 14px; border-bottom:1px solid #1a1a3a; gap:12px; font-size:13px; }
        .dl-row:hover { background:#1a1a3a; }
        .dl-time { color:#888; min-width:140px; flex-shrink:0; font-size:12px; }
        .dl-badge { padding:2px 8px; border-radius:4px; font-size:11px; font-weight:600; min-width:80px; text-align:center; flex-shrink:0; }
        .dl-badge.Alarm { background:#3a2a1a; color:#f0a030; }
        .dl-badge.Exception { background:#3a1a1a; color:#e94560; }
        .dl-badge.Operation { background:#1a2a3a; color:#4ea8de; }
        .dl-badge.Information { background:#1a3a2a; color:#4ecca3; }
        .dl-event { color:#ccc; flex:1; }
        .dl-detail { color:#666; font-size:11px; }
        .dl-summary { display:flex; gap:12px; margin-bottom:12px; flex-wrap:wrap; }
        .dl-stat { background:#12122a; border:1px solid #1e1e3a; border-radius:8px; padding:12px 18px; text-align:center; min-width:100px; }
        .dl-stat .num { font-size:24px; font-weight:700; }
        .dl-stat .label { font-size:11px; color:#888; margin-top:4px; }

        /* Refresh pulse — shows when loadStatus/loadVPN completes */
        .refresh-pulse {
            display: inline-block; width: 8px; height: 8px; border-radius: 50%;
            background: #4ecca3; margin-right: 6px; vertical-align: middle;
            opacity: 0;
        }
        .refresh-pulse.flash { animation: rp-flash 800ms ease-out; }
        @keyframes rp-flash {
            0%   { opacity: 1; transform: scale(1);   box-shadow: 0 0 0 0 rgba(78, 204, 163, 0.7); }
            100% { opacity: 0; transform: scale(2.3); box-shadow: 0 0 0 10px rgba(78, 204, 163, 0); }
        }

        /* VPN-detected banner — slide-down entry */
        #vpnDetectedBanner {
            animation: slide-down 320ms ease-out;
            overflow: hidden;
        }
        @keyframes slide-down {
            from { transform: translateY(-100%); opacity: 0; }
            to   { transform: translateY(0);     opacity: 1; }
        }

        /* Clickable IP links */
        .ip-link { color: #4ecca3; text-decoration: none; border-bottom: 1px dotted rgba(78,204,163,0.4); }
        .ip-link:hover { color: #5edcb3; border-bottom-color: #5edcb3; }

        /* Search/filter input */
        .filter-box {
            width: 100%; padding: 8px 12px; margin-bottom: 12px;
            background: #1a1a3a; border: 1px solid #2a2a5a; border-radius: 6px;
            color: #fff; font-size: 13px;
        }
        .filter-box:focus { outline: none; border-color: #4ecca3; }

        /* Mobile responsive */
        @media (max-width: 768px) {
            .container { padding: 10px; }
            .header { padding: 12px 14px; }
            .header h1 { font-size: 18px; }
            .tabs { flex-wrap: wrap; gap: 4px; }
            .tab { padding: 6px 10px; font-size: 12px; }
            .site-card { margin-bottom: 12px; }
            .site-header { flex-wrap: wrap; gap: 8px; }
            .device-row { flex-wrap: wrap; }
            .modal { max-width: 92vw; }
            .dl-summary { gap: 8px; }
            .dl-stat { min-width: 70px; padding: 8px 12px; }
        }
        @media (max-width: 480px) {
            .tabs { gap: 2px; }
            .tab { padding: 6px 8px; font-size: 11px; }
            .btn { font-size: 12px; padding: 7px 10px; }
            .dl-stat .num { font-size: 18px; }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>NetWatch</h1>
        <div class="status" id="lastCheck"><span class="refresh-pulse" id="refreshPulse"></span><span id="lastCheckText">Loading...</span></div>
    </div>
    <div id="vpnDetectedBanner" style="display:none;background:linear-gradient(90deg,#1a4a2a,#2a6a3a);border-bottom:2px solid #4caf50;padding:12px 16px;color:#fff;"></div>
    <div class="container">
        <div class="tabs">
            <div class="tab active" onclick="showTab('status')">Status</div>
            <div class="tab" onclick="showTab('manage')">Manage</div>
            <div class="tab" onclick="showTab('vpn')">VPN</div>
            <div class="tab" onclick="showTab('scanner')">Scanner</div>
            <div class="tab" onclick="showTab('devicelogs')">Device Logs</div>
            <div class="tab" onclick="showTab('logs')">Logs</div>
        </div>

        <div class="panel active" id="panel-status"></div>
        <div class="panel" id="panel-manage"></div>
        <div class="panel" id="panel-vpn"></div>
        <div class="panel" id="panel-scanner">
            <div class="site-card" style="padding:16px">
                <div style="display:flex;gap:8px;align-items:center;flex-wrap:wrap;">
                    <input type="text" id="scanSubnet" placeholder="e.g. 192.168.1.0/24 or 10.0.0.0/24" style="flex:1;min-width:200px;padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                    <button class="btn btn-primary" onclick="startScan(false)">Full Scan</button>
                    <button class="btn btn-secondary" onclick="startScan(true)">Quick Scan</button>
                </div>
                <p style="color:#666;font-size:11px;margin-top:6px;">Full scan: ports + OS detection (~2 min) | Quick scan: ping only (~15 sec)</p>
            </div>
            <div id="scanResults"></div>
        </div>
        <div class="panel" id="panel-devicelogs">
            <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center;">
                <select id="dlSite" onchange="dlUpdateDevices();loadDeviceLogs()" style="padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                </select>
                <select id="dlDevice" onchange="loadDeviceLogs()" style="padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                </select>
                <select id="dlType" onchange="loadDeviceLogs()" style="padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                    <option value="all">All Types</option>
                    <option value="Exception">Exceptions</option>
                    <option value="Operation">Operations</option>
                    <option value="Information">Information</option>
                </select>
                <input type="date" id="dlDateFrom" onchange="dlInited && loadDeviceLogs()" style="padding:7px 10px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:12px;width:130px;" title="From">
                <span style="color:#666;font-size:12px;">—</span>
                <input type="date" id="dlDateTo" onchange="dlInited && loadDeviceLogs()" style="padding:7px 10px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:12px;width:130px;" title="To">
                <button class="btn btn-primary" onclick="loadDeviceLogs()">Refresh</button>
            </div>
            <div id="dlLoading" style="display:none;text-align:center;padding:20px;color:#888;">Loading logs...</div>
            <div id="dlContent"></div>
        </div>

        <div class="panel" id="panel-logs">
            <div style="display:flex;gap:8px;margin-bottom:12px;flex-wrap:wrap;align-items:center;">
                <select id="logFilter" onchange="loadLogs()" style="padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                    <option value="all">ყველა ობიექტი</option>
                </select>
                <select id="logDeviceFilter" onchange="loadLogs()" style="padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                    <option value="all">ყველა მოწყობილობა</option>
                </select>
                <select id="logType" onchange="loadLogs()" style="padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                    <option value="all">ყველა ჩანაწერი</option>
                    <option value="alerts">მხოლოდ შეტყობინებები</option>
                </select>
                <select id="logCount" onchange="loadLogs()" style="padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                    <option value="30">30 ჩანაწერი</option>
                    <option value="50">50 ჩანაწერი</option>
                    <option value="100">100 ჩანაწერი</option>
                </select>
            </div>
            <div class="site-card"><pre id="logContent" style="padding:16px;font-size:12px;color:#aaa;max-height:600px;overflow-y:auto;white-space:pre-wrap;"></pre></div>
        </div>
    </div>

    <!-- Add Site Modal -->
    <div class="modal-overlay" id="addSiteModal">
        <div class="modal">
            <h3>Add Site</h3>
            <div id="vpnSiteList" style="margin-bottom:12px;display:none;">
                <label style="font-size:12px;color:#888;margin-bottom:4px;display:block;">Link existing VPN site</label>
                <select id="vpnSiteSelect" onchange="vpnSiteSelected()" style="width:100%;padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;">
                    <option value="">-- New site (manual) --</option>
                </select>
            </div>
            <div class="form-group">
                <label>Site Name</label>
                <input type="text" id="siteName" placeholder="e.g. Bank Isani Branch">
            </div>
            <div class="form-group">
                <label>Client Telegram Group ID (optional)</label>
                <input type="text" id="siteTelegramId" placeholder="Leave empty to add later">
            </div>
            <p style="color:#666;font-size:11px;margin-top:4px;">Create a Telegram group, add @YourBotName to it, then send /chatid in the group to get the ID</p>
            <div class="form-group" id="siteNotifGroup" style="margin-top:16px;">
                <label style="font-size:13px;">Client chat — which alerts should this site's chat receive?</label>
                <p style="color:#666;font-size:11px;margin:4px 0 8px 0;">Admin chat always gets everything. These toggles only affect the client group.</p>
                <div style="display:flex;gap:6px;margin-bottom:8px;">
                    <button type="button" class="notif-tab-btn active" data-target="siteNotifChecks" data-group="nvr"
                            onclick="switchNotifTab(this)"
                            style="padding:6px 14px;background:#2a2a5a;border:none;border-radius:6px 6px 0 0;color:#fff;font-size:12px;cursor:pointer;">NVR</button>
                    <button type="button" class="notif-tab-btn" data-target="siteNotifChecks" data-group="network"
                            onclick="switchNotifTab(this)"
                            style="padding:6px 14px;background:#1a1a3a;border:none;border-radius:6px 6px 0 0;color:#aaa;font-size:12px;cursor:pointer;">Network devices</button>
                </div>
                <div id="siteNotifChecks" style="padding:10px;background:#0f0f28;border:1px solid #2a2a5a;border-radius:6px;"></div>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('addSiteModal')">Cancel</button>
                <button class="btn btn-primary" onclick="addSite()">Add Site</button>
            </div>
        </div>
    </div>

    <!-- Mute (maintenance mode) Modal -->
    <div class="modal-overlay" id="muteModal">
        <div class="modal">
            <h3>Mute alerts — <span id="muteSiteName"></span></h3>
            <p style="color:#888;font-size:12px;margin:4px 0 10px 0;">
                While muted, no alerts fire for this site — not to you, not to the client.
                Use this during scheduled maintenance so you don't wake up to false alarms.
            </p>
            <div style="display:grid;grid-template-columns:repeat(3, 1fr);gap:8px;margin:12px 0;">
                <button class="btn btn-secondary" onclick="applyMute(15)">15 min</button>
                <button class="btn btn-secondary" onclick="applyMute(30)">30 min</button>
                <button class="btn btn-secondary" onclick="applyMute(60)">1 hour</button>
                <button class="btn btn-secondary" onclick="applyMute(120)">2 hours</button>
                <button class="btn btn-secondary" onclick="applyMute(240)">4 hours</button>
                <button class="btn btn-secondary" onclick="applyMute(480)">8 hours</button>
            </div>
            <div class="form-group">
                <label>Custom (minutes, max 10080 = 1 week)</label>
                <input type="number" id="muteCustomMin" min="1" max="10080" placeholder="e.g. 90">
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('muteModal')">Cancel</button>
                <button class="btn btn-primary" onclick="applyMuteCustom()">Apply custom</button>
            </div>
        </div>
    </div>

    <!-- SLA report Modal -->
    <div class="modal-overlay" id="slaModal">
        <div class="modal" style="max-width:640px;">
            <h3>📊 SLA Report — <span id="slaSiteName"></span></h3>
            <div style="display:flex;gap:8px;margin:10px 0 16px;">
                <button class="btn btn-secondary" onclick="loadSLA(7)">7 days</button>
                <button class="btn btn-secondary" onclick="loadSLA(30)">30 days</button>
                <button class="btn btn-secondary" onclick="loadSLA(90)">90 days</button>
            </div>
            <div id="slaContent" style="font-size:13px;color:#ccc;"></div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('slaModal')">Close</button>
            </div>
        </div>
    </div>

    <!-- Edit Notifications Modal -->
    <div class="modal-overlay" id="editNotifModal">
        <div class="modal">
            <h3>Notifications — <span id="editNotifSiteName"></span></h3>
            <p style="color:#888;font-size:12px;margin:4px 0 10px 0;">
                Choose which alert types the client's Telegram chat should receive.
                The admin chat still gets all alerts.
            </p>
            <div style="display:flex;gap:6px;margin-bottom:8px;">
                <button type="button" class="notif-tab-btn active" data-target="editNotifChecks" data-group="nvr"
                        onclick="switchNotifTab(this)"
                        style="padding:6px 14px;background:#2a2a5a;border:none;border-radius:6px 6px 0 0;color:#fff;font-size:12px;cursor:pointer;">NVR</button>
                <button type="button" class="notif-tab-btn" data-target="editNotifChecks" data-group="network"
                        onclick="switchNotifTab(this)"
                        style="padding:6px 14px;background:#1a1a3a;border:none;border-radius:6px 6px 0 0;color:#aaa;font-size:12px;cursor:pointer;">Network devices</button>
            </div>
            <div id="editNotifChecks" style="padding:10px;background:#0f0f28;border:1px solid #2a2a5a;border-radius:6px;"></div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('editNotifModal')">Cancel</button>
                <button class="btn btn-primary" onclick="saveNotifications()">Save</button>
            </div>
        </div>
    </div>

    <!-- Add Device Modal -->
    <div class="modal-overlay" id="addDeviceModal">
        <div class="modal">
            <h3>Add Device</h3>
            <input type="hidden" id="deviceSiteIndex">
            <div class="form-group">
                <label>Device Name</label>
                <input type="text" id="deviceName" placeholder="e.g. Main NVR">
            </div>
            <div class="form-group">
                <label>Type</label>
                <select id="deviceType" onchange="toggleCredFields()">
                    <optgroup label="NVR / DVR">
                        <option value="auto_nvr">NVR/DVR (Auto-detect brand)</option>
                        <option value="hikvision_nvr">Hikvision</option>
                        <option value="dahua_nvr">Dahua</option>
                        <option value="uniview_nvr">Uniview</option>
                        <option value="hanwha_nvr">Hanwha (Samsung)</option>
                        <option value="axis_device">Axis</option>
                        <option value="bosch_device">Bosch</option>
                        <option value="onvif_device">ONVIF (Universal)</option>
                    </optgroup>
                    <optgroup label="Network Equipment">
                        <option value="switch">Switch</option>
                        <option value="poe_switch">PoE Switch</option>
                        <option value="router">Router</option>
                        <option value="firewall">Firewall</option>
                        <option value="access_point">Access Point</option>
                    </optgroup>
                    <optgroup label="Cameras">
                        <option value="ip_camera">IP Camera</option>
                    </optgroup>
                    <optgroup label="Power">
                        <option value="ups">UPS</option>
                    </optgroup>
                    <optgroup label="IT Equipment">
                        <option value="server">Server</option>
                        <option value="nas">NAS Storage</option>
                        <option value="printer">Printer</option>
                        <option value="voip_phone">VoIP Phone</option>
                        <option value="pbx">PBX / IP Telephony</option>
                    </optgroup>
                    <optgroup label="Security">
                        <option value="access_control">Access Control</option>
                        <option value="intercom">Intercom</option>
                    </optgroup>
                    <optgroup label="Other">
                        <option value="http_device">Web Service (HTTP check)</option>
                        <option value="iot_device">IoT Device</option>
                        <option value="network_device">Other (Ping only)</option>
                    </optgroup>
                </select>
            </div>
            <div class="form-group">
                <label>IP Address</label>
                <input type="text" id="deviceIP" placeholder="e.g. 192.168.1.64">
            </div>
            <div class="form-group">
                <label>Port</label>
                <input type="number" id="devicePort" value="80" placeholder="80">
            </div>
            <div id="credFields">
                <div class="form-group">
                    <label>Username</label>
                    <input type="text" id="deviceUser" placeholder="admin">
                </div>
                <div class="form-group">
                    <label>Password</label>
                    <input type="password" id="devicePass" placeholder="password">
                </div>
            </div>
            <div id="snmpFields" style="display:none">
                <div class="form-group">
                    <label>SNMP Community</label>
                    <input type="text" id="snmpCommunity" placeholder="public" value="public">
                </div>
            </div>
            <div id="testResult"></div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('addDeviceModal')">Cancel</button>
                <button class="btn btn-secondary" onclick="testConnection()">Test Connection</button>
                <button class="btn btn-primary" onclick="addDevice()">Add Device</button>
            </div>
        </div>
    </div>

    <!-- Add VPN Site Modal -->
    <div class="modal-overlay" id="addVPNModal">
        <div class="modal">
            <h3>Add VPN Site</h3>
            <div class="form-group">
                <label>Site Name</label>
                <input type="text" id="vpnSiteName" placeholder="e.g. Bank Isani Branch">
            </div>
            <div class="form-group">
                <label>Subnets (comma separated)</label>
                <input type="text" id="vpnSubnets" placeholder="e.g. 192.168.1.0/24, 10.0.0.0/24">
            </div>
            <div class="form-group">
                <label>Router Brand</label>
                <select id="vpnRouterBrand">
                    <optgroup label="WireGuard Native">
                        <option value="mikrotik">MikroTik (RouterOS 7)</option>
                        <option value="keenetic">Keenetic</option>
                        <option value="ubiquiti">Ubiquiti (EdgeOS 3+)</option>
                        <option value="pfsense">pfSense / OPNsense</option>
                        <option value="tplink">TP-Link (Omada/ER V2+)</option>
                        <option value="asus">ASUS (388+)</option>
                    </optgroup>
                    <optgroup label="IPsec Only (No WireGuard)">
                        <option value="cisco">Cisco</option>
                        <option value="fortinet">Fortinet FortiGate</option>
                        <option value="sonicwall">SonicWall</option>
                        <option value="juniper">Juniper SRX</option>
                        <option value="zyxel">Zyxel USG/ATP</option>
                        <option value="netgear">Netgear ProSafe</option>
                    </optgroup>
                    <optgroup label="Port Forward Only">
                        <option value="huawei">Huawei</option>
                        <option value="zte">ZTE (ISP Router)</option>
                        <option value="dlink">D-Link</option>
                        <option value="tenda">Tenda</option>
                    </optgroup>
                    <optgroup label="Other">
                        <option value="generic">Generic WireGuard</option>
                    </optgroup>
                </select>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('addVPNModal')">Cancel</button>
                <button class="btn btn-primary" onclick="addVPNSite()">Generate Config</button>
            </div>
        </div>
    </div>

    <!-- VPN Config Display Modal -->
    <div class="modal-overlay" id="vpnConfigModal">
        <div class="modal" style="max-width:700px;max-height:90vh;overflow-y:auto;">
            <h3 id="vpnConfigTitle">Router Config</h3>
            <p style="color:#888;font-size:12px;margin-bottom:12px;">Copy and paste this into the router</p>
            <pre id="vpnConfigContent" style="background:#0a0a1a;padding:14px;border-radius:6px;color:#4ecca3;font-size:12px;white-space:pre-wrap;max-height:400px;overflow-y:auto;cursor:pointer;" onclick="copyConfig()"></pre>
            <div id="vpnCopyMsg" style="color:#4ecca3;font-size:12px;margin-top:6px;display:none;">Copied!</div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('vpnConfigModal')">Close</button>
                <button class="btn btn-primary" onclick="copyConfig()">Copy Config</button>
            </div>
        </div>
    </div>

    <!-- Notes Modal -->
    <div class="modal-overlay" id="notesModal">
        <div class="modal">
            <h3 id="notesTitle">Notes</h3>
            <input type="hidden" id="notesSiteIndex">
            <div class="form-group">
                <label>Router Login</label>
                <input type="text" id="notesRouter" placeholder="admin / password123">
            </div>
            <div class="form-group">
                <label>Site Address</label>
                <input type="text" id="notesAddress" placeholder="123 Main St">
            </div>
            <div class="form-group">
                <label>Contact Person</label>
                <input type="text" id="notesContact" placeholder="Name - Phone">
            </div>
            <div class="form-group">
                <label>Public IP</label>
                <input type="text" id="notesPublicIP" placeholder="x.x.x.x">
            </div>
            <div class="form-group">
                <label>Notes</label>
                <textarea id="notesText" rows="4" placeholder="Any other info..." style="width:100%;padding:8px 12px;background:#1a1a3a;border:1px solid #2a2a5a;border-radius:6px;color:#fff;font-size:13px;resize:vertical;"></textarea>
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('notesModal')">Cancel</button>
                <button class="btn btn-primary" onclick="saveNotes()">Save</button>
            </div>
        </div>
    </div>

    <!-- Edit Site Modal -->
    <div class="modal-overlay" id="editSiteModal">
        <div class="modal">
            <h3>Edit Site</h3>
            <input type="hidden" id="editSiteIndex">
            <div class="form-group">
                <label>Site Name</label>
                <input type="text" id="editSiteName">
            </div>
            <div class="form-group">
                <label>Telegram Group Chat ID</label>
                <input type="text" id="editSiteTelegram" placeholder="e.g. -100123456789">
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('editSiteModal')">Cancel</button>
                <button class="btn btn-primary" onclick="saveSiteEdit()">Save</button>
            </div>
        </div>
    </div>

    <!-- Edit Device Modal -->
    <div class="modal-overlay" id="editDeviceModal">
        <div class="modal">
            <h3>Edit Device</h3>
            <input type="hidden" id="editDevSiteIndex">
            <input type="hidden" id="editDevIndex">
            <div class="form-group">
                <label>Device Name</label>
                <input type="text" id="editDevName">
            </div>
            <div class="form-group">
                <label>Type</label>
                <input type="text" id="editDevType" disabled style="opacity:0.6">
            </div>
            <div class="form-group">
                <label>IP Address</label>
                <input type="text" id="editDevIP">
            </div>
            <div class="form-group">
                <label>Port</label>
                <input type="number" id="editDevPort">
            </div>
            <div class="form-group">
                <label>Username</label>
                <input type="text" id="editDevUser">
            </div>
            <div class="form-group">
                <label>Password <span onclick="toggleEditPw()" style="cursor:pointer;color:#4ecca3;font-size:10px;" id="editPwToggle">show</span></label>
                <input type="password" id="editDevPass">
            </div>
            <div class="modal-actions">
                <button class="btn btn-secondary" onclick="closeModal('editDeviceModal')">Cancel</button>
                <button class="btn btn-primary" onclick="saveDeviceEdit()">Save</button>
            </div>
        </div>
    </div>

    <script>
        var config = null;
        var state = null;

        function esc(s) {
            if (!s) return '';
            var d = document.createElement('div');
            d.textContent = s;
            return d.innerHTML;
        }

        // Render an IP as a clickable link that opens http://ip[:port] in a new tab.
        // Only works from a network with routing to the IP (LAN or Tailscale + subnet routes).
        function ipLink(ip, port) {
            if (!ip) return '';
            var url = 'http://' + ip + (port && port != 80 ? ':' + port : '');
            return '<a class="ip-link" href="' + esc(url) + '" target="_blank" rel="noopener" title="Open ' + esc(url) + '">' + esc(ip) + '</a>';
        }

        // Flash the refresh indicator dot briefly on every successful data reload
        function pulseRefresh() {
            var el = document.getElementById('refreshPulse');
            if (!el) return;
            el.classList.remove('flash');
            // Force reflow so the animation restarts even if already applied
            void el.offsetWidth;
            el.classList.add('flash');
        }

        // Filter visible cards in a container by query (matches card.textContent)
        function applyFilter(containerSelector, cardSelector, query) {
            var q = (query || '').toLowerCase().trim();
            document.querySelectorAll(containerSelector + ' ' + cardSelector).forEach(function(card) {
                var match = !q || card.textContent.toLowerCase().indexOf(q) >= 0;
                card.style.display = match ? '' : 'none';
            });
        }

        // Preserve a filter input's value across panel re-renders (which nuke the DOM).
        // Call BEFORE setting innerHTML to capture, then call AFTER to restore + re-apply.
        var _filterCache = {};
        function saveFilter(inputId) {
            var el = document.getElementById(inputId);
            if (el) _filterCache[inputId] = el.value;
        }
        function restoreFilter(inputId, containerSelector, cardSelector) {
            var val = _filterCache[inputId];
            if (!val) return;
            var el = document.getElementById(inputId);
            if (el) {
                el.value = val;
                applyFilter(containerSelector, cardSelector, val);
            }
        }

        function showTab(name) {
            document.querySelectorAll('.tab').forEach(function(t) { t.classList.remove('active'); });
            document.querySelectorAll('.panel').forEach(function(p) { p.classList.remove('active'); });
            event.target.classList.add('active');
            document.getElementById('panel-' + name).classList.add('active');
            if (name === 'status') loadStatus();
            if (name === 'manage') loadManage();
            if (name === 'vpn') loadVPN();
            if (name === 'scanner') {}
            if (name === 'devicelogs') initDeviceLogs();
            if (name === 'logs') loadLogs();
        }

        function api(method, path, body, cb) {
            var x = new XMLHttpRequest();
            x.open(method, path);
            x.setRequestHeader('Content-Type', 'application/json');
            x.onload = function() { cb(JSON.parse(x.responseText)); };
            x.onerror = function() { cb({error: 'Request failed'}); };
            if (body) x.send(JSON.stringify(body));
            else x.send();
        }

        function loadStatus() {
            api('GET', '/api/status', null, function(data) {
                state = data.state;
                config = data.config;
                var html = '';
                var lastCheck = state.last_check || 'Never';
                document.getElementById('lastCheckText').textContent = 'Last check: ' + lastCheck;
                pulseRefresh();

                if (!config.sites || config.sites.length === 0) {
                    html = '<div class="empty">No sites configured. Go to Manage to add sites.</div>';
                } else {
                    if (config.sites.length > 4) {
                        html += '<input type="text" class="filter-box" id="statusFilter" placeholder="🔍 Filter sites..." oninput="applyFilter(&#39;#panel-status&#39;, &#39;.site-card&#39;, this.value)">';
                    }
                    config.sites.forEach(function(site) {
                        var siteState = (state.sites || {})[site.name] || [];
                        var allOnline = siteState.every(function(d) { return d.online; });
                        var offlineCount = siteState.filter(function(d) { return !d.online; }).length;

                        html += '<div class="site-card">';
                        html += '<div class="site-header"><span class="site-name">' + esc(site.name) + '</span>';
                        html += '<span class="site-status ' + (allOnline ? 'ok' : 'alert') + '">';
                        html += allOnline ? 'All OK' : offlineCount + ' issue(s)';
                        html += '</span></div>';
                        html += '<div class="device-list">';

                        site.devices.forEach(function(dev) {
                            var devState = siteState.find(function(s) { return s.ip === dev.ip; }) || {};
                            var online = devState.online || false;

                            html += '<div class="device-row">';
                            html += '<div class="device-dot ' + (online ? 'online' : 'offline') + '"></div>';
                            html += '<div class="device-info"><div class="device-name">' + esc(dev.name) + '</div>';
                            html += '<div class="device-ip">' + ipLink(dev.ip, dev.port) + ':' + (dev.port || 80) + ' — ' + esc(dev.type) + '</div>';

                            if (devState.cameras && devState.cameras.length > 0) {
                                html += '<div class="cam-list">';
                                devState.cameras.forEach(function(cam) {
                                    html += '<div class="cam-dot ' + (cam.online ? 'on' : 'off') + '" title="CH' + cam.id + ' ' + cam.ip + ' ' + cam.status + '"></div>';
                                });
                                html += '</div>';
                            }
                            html += '</div>';

                            html += '<div class="device-detail">';
                            if (devState.device_info && devState.device_info.model) {
                                html += esc(devState.device_info.model) + '<br>';
                            }
                            if (devState.hdds && devState.hdds.length > 0) {
                                html += devState.hdds.length + ' HDD(s)<br>';
                            }
                            if (devState.uptime) {
                                var h = Math.floor(devState.uptime / 3600);
                                var m = Math.floor((devState.uptime % 3600) / 60);
                                html += 'Up ' + h + 'h ' + m + 'm';
                            }
                            html += '</div></div>';
                        });

                        html += '</div></div>';
                    });
                }

                saveFilter('statusFilter');
                document.getElementById('panel-status').innerHTML = html;
                restoreFilter('statusFilter', '#panel-status', '.site-card');
            });
        }

        function loadManage() {
            api('GET', '/api/config/manage', null, function(data) {
                config = data;
                var html = '<button class="btn btn-primary" onclick="openAddSite()" style="margin-bottom:16px">+ Add Site</button>';

                if (!config.sites || config.sites.length === 0) {
                    html += '<div class="empty">No sites yet. Click "Add Site" to get started.</div>';
                } else {
                    config.sites.forEach(function(site, si) {
                        html += '<div class="site-manage">';
                        html += '<div class="site-manage-header"><h3>' + esc(site.name) + '</h3>';
                        html += '<div>';
                        html += '<button class="btn btn-secondary" onclick="editSite(' + si + ')" style="margin-right:6px">Edit</button>';
                        html += '<button class="btn btn-secondary" onclick="openNotes(' + si + ',&quot;' + esc(site.name) + '&quot;)" style="margin-right:6px">Notes</button>';
                        html += '<button class="btn btn-secondary" onclick="openEditNotifications(' + si + ')" style="margin-right:6px" title="Which alerts the client chat receives">🔔 Notifications</button>';
                        var muted = site.mute_until && site.mute_until > (Date.now() / 1000);
                        if (muted) {
                            var until = new Date(site.mute_until * 1000).toLocaleTimeString([], {hour: '2-digit', minute: '2-digit'});
                            html += '<button class="btn btn-secondary" style="margin-right:6px;background:#553a1a;color:#ffb73d" onclick="unmuteSite(' + si + ')" title="Unmute now">🔕 Muted until ' + esc(until) + ' — Unmute</button>';
                        } else {
                            html += '<button class="btn btn-secondary" onclick="openMute(' + si + ')" style="margin-right:6px" title="Suppress all alerts while doing maintenance">🔕 Mute</button>';
                        }
                        html += '<button class="btn btn-secondary" onclick="openSLA(' + si + ')" style="margin-right:6px" title="Uptime report">📊 SLA</button>';
                        html += '<button class="btn btn-primary" onclick="openAddDevice(' + si + ')" style="margin-right:6px">+ Device</button>';
                        html += '<button class="btn btn-danger" onclick="removeSite(' + si + ')">Delete</button>';
                        html += '</div></div>';
                        if (site.telegram_chat_id) {
                            html += '<div style="padding:4px 16px;color:#666;font-size:11px;">Telegram: ' + esc(site.telegram_chat_id) + '</div>';
                        }

                        if (site.devices.length === 0) {
                            html += '<div class="empty" style="padding:16px">No devices. Click "+ Device" to add one.</div>';
                        } else {
                            site.devices.forEach(function(dev, di) {
                                html += '<div class="device-manage-row">';
                                html += '<div class="device-manage-info"><div class="device-manage-name">' + esc(dev.name) + '</div>';
                                html += '<div class="device-manage-type">' + esc(dev.type) + ' — ' + ipLink(dev.ip, dev.port) + ':' + (dev.port || 80);
                                if (dev.username) html += ' — ' + esc(dev.username) + ':<span id="pw-' + si + '-' + di + '">••••••</span> <span onclick="togglePw(' + si + ',' + di + ')" style="cursor:pointer;color:#4ecca3;font-size:10px;" id="pwbtn-' + si + '-' + di + '">show</span>';
                                html += '</div></div>';
                                html += '<div>';
                                html += '<button class="btn btn-secondary" onclick="editDevice(' + si + ',' + di + ')" style="margin-right:6px;font-size:11px;padding:4px 10px">Edit</button>';
                                html += '<button class="btn btn-danger" onclick="removeDevice(' + si + ',' + di + ')" style="font-size:11px;padding:4px 10px">Remove</button>';
                                html += '</div></div>';
                            });
                        }
                        html += '</div>';
                    });
                }

                document.getElementById('panel-manage').innerHTML = html;
            });
        }

        function loadLogs() {
            // Populate site filter dropdown
            api('GET', '/api/config', null, function(cfg) {
                var siteSelect = document.getElementById('logFilter');
                var devSelect = document.getElementById('logDeviceFilter');
                var currentSite = siteSelect.value;
                var currentDev = devSelect.value;

                // Only rebuild if empty (first load)
                if (siteSelect.options.length <= 1) {
                    siteSelect.innerHTML = '<option value="all">ყველა ობიექტი</option>';
                    devSelect.innerHTML = '<option value="all">ყველა მოწყობილობა</option>';
                    cfg.sites.forEach(function(site) {
                        siteSelect.innerHTML += '<option value="' + site.name + '">' + site.name + '</option>';
                        site.devices.forEach(function(dev) {
                            devSelect.innerHTML += '<option value="' + dev.ip + '">' + dev.name + ' (' + dev.ip + ')</option>';
                        });
                    });
                    siteSelect.value = currentSite;
                    devSelect.value = currentDev;
                }
            });

            var site = document.getElementById('logFilter').value;
            var device = document.getElementById('logDeviceFilter').value;
            var type = document.getElementById('logType').value;
            var count = document.getElementById('logCount').value;

            var url = '/api/logs?count=' + count;
            if (site !== 'all') url += '&site=' + encodeURIComponent(site);
            if (device !== 'all') url += '&device=' + encodeURIComponent(device);
            if (type === 'alerts') url += '&alerts=1';

            api('GET', url, null, function(data) {
                document.getElementById('logContent').textContent = data.logs || 'ჩანაწერები არ მოიძებნა';
            });
        }

        function openModal(id) { document.getElementById(id).classList.add('show'); }
        function closeModal(id) { document.getElementById(id).classList.remove('show'); document.getElementById('testResult').innerHTML = ''; }

        function openAddDevice(siteIndex) {
            document.getElementById('deviceSiteIndex').value = siteIndex;
            document.getElementById('deviceName').value = '';
            document.getElementById('deviceIP').value = '';
            document.getElementById('devicePort').value = '80';
            document.getElementById('deviceUser').value = '';
            document.getElementById('devicePass').value = '';
            document.getElementById('testResult').innerHTML = '';
            openModal('addDeviceModal');
        }

        function toggleCredFields() {
            var t = document.getElementById('deviceType').value;
            var needsCreds = ['hikvision_nvr','dahua_nvr','uniview_nvr','hanwha_nvr','axis_device','bosch_device','onvif_device','auto_nvr'].indexOf(t) >= 0;
            var needsSnmp = ['switch','poe_switch','router','firewall','access_point','ups','printer','voip_phone','pbx','nas','server'].indexOf(t) >= 0;
            document.getElementById('credFields').style.display = needsCreds ? 'block' : 'none';
            document.getElementById('snmpFields').style.display = needsSnmp ? 'block' : 'none';
        }

        var NOTIF_CATEGORIES = null;  // loaded lazily
        function loadNotifCategories(cb) {
            if (NOTIF_CATEGORIES) { cb(NOTIF_CATEGORIES); return; }
            api('GET', '/api/notification-categories', null, function(data) {
                NOTIF_CATEGORIES = (data && data.categories) || [];
                cb(NOTIF_CATEGORIES);
            });
        }

        // Track current state per checkbox key per container so tab switches
        // preserve unsaved changes even while only one tab's DOM is rendered.
        var notifState = {};  // notifState[containerId] = {key: bool, ...}

        function renderNotifChecks(containerId, prefs, idPrefix) {
            loadNotifCategories(function(cats) {
                // Seed state with current prefs (defaulting missing to true)
                var state = {};
                cats.forEach(function(c) {
                    state[c.key] = (prefs && c.key in prefs) ? !!prefs[c.key] : true;
                });
                notifState[containerId] = state;
                // Render the initial active tab (default: nvr)
                renderNotifTab(containerId, idPrefix, 'nvr');
            });
        }

        function renderNotifTab(containerId, idPrefix, group) {
            var box = document.getElementById(containerId);
            if (!box) return;
            var cats = (NOTIF_CATEGORIES || []).filter(function(c) {
                return (c.groups || []).indexOf(group) !== -1;
            });
            var state = notifState[containerId] || {};
            box.innerHTML = '';
            box.style.display = 'grid';
            box.style.gridTemplateColumns = '1fr 1fr';
            box.style.gap = '6px 14px';
            cats.forEach(function(c) {
                var row = document.createElement('label');
                row.style.cssText = 'display:flex;align-items:center;gap:8px;font-size:13px;color:#ccc;cursor:pointer;';
                var cb = document.createElement('input');
                cb.type = 'checkbox';
                cb.id = idPrefix + '-' + c.key;
                cb.dataset.key = c.key;
                cb.dataset.container = containerId;
                cb.checked = state[c.key] !== false;  // default true
                cb.style.cssText = 'width:15px;height:15px;accent-color:#4ecca3;';
                cb.addEventListener('change', function() {
                    // Keep state in sync so switching tabs preserves the value
                    notifState[containerId][c.key] = cb.checked;
                });
                row.appendChild(cb);
                var text = document.createElement('span');
                text.textContent = c.label;
                row.appendChild(text);
                box.appendChild(row);
            });
        }

        function switchNotifTab(btn) {
            var containerId = btn.dataset.target;
            var group = btn.dataset.group;
            // flush current checkbox values into state before switching
            var box = document.getElementById(containerId);
            if (box) {
                box.querySelectorAll('input[type="checkbox"][data-key]').forEach(function(cb) {
                    notifState[containerId][cb.dataset.key] = cb.checked;
                });
            }
            // toggle button visual state for this group of tabs
            var siblings = document.querySelectorAll('.notif-tab-btn[data-target="' + containerId + '"]');
            siblings.forEach(function(b) {
                if (b === btn) {
                    b.classList.add('active');
                    b.style.background = '#2a2a5a';
                    b.style.color = '#fff';
                } else {
                    b.classList.remove('active');
                    b.style.background = '#1a1a3a';
                    b.style.color = '#aaa';
                }
            });
            // Figure out idPrefix from any existing checkbox in the box
            var idPrefix = 'notif';
            var firstCb = box ? box.querySelector('input[type="checkbox"][data-key]') : null;
            if (firstCb) {
                idPrefix = firstCb.id.replace(/-[^-]+$/, '');
            } else if (containerId === 'siteNotifChecks') {
                idPrefix = 'new-notif';
            } else if (containerId === 'editNotifChecks') {
                idPrefix = 'edit-notif';
            }
            renderNotifTab(containerId, idPrefix, group);
        }

        function collectNotifChecks(containerId) {
            // Flush currently-rendered tab into state
            var box = document.getElementById(containerId);
            if (box) {
                box.querySelectorAll('input[type="checkbox"][data-key]').forEach(function(cb) {
                    if (!notifState[containerId]) notifState[containerId] = {};
                    notifState[containerId][cb.dataset.key] = cb.checked;
                });
            }
            // Return the cumulative state (has every key, both tabs)
            return notifState[containerId] || {};
        }

        function resetNotifTabs(containerId) {
            var btns = document.querySelectorAll('.notif-tab-btn[data-target="' + containerId + '"]');
            btns.forEach(function(b, i) {
                if (b.dataset.group === 'nvr') {
                    b.classList.add('active');
                    b.style.background = '#2a2a5a';
                    b.style.color = '#fff';
                } else {
                    b.classList.remove('active');
                    b.style.background = '#1a1a3a';
                    b.style.color = '#aaa';
                }
            });
        }

        function openAddSite() {
            document.getElementById('siteName').value = '';
            document.getElementById('siteTelegramId').value = '';
            resetNotifTabs('siteNotifChecks');
            renderNotifChecks('siteNotifChecks', null, 'new-notif');
            // Load unlinked VPN sites
            api('GET', '/api/vpn/unlinked', null, function(data) {
                var sel = document.getElementById('vpnSiteSelect');
                var wrap = document.getElementById('vpnSiteList');
                sel.innerHTML = '<option value="">-- ახალი ობიექტი (ხელით) --</option>';
                if (data && data.length > 0) {
                    data.forEach(function(s) {
                        var icon = s.connected ? '🟢' : '🔴';
                        sel.innerHTML += '<option value="' + esc(s.name) + '">' + icon + ' ' + esc(s.name) + ' (VPN: ' + esc(s.client_ip) + ')</option>';
                    });
                    wrap.style.display = 'block';
                } else {
                    wrap.style.display = 'none';
                }
            });
            openModal('addSiteModal');
        }

        function vpnSiteSelected() {
            var name = document.getElementById('vpnSiteSelect').value;
            if (name) {
                document.getElementById('siteName').value = name;
            }
        }

        function addSite() {
            var name = document.getElementById('siteName').value.trim();
            if (!name) return;
            var chatId = document.getElementById('siteTelegramId').value.trim();
            var notifs = collectNotifChecks('siteNotifChecks');
            api('POST', '/api/sites', {name: name, telegram_chat_id: chatId, notifications: notifs}, function(data) {
                closeModal('addSiteModal');
                document.getElementById('siteName').value = '';
                document.getElementById('siteTelegramId').value = '';
                document.getElementById('vpnSiteSelect').value = '';
                loadManage();
            });
        }

        var currentNotifSite = null;
        function openEditNotifications(si) {
            currentNotifSite = si;
            var site = config.sites[si];
            document.getElementById('editNotifSiteName').textContent = site.name;
            resetNotifTabs('editNotifChecks');
            renderNotifChecks('editNotifChecks', site.notifications || {}, 'edit-notif');
            openModal('editNotifModal');
        }

        function saveNotifications() {
            if (currentNotifSite === null) return;
            var notifs = collectNotifChecks('editNotifChecks');
            api('POST', '/api/sites/' + currentNotifSite + '/notifications', {notifications: notifs}, function(data) {
                closeModal('editNotifModal');
                currentNotifSite = null;
                loadManage();
            });
        }

        // === Mute (maintenance mode) ===
        var currentMuteSite = null;
        function openMute(si) {
            currentMuteSite = si;
            var name = (config && config.sites && config.sites[si]) ? config.sites[si].name : '';
            document.getElementById('muteSiteName').textContent = name;
            document.getElementById('muteCustomMin').value = '';
            openModal('muteModal');
        }
        function applyMute(minutes) {
            if (currentMuteSite === null) return;
            api('POST', '/api/sites/' + currentMuteSite + '/mute', {minutes: minutes}, function(data) {
                closeModal('muteModal');
                currentMuteSite = null;
                loadManage();
            });
        }
        function applyMuteCustom() {
            var min = parseInt(document.getElementById('muteCustomMin').value, 10);
            if (!min || min < 1 || min > 10080) { alert('Enter 1..10080 minutes'); return; }
            applyMute(min);
        }
        function unmuteSite(si) {
            api('POST', '/api/sites/' + si + '/unmute', {}, function() { loadManage(); });
        }

        // === SLA report ===
        var currentSLASite = null;
        function openSLA(si) {
            currentSLASite = si;
            var name = (config && config.sites && config.sites[si]) ? config.sites[si].name : '';
            document.getElementById('slaSiteName').textContent = name;
            document.getElementById('slaContent').innerHTML = '<div class="empty">Loading…</div>';
            openModal('slaModal');
            loadSLA(30);
        }
        function fmtDuration(sec) {
            if (sec === 0 || sec == null) return '0';
            if (sec < 60) return sec + 's';
            if (sec < 3600) return Math.round(sec / 60) + 'm';
            if (sec < 86400) {
                var h = Math.floor(sec / 3600);
                var m = Math.round((sec % 3600) / 60);
                return h + 'h ' + m + 'm';
            }
            var d = Math.floor(sec / 86400);
            var h = Math.round((sec % 86400) / 3600);
            return d + 'd ' + h + 'h';
        }
        function loadSLA(days) {
            if (currentSLASite === null) return;
            api('GET', '/api/sites/' + currentSLASite + '/sla?days=' + days, null, function(data) {
                if (data.error) {
                    document.getElementById('slaContent').innerHTML = '<div class="empty">' + esc(data.error) + '</div>';
                    return;
                }
                var devs = data.devices || {};
                var rows = Object.keys(devs).map(function(ip) { return Object.assign({ip: ip}, devs[ip]); });
                rows.sort(function(a, b) { return a.uptime_percent - b.uptime_percent; });

                var pct = data.site_uptime_percent;
                var pctColor = pct >= 99.5 ? '#4ecca3' : pct >= 98 ? '#ffb73d' : '#e94560';
                var html = '<div style="display:grid;grid-template-columns:1fr 1fr 1fr;gap:12px;margin-bottom:16px;">';
                html += '<div style="padding:12px;background:#0f0f28;border-radius:6px;text-align:center;">';
                html += '<div style="font-size:11px;color:#888;">Site uptime (' + data.window_days + 'd)</div>';
                html += '<div style="font-size:26px;color:' + pctColor + ';font-weight:bold;">' + pct.toFixed(2) + '%</div>';
                html += '</div>';
                html += '<div style="padding:12px;background:#0f0f28;border-radius:6px;text-align:center;">';
                html += '<div style="font-size:11px;color:#888;">Incidents</div>';
                html += '<div style="font-size:26px;color:#fff;font-weight:bold;">' + data.total_incidents + '</div>';
                html += '</div>';
                html += '<div style="padding:12px;background:#0f0f28;border-radius:6px;text-align:center;">';
                html += '<div style="font-size:11px;color:#888;">Longest outage</div>';
                html += '<div style="font-size:20px;color:#fff;font-weight:bold;">' + fmtDuration(data.longest_outage_sec) + '</div>';
                html += '</div>';
                html += '</div>';

                html += '<div style="font-size:12px;color:#888;margin-bottom:6px;">Period: ' + esc(data.period_start) + ' → ' + esc(data.period_end) + '</div>';

                if (rows.length === 0) {
                    html += '<div class="empty">No outage events recorded in this window. Either all devices stayed up, or monitoring started less than ' + data.window_days + ' days ago.</div>';
                } else {
                    html += '<table style="width:100%;border-collapse:collapse;font-size:13px;">';
                    html += '<tr style="border-bottom:1px solid #2a2a5a;color:#888;"><th style="text-align:left;padding:6px;">Device</th><th style="text-align:right;padding:6px;">Uptime</th><th style="text-align:right;padding:6px;">Incidents</th><th style="text-align:right;padding:6px;">Longest</th><th style="text-align:right;padding:6px;">Total down</th></tr>';
                    rows.forEach(function(r) {
                        var c = r.uptime_percent >= 99.5 ? '#4ecca3' : r.uptime_percent >= 98 ? '#ffb73d' : '#e94560';
                        html += '<tr style="border-bottom:1px solid #1a1a3a;">';
                        html += '<td style="padding:6px;">' + esc(r.name) + '</td>';
                        html += '<td style="padding:6px;text-align:right;color:' + c + ';">' + r.uptime_percent.toFixed(2) + '%</td>';
                        html += '<td style="padding:6px;text-align:right;">' + r.incidents + '</td>';
                        html += '<td style="padding:6px;text-align:right;">' + fmtDuration(r.longest_outage_sec) + '</td>';
                        html += '<td style="padding:6px;text-align:right;">' + fmtDuration(r.total_outage_sec) + '</td>';
                        html += '</tr>';
                    });
                    html += '</table>';
                }
                document.getElementById('slaContent').innerHTML = html;
            });
        }

        function removeSite(index) {
            if (confirm('Delete this site and all its devices?')) {
                api('DELETE', '/api/sites/' + index, null, function() { loadManage(); });
            }
        }

        function togglePw(si, di) {
            var el = document.getElementById('pw-' + si + '-' + di);
            var btn = document.getElementById('pwbtn-' + si + '-' + di);
            if (el.textContent !== '••••••') {
                el.textContent = '••••••';
                btn.textContent = 'show';
                return;
            }
            btn.textContent = '...';
            api('GET', '/api/device-password/' + si + '/' + di, null, function(data) {
                el.textContent = data.password || '?';
                btn.textContent = 'hide';
                setTimeout(function() {
                    el.textContent = '••••••';
                    btn.textContent = 'show';
                }, 5000);
            });
        }

        function editSite(si) {
            var site = config.sites[si];
            document.getElementById('editSiteIndex').value = si;
            document.getElementById('editSiteName').value = site.name;
            document.getElementById('editSiteTelegram').value = site.telegram_chat_id || '';
            openModal('editSiteModal');
        }

        function saveSiteEdit() {
            var si = document.getElementById('editSiteIndex').value;
            var name = document.getElementById('editSiteName').value.trim();
            var telegram = document.getElementById('editSiteTelegram').value.trim();
            if (!name) return;
            api('POST', '/api/sites/' + si + '/edit', {name: name, telegram_chat_id: telegram}, function() {
                closeModal('editSiteModal');
                loadManage();
            });
        }

        function toggleEditPw() {
            var el = document.getElementById('editDevPass');
            var btn = document.getElementById('editPwToggle');
            if (el.type === 'password') {
                el.type = 'text';
                btn.textContent = 'hide';
                setTimeout(function() { el.type = 'password'; btn.textContent = 'show'; }, 5000);
            } else {
                el.type = 'password';
                btn.textContent = 'show';
            }
        }

        function editDevice(si, di) {
            var dev = config.sites[si].devices[di];
            document.getElementById('editDevSiteIndex').value = si;
            document.getElementById('editDevIndex').value = di;
            document.getElementById('editDevName').value = dev.name || '';
            document.getElementById('editDevType').value = dev.type || '';
            document.getElementById('editDevIP').value = dev.ip || '';
            document.getElementById('editDevPort').value = dev.port || 80;
            document.getElementById('editDevUser').value = dev.username || '';
            document.getElementById('editDevPass').value = '';
            // Fetch actual password from server
            api('GET', '/api/device-password/' + si + '/' + di, null, function(data) {
                document.getElementById('editDevPass').value = data.password || '';
            });
            openModal('editDeviceModal');
        }

        function saveDeviceEdit() {
            var si = document.getElementById('editDevSiteIndex').value;
            var di = document.getElementById('editDevIndex').value;
            var data = {
                name: document.getElementById('editDevName').value.trim(),
                ip: document.getElementById('editDevIP').value.trim(),
                port: parseInt(document.getElementById('editDevPort').value) || 80,
                username: document.getElementById('editDevUser').value.trim(),
                password: document.getElementById('editDevPass').value
            };
            api('POST', '/api/sites/' + si + '/devices/' + di + '/edit', data, function() {
                closeModal('editDeviceModal');
                loadManage();
            });
        }

        function addDevice() {
            var si = document.getElementById('deviceSiteIndex').value;
            var dev = {
                name: document.getElementById('deviceName').value.trim(),
                type: document.getElementById('deviceType').value,
                ip: document.getElementById('deviceIP').value.trim(),
                port: parseInt(document.getElementById('devicePort').value) || 80,
                monitor: { ping: true }
            };
            if (dev.type.indexOf('nvr') >= 0) {
                dev.username = document.getElementById('deviceUser').value.trim();
                dev.password = document.getElementById('devicePass').value;
                dev.monitor = { ping: true, hdd_health: true, camera_status: true, uptime: true };
            }
            if (dev.type === 'switch' || dev.type === 'router' || dev.type === 'access_point') {
                dev.snmp_community = document.getElementById('snmpCommunity').value.trim() || 'public';
                dev.monitor = { ping: true };
            }
            if (!dev.name || !dev.ip) return;
            api('POST', '/api/sites/' + si + '/devices', dev, function() {
                closeModal('addDeviceModal');
                loadManage();
            });
        }

        function removeDevice(si, di) {
            if (confirm('Remove this device?')) {
                api('DELETE', '/api/sites/' + si + '/devices/' + di, null, function() { loadManage(); });
            }
        }

        function testConnection() {
            var ip = document.getElementById('deviceIP').value.trim();
            var port = parseInt(document.getElementById('devicePort').value) || 80;
            var type = document.getElementById('deviceType').value;
            var user = document.getElementById('deviceUser').value.trim();
            var pass = document.getElementById('devicePass').value;

            document.getElementById('testResult').innerHTML = '<div class="test-result" style="background:#1a1a3a;color:#888">Testing...</div>';

            api('POST', '/api/test', {ip: ip, port: port, type: type, username: user, password: pass}, function(data) {
                var el = document.getElementById('testResult');
                if (data.ping && (data.api || type !== 'hikvision_nvr')) {
                    var info = data.info || {};
                    el.innerHTML = '<div class="test-result success">✓ Connected!' +
                        (info.model ? ' — ' + info.model : '') +
                        (info.firmware ? ' (FW: ' + info.firmware + ')' : '') + '</div>';
                } else {
                    el.innerHTML = '<div class="test-result error">✗ ' + (data.error || 'Connection failed') + '</div>';
                }
            });
        }

        function openNotes(siteIndex, siteName) {
            document.getElementById('notesSiteIndex').value = siteName;
            document.getElementById('notesTitle').textContent = 'Notes - ' + siteName;
            // Load existing notes
            api('GET', '/api/notes/' + encodeURIComponent(siteName), null, function(data) {
                document.getElementById('notesRouter').value = data.router || '';
                document.getElementById('notesAddress').value = data.address || '';
                document.getElementById('notesContact').value = data.contact || '';
                document.getElementById('notesPublicIP').value = data.public_ip || '';
                document.getElementById('notesText').value = data.notes || '';
            });
            openModal('notesModal');
        }

        function saveNotes() {
            var siteName = document.getElementById('notesSiteIndex').value;
            var data = {
                router: document.getElementById('notesRouter').value,
                address: document.getElementById('notesAddress').value,
                contact: document.getElementById('notesContact').value,
                public_ip: document.getElementById('notesPublicIP').value,
                notes: document.getElementById('notesText').value
            };
            api('POST', '/api/notes/' + encodeURIComponent(siteName), data, function() {
                closeModal('notesModal');
            });
        }

        function startScan(quick) {
            var subnet = document.getElementById('scanSubnet').value.trim();
            if (!subnet) { alert('Enter a subnet'); return; }

            document.getElementById('scanResults').innerHTML = '<div class="site-card" style="padding:20px;text-align:center;color:#888">Scanning ' + subnet + '... this may take a minute</div>';

            api('POST', '/api/scan', {subnet: subnet, quick: quick}, function(data) {
                if (data.error) {
                    document.getElementById('scanResults').innerHTML = '<div class="site-card" style="padding:16px;color:#e94560">' + data.error + '</div>';
                    return;
                }

                var html = '<div style="margin:12px 0;color:#888;font-size:13px">Found <b style="color:#4ecca3">' + data.device_count + '</b> devices on ' + data.subnet + '</div>';

                var typeIcons = {nvr:'🎬', camera_or_nvr:'📹', ip_camera:'📷', router:'🌐', network_equipment:'🔌',
                    voip:'📞', ups:'🔋', server:'🖥', printer:'🖨', nas:'💾', snmp_device:'📊', unknown:'❓'};

                var typeLabels = {nvr:'NVR/DVR', camera_or_nvr:'Camera/NVR', ip_camera:'IP Camera', router:'Router',
                    network_equipment:'Network Equipment', voip:'VoIP', ups:'UPS', server:'Server', printer:'Printer',
                    nas:'NAS', snmp_device:'SNMP Device', unknown:'Unknown'};

                // Show changes from previous scan
                if (data.changes) {
                    var ch = data.changes;
                    if (ch.new_devices && ch.new_devices.length > 0) {
                        html += '<div style="background:#1a3a2a;border:1px solid #2a5a3a;border-radius:6px;padding:10px;margin-bottom:8px;color:#4ecca3;font-size:13px">';
                        html += '🆕 New devices since last scan: <b>' + ch.new_devices.join(', ') + '</b></div>';
                    }
                    if (ch.missing_devices && ch.missing_devices.length > 0) {
                        html += '<div style="background:#3a1a1a;border:1px solid #5a2a2a;border-radius:6px;padding:10px;margin-bottom:8px;color:#e94560;font-size:13px">';
                        html += '❌ Missing since last scan: <b>' + ch.missing_devices.join(', ') + '</b></div>';
                    }
                    if (ch.previous_scan && ch.previous_scan !== 'never') {
                        html += '<div style="color:#555;font-size:11px;margin-bottom:8px">Previous scan: ' + ch.previous_scan + '</div>';
                    }
                }

                data.devices.forEach(function(dev) {
                    var icon = typeIcons[dev.device_type] || '❓';
                    var label = typeLabels[dev.device_type] || dev.device_type;
                    var vendor = dev.brand ? dev.brand.charAt(0).toUpperCase() + dev.brand.slice(1) : dev.mac_vendor || 'Unknown';
                    var info = dev.device_info || {};

                    var borderColor = dev.is_new ? '#4ecca3' : '#1e1e3a';
                    html += '<div class="device-row" style="background:#12122a;margin:4px 0;border-radius:6px;border:1px solid ' + borderColor + '">';
                    html += '<div style="font-size:24px;margin-right:12px">' + icon + '</div>';
                    html += '<div class="device-info" style="flex:1">';

                    var nameParts = [ipLink(dev.ip, 80)];
                    if (info.hostname) nameParts.push('(' + info.hostname + ')');
                    if (dev.is_new) nameParts.push('<span style="color:#4ecca3;font-size:10px">NEW</span>');
                    html += '<div class="device-name">' + nameParts.join(' ') + '</div>';

                    var detailParts = [vendor];
                    if (info.brand) detailParts = [info.brand];
                    if (info.model) detailParts.push(info.model);
                    detailParts.push(label);
                    if (dev.onvif) detailParts.push('ONVIF');
                    if (dev.snmp_info) detailParts.push('SNMP');
                    if (dev.open_ports && dev.open_ports.length) detailParts.push('Ports: ' + dev.open_ports.join(','));
                    html += '<div class="device-ip">' + detailParts.join(' | ') + '</div>';

                    if (info.onvif_name || info.onvif_hardware) {
                        html += '<div class="device-ip" style="color:#4ecca3">' + esc(info.onvif_name || '') + ' ' + esc(info.onvif_hardware || '') + '</div>';
                    }
                    if (info.snmp_description) {
                        html += '<div class="device-ip">' + esc(info.snmp_description.substring(0,80)) + '</div>';
                    }
                    if (dev.default_password) {
                        html += '<div class="device-ip" style="color:#e94560">⚠️ DEFAULT PASSWORD!</div>';
                    }

                    html += '<div class="device-ip">' + dev.mac + '</div>';
                    html += '</div>';
                    html += '<button class="btn btn-primary" style="font-size:11px;padding:4px 10px" onclick="addScannedDevice(&quot;' + dev.ip + '&quot;,&quot;' + vendor + '&quot;,&quot;' + dev.device_type + '&quot;)">+ Add</button>';
                    html += '</div>';
                });

                document.getElementById('scanResults').innerHTML = html;
            });
        }

        function addScannedDevice(ip, vendor, dtype) {
            var nvrTypes = {hikvision:'hikvision_nvr', dahua:'dahua_nvr', uniview:'uniview_nvr',
                samsung:'hanwha_nvr', axis:'axis_device', bosch:'bosch_device'};
            var deviceType = nvrTypes[vendor.toLowerCase()] || (dtype === 'nvr' || dtype === 'camera_or_nvr' ? 'auto_nvr' :
                dtype === 'router' || dtype === 'network_equipment' ? 'router' :
                dtype === 'ip_camera' ? 'ip_camera' :
                dtype === 'ups' ? 'ups' :
                dtype === 'printer' ? 'printer' :
                dtype === 'voip' ? 'voip_phone' : 'network_device');

            document.getElementById('deviceIP').value = ip;
            // Set the device type dropdown
            var sel = document.getElementById('deviceType');
            for (var i = 0; i < sel.options.length; i++) {
                if (sel.options[i].value === deviceType) { sel.selectedIndex = i; break; }
            }
            toggleCredFields();
            // Need to select which site to add to
            document.getElementById('deviceSiteIndex').value = '0';
            document.getElementById('deviceName').value = vendor + ' ' + ip;
            openModal('addDeviceModal');
        }

        function loadVPN() {
            api('GET', '/api/vpn', null, function(data) {
                var html = '<button class="btn btn-primary" onclick="openModal(&quot;addVPNModal&quot;)" style="margin-bottom:16px">+ Add VPN Site</button>';

                if (!data.sites || data.sites.length === 0) {
                    html += '<div class="empty">No VPN sites. Click "+ Add VPN Site" to connect a client site.</div>';
                } else {
                    if (data.sites.length > 4) {
                        html += '<input type="text" class="filter-box" id="vpnFilter" placeholder="🔍 Filter VPN sites..." oninput="applyFilter(&#39;#panel-vpn&#39;, &#39;.site-card&#39;, this.value)">';
                    }
                    data.sites.forEach(function(site) {
                        var connected = site.connected;
                        var now = Math.floor(Date.now() / 1000);
                        var hsAge = site.last_handshake ? (now - site.last_handshake) : null;
                        var hsText = 'never';
                        if (hsAge !== null) {
                            if (hsAge < 5) hsText = 'just now';
                            else if (hsAge < 60) hsText = hsAge + 's ago';
                            else if (hsAge < 3600) hsText = Math.floor(hsAge/60) + 'm ' + (hsAge%60) + 's ago';
                            else hsText = Math.floor(hsAge/3600) + 'h ago';
                        }
                        html += '<div class="site-card">';
                        html += '<div class="site-header">';
                        html += '<span class="site-name"><span class="device-dot ' + (connected ? 'online' : 'offline') + '" style="display:inline-block;vertical-align:middle;margin-right:8px"></span>' + esc(site.name) + '</span>';
                        html += '<span class="site-status ' + (connected ? 'ok' : 'alert') + '">' + (connected ? 'Connected' : 'Disconnected') + '</span>';
                        html += '</div>';
                        html += '<div class="device-list" style="padding:12px 16px">';
                        html += '<div style="display:flex;gap:24px;flex-wrap:wrap;font-size:13px;color:#888;">';
                        html += '<div>VPN IP: ' + ipLink(site.client_ip, 80) + '</div>';
                        // Multi-NAT: prefer nat_mappings (new format), fall back to legacy nat_subnet
                        var mappings = site.nat_mappings || [];
                        if (mappings.length) {
                            var natLines = mappings.map(function(m) {
                                return '<code>' + esc(m.local || '?') + '</code> → <code>' + esc(m.nat || '?') + '</code>';
                            }).join('<br>');
                            html += '<div style="flex:1 1 100%">NAT mappings:<br><span style="color:#fff;font-size:12px;line-height:1.7">' + natLines + '</span></div>';
                        } else if (site.nat_subnet) {
                            html += '<div>NAT: <span style="color:#fff">' + esc(site.nat_subnet) + '</span></div>';
                        }
                        html += '<div>Subnets: <span style="color:#fff">' + (site.subnets || []).map(esc).join(', ') + '</span></div>';
                        html += '<div>Router: <span style="color:#fff">' + esc(site.router_brand || 'unknown') + '</span></div>';
                        if (site.hardened) {
                            html += '<div>🔒 <span style="color:#4caf50">Hardened</span></div>';
                        }
                        html += '<div>Last handshake: <span style="color:' + (connected ? '#4caf50' : '#e94560') + '">' + hsText + '</span></div>';
                        if (site.endpoint) {
                            html += '<div>Endpoint: <span style="color:#fff">' + esc(site.endpoint) + '</span></div>';
                        }
                        var rx = ((site.rx_bytes || 0) / 1048576).toFixed(1);
                        var tx = ((site.tx_bytes || 0) / 1048576).toFixed(1);
                        html += '<div>Traffic: <span style="color:#fff">↓' + rx + 'MB ↑' + tx + 'MB</span></div>';
                        html += '</div>';
                        html += '<div style="margin-top:10px;display:flex;gap:6px">';
                        html += '<button class="btn btn-secondary" onclick="showVPNConfig(&quot;' + site.name + '&quot;)">Show Config</button>';
                        html += '<button class="btn btn-danger" onclick="removeVPNSite(&quot;' + site.name + '&quot;)">Remove</button>';
                        html += '</div></div></div>';
                    });
                }

                saveFilter('vpnFilter');
                document.getElementById('panel-vpn').innerHTML = html;
                restoreFilter('vpnFilter', '#panel-vpn', '.site-card');
                pulseRefresh();
            });
        }

        function addVPNSite() {
            var name = document.getElementById('vpnSiteName').value.trim();
            var subnets = document.getElementById('vpnSubnets').value.trim();
            var brand = document.getElementById('vpnRouterBrand').value;
            if (!name) return;

            api('POST', '/api/vpn/add', {name: name, subnets: subnets, brand: brand}, function(data) {
                closeModal('addVPNModal');
                if (data.error) {
                    alert(data.error);
                } else if (data.router_config) {
                    document.getElementById('vpnConfigTitle').textContent = name + ' - Router Config';
                    document.getElementById('vpnConfigContent').textContent = data.router_config;
                    openModal('vpnConfigModal');
                }
                document.getElementById('vpnSiteName').value = '';
                document.getElementById('vpnSubnets').value = '';
                loadVPN();
            });
        }

        function showVPNConfig(name) {
            api('GET', '/api/vpn/config/' + encodeURIComponent(name), null, function(data) {
                if (data.router_config) {
                    document.getElementById('vpnConfigTitle').textContent = name + ' - Router Config';
                    document.getElementById('vpnConfigContent').textContent = data.router_config;
                    openModal('vpnConfigModal');
                }
            });
        }

        function copyConfig() {
            var text = document.getElementById('vpnConfigContent').textContent;
            navigator.clipboard.writeText(text).then(function() {
                var msg = document.getElementById('vpnCopyMsg');
                msg.style.display = 'block';
                setTimeout(function() { msg.style.display = 'none'; }, 2000);
            });
        }

        function removeVPNSite(name) {
            if (confirm('Remove VPN site "' + name + '"?')) {
                api('DELETE', '/api/vpn/' + encodeURIComponent(name), null, function() { loadVPN(); });
            }
        }

        // ---- Device Logs ----
        var dlInited = false;
        var dlLoaded = false;
        function initDeviceLogs() {
            if (!dlInited) {
                var today = new Date().toISOString().split('T')[0];
                document.getElementById('dlDateFrom').value = today;
                document.getElementById('dlDateTo').value = today;
                api('GET', '/api/config', null, function(cfg) {
                    config = cfg;
                    var ss = document.getElementById('dlSite');
                    ss.innerHTML = '';
                    cfg.sites.forEach(function(site, si) {
                        ss.innerHTML += '<option value="' + si + '">' + site.name + '</option>';
                    });
                    dlUpdateDevices();
                    dlInited = true;
                    loadDeviceLogs();
                });
            }
            // Don't reload if already loaded — cache stays
        }

        function dlUpdateDevices() {
            var si = document.getElementById('dlSite').value;
            var ds = document.getElementById('dlDevice');
            ds.innerHTML = '';
            if (config && config.sites && config.sites[si]) {
                config.sites[si].devices.forEach(function(dev, di) {
                    if (dev.type === 'hikvision_nvr' || dev.type === 'auto_nvr') {
                        ds.innerHTML += '<option value="nvr:' + di + '">' + dev.name + ' (' + dev.ip + ')</option>';
                    }
                });
            }
            // Append syslog sources — every unique src IP that has sent messages
            api('GET', '/api/syslog/sources', null, function(data) {
                var sources = (data && data.sources) || [];
                // Map known IPs to config device names so they show friendly labels
                var knownByIp = {};
                if (config && config.sites) {
                    config.sites.forEach(function(site) {
                        (site.devices || []).forEach(function(d) {
                            knownByIp[d.ip] = d.name;
                        });
                    });
                }
                sources.sort(function(a, b) { return a.src.localeCompare(b.src); });
                sources.forEach(function(s) {
                    var label = knownByIp[s.src] || s.device || s.src;
                    var opt = document.createElement('option');
                    opt.value = 'syslog:' + s.src;
                    opt.textContent = label + ' (' + s.src + ') (syslog)';
                    ds.appendChild(opt);
                });
                if (ds.options.length === 0) {
                    ds.innerHTML = '<option value="">No supported devices</option>';
                }
            });
        }

        var dlTypeNames = {
            'motionStart': 'Motion Detected', 'motionStop': 'Motion Stopped',
            'lineDetectionStart': 'Line Crossing', 'lineDetectionStop': 'Line Crossing Stopped',
            'fieldDetectionStart': 'Intrusion Detected', 'fieldDetectionStop': 'Intrusion Stopped',
            'regionEntranceStart': 'Region Entry', 'regionExitingStart': 'Region Exit',
            'faceSnapStart': 'Face Detected', 'humanRecognitionStart': 'Person Detected',
            'vehicleDetectionStart': 'Vehicle Detected', 'fireDetectionStart': 'Fire Detected',
            'smokeDetectionStart': 'Smoke Detected',
            'videoLost': 'Video Lost', 'videoException': 'Video Error',
            'hdFull': 'HDD Full', 'hdError': 'HDD Error', 'hdBadBlock': 'HDD Bad Block',
            'highHDTemperature': 'HDD High Temp', 'severeHDFailure': 'HDD Critical Failure',
            'netBroken': 'Network Disconnected', 'ipConflict': 'IP Conflict',
            'ipcDisconnect': 'Camera Disconnected', 'recordError': 'Recording Error',
            'illlegealAccess': 'Illegal Access Attempt', 'raidError': 'RAID Error',
            'localLogin': 'Local Login', 'localLogOut': 'Local Logout',
            'remoteLogin': 'Remote Login', 'remoteLogout': 'Remote Logout',
            'localCfgPara': 'Local Config Change', 'remoteCfgPara': 'Remote Config Change',
            'localFormatDisk': 'HDD Formatted (Local)', 'remoteFormatHd': 'HDD Formatted (Remote)',
            'devicePowerOn': 'Power On', 'devicePowerOff': 'Power Off',
            'localUpdate': 'Firmware Update', 'remoteUpgrade': 'Remote Firmware Update',
            'localAddIpc': 'Camera Added', 'remoteAddIpc': 'Camera Added (Remote)',
            'localDelIpc': 'Camera Removed', 'remoteDelIpc': 'Camera Removed (Remote)',
            'hddInfo': 'HDD Info', 'startRec': 'Recording Started', 'stopRec': 'Recording Stopped',
            'hdFormatStart': 'HDD Format Started', 'hdFormatStop': 'HDD Format Complete',
            'runStatusInfo': 'System Status', 'ipcConnect': 'Camera Connected',
            'smartInfo': 'SMART Info', 'timing': 'Time Sync',
        };

        function dlFormatEvent(metaId) {
            var parts = metaId.replace('log.hikvision.com/', '').split('/');
            var type = parts[0];
            var event = parts[1] || '';
            var ch = parts[2] || '';
            var name = dlTypeNames[event] || event;
            var chStr = ch ? ' (CH' + ch + ')' : '';
            return { type: type, name: name + chStr, event: event };
        }

        function loadDeviceLogs(loadAll) {
            var si = document.getElementById('dlSite').value;
            var di = document.getElementById('dlDevice').value;
            var typeFilter = document.getElementById('dlType').value;
            var dateFrom = document.getElementById('dlDateFrom').value;
            var dateTo = document.getElementById('dlDateTo').value;
            if (!di) { document.getElementById('dlContent').innerHTML = '<div class="empty">No supported NVR devices found.</div>'; return; }

            // Branch for syslog sources
            if (di.indexOf('syslog:') === 0) {
                var src = di.substring(7);
                var count = loadAll ? 1000 : 200;
                document.getElementById('dlLoading').style.display = 'block';
                document.getElementById('dlContent').innerHTML = '';
                api('GET', '/api/syslog?src=' + encodeURIComponent(src) + '&count=' + count, null, function(data) {
                    document.getElementById('dlLoading').style.display = 'none';
                    var entries = (data && data.entries) || [];
                    entries.reverse(); // newest first
                    var counts = {crit: 0, err: 0, warn: 0, info: 0};
                    entries.forEach(function(e) { if (counts[e.severity] !== undefined) counts[e.severity]++; });
                    var html = '<div class="dl-summary">';
                    html += '<div class="dl-stat"><div class="num" style="color:#e94560">' + counts.crit + '</div><div class="label">Critical</div></div>';
                    html += '<div class="dl-stat"><div class="num" style="color:#ff6b6b">' + counts.err + '</div><div class="label">Errors</div></div>';
                    html += '<div class="dl-stat"><div class="num" style="color:#ffb73d">' + counts.warn + '</div><div class="label">Warnings</div></div>';
                    html += '<div class="dl-stat"><div class="num" style="color:#4ecca3">' + counts.info + '</div><div class="label">Info</div></div>';
                    html += '</div>';
                    html += '<div class="site-card">';
                    if (entries.length === 0) {
                        html += '<div class="empty">No syslog entries from ' + esc(src) + '.</div>';
                    } else {
                        var sevColor = {crit:'#e94560', err:'#ff6b6b', warn:'#ffb73d', info:'#4ecca3', debug:'#888'};
                        entries.forEach(function(e) {
                            var c = sevColor[e.severity] || '#888';
                            html += '<div class="dl-row">';
                            html += '<div class="dl-time">' + esc((e.ts || '').replace('T', ' ')) + '</div>';
                            html += '<div class="dl-badge" style="background:' + c + '22;color:' + c + ';border:1px solid ' + c + '44">' + esc(e.severity || '-') + '</div>';
                            html += '<div class="dl-event">';
                            if (e.subsystem) html += '<span class="dl-detail">[' + esc(e.subsystem) + ']</span> ';
                            html += esc(e.message || '');
                            html += '</div>';
                            html += '</div>';
                        });
                    }
                    html += '</div>';
                    if (!loadAll && entries.length >= 200) {
                        html += '<div style="text-align:center;padding:16px;">';
                        html += '<button class="btn btn-secondary" onclick="loadDeviceLogs(true)" style="font-size:13px;">Load More Syslog</button>';
                        html += '</div>';
                    }
                    document.getElementById('dlContent').innerHTML = html;
                });
                return;
            }

            // NVR branch (existing path)
            var idx = parseInt(di.indexOf('nvr:') === 0 ? di.substring(4) : di);
            document.getElementById('dlLoading').style.display = 'block';
            document.getElementById('dlContent').innerHTML = '';

            var payload = {site: parseInt(si), device: idx, date_from: dateFrom, date_to: dateTo, type: typeFilter};
            if (loadAll) payload.limit = 5000;

            api('POST', '/api/device-logs', payload, function(data) {
                document.getElementById('dlLoading').style.display = 'none';
                if (data.error) {
                    document.getElementById('dlContent').innerHTML = '<div class="site-card" style="padding:16px"><div class="test-result error">' + data.error + '</div></div>';
                    return;
                }
                var logs = data.logs || [];
                var counts = {Exception:0, Operation:0, Information:0};
                logs.forEach(function(l) { if (counts[l.type] !== undefined) counts[l.type]++; });

                var html = '<div class="dl-summary">';
                html += '<div class="dl-stat"><div class="num" style="color:#e94560">' + counts.Exception + '</div><div class="label">Exceptions</div></div>';
                html += '<div class="dl-stat"><div class="num" style="color:#4ea8de">' + counts.Operation + '</div><div class="label">Operations</div></div>';
                html += '<div class="dl-stat"><div class="num" style="color:#4ecca3">' + counts.Information + '</div><div class="label">Information</div></div>';
                html += '</div>';

                html += '<div class="site-card">';
                if (logs.length === 0) {
                    html += '<div class="empty">No logs found for this date.</div>';
                } else {
                    logs.forEach(function(l) {
                        html += '<div class="dl-row">';
                        html += '<div class="dl-time">' + esc(l.time || '') + '</div>';
                        html += '<div class="dl-badge ' + l.type + '">' + l.type + '</div>';
                        html += '<div class="dl-event">' + esc(l.event);
                        if (l.user) html += ' <span class="dl-detail">user: ' + esc(l.user) + '</span>';
                        if (l.ip) html += ' <span class="dl-detail">ip: ' + esc(l.ip) + '</span>';
                        if (l.detail) html += '<br><span class="dl-detail">' + esc(l.detail) + '</span>';
                        html += '</div>';
                        html += '</div>';
                    });
                }
                html += '</div>';
                if (data.has_more) {
                    html += '<div style="text-align:center;padding:16px;">';
                    html += '<span style="color:#888;font-size:13px;">Showing ' + data.total + ' of ' + (data.total_on_device || '?') + ' logs — </span>';
                    html += '<button class="btn btn-secondary" onclick="loadDeviceLogs(true)" style="font-size:13px;">Load All Logs</button>';
                    html += '</div>';
                }
                document.getElementById('dlContent').innerHTML = html;
            });
        }

        // Auto refresh — Status + VPN panels stay live while visible
        loadStatus();
        setInterval(function() {
            if (document.querySelector('#panel-status.active')) loadStatus();
            else if (document.querySelector('#panel-vpn.active')) loadVPN();
        }, 10000);

        // Auto refresh device logs every 60 seconds (lightweight — only fetches if new logs exist)
        setInterval(function() {
            if (document.querySelector('#panel-devicelogs.active') && dlInited) {
                loadDeviceLogs();
            }
        }, 60000);

        // Poll for newly-online VPN sites that aren't yet linked to monitoring
        var dismissedVPN = JSON.parse(sessionStorage.getItem('dismissedVPN') || '[]');
        function checkNewVPN() {
            api('GET', '/api/vpn/new-detected', null, function(detected) {
                var banner = document.getElementById('vpnDetectedBanner');
                var fresh = (detected || []).filter(function(s) { return dismissedVPN.indexOf(s.name) < 0; });
                if (!fresh.length) { banner.style.display = 'none'; return; }
                banner.style.display = 'block';
                var html = '';
                banner.innerHTML = '';
                fresh.forEach(function(s) {
                    var div = document.createElement('div');
                    div.style.cssText = 'display:flex;align-items:center;gap:12px;padding:4px 0;';
                    var sub = s.nat_subnet ? ' &nbsp;NAT: <code>' + esc(s.nat_subnet) + '</code>' : '';
                    div.innerHTML = '<span style="font-size:18px;">🟢</span>'
                                  + '<span><b>' + esc(s.name) + '</b> just came online (VPN ' + esc(s.client_ip) + sub + ')</span>';
                    var addBtn = document.createElement('button');
                    addBtn.className = 'btn btn-primary';
                    addBtn.style.marginLeft = 'auto';
                    addBtn.textContent = 'Add monitoring';
                    addBtn.addEventListener('click', function() { linkNewVPN(s.name); });
                    var dismissBtn = document.createElement('button');
                    dismissBtn.className = 'btn btn-secondary';
                    dismissBtn.textContent = 'Dismiss';
                    dismissBtn.addEventListener('click', function() { dismissVPN(s.name); });
                    div.appendChild(addBtn);
                    div.appendChild(dismissBtn);
                    banner.appendChild(div);
                });
            });
        }
        function linkNewVPN(name) {
            // Switch to Manage tab and trigger the existing add-site flow with VPN name pre-filled
            showTab('manage');
            setTimeout(function() {
                if (typeof openAddSite === 'function') {
                    openAddSite();
                    setTimeout(function() {
                        var sel = document.getElementById('vpnSiteSelect');
                        if (sel) {
                            for (var i = 0; i < sel.options.length; i++) {
                                if (sel.options[i].value === name) {
                                    sel.selectedIndex = i;
                                    if (typeof vpnSiteSelected === 'function') vpnSiteSelected();
                                    break;
                                }
                            }
                        }
                        var nm = document.getElementById('siteName');
                        if (nm && !nm.value) nm.value = name;
                    }, 250);
                }
            }, 100);
        }
        function dismissVPN(name) {
            dismissedVPN.push(name);
            sessionStorage.setItem('dismissedVPN', JSON.stringify(dismissedVPN));
            checkNewVPN();
        }
        checkNewVPN();
        setInterval(checkNewVPN, 15000);
    </script>

    <!-- Discreet copyright footer — click © to see full claim -->
    <div id="cr-dot" onclick="document.getElementById('cr-modal').style.display='flex'"
         style="position:fixed;bottom:8px;right:10px;font-size:16px;color:#4ecca3;cursor:pointer;user-select:none;opacity:0.9;z-index:9998;padding:8px 14px;background:rgba(20,20,48,0.8);border:1px solid #2a2a5a;border-radius:6px;"
         title="About NetWatch">© NetWatch</div>
    <div id="cr-modal" onclick="if(event.target.id==='cr-modal')this.style.display='none'"
         style="display:none;position:fixed;inset:0;background:rgba(0,0,0,0.7);z-index:9999;align-items:center;justify-content:center;">
        <div style="background:#141430;border:1px solid #2a2a5a;border-radius:10px;padding:22px 26px;max-width:520px;color:#e0e0e0;font-size:13px;line-height:1.55;">
            <div style="font-size:15px;font-weight:600;margin-bottom:10px;color:#4ecca3;">NetWatch</div>
            <div>Copyright &copy; 2026 <b>NetWatch</b>. All rights reserved.</div>
            <div style="margin-top:12px;color:#888;font-size:12px;">
                Proprietary software. No person or entity may use, copy, modify,
                distribute, host, or deploy this software, in whole or in part,
                without permission. See LICENSE.
            </div>
            <div style="text-align:right;margin-top:16px;">
                <button onclick="document.getElementById('cr-modal').style.display='none'"
                        style="padding:6px 14px;background:#2a2a5a;border:none;border-radius:6px;color:#fff;font-size:12px;cursor:pointer;">Close</button>
            </div>
        </div>
    </div>
</body>
</html>"""


class NetWatchWebHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        path = urlparse(self.path).path

        if path == '/':
            if not check_auth(self):
                self.send_html(LOGIN_HTML)
                return
            self.send_html(PAGE_HTML)
            return

        # All API endpoints require auth
        if path.startswith('/api/') and path != '/api/login' and not check_auth(self):
            self.send_json({'error': 'unauthorized'})
            return

        if path == '/api/status':
            cfg = load_config()
            # Strip sensitive data before sending to client
            safe_cfg = json.loads(json.dumps(cfg))
            safe_cfg.pop('telegram', None)
            for site in safe_cfg.get('sites', []):
                for dev in site.get('devices', []):
                    dev.pop('password', None)
            # Include auth-circuit-breaker blocked IPs so UI can show 🔒 indicator
            blocked = []
            try:
                import sys as _sys
                _sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
                from devices import list_blocked_ips
                blocked = list_blocked_ips()
            except Exception:
                pass
            self.send_json({'state': load_state(), 'config': safe_cfg,
                            'auth_blocked_ips': blocked})
        elif path == '/api/config':
            cfg = load_config()
            safe_cfg = json.loads(json.dumps(cfg))
            safe_cfg.pop('telegram', None)
            for site in safe_cfg.get('sites', []):
                for dev in site.get('devices', []):
                    dev.pop('password', None)
            self.send_json(safe_cfg)
        elif path == '/api/config/manage':
            # Config for manage page — NO passwords, NO telegram token
            cfg = json.loads(json.dumps(load_config()))
            cfg.pop('telegram', None)
            for site in cfg.get('sites', []):
                for dev in site.get('devices', []):
                    if dev.get('password'):
                        dev['password'] = '••••••'
            self.send_json(cfg)
        elif path.startswith('/api/device-password/'):
            # Rate limit password reveals
            cookie = self.headers.get('Cookie', '')
            sess_token = ''
            for part in cookie.split(';'):
                part = part.strip()
                if part.startswith('session='):
                    sess_token = part.split('=', 1)[1]
            now = time.time()
            reveals = [t for t in _pw_reveals.get(sess_token, []) if now - t < _PW_REVEAL_WINDOW]
            if len(reveals) >= _PW_REVEAL_MAX:
                self.send_json({'error': 'Too many requests. Wait a minute.'})
                return
            reveals.append(now)
            _pw_reveals[sess_token] = reveals

            try:
                parts = path.split('/')
                si = int(parts[3])
                di = int(parts[4])
                cfg = load_config()
                pw = cfg['sites'][si]['devices'][di].get('password', '')
                self.send_json({'password': pw})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})
        elif path == '/api/logs':
            try:
                params = parse_qs(urlparse(self.path).query)
                count = int(params.get('count', ['30'])[0])
                site_filter = params.get('site', [None])[0]
                device_filter = params.get('device', [None])[0]
                alerts_only = params.get('alerts', ['0'])[0] == '1'

                with open(Path(__file__).parent / 'netwatch.log') as f:
                    lines = f.readlines()

                if alerts_only:
                    lines = [l for l in lines if 'ALERT' in l or 'WARNING' in l]
                if site_filter:
                    lines = [l for l in lines if site_filter.lower() in l.lower()]
                if device_filter:
                    lines = [l for l in lines if device_filter in l]

                lines = lines[-count:]
                self.send_json({'logs': ''.join(lines) if lines else 'ჩანაწერები არ მოიძებნა'})
            except:
                self.send_json({'logs': 'ჩანაწერები ვერ წაიკითხა'})
        elif path.startswith('/api/sites/') and path.endswith('/sla'):
            try:
                si = int(path.split('/')[3])
                cfg = load_config()
                if si < 0 or si >= len(cfg['sites']):
                    self.send_json({'error': 'Invalid site index'})
                    return
                days = int(parse_qs(urlparse(self.path).query).get('days', ['30'])[0])
                days = max(1, min(days, 365))
                from netwatch import compute_sla
                report = compute_sla(site_name=cfg['sites'][si]['name'], days=days)
                # Roll up site-wide uptime = average of per-device uptimes
                devs = list(report.get('devices', {}).values())
                if devs:
                    report['site_uptime_percent'] = round(
                        sum(d['uptime_percent'] for d in devs) / len(devs), 3)
                    report['total_incidents'] = sum(d['incidents'] for d in devs)
                    report['longest_outage_sec'] = max((d['longest_outage_sec'] for d in devs), default=0)
                else:
                    report['site_uptime_percent'] = 100.0
                    report['total_incidents'] = 0
                    report['longest_outage_sec'] = 0
                self.send_json(report)
            except (ValueError, IndexError) as e:
                self.send_json({'error': f'Invalid request: {e}'})
            return

        elif path == '/api/notification-categories':
            try:
                from netwatch import NOTIFICATION_CATEGORIES
                cats = []
                for item in NOTIFICATION_CATEGORIES:
                    if len(item) == 3:
                        k, label, groups = item
                    else:
                        k, label = item
                        groups = ['nvr', 'network']
                    cats.append({'key': k, 'label': label, 'groups': groups})
                self.send_json({'categories': cats})
            except Exception as e:
                self.send_json({'categories': [], 'error': str(e)})
        elif path == '/api/syslog/sources':
            try:
                from syslog_collector import LOG_DIR as _SYSLOG_DIR
                sources = {}
                # Scan files from newest to oldest until we have a reasonable sample
                for file in sorted(_SYSLOG_DIR.glob('*.jsonl'), reverse=True)[:7]:
                    with open(file, 'rb') as f:
                        f.seek(0, 2)
                        size = f.tell()
                        pos = max(0, size - 512 * 1024)
                        f.seek(pos)
                        data = f.read().decode('utf-8', errors='replace')
                    for line in data.splitlines():
                        if not line.strip():
                            continue
                        try:
                            e = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        src = e.get('src')
                        if not src:
                            continue
                        device = e.get('device')
                        entry = sources.setdefault(src, {'src': src, 'count': 0, 'device': None, 'last_ts': None})
                        entry['count'] += 1
                        if device:
                            entry['device'] = device
                        ts = e.get('ts')
                        if ts and (entry['last_ts'] is None or ts > entry['last_ts']):
                            entry['last_ts'] = ts
                self.send_json({'sources': list(sources.values())})
            except Exception as e:
                self.send_json({'sources': [], 'error': str(e)})
        elif path == '/api/syslog':
            try:
                params = parse_qs(urlparse(self.path).query)
                count = min(int(params.get('count', ['100'])[0]), 1000)
                src_filter = params.get('src', [None])[0]
                severity_filter = params.get('severity', [None])[0]
                device_filter = params.get('device', [None])[0]
                search = params.get('q', [None])[0]

                from syslog_collector import LOG_DIR as _SYSLOG_DIR
                entries = []
                # Walk files newest → oldest, stop once we've gathered enough
                for file in sorted(_SYSLOG_DIR.glob('*.jsonl'), reverse=True):
                    with open(file, 'rb') as f:
                        f.seek(0, 2)
                        size = f.tell()
                        buf = b''
                        chunk = 65536
                        pos = size
                        while pos > 0 and buf.count(b'\n') < count * 3:
                            read = min(chunk, pos)
                            pos -= read
                            f.seek(pos)
                            buf = f.read(read) + buf
                    file_entries = []
                    for line in buf.decode('utf-8', errors='replace').splitlines():
                        if not line.strip():
                            continue
                        try:
                            e = json.loads(line)
                        except json.JSONDecodeError:
                            continue
                        if src_filter and e.get('src') != src_filter:
                            continue
                        if severity_filter and e.get('severity') != severity_filter:
                            continue
                        if device_filter and device_filter not in (e.get('device') or ''):
                            continue
                        if search and search.lower() not in (e.get('message') or '').lower():
                            continue
                        file_entries.append(e)
                    # file_entries are in file order (oldest first within a day) — prepend to result
                    entries = file_entries + entries
                    if len(entries) >= count:
                        break
                entries = entries[-count:]
                self.send_json({'entries': entries, 'count': len(entries)})
            except Exception as e:
                self.send_json({'entries': [], 'error': str(e)})
        elif path == '/api/vpn/unlinked':
            from vpn import get_site_status
            vpn_data = get_site_status()
            cfg = load_config()
            existing = [s['name'].lower() for s in cfg['sites']]
            unlinked = [{'name': s['name'], 'client_ip': s['client_ip'],
                         'nat_subnet': s.get('nat_subnet', ''),
                         'connected': s.get('connected', False),
                         'last_handshake': s.get('last_handshake', 0)}
                       for s in vpn_data.get('sites', []) if s['name'].lower() not in existing]
            self.send_json(unlinked)
        elif path == '/api/vpn/new-detected':
            from vpn import get_site_status
            vpn_data = get_site_status()
            cfg = load_config()
            existing = [s['name'].lower() for s in cfg['sites']]
            detected = [{'name': s['name'], 'client_ip': s['client_ip'],
                         'nat_subnet': s.get('nat_subnet', ''),
                         'last_handshake': s.get('last_handshake', 0)}
                       for s in vpn_data.get('sites', [])
                       if s['name'].lower() not in existing and s.get('connected', False)]
            self.send_json(detected)
        elif path == '/api/vpn':
            from vpn import get_site_status
            self.send_json(get_site_status())
        elif path.startswith('/api/vpn/config/'):
            from vpn import get_site_config
            from urllib.parse import unquote
            name = unquote(path.split('/api/vpn/config/', 1)[1])
            result = get_site_config(name)
            self.send_json(result or {})
        elif path.startswith('/api/notes/'):
            site_name = path.split('/api/notes/', 1)[1]
            from urllib.parse import unquote
            site_name = unquote(site_name)
            notes = load_notes()
            self.send_json(notes.get(site_name, {}))
        else:
            self.send_response(404)
            self.end_headers()

    def do_POST(self):
        path = urlparse(self.path).path
        content_len = int(self.headers.get('Content-Length', 0))
        if content_len > 1_000_000:  # 1MB limit
            self.send_response(413)
            self.end_headers()
            return
        body = json.loads(self.rfile.read(content_len))

        if path == '/api/login':
            client_ip = self.client_address[0]
            now = time.time()

            # Per-IP lockout
            attempts = _login_attempts.get(client_ip, [])
            attempts = [t for t in attempts if now - t < _LOGIN_LOCKOUT_SECONDS]
            _login_attempts[client_ip] = attempts

            if len(attempts) >= _LOGIN_MAX_ATTEMPTS:
                self.send_json({'ok': False, 'error': 'Too many attempts. Try again later.'})
                return

            # Global brute-force delay
            global _global_login_failures
            _global_login_failures = [t for t in _global_login_failures if now - t < 300]
            if len(_global_login_failures) >= _GLOBAL_MAX_FAILURES:
                time.sleep(_GLOBAL_DELAY)

            if body.get('user') == AUTH_USER and body.get('pass') == AUTH_PASS:
                _login_attempts.pop(client_ip, None)
                token = create_session()
                self.send_response(200)
                self.send_header('Content-Type', 'application/json')
                self.send_header('Set-Cookie', f'session={token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=86400')
                self.end_headers()
                self.wfile.write(json.dumps({'ok': True}).encode())
            else:
                attempts.append(now)
                _login_attempts[client_ip] = attempts
                _global_login_failures.append(now)
                self.send_json({'ok': False})
            return

        # All other POST endpoints require auth
        if not check_auth(self):
            self.send_json({'error': 'unauthorized'})
            return

        if path.startswith('/api/notes/'):
            from urllib.parse import unquote
            site_name = unquote(path.split('/api/notes/', 1)[1])
            notes = load_notes()
            notes[site_name] = body
            save_notes(notes)
            self.send_json({'ok': True})
            return

        elif path == '/api/vpn/add':
            from vpn import add_site
            vpn_name = body.get('name', '')
            if not vpn_name or not re.match(r'^[a-zA-Z0-9_\- ]{1,50}$', vpn_name):
                self.send_json({'error': 'Invalid site name'})
                return
            result, error = add_site(vpn_name, body.get('subnets', ''), body.get('brand', 'mikrotik'))
            if error:
                self.send_json({'error': error})
            else:
                self.send_json(result)
            return

        elif path == '/api/sites':
            config = load_config()
            new_site = {
                'name': body['name'],
                'telegram_chat_id': body.get('telegram_chat_id', ''),
                'devices': []
            }
            # Accept per-category notification prefs if provided; missing = all-on default.
            if isinstance(body.get('notifications'), dict):
                new_site['notifications'] = {
                    k: bool(v) for k, v in body['notifications'].items()
                }
            config['sites'].append(new_site)
            save_config(config)
            self.send_json({'ok': True})

        elif path.startswith('/api/sites/') and path.endswith('/notifications'):
            try:
                si = int(path.split('/')[3])
                config = load_config()
                if si < 0 or si >= len(config['sites']):
                    self.send_json({'error': 'Invalid site index'})
                    return
                prefs = body.get('notifications') or {}
                if not isinstance(prefs, dict):
                    self.send_json({'error': 'notifications must be an object'})
                    return
                config['sites'][si]['notifications'] = {
                    k: bool(v) for k, v in prefs.items()
                }
                save_config(config)
                self.send_json({'ok': True})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})
            return

        elif path.startswith('/api/sites/') and path.endswith('/mute'):
            try:
                si = int(path.split('/')[3])
                config = load_config()
                if si < 0 or si >= len(config['sites']):
                    self.send_json({'error': 'Invalid site index'})
                    return
                minutes = int(body.get('minutes', 60))
                if minutes <= 0 or minutes > 7 * 24 * 60:
                    self.send_json({'error': 'minutes must be 1..10080'})
                    return
                config['sites'][si]['mute_until'] = time.time() + minutes * 60
                save_config(config)
                self.send_json({'ok': True, 'mute_until': config['sites'][si]['mute_until']})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})
            return

        elif path.startswith('/api/sites/') and path.endswith('/unmute'):
            try:
                si = int(path.split('/')[3])
                config = load_config()
                if si < 0 or si >= len(config['sites']):
                    self.send_json({'error': 'Invalid site index'})
                    return
                config['sites'][si].pop('mute_until', None)
                save_config(config)
                self.send_json({'ok': True})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})
            return

        elif path.startswith('/api/sites/') and path.endswith('/edit') and '/devices/' not in path:
            # Edit site
            try:
                si = int(path.split('/')[3])
                config = load_config()
                if si < 0 or si >= len(config['sites']):
                    self.send_json({'error': 'Invalid site index'})
                    return
                if body.get('name'):
                    config['sites'][si]['name'] = body['name']
                config['sites'][si]['telegram_chat_id'] = body.get('telegram_chat_id', '')
                save_config(config)
                self.send_json({'ok': True})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})
            return

        elif path.startswith('/api/sites/') and '/devices/' in path and path.endswith('/edit'):
            # Edit device
            try:
                parts = path.split('/')
                si = int(parts[3])
                di = int(parts[5])
                config = load_config()
                if si < 0 or si >= len(config['sites']) or di < 0 or di >= len(config['sites'][si]['devices']):
                    self.send_json({'error': 'Invalid index'})
                    return
                dev = config['sites'][si]['devices'][di]
                if body.get('name'):
                    dev['name'] = body['name']
                if body.get('ip'):
                    if not _validate_ip(body['ip']):
                        self.send_json({'error': 'Invalid IP address'})
                        return
                    dev['ip'] = body['ip']
                if body.get('port'):
                    if not _validate_port(body['port']):
                        self.send_json({'error': 'Invalid port'})
                        return
                    dev['port'] = int(body['port'])
                if 'username' in body:
                    dev['username'] = body['username']
                if 'password' in body:
                    dev['password'] = body['password']
                save_config(config)
                self.send_json({'ok': True})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})
            return

        elif path.startswith('/api/sites/') and path.endswith('/devices'):
            # Validate device input
            dev_ip = body.get('ip', '')
            dev_port = body.get('port', 80)
            if not _validate_ip(dev_ip):
                self.send_json({'error': 'Invalid IP address'})
                return
            if not _validate_port(dev_port):
                self.send_json({'error': 'Invalid port'})
                return
            si = int(path.split('/')[3])
            config = load_config()
            if si < 0 or si >= len(config['sites']):
                self.send_json({'error': 'Invalid site index'})
                return
            config['sites'][si]['devices'].append(body)
            save_config(config)
            self.send_json({'ok': True})

        elif path == '/api/device-logs':
            result = fetch_device_logs(body)
            self.send_json(result)
            return

        elif path == '/api/scan':
            from scanner import scan_network, quick_scan
            subnet = body.get('subnet', '')
            # Validate subnet format (e.g. 192.168.1.0/24)
            if not re.match(r'^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}$', subnet):
                self.send_json({'error': 'Invalid subnet format'})
                return
            try:
                ipaddress.ip_network(subnet, strict=False)
            except ValueError:
                self.send_json({'error': 'Invalid subnet'})
                return
            if body.get('quick'):
                result = quick_scan(subnet)
            else:
                result = scan_network(subnet)
            self.send_json(result)
            return

        elif path == '/api/test':
            result = test_device(
                body['ip'], body.get('port', 80),
                body.get('username', ''), body.get('password', ''),
                body['type'], body.get('snmp_community', 'public')
            )
            self.send_json(result)

        else:
            self.send_response(404)
            self.end_headers()

    def do_DELETE(self):
        if not check_auth(self):
            self.send_json({'error': 'unauthorized'})
            return
        path = urlparse(self.path).path

        if path.startswith('/api/vpn/'):
            from vpn import remove_site
            from urllib.parse import unquote
            name = unquote(path.split('/api/vpn/', 1)[1])
            ok, error = remove_site(name)
            self.send_json({'ok': ok, 'error': error})
            return

        parts = path.split('/')
        config = load_config()

        if len(parts) == 4 and parts[2] == 'sites':
            try:
                si = int(parts[3])
                if si < 0 or si >= len(config['sites']):
                    self.send_json({'error': 'Invalid site index'})
                    return
                config['sites'].pop(si)
                save_config(config)
                self.send_json({'ok': True})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})

        elif len(parts) == 6 and parts[4] == 'devices':
            try:
                si = int(parts[3])
                di = int(parts[5])
                if si < 0 or si >= len(config['sites']) or di < 0 or di >= len(config['sites'][si]['devices']):
                    self.send_json({'error': 'Invalid index'})
                    return
                config['sites'][si]['devices'].pop(di)
                save_config(config)
                self.send_json({'ok': True})
            except (ValueError, IndexError):
                self.send_json({'error': 'Invalid request'})

        else:
            self.send_response(404)
            self.end_headers()

    def _security_headers(self):
        self.send_header('X-Content-Type-Options', 'nosniff')
        self.send_header('X-Frame-Options', 'DENY')
        self.send_header('X-XSS-Protection', '1; mode=block')
        self.send_header('Referrer-Policy', 'no-referrer')
        self.send_header('Cache-Control', 'no-store, no-cache')
        self.send_header('X-Powered-By', 'NetWatch (source-available, see LICENSE)')

    def send_json(self, data):
        self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self._security_headers()
        self.end_headers()
        self.wfile.write(json.dumps(data, default=str).encode())

    def send_html(self, html):
        self.send_response(200)
        self.send_header('Content-Type', 'text/html')
        self._security_headers()
        self.end_headers()
        self.wfile.write(html.encode())

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, DELETE, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def log_message(self, *args):
        pass


if __name__ == '__main__':
    print(f"NetWatch Web UI running on http://0.0.0.0:{PORT}")
    class ThreadedServer(ThreadingMixIn, HTTPServer):
        daemon_threads = True
    ThreadedServer(('0.0.0.0', PORT), NetWatchWebHandler).serve_forever()
