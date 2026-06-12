#!/usr/bin/env python3
"""
Device monitors — one class per vendor / device type
(Hikvision, Dahua, Uniview, Hanwha, Axis, Bosch, ONVIF, SNMP, UPS, …).
"""
import subprocess
import socket
import json
import time
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from requests.auth import HTTPDigestAuth, HTTPBasicAuth


# ────────────────────────────────────────────────────────────────────
#  AUTH CIRCUIT BREAKER (persistent, threshold = 1)
#
#  Rule: on the FIRST 401, stop all authenticated requests to that IP
#  immediately. Ping still runs (no auth). The block state survives
#  netwatch restarts by writing to auth_breaker.json — otherwise each
#  restart would generate another 401 and NVRs with progressive lockout
#  (Hikvision escalates 2min → 20min → ...) would keep getting worse.
#
#  The block clears ONLY when the user updates the device's credentials
#  via the web UI / bot — web.py's save_config() calls clear_auth_failure()
#  for every device in the new config that has a non-empty password.
# ────────────────────────────────────────────────────────────────────

from pathlib import Path as _Path
_AUTH_BREAKER_PATH = _Path(__file__).parent / 'auth_breaker.json'
_AUTH_FAILURE_THRESHOLD = 1   # first 401 = hard stop (no second chance to avoid NVR lockout escalation)
_auth_blocked_logged = set()


def _load_auth_state():
    try:
        with open(_AUTH_BREAKER_PATH) as f:
            import json as _json
            return _json.load(f).get('failures', {})
    except Exception:
        return {}


def _save_auth_state():
    try:
        import json as _json
        import os as _os
        tmp = str(_AUTH_BREAKER_PATH) + '.tmp'
        with open(tmp, 'w') as f:
            _json.dump({'failures': _auth_failure_counts}, f)
        _os.replace(tmp, _AUTH_BREAKER_PATH)
        try:
            _os.chmod(_AUTH_BREAKER_PATH, 0o600)
        except Exception:
            pass
    except Exception as e:
        print(f"[auth-circuit-breaker] persist failed: {e}")


_auth_failure_counts = _load_auth_state()  # persisted across restarts


def _auth_is_blocked(ip):
    return _auth_failure_counts.get(ip, 0) >= _AUTH_FAILURE_THRESHOLD


def _record_auth_result(ip, success):
    """Track auth outcome per IP. On success: clear and persist.
    On 401: increment; at threshold, log once + persist."""
    if success:
        if ip in _auth_failure_counts:
            _auth_failure_counts.pop(ip, None)
            _auth_blocked_logged.discard(ip)
            _save_auth_state()
        return
    n = _auth_failure_counts.get(ip, 0) + 1
    _auth_failure_counts[ip] = n
    if n >= _AUTH_FAILURE_THRESHOLD and ip not in _auth_blocked_logged:
        _auth_blocked_logged.add(ip)
        print(f"[auth-circuit-breaker] {ip}: 401 — PAUSED all auth requests. "
              "Update the device credentials in the web UI to resume.")
    _save_auth_state()


def clear_auth_failure(ip):
    """Called by save_config() after credentials are edited — unblocks the IP."""
    if ip in _auth_failure_counts:
        _auth_failure_counts.pop(ip, None)
        _auth_blocked_logged.discard(ip)
        _save_auth_state()


def list_blocked_ips():
    """Return list of IPs currently blocked (for web-UI status display)."""
    return [ip for ip, n in _auth_failure_counts.items() if n >= _AUTH_FAILURE_THRESHOLD]

NS = {'ns': 'http://www.isapi.org/ver20/XMLSchema'}


def diagnose_offline(ip, port=80):
    """Figure out WHY a device is offline."""
    reasons = []
    try:
        r = subprocess.run(['ping', '-c', '1', '-W', '2', ip], capture_output=True, timeout=5)
        ping_ok = r.returncode == 0
    except:
        ping_ok = False

    if not ping_ok:
        try:
            gw = subprocess.run(['ip', 'route', 'get', ip], capture_output=True, text=True, timeout=5)
            for i, part in enumerate(gw.stdout.split()):
                if part == 'via' and i + 1 < len(gw.stdout.split()):
                    gateway_ip = gw.stdout.split()[i + 1]
                    gw_ping = subprocess.run(['ping', '-c', '1', '-W', '1', gateway_ip],
                                            capture_output=True, timeout=3)
                    if gw_ping.returncode != 0:
                        reasons.append("ქსელი მიუწვდომელია — შესაძლოა, ინტერნეტი გათიშულია ობიექტზე")
                        return reasons
                    break
        except:
            pass

        if ip.startswith(('10.', '192.168.', '172.')):
            reasons.append("მოწყობილობა არ პასუხობს — შესაძლოა, გამორთულია ან კაბელი გამოეთიშა")
        else:
            reasons.append("მოწყობილობა მიუწვდომელია — შესაძლოა, ინტერნეტი გათიშულია ობიექტზე, მოწყობილობა გამორთულია ან პორტი დაბლოკილია")
        return reasons

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(3)
        result = sock.connect_ex((ip, port))
        sock.close()
        if result != 0:
            reasons.append(f"მოწყობილობა ხელმისაწვდომია, მაგრამ პორტი {port} დახურულია — პროგრამა გათიშულია ან გადატვირთვის პროცესშია")
            return reasons
    except:
        pass

    return reasons


# Plain-language meaning of Hikvision HDD status values (Georgian), plus the
# practical consequence — so an alert reads "drive failed, recording stopped,
# replace it" instead of a bare "#2 (): error".
_HDD_STATUS_MEANING = {
    'error':       'დისკი გაფუჭდა — ჩამწერმა მასზე ჩაწერა შეწყვიტა. საჭიროა შეცვლა.',
    'failed':      'დისკი მწყობრიდან გამოვიდა. საჭიროა შეცვლა.',
    'fault':       'დისკის გაუმართაობა. შეამოწმე/შეცვალე.',
    'abnormal':    'დისკი არანორმალურ მდგომარეობაშია — შესაძლო გაუმართაობა.',
    'smartfailed': 'SMART პროგნოზირებს მწყობრიდან გამოსვლას — დისკი მალე გაფუჭდება, შეცვალე.',
    'smart failed':'SMART პროგნოზირებს მწყობრიდან გამოსვლას — დისკი მალე გაფუჭდება, შეცვალე.',
    'offline':     'დისკი არ აღმოჩნდა — შესაძლოა გამოეთიშა ან მთლიანად გამოვიდა მწყობრიდან.',
    'missing':     'დისკი არ აღმოჩნდა (ფიზიკურად ვერ პოულობს).',
    'miss':        'დისკი არ აღმოჩნდა (ფიზიკურად ვერ პოულობს).',
    'damaged':     'დისკი დაზიანებულია.',
    'badsector':   'დისკზე დაზიანებული სექტორებია.',
    'unformatted': 'დისკი დაუფორმატებელია — საჭიროა ფორმატირება NVR-ის მენიუდან.',
}


def _hdd_status_meaning(status):
    s = (status or '').lower().strip()
    for key, meaning in _HDD_STATUS_MEANING.items():
        if key in s:
            return meaning
    return f'სტატუსი: {status}'


def _fmt_capacity(mb):
    """Human capacity from megabytes: 3815447 MB -> '4 TB', 500000 MB -> '500 GB'."""
    try:
        gb = int(mb) / 1024
    except (TypeError, ValueError):
        return ''
    if gb >= 1000:
        return f"{gb/1024:.0f} TB"
    return f"{gb:.0f} GB"


# ============================================================
# BASE CLASS
# ============================================================
class BaseDevice:
    def __init__(self, config):
        self.name = config['name']
        self.ip = config['ip']
        self.port = config.get('port', 80)
        self.monitor_cfg = config.get('monitor', {})
        # Unique device identity for alert keys + per-device state. Multiple
        # NVRs are often port-forwarded behind ONE public IP (e.g. four NVRs
        # on 203.0.113.10 ports 81-84). Keying alerts/state by IP alone makes
        # their camera/HDD/clock alerts collide. ip:port keeps them distinct.
        self.uid = f"{self.ip}:{self.port}"

    def _ping(self):
        try:
            r = subprocess.run(['ping', '-c', '1', '-W', '2', self.ip], capture_output=True, timeout=5)
            return r.returncode == 0
        except:
            return False

    def _tcp_check(self, port=None):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            result = sock.connect_ex((self.ip, port or self.port))
            sock.close()
            return result == 0
        except:
            return False

    def _rtsp_check(self, port=554):
        """Send an RTSP OPTIONS and confirm an RTSP/ reply."""
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(3)
            sock.connect((self.ip, port))
            sock.send(b"OPTIONS rtsp://%s:%d RTSP/1.0\r\nCSeq: 1\r\n\r\n" % (self.ip.encode(), port))
            data = sock.recv(1024)
            sock.close()
            return b'RTSP' in data
        except:
            return False

    def check_all(self, alert_mgr):
        return []

    def get_status(self):
        return {
            'name': self.name, 'ip': self.ip,
            'type': 'unknown', 'online': self._ping(),
            'timestamp': datetime.now().isoformat()
        }

    def _offline_alerts(self, alert_mgr):
        alerts = []
        is_online = self._ping()
        # Route through AlertManager so a transient single-packet miss doesn't
        # immediately count as offline — threshold must be crossed first.
        just_offline, _ = alert_mgr.record_ping(self.ip, is_online, device_name=self.name)

        if just_offline:
            reasons = diagnose_offline(self.ip, self.port)
            reason_text = '\n'.join(['• ' + r for r in reasons]) if reasons else '• მიზეზი უცნობია'
            alerts.append({
                'key': f"{self.ip}_offline",
                'severity': 'critical',
                'message': (
                    f"🔴 <b>{self.name}</b> გათიშულია!\n"
                    f"📍 IP: {self.ip}\n\n"
                    f"<b>სავარაუდო მიზეზი:</b>\n{reason_text}"
                )
            })

        # Downstream checks (HDD, cameras, etc.) should only be skipped once we
        # have really given up on the device — use the effective state.
        # Recovery ("back online") alerts are emitted from the main loop's
        # record_ping transition, not here.
        effective_online = not alert_mgr.was_offline(self.ip)
        return alerts, effective_online


# ============================================================
# HTTP API BASE (for NVRs that use HTTP APIs)
# ============================================================
class HTTPAPIDevice(BaseDevice):
    def __init__(self, config):
        super().__init__(config)
        self.username = config.get('username', 'admin')
        self.password = config.get('password', '')
        self.base_url = f"http://{self.ip}:{self.port}"
        self.timeout = 10

    def _get_digest(self, path):
        if _auth_is_blocked(self.ip):
            return None
        try:
            resp = requests.get(f"{self.base_url}{path}",
                              auth=HTTPDigestAuth(self.username, self.password),
                              timeout=self.timeout)
            _record_auth_result(self.ip, resp.status_code != 401)
            return resp if resp.ok else None
        except:
            return None

    def _get_basic(self, path):
        if _auth_is_blocked(self.ip):
            return None
        try:
            resp = requests.get(f"{self.base_url}{path}",
                              auth=HTTPBasicAuth(self.username, self.password),
                              timeout=self.timeout)
            _record_auth_result(self.ip, resp.status_code != 401)
            return resp if resp.ok else None
        except:
            return None

    def _get_any_auth(self, path):
        """Try digest first, then basic."""
        resp = self._get_digest(path)
        if resp:
            return resp
        return self._get_basic(path)

    def _xml_raw(self, path):
        """GET + parse, returning (stripped_tree, namespace_uri, version_attr).

        The normal _xml() strips namespaces so XPath works across firmware
        variants — but a WRITE must echo the device's OWN namespace + version
        back in the PUT body or the device rejects it (statusCode 6, Invalid
        XML). This helper captures the raw root namespace + version BEFORE
        stripping, so the write path can reproduce them byte-for-byte.

        Returns (None, None, None) on any failure / auth-block.
        """
        resp = self._get_digest(path)
        if not resp:
            return None, None, None
        try:
            root = ET.fromstring(resp.text)
        except Exception:
            return None, None, None
        # Capture raw namespace from the root tag '{ns}Tag'
        ns_uri = None
        if isinstance(root.tag, str) and root.tag.startswith('{'):
            ns_uri = root.tag[1:root.tag.index('}')]
        version = root.attrib.get('version')
        # Now strip namespaces for convenient XPath (same as _xml()).
        for el in root.iter():
            if isinstance(el.tag, str) and '}' in el.tag:
                el.tag = el.tag.split('}', 1)[1]
        return root, ns_uri, version

    def _put_xml(self, path, body, allow_blocked=False):
        """Breaker-guarded ISAPI PUT. Modeled on _get_digest: refuse if the IP
        is already auth-blocked, record the auth outcome after, never raise.

        WRITE primitive — used only by deliberate, human-triggered remediation
        (e.g. clock fix). Returns a dict {ok, statusCode, statusString,
        subStatusCode, http} or None on transport failure / auth-block.

        allow_blocked=True bypasses the breaker check — used ONLY for a
        best-effort rollback PUT: if the breaker tripped mid-sequence we still
        want the restore request to actually leave the host rather than silently
        no-op and leave the NVR half-written.
        """
        if _auth_is_blocked(self.ip) and not allow_blocked:
            return None
        try:
            resp = requests.put(
                f"{self.base_url}{path}",
                data=body.encode('utf-8') if isinstance(body, str) else body,
                auth=HTTPDigestAuth(self.username, self.password),
                headers={'Content-Type': 'application/xml'},
                timeout=self.timeout,
            )
            _record_auth_result(self.ip, resp.status_code != 401)
        except Exception:
            return None
        # Parse Hikvision ResponseStatus (namespace-agnostic).
        status_code = status_string = sub_status = None
        try:
            r = ET.fromstring(resp.text)
            for el in r.iter():
                tag = el.tag.split('}', 1)[1] if isinstance(el.tag, str) and '}' in el.tag else el.tag
                if tag == 'statusCode' and el.text:
                    status_code = el.text.strip()
                elif tag == 'statusString' and el.text:
                    status_string = el.text.strip()
                elif tag == 'subStatusCode' and el.text:
                    sub_status = el.text.strip()
        except Exception:
            pass
        return {
            'ok': status_code == '1',
            'statusCode': status_code,
            'statusString': status_string,
            'subStatusCode': sub_status,
            'http': resp.status_code,
        }

    def _camera_reason(self, status):
        s = status.lower() if status else ''
        if 'password' in s or 'username' in s or 'auth' in s:
            return "არასწორი მომხმარებელი/პაროლი"
        elif 'timeout' in s or 'unreachable' in s:
            return "კავშირი ვერ მყარდება — კამერა შესაძლოა გამორთულია"
        elif 'offline' in s or 'disconnect' in s:
            return "კამერა მიუწვდომელია — შესაძლოა, კვება გაითიშა"
        elif 'resolution' in s:
            return "არასწორი რეზოლუციის კონფიგურაცია"
        return f"მდგომარეობა: {status}"


# ============================================================
# HIKVISION NVR/DVR
# ============================================================
class HikvisionNVR(HTTPAPIDevice):
    def _xml(self, path):
        resp = self._get_digest(path)
        if resp:
            try:
                root = ET.fromstring(resp.text)
                # Hikvision firmware varies the XML namespace between
                # http://www.isapi.org/..., http://www.hikvision.com/...,
                # and http://www.std-cgi.com/... — strip namespaces so our
                # XPath queries work regardless of which one the device uses.
                for el in root.iter():
                    if isinstance(el.tag, str) and '}' in el.tag:
                        el.tag = el.tag.split('}', 1)[1]
                return root
            except Exception:
                pass
        return None

    def _xt(self, el, path):
        """XML text helper (namespaces already stripped by _xml)."""
        found = el.find(path)
        return found.text.strip() if found is not None and found.text else None

    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'hikvision_nvr',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'hdds': [], 'cameras': [], 'device_info': {}, 'uptime': None
        }
        if not status['online']:
            return status

        xml = self._xml('/ISAPI/System/deviceInfo')
        if xml is not None:
            status['device_info'] = {
                'model': self._xt(xml, './/model'),
                'firmware': self._xt(xml, './/firmwareVersion'),
                'serial': self._xt(xml, './/serialNumber'),
            }

        xml = self._xml('/ISAPI/System/status')
        if xml is not None:
            v = self._xt(xml, './/deviceUpTime')
            if v: status['uptime'] = int(float(v))

        xml = self._xml('/ISAPI/ContentMgmt/Storage')
        if xml is not None:
            for hdd in xml.findall('.//hdd'):
                status['hdds'].append({
                    'id': self._xt(hdd, 'id'),
                    'status': self._xt(hdd, 'status'),
                    'capacity_mb': int(self._xt(hdd, 'capacity') or 0),
                    'free_mb': int(self._xt(hdd, 'freeSpace') or 0),
                    'model': self._xt(hdd, 'hddModel'),
                })

        xml = self._xml('/ISAPI/ContentMgmt/InputProxy/channels/status')
        if xml is not None:
            for ch in xml.findall('.//InputProxyChannelStatus'):
                status['cameras'].append({
                    'id': self._xt(ch, 'id'),
                    'ip': self._xt(ch, './/ipAddress'),
                    'online': self._xt(ch, 'online') == 'true',
                    'status': self._xt(ch, 'chanDetectResult'),
                })

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online:
            return alerts

        prev_cameras = {}
        prev_hdds = {}

        # Read uptime up-front. Right after a reboot an NVR drops ALL its cameras
        # offline for a few minutes while it reconnects to them, then they return —
        # a storm of camera offline→online alerts that is really just the reboot.
        # During a grace window after boot we suppress camera alerts entirely; the
        # single "NVR rebooted" alert below is the useful signal.
        REBOOT_CAMERA_GRACE = 600  # seconds (~10 min) for cameras to reconnect
        uptime = None
        status_xml = self._xml('/ISAPI/System/status')
        if status_xml is not None:
            v = self._xt(status_xml, './/deviceUpTime')
            if v:
                try:
                    uptime = int(float(v))
                except ValueError:
                    pass
        in_reboot_grace = uptime is not None and uptime < REBOOT_CAMERA_GRACE

        # HDD — alert ONLY on genuinely-bad statuses.
        # Surveillance NVRs normally report "idle"/"standby"/"sleeping" for disks
        # not currently being written, and run disks at ~100% full by design
        # (continuous loop recording overwrites oldest footage). So we do NOT
        # alert on full disks or on idle/standby states — only on real faults.
        # A "disk full + recording stopped" failure surfaces as a recordError
        # log event instead (handled in check_nvr_logs).
        HDD_BAD = ('error', 'abnormal', 'failed', 'smartfailed', 'smart failed',
                   'offline', 'missing', 'miss', 'fault', 'damaged', 'badsector',
                   'unformatted')
        xml = self._xml('/ISAPI/ContentMgmt/Storage')
        if xml is not None:
            for hdd in xml.findall('.//hdd'):
                hid = self._xt(hdd, 'id')
                st = (self._xt(hdd, 'status') or '').lower()
                model = self._xt(hdd, 'hddModel') or ''
                name = self._xt(hdd, 'hddName') or ''
                cap = _fmt_capacity(self._xt(hdd, 'capacity'))
                prev_hdds[hid] = st

                is_bad = any(bad in st for bad in HDD_BAD)
                if is_bad:
                    if alert_mgr.get_prev_hdd_state(self.uid, hid) != st:
                        # Build a human description: "დისკი #2 — 4 TB (hddb, Seagate)"
                        bits = [b for b in (cap, name, model) if b]
                        desc = f"დისკი #{hid}" + (f" — {', '.join(bits)}" if bits else '')
                        alerts.append({'key': f"{self.uid}_hdd{hid}", 'severity': 'critical',
                            'message': (f"💾 <b>{self.name}</b> — HDD პრობლემა!\n"
                                        f"📍 IP: {self.ip}\n"
                                        f"💽 {desc}\n"
                                        f"⚠️ {_hdd_status_meaning(st)}")})
                else:
                    # Healthy (ok / normal / idle / standby / sleeping / repairing) —
                    # clear any stale alert so the next real fault will alert again.
                    alert_mgr.clear(f"{self.uid}_hdd{hid}")

        # Cameras — skipped entirely during the post-reboot grace window so a
        # reconnecting camera never produces a spurious offline/recovery pair.
        # prev_cameras=None tells update_state to PRESERVE the pre-reboot camera
        # baseline, so a camera that was online before the reboot and is online
        # after produces zero alerts, while a camera still genuinely offline once
        # the grace ends will alert normally on the next cycle.
        if in_reboot_grace:
            prev_cameras = None
        else:
            xml = self._xml('/ISAPI/ContentMgmt/InputProxy/channels/status')
            if xml is not None:
                for ch in xml.findall('.//InputProxyChannelStatus'):
                    cid = self._xt(ch, 'id')
                    online = self._xt(ch, 'online') == 'true'
                    st = self._xt(ch, 'chanDetectResult') or ''
                    cip = self._xt(ch, './/ipAddress') or ''
                    prev_cameras[cid] = online

                    # Alert ONLY on a real online→offline transition (prev was True).
                    # First-seen-offline (prev None, e.g. right after a restart) just
                    # records the baseline silently — otherwise every already-offline
                    # camera would re-alert on each restart. The current offline count
                    # is always visible on the dashboard regardless.
                    if not online and alert_mgr.get_prev_camera_state(self.uid, cid) is True:
                        alerts.append({'key': f"{self.uid}_cam{cid}", 'severity': 'warning',
                            'message': f"📷 <b>{self.name}</b> — კამერა გათიშულია!\n📍 NVR: {self.ip}\n🎥 არხი {cid} ({cip})\n⚠️ {self._camera_reason(st)}"})
                    if online and alert_mgr.get_prev_camera_state(self.uid, cid) is False:
                        alerts.append({'key': f"{self.uid}_cam{cid}_recovery", 'severity': 'info', 'force': True,
                            'message': f"✅ <b>{self.name}</b> — კამერა ისევ ხელმისაწვდომია\n📍 NVR: {self.ip}\n🎥 არხი {cid} ({cip})"})
                        alert_mgr.clear(f"{self.uid}_cam{cid}")

        # Recording — check schedule status, not manual tracks
        # /ISAPI/ContentMgmt/record/tracks shows manual recording (usually disabled)
        # The NVR records via schedule which is always on, so we skip this check
        # Recording issues are detected via Exception logs (recordError) instead

        # Uptime / reboot alert — reuse the value read up-front.
        xml = status_xml
        if xml is not None:
            v = self._xt(xml, './/deviceUpTime')
            if v and int(float(v)) < 120:
                alerts.append({'key': f"{self.uid}_reboot", 'severity': 'warning',
                    'message': f"🔄 <b>{self.name}</b> ახლახან გადაირთო!\n📍 IP: {self.ip}\n⏱ Uptime: {int(float(v))} წამი"})
            elif v and int(float(v)) > 300:
                # Past the reboot window — clear the alert so the next reboot will trigger again
                alert_mgr.clear(f"{self.uid}_reboot")

        # Clock drift — compare the NVR's own time to the server's.
        # A dead CR2032 battery makes the NVR boot to 1970, which files
        # recordings under the wrong date (playback shows nothing). We alert
        # if the NVR clock is more than 5 minutes off from real time.
        xml = self._xml('/ISAPI/System/time')
        if xml is not None:
            nvr_time = self._xt(xml, './/localTime')
            if nvr_time:
                try:
                    from datetime import datetime as _dt, timezone as _tz
                    nvr_dt = _dt.fromisoformat(nvr_time)
                    now_ref = _dt.now(nvr_dt.tzinfo) if nvr_dt.tzinfo else _dt.now()
                    drift = abs((now_ref - nvr_dt).total_seconds())
                    if drift > 300:
                        mins = int(drift // 60)
                        human = f"{mins} წუთი" if mins < 1440 else f"{mins // 1440} დღე"
                        alerts.append({'key': f"{self.uid}_clock", 'severity': 'warning',
                            'message': (f"🕐 <b>{self.name}</b> — საათი აცდენილია!\n"
                                        f"📍 IP: {self.ip}\n"
                                        f"⏱ აცდენა: {human}\n"
                                        f"🗓 NVR-ის დრო: {nvr_time}\n"
                                        f"❗ ჩანაწერები შესაძლოა არასწორი თარიღით ინახებოდეს")})
                    else:
                        alert_mgr.clear(f"{self.uid}_clock")
                except Exception:
                    pass

        # RAID
        xml = self._xml('/ISAPI/ContentMgmt/Storage/raid')
        if xml is not None:
            for el in xml.iter():
                tag = el.tag.split('}')[-1] if '}' in el.tag else el.tag
                if tag.lower() == 'status' and el.text and el.text.strip().lower() not in ('normal', 'ok', 'healthy'):
                    alerts.append({'key': f"{self.uid}_raid", 'severity': 'critical',
                        'message': f"🔶 <b>{self.name}</b> — RAID პრობლემა!\n📍 IP: {self.ip}\n⚠️ {el.text.strip()}"})

        # SMART
        for hid in range(1, 17):
            xml = self._xml(f'/ISAPI/ContentMgmt/Storage/hdd/{hid}/SMARTTest/report')
            if xml is None: break
            r = self._xt(xml, './/testResult')
            if r and r.lower() not in ('ok', 'passed', 'normal', 'good'):
                alerts.append({'key': f"{self.uid}_smart{hid}", 'severity': 'critical',
                    'message': f"💾 <b>{self.name}</b> — SMART!\n📍 IP: {self.ip}\n💽 #{hid}: {r}\n❗ დისკი მალე გაფუჭდება"})

        alert_mgr.update_state(self.uid, True, prev_cameras, prev_hdds)
        return alerts

    # ────────────────────────────────────────────────────────────────────
    #  CLOCK FIX (the ONLY write path to an NVR) — human-triggered, opt-in.
    #  Reads current time/NTP config, then sets NTP (two PUTs). Never writes
    #  the time directly. Default dry_run=True logs the exact bodies and sends
    #  nothing. Every request is breaker-guarded via _xml_raw/_put_xml.
    # ────────────────────────────────────────────────────────────────────

    def read_clock_state(self):
        """Read-only snapshot used for enrollment, drift detection, and the
        pre-write capture. Returns a dict or None on failure/auth-block."""
        info_tree, _, _ = self._xml_raw('/ISAPI/System/deviceInfo')
        serial = model = firmware = None
        if info_tree is not None:
            s = info_tree.find('.//serialNumber'); serial = s.text.strip() if s is not None and s.text else None
            m = info_tree.find('.//model');        model = m.text.strip() if m is not None and m.text else None
            f = info_tree.find('.//firmwareVersion'); firmware = f.text.strip() if f is not None and f.text else None

        time_tree, ns_uri, version = self._xml_raw('/ISAPI/System/time')
        if time_tree is None:
            return None
        tm = time_tree.find('.//timeMode')
        lt = time_tree.find('.//localTime')
        tz = time_tree.find('.//timeZone')
        return {
            'uid': self.uid, 'ip': self.ip, 'port': self.port,
            'serial': serial, 'model': model, 'firmware': firmware,
            'time_ns': ns_uri, 'time_version': version,
            'timeMode': tm.text.strip() if tm is not None and tm.text else None,
            'localTime': lt.text.strip() if lt is not None and lt.text else None,
            'timeZone': tz.text.strip() if tz is not None and tz.text else None,
            'raw_time_xml': ET.tostring(time_tree, encoding='unicode'),
        }

    def supports_ntp(self):
        """Confirm the device advertises NTP as a timeMode before we try to set
        it. Returns True/False/None(unknown)."""
        cap, _, _ = self._xml_raw('/ISAPI/System/time/capabilities')
        if cap is None:
            return None
        txt = ET.tostring(cap, encoding='unicode').lower()
        return 'ntp' in txt

    def fix_clock_via_ntp(self, ntp_server, addressing='ipaddress', slot_id=1,
                          interval_min=60, dry_run=True):
        """Configure NTP on this NVR. Returns a structured result dict; performs
        live GETs always, and the two PUTs only when dry_run is False.

        Safety: caller is responsible for the opt-in flag, the kill-switch, the
        single-shot/24h guard (clock_fix.recently_attempted), and the one-NVR-
        per-shared-IP serialization. This method handles capability check,
        identity capture, namespace echo, the ordered writes, and read-back.
        """
        import clock_fix as _cf
        result = {'uid': self.uid, 'dry_run': dry_run, 'steps': [], 'ok': False}

        def step(name, detail):
            result['steps'].append({'step': name, 'detail': detail})

        # 1. capability gate
        sup = self.supports_ntp()
        if sup is False:
            result['error'] = 'device does not advertise NTP timeMode'
            step('capability', 'NTP not advertised — abort')
            return result
        step('capability', f'ntp_advertised={sup}')

        # 2. read current state (also gives us the raw NS+version + timeZone)
        snap = self.read_clock_state()
        if not snap:
            result['error'] = 'could not read /ISAPI/System/time (auth-block or unreachable)'
            step('read', 'failed')
            return result
        result['before'] = {k: snap[k] for k in ('serial', 'model', 'timeMode', 'localTime', 'timeZone')}
        step('read', f"timeMode={snap['timeMode']} tz={snap['timeZone']} ns={snap['time_ns']} ver={snap['time_version']}")

        # 3. skip if already on NTP (don't disturb a working config)
        if (snap.get('timeMode') or '').upper() == 'NTP':
            result['skipped'] = 'already in NTP mode'
            step('skip', 'already NTP — no write')
            result['ok'] = True
            return result

        ns, ver, tz = snap['time_ns'], snap['time_version'], snap['timeZone']
        prior_mode = snap['timeMode']

        # 4. build the bodies (pure). The restore body echoes the device's own
        #    namespace and writes back ONLY the prior timeMode + timeZone —
        #    NEVER <localTime> (that would step the clock), fixing the bug where
        #    the old restore re-sent the namespace-stripped, localTime-bearing
        #    raw GET XML.
        ntp_body = _cf.build_ntp_server_body(ns, ver, slot_id, ntp_server, addressing, 123, interval_min)
        time_body = _cf.build_time_body(ns, ver, 'NTP', tz)
        restore_body = _cf.build_time_body(ns, ver, prior_mode, tz)
        result['ntp_put'] = {'path': f'/ISAPI/System/time/ntpServers/{slot_id}', 'body': ntp_body}
        result['time_put'] = {'path': '/ISAPI/System/time', 'body': time_body}
        result['restore_body'] = restore_body

        if dry_run:
            step('dry_run', 'built both PUT bodies; sent nothing')
            result['ok'] = True   # dry-run "succeeded" = it produced valid bodies
            return result

        # 5. LIVE: server first, then mode. statusCode==1 required at each step.
        r1 = self._put_xml(f'/ISAPI/System/time/ntpServers/{slot_id}', ntp_body)
        result['ntp_put_result'] = r1
        if not r1 or not r1.get('ok'):
            result['error'] = f'NTP-server PUT failed: {r1}'
            step('put_ntp', f'FAILED {r1}')
            return result
        step('put_ntp', 'ok')

        r2 = self._put_xml('/ISAPI/System/time', time_body)
        result['time_put_result'] = r2
        if not r2 or not r2.get('ok'):
            # Partial state — NTP server set but mode not flipped. Best-effort
            # restore that FIRES EVEN IF THE BREAKER TRIPPED (allow_blocked) and
            # carries a safe body (no localTime, proper namespace).
            step('put_time', f'FAILED {r2} — attempting restore')
            restore = self._put_xml('/ISAPI/System/time', restore_body, allow_blocked=True)
            result['restore_result'] = restore
            result['restore_ok'] = bool(restore and restore.get('ok'))
            result['error'] = ('time-mode PUT failed; restore '
                               + ('succeeded' if result['restore_ok'] else 'ALSO FAILED — NVR may be half-written'))
            return result
        step('put_time', 'ok')

        # 6. READ-BACK: prove the config actually applied (not just HTTP/status).
        rb = self.read_clock_state()
        if not rb:
            result['error'] = 'writes returned ok but read-back failed (cannot verify)'
            step('verify', 'read-back failed')
            return result
        applied = (rb.get('timeMode') or '').upper() == 'NTP'
        result['after'] = {'timeMode': rb.get('timeMode'), 'localTime': rb.get('localTime'), 'timeZone': rb.get('timeZone')}
        result['config_verified'] = applied
        step('verify', f"read-back timeMode={rb.get('timeMode')} applied={applied}")
        # config_verified = the NVR accepted NTP mode. Actual clock convergence
        # (drift < 5min) is async and must be checked on a later pass — callers
        # must NOT claim "synced" yet.
        result['ok'] = applied
        if not applied:
            result['error'] = 'NTP write reported success but read-back shows timeMode != NTP'
        return result

    def fix_timezone(self, new_timezone, dry_run=True):
        """Correct the timeZone string (e.g. strip a bogus DST clause) WITHOUT
        touching the time source or stepping the clock. Preserves the current
        timeMode, never emits <localTime>. Reads back the timeZone STRING to
        prove it applied (the drift check is blind to DST errors). Returns a
        structured result like fix_clock_via_ntp.

        Caller owns the kill-switch / opt-in / 24h guard / single-NVR-per-IP.
        """
        import clock_fix as _cf
        result = {'uid': self.uid, 'dry_run': dry_run, 'steps': [], 'ok': False, 'action': 'fix_timezone'}

        def step(name, detail):
            result['steps'].append({'step': name, 'detail': detail})

        snap = self.read_clock_state()
        if not snap:
            result['error'] = 'could not read /ISAPI/System/time (auth-block or unreachable)'
            step('read', 'failed')
            return result
        ns, ver = snap['time_ns'], snap['time_version']
        cur_tz, mode = snap['timeZone'], snap['timeMode']
        result['before'] = {k: snap[k] for k in ('serial', 'model', 'timeMode', 'localTime', 'timeZone')}
        step('read', f"timeMode={mode} tz={cur_tz}")

        if (cur_tz or '') == (new_timezone or ''):
            result['skipped'] = 'timezone already correct'
            step('skip', 'no change needed')
            result['ok'] = True
            return result

        # Body: preserve current timeMode, set the corrected timezone. No localTime.
        body = _cf.build_time_body(ns, ver, mode, new_timezone)
        restore_body = _cf.build_time_body(ns, ver, mode, cur_tz)
        result['time_put'] = {'path': '/ISAPI/System/time', 'body': body}
        result['restore_body'] = restore_body

        if dry_run:
            step('dry_run', 'built timezone PUT body; sent nothing')
            result['ok'] = True
            return result

        r = self._put_xml('/ISAPI/System/time', body)
        result['put_result'] = r
        if not r or not r.get('ok'):
            result['error'] = f'timezone PUT failed: {r}'
            step('put', f'FAILED {r}')
            return result
        step('put', 'ok')

        # READ-BACK the timeZone STRING — the only valid proof (drift is blind to DST).
        rb = self.read_clock_state()
        if not rb:
            result['error'] = 'write returned ok but read-back failed (cannot verify)'
            step('verify', 'read-back failed')
            return result
        result['after'] = {'timeMode': rb.get('timeMode'), 'localTime': rb.get('localTime'), 'timeZone': rb.get('timeZone')}
        applied = (rb.get('timeZone') or '') == (new_timezone or '')
        result['config_verified'] = applied
        step('verify', f"read-back tz={rb.get('timeZone')} applied={applied}")
        result['ok'] = applied
        if not applied:
            result['error'] = f"timezone write reported success but read-back tz={rb.get('timeZone')} != {new_timezone}"
        return result


# ============================================================
# DAHUA NVR/DVR
# ============================================================
class DahuaNVR(HTTPAPIDevice):
    def _parse(self, text):
        result = {}
        if not text: return result
        for line in text.strip().split('\n'):
            if '=' in line:
                k, v = line.split('=', 1)
                result[k.strip()] = v.strip()
        return result

    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'dahua_nvr',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'hdds': [], 'cameras': [], 'device_info': {}, 'uptime': None
        }
        if not status['online']: return status

        resp = self._get_digest('/cgi-bin/magicBox.cgi?action=getSystemInfo')
        if resp:
            d = self._parse(resp.text)
            status['device_info'] = {'model': d.get('deviceType', ''), 'firmware': d.get('softWareVersion', ''), 'serial': d.get('serialNumber', '')}

        resp = self._get_digest('/cgi-bin/storageDevice.cgi?action=factory.getCollect')
        if resp:
            d = self._parse(resp.text)
            i = 0
            while f'info[{i}].Name' in d:
                status['hdds'].append({
                    'id': str(i+1), 'status': d.get(f'info[{i}].State', ''),
                    'capacity_mb': int(float(d.get(f'info[{i}].TotalBytes', 0)) / 1048576),
                    'free_mb': int(float(d.get(f'info[{i}].RemainBytes', 0)) / 1048576),
                    'model': d.get(f'info[{i}].Name', ''),
                })
                i += 1

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts

        status = self.get_status()
        for hdd in status.get('hdds', []):
            if hdd['status'].lower() not in ('ok', 'normal', 'good', '0', ''):
                alerts.append({'key': f"{self.ip}_hdd{hdd['id']}", 'severity': 'critical',
                    'message': (f"💾 <b>{self.name}</b> — HDD პრობლემა!\n📍 IP: {self.ip}\n"
                                f"💽 დისკი #{hdd['id']}" + (f" — {_fmt_capacity(hdd.get('capacity_mb'))}" if hdd.get('capacity_mb') else '') +
                                (f" ({hdd['model']})" if hdd.get('model') else '') +
                                f"\n⚠️ {_hdd_status_meaning(hdd['status'])}")})
            else:
                alert_mgr.clear(f"{self.ip}_hdd{hdd['id']}")

        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# UNIVIEW NVR/DVR
# ============================================================
class UniviewNVR(HTTPAPIDevice):
    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'uniview_nvr',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'hdds': [], 'cameras': [], 'device_info': {}, 'uptime': None
        }
        if not status['online']: return status

        resp = self._get_any_auth('/LAPI/V1.0/System/DeviceInfo')
        if resp:
            try:
                d = resp.json().get('Response', {}).get('Data', {})
                status['device_info'] = {'model': d.get('DeviceModel', ''), 'firmware': d.get('SoftwareVersion', ''), 'serial': d.get('SerialNumber', '')}
            except: pass

        resp = self._get_any_auth('/LAPI/V1.0/Channels')
        if resp:
            try:
                for ch in resp.json().get('Response', {}).get('Data', []):
                    status['cameras'].append({
                        'id': str(ch.get('ID', '')), 'ip': ch.get('SrcIP', ''),
                        'online': ch.get('Status', '') == 'Online', 'status': ch.get('Status', 'unknown'),
                    })
            except: pass

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts

        status = self.get_status()
        prev_cameras = {}
        for cam in status.get('cameras', []):
            prev_cameras[cam['id']] = cam['online']
            if not cam['online'] and alert_mgr.get_prev_camera_state(self.ip, cam['id']) is not False:
                alerts.append({'key': f"{self.ip}_cam{cam['id']}", 'severity': 'warning',
                    'message': f"📷 <b>{self.name}</b> — კამერა გათიშულია!\n📍 NVR: {self.ip}\n🎥 არხი {cam['id']}"})
            if cam['online'] and alert_mgr.get_prev_camera_state(self.ip, cam['id']) is False:
                alerts.append({'key': f"{self.ip}_cam{cam['id']}_recovery", 'severity': 'info', 'force': True,
                    'message': f"✅ <b>{self.name}</b> — კამერა ისევ ხელმისაწვდომია\n📍 NVR: {self.ip}\n🎥 არხი {cam['id']}"})
                alert_mgr.clear(f"{self.ip}_cam{cam['id']}")

        alert_mgr.update_state(self.ip, True, prev_cameras)
        return alerts


# ============================================================
# HANWHA (Samsung) NVR/DVR - uses Sunapi
# ============================================================
class HanwhaNVR(HTTPAPIDevice):
    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'hanwha_nvr',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'hdds': [], 'cameras': [], 'device_info': {}, 'uptime': None
        }
        if not status['online']: return status

        resp = self._get_any_auth('/stw-cgi/system.cgi?msubmenu=deviceinfo&action=view')
        if resp:
            d = {}
            for line in resp.text.strip().split('\n'):
                if '=' in line:
                    k, v = line.split('=', 1)
                    d[k.strip()] = v.strip()
            status['device_info'] = {'model': d.get('Model', ''), 'firmware': d.get('FirmwareVersion', ''), 'serial': d.get('SerialNumber', '')}

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts
        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# AXIS Camera/NVR - uses VAPIX API
# ============================================================
class AxisDevice(HTTPAPIDevice):
    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'axis_device',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'hdds': [], 'cameras': [], 'device_info': {}, 'uptime': None
        }
        if not status['online']: return status

        resp = self._get_any_auth('/axis-cgi/basicdeviceinfo.cgi')
        if resp:
            try:
                root = ET.fromstring(resp.text)
                for prop in root.iter():
                    if 'ProdFullName' in prop.tag: status['device_info']['model'] = prop.text
                    if 'Version' in prop.tag: status['device_info']['firmware'] = prop.text
                    if 'SerialNumber' in prop.tag: status['device_info']['serial'] = prop.text
            except: pass

        resp = self._get_any_auth('/axis-cgi/disks/list.cgi?diskid=all')
        if resp:
            try:
                root = ET.fromstring(resp.text)
                for disk in root.iter('disk'):
                    status['hdds'].append({
                        'id': disk.get('diskid', ''), 'status': disk.get('status', ''),
                        'capacity_mb': int(disk.get('totalsize', 0)), 'free_mb': int(disk.get('freesize', 0)),
                        'model': disk.get('name', ''),
                    })
            except: pass

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts

        status = self.get_status()
        for hdd in status.get('hdds', []):
            if hdd['status'].lower() not in ('ok', 'normal', 'good', ''):
                alerts.append({'key': f"{self.ip}_hdd{hdd['id']}", 'severity': 'critical',
                    'message': (f"💾 <b>{self.name}</b> — HDD პრობლემა!\n📍 IP: {self.ip}\n"
                                f"💽 დისკი #{hdd['id']}" + (f" — {_fmt_capacity(hdd.get('capacity_mb'))}" if hdd.get('capacity_mb') else '') +
                                (f" ({hdd['model']})" if hdd.get('model') else '') +
                                f"\n⚠️ {_hdd_status_meaning(hdd['status'])}")})
            else:
                alert_mgr.clear(f"{self.ip}_hdd{hdd['id']}")

        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# BOSCH NVR/Camera
# ============================================================
class BoschDevice(HTTPAPIDevice):
    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'bosch_device',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'hdds': [], 'cameras': [], 'device_info': {}, 'uptime': None
        }
        if not status['online']: return status

        resp = self._get_any_auth('/rcp.xml?command=0x0001&type=T_DWORD&direction=READ')
        if resp:
            status['device_info']['model'] = 'Bosch Device'

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts
        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# ONVIF DEVICE (universal - works with any ONVIF camera/NVR)
# ============================================================
class ONVIFDevice(HTTPAPIDevice):
    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'onvif_device',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'hdds': [], 'cameras': [], 'device_info': {}, 'uptime': None
        }
        if not status['online']: return status

        try:
            from onvif import ONVIFCamera
            cam = ONVIFCamera(self.ip, self.port, self.username, self.password)
            info = cam.devicemgmt.GetDeviceInformation()
            status['device_info'] = {
                'model': getattr(info, 'Model', ''),
                'firmware': getattr(info, 'FirmwareVersion', ''),
                'serial': getattr(info, 'SerialNumber', ''),
            }
        except:
            # Fallback - just check if port responds
            if self._tcp_check():
                status['device_info'] = {'model': 'ONVIF Device (details unavailable)'}

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts
        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# SNMP DEVICE (switches, routers, APs, UPS, NAS, printers)
# ============================================================
class SNMPDevice(BaseDevice):
    def __init__(self, config):
        super().__init__(config)
        self.community = config.get('snmp_community', 'public')

    def _snmp_get(self, oid):
        try:
            r = subprocess.run(['snmpget', '-v2c', '-c', self.community, '-t', '3', '-r', '1', self.ip, oid],
                              capture_output=True, text=True, timeout=10)
            if r.returncode == 0 and '=' in r.stdout:
                return r.stdout.split('=', 1)[1].strip().strip('"')
        except: pass
        return None

    def _snmp_walk(self, oid):
        try:
            r = subprocess.run(['snmpwalk', '-v2c', '-c', self.community, '-t', '3', '-r', '1', self.ip, oid],
                              capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                return [l for l in r.stdout.strip().split('\n') if '=' in l]
        except: pass
        return []

    def get_status(self):
        status = {
            'name': self.name, 'ip': self.ip, 'type': 'snmp_device',
            'online': self._ping(), 'timestamp': datetime.now().isoformat(),
            'device_info': {}, 'uptime': None, 'interfaces': [], 'snmp_available': False
        }
        if not status['online']: return status

        desc = self._snmp_get('sysDescr.0')
        if desc:
            status['device_info']['model'] = desc[:100]
            status['snmp_available'] = True

            name = self._snmp_get('sysName.0')
            if name: status['device_info']['hostname'] = name

            uptime = self._snmp_get('sysUpTime.0')
            if uptime:
                try:
                    ticks = int(uptime.split('(')[1].split(')')[0]) if '(' in uptime else int(uptime)
                    status['uptime'] = ticks // 100
                except: pass

            if_names = self._snmp_walk('ifDescr')
            if_statuses = self._snmp_walk('ifOperStatus')
            for i, name_line in enumerate(if_names):
                if_name = name_line.split('=')[-1].strip().strip('"')
                if_status = 'unknown'
                if i < len(if_statuses):
                    if 'up(1)' in if_statuses[i] or ': 1' in if_statuses[i]: if_status = 'up'
                    elif 'down(2)' in if_statuses[i] or ': 2' in if_statuses[i]: if_status = 'down'
                status['interfaces'].append({'name': if_name, 'status': if_status})

        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts

        status = self.get_status()
        if status.get('snmp_available'):
            for iface in status.get('interfaces', []):
                n = iface['name']
                s = iface['status']
                if any(skip in n.lower() for skip in ['loopback', 'lo', 'null', 'vlan', 'stack']): continue
                state_key = f'if_{n}'
                if s == 'down' and alert_mgr.device_states.get(self.ip, {}).get(state_key) != 'down':
                    alerts.append({'key': f"{self.ip}_{state_key}", 'severity': 'warning',
                        'message': f"🔌 <b>{self.name}</b> — პორტი გათიშულია!\n📍 IP: {self.ip}\n🔗 {n}: DOWN"})
                elif s == 'up' and alert_mgr.device_states.get(self.ip, {}).get(state_key) == 'down':
                    alerts.append({'key': f"{self.ip}_{state_key}_recovery", 'severity': 'info', 'force': True,
                        'message': f"✅ <b>{self.name}</b> — პორტი აღდგა\n📍 IP: {self.ip}\n🔗 {n}: UP"})
                if self.ip not in alert_mgr.device_states: alert_mgr.device_states[self.ip] = {'online': True}
                alert_mgr.device_states[self.ip][state_key] = s

            if status.get('uptime') and status['uptime'] < 120:
                alerts.append({'key': f"{self.ip}_reboot", 'severity': 'warning',
                    'message': f"🔄 <b>{self.name}</b> გადაირთო!\n📍 IP: {self.ip}"})

        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# UPS (via SNMP)
# ============================================================
class UPSDevice(SNMPDevice):
    def get_status(self):
        status = super().get_status()
        status['type'] = 'ups'
        status['battery'] = {}

        if not status['online']: return status

        # Standard UPS MIB
        battery_status = self._snmp_get('1.3.6.1.2.1.33.1.2.1.0')  # upsAlarmOnBattery
        battery_charge = self._snmp_get('1.3.6.1.2.1.33.1.2.4.0')  # upsEstimatedChargeRemaining
        battery_runtime = self._snmp_get('1.3.6.1.2.1.33.1.2.3.0')  # upsEstimatedMinutesRemaining
        input_voltage = self._snmp_get('1.3.6.1.2.1.33.1.3.3.1.3.1')  # upsInputVoltage
        output_load = self._snmp_get('1.3.6.1.2.1.33.1.4.4.1.5.1')  # upsOutputPercentLoad

        status['battery'] = {
            'status': battery_status, 'charge': battery_charge,
            'runtime_min': battery_runtime, 'input_voltage': input_voltage,
            'load_pct': output_load
        }
        return status

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts

        status = self.get_status()
        bat = status.get('battery', {})

        if bat.get('charge'):
            try:
                charge = int(bat['charge'])
                if charge < 30:
                    alerts.append({'key': f"{self.ip}_battery_low", 'severity': 'critical',
                        'message': f"🔋 <b>{self.name}</b> — ბატარეა დაბალია!\n📍 IP: {self.ip}\n⚡ {charge}%"})
            except: pass

        if bat.get('input_voltage'):
            try:
                voltage = int(bat['input_voltage'])
                if voltage == 0:
                    alerts.append({'key': f"{self.ip}_power_out", 'severity': 'critical',
                        'message': f"⚡ <b>{self.name}</b> — დენი გათიშულია! UPS ბატარეაზეა!\n📍 IP: {self.ip}"})
            except: pass

        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# GENERIC NVR (auto-detect brand)
# ============================================================
class GenericNVR(HTTPAPIDevice):
    def __init__(self, config):
        super().__init__(config)
        self._detected_type = None
        self._inner = None

    def _detect(self):
        if self._inner: return self._inner

        cfg = {'name': self.name, 'ip': self.ip, 'port': self.port,
               'username': self.username, 'password': self.password, 'monitor': self.monitor_cfg}

        checks = [
            ('hikvision', '/ISAPI/System/deviceInfo', 'DeviceInfo', HikvisionNVR),
            ('dahua', '/cgi-bin/magicBox.cgi?action=getSystemInfo', 'deviceType', DahuaNVR),
            ('uniview', '/LAPI/V1.0/System/DeviceInfo', 'DeviceModel', UniviewNVR),
            ('hanwha', '/stw-cgi/system.cgi?msubmenu=deviceinfo&action=view', 'Model', HanwhaNVR),
            ('axis', '/axis-cgi/basicdeviceinfo.cgi', 'ProdFullName', AxisDevice),
        ]

        for brand, path, key, cls in checks:
            if _auth_is_blocked(self.ip):
                break
            try:
                resp = requests.get(f"http://{self.ip}:{self.port}{path}",
                    auth=HTTPDigestAuth(self.username, self.password), timeout=5)
                _record_auth_result(self.ip, resp.status_code != 401)
                if resp.ok and key in resp.text:
                    self._detected_type = brand
                    self._inner = cls(cfg)
                    return self._inner
            except: pass

        # Try ONVIF
        try:
            from onvif import ONVIFCamera
            cam = ONVIFCamera(self.ip, self.port, self.username, self.password)
            cam.devicemgmt.GetDeviceInformation()
            self._detected_type = 'onvif'
            self._inner = ONVIFDevice(cfg)
            return self._inner
        except: pass

        return None

    def get_status(self):
        d = self._detect()
        if d:
            s = d.get_status()
            s['type'] = f'auto ({self._detected_type})'
            return s
        return {'name': self.name, 'ip': self.ip, 'type': 'auto (unknown)',
                'online': self._ping(), 'timestamp': datetime.now().isoformat(),
                'hdds': [], 'cameras': [], 'device_info': {}}

    def check_all(self, alert_mgr):
        d = self._detect()
        if d: return d.check_all(alert_mgr)
        alerts, _ = self._offline_alerts(alert_mgr)
        alert_mgr.update_state(self.ip, self._ping())
        return alerts


# ============================================================
# PING ONLY (any device)
# ============================================================
class NetworkDevice(BaseDevice):
    def get_status(self):
        return {'name': self.name, 'ip': self.ip, 'type': 'network_device',
                'online': self._ping(), 'timestamp': datetime.now().isoformat()}

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if is_online: alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# HTTP CHECK (web servers, web interfaces)
# ============================================================
class HTTPDevice(BaseDevice):
    def __init__(self, config):
        super().__init__(config)
        self.url = config.get('url', f"http://{self.ip}:{self.port}")
        self.expected_code = config.get('expected_code', 200)

    def get_status(self):
        online = self._ping()
        http_ok = False
        if online:
            try:
                resp = requests.get(self.url, timeout=10, verify=False)
                http_ok = resp.status_code == self.expected_code
            except: pass
        return {'name': self.name, 'ip': self.ip, 'type': 'http_device',
                'online': online, 'http_ok': http_ok, 'timestamp': datetime.now().isoformat()}

    def check_all(self, alert_mgr):
        alerts, is_online = self._offline_alerts(alert_mgr)
        if not is_online: return alerts

        try:
            resp = requests.get(self.url, timeout=10, verify=False)
            if resp.status_code != self.expected_code:
                if alert_mgr.should_alert(f"{self.ip}_http"):
                    alerts.append({'key': f"{self.ip}_http", 'severity': 'warning',
                        'message': f"🌐 <b>{self.name}</b> — HTTP შეცდომა!\n📍 {self.url}\n⚠️ კოდი: {resp.status_code} (მოსალოდნელი: {self.expected_code})"})
        except:
            if alert_mgr.should_alert(f"{self.ip}_http"):
                alerts.append({'key': f"{self.ip}_http", 'severity': 'warning',
                    'message': f"🌐 <b>{self.name}</b> — ვებ ინტერფეისი არ პასუხობს!\n📍 {self.url}"})

        alert_mgr.update_state(self.ip, True)
        return alerts


# ============================================================
# FACTORY
# ============================================================
DEVICE_TYPES = {
    # NVRs/DVRs
    'hikvision_nvr': HikvisionNVR,
    'dahua_nvr': DahuaNVR,
    'uniview_nvr': UniviewNVR,
    'hanwha_nvr': HanwhaNVR,
    'axis_device': AxisDevice,
    'bosch_device': BoschDevice,
    'onvif_device': ONVIFDevice,
    'auto_nvr': GenericNVR,
    # Network equipment (SNMP)
    'switch': SNMPDevice,
    'router': SNMPDevice,
    'access_point': SNMPDevice,
    'firewall': SNMPDevice,
    'poe_switch': SNMPDevice,
    # Power
    'ups': UPSDevice,
    # Monitoring
    'http_device': HTTPDevice,
    # Generic
    'ip_camera': NetworkDevice,
    'printer': SNMPDevice,
    'voip_phone': SNMPDevice,
    'pbx': SNMPDevice,
    'nas': SNMPDevice,
    'server': SNMPDevice,
    'access_control': NetworkDevice,
    'intercom': NetworkDevice,
    'iot_device': NetworkDevice,
    'network_device': NetworkDevice,
}

def create_monitor(device_config):
    device_type = device_config.get('type', 'network_device')
    cls = DEVICE_TYPES.get(device_type, NetworkDevice)
    return cls(device_config)
