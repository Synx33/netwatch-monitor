#!/usr/bin/env python3
"""
NetWatch monitoring engine — the fast ping loop, the periodic deep health
checks, and the alert manager that decides what is actually worth a message.
"""
import json
import re
import time
import logging
import uuid
import requests
import xml.etree.ElementTree as ET
from datetime import datetime
from pathlib import Path
from requests.auth import HTTPDigestAuth
from devices import create_monitor, diagnose_offline

logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s [%(levelname)s] %(message)s',
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(str(Path(__file__).parent / 'netwatch.log'))
    ]
)
log = logging.getLogger('netwatch')

CONFIG_PATH = Path(__file__).parent / 'config.json'
STATE_PATH = Path(__file__).parent / 'state.json'


class TelegramBot:
    def __init__(self, token, chat_id):
        self.token = token
        self.chat_id = chat_id
        self.enabled = bool(token and chat_id)

    def send(self, message, extra_chat_ids=None):
        if not self.enabled:
            return False
        self._send_to(self.chat_id, message)
        if extra_chat_ids:
            for cid in extra_chat_ids:
                if cid and cid != self.chat_id:
                    self._send_to(cid, message)
        return True

    def _send_to(self, chat_id, message):
        try:
            requests.post(
                f"https://api.telegram.org/bot{self.token}/sendMessage",
                json={"chat_id": chat_id, "text": message, "parse_mode": "HTML"},
                timeout=10
            )
        except Exception as e:
            log.error(f"Telegram failed for {chat_id}: {e}")


# Per-site notification categories. Each site has a `notifications` dict in
# config.json mapping these keys to True/False. When a category is False,
# alerts in that category are NOT sent to the site's client chat (admin chat
# still receives everything). New sites default to all True.
# Each tuple: (key, label, [groups])
# Groups are purely for UI tabbing. A category in multiple groups renders on
# every matching tab but maps to one underlying toggle — toggling one updates
# the rest. Same-named group keys in the UI: 'nvr' and 'network'.
NOTIFICATION_CATEGORIES = [
    ('offline',      'Device offline / online',   ['nvr', 'network']),
    ('reboot',       'Device rebooted',           ['nvr', 'network']),
    ('power_outage', 'Site-wide power outage',    ['nvr', 'network']),
    ('hdd',          'HDD / RAID / SMART',        ['nvr']),
    ('camera',       'Camera offline / restored', ['nvr']),
    ('recording',    'Recording stopped / failed',['nvr']),
    ('clock',        'NVR clock out of sync',     ['nvr']),
    ('clock_fix',    'Clock auto-fix actions',    ['nvr']),
    ('port',         'Switch port up / down',     ['network']),
    ('ups',          'UPS battery low',           ['network']),
    ('http',         'HTTP service errors',       ['network']),
]

_CATEGORY_PATTERNS = [
    ('power_outage', ('_power', 'site_')),
    ('hdd', ('_hdd', '_raid', '_smart')),
    ('camera', ('_cam',)),
    ('recording', ('_record',)),
    # clock_fix MUST precede clock — '_clock' is a substring of '_clockfix'
    # and alert_category() returns the first matching pattern.
    ('clock_fix', ('_clockfix',)),
    ('clock', ('_clock', '_time')),
    ('reboot', ('_reboot',)),
    ('ups', ('_battery', '_ups')),
    ('port', ('_port',)),
    ('http', ('_http',)),
    ('offline', ('_offline', '_recovery')),
]


def alert_category(key):
    """Map an alert key (or site-level pseudo-key) to a notification category."""
    for category, needles in _CATEGORY_PATTERNS:
        for n in needles:
            if n in key:
                return category
    return 'offline'  # safe fallback


def site_wants_category(site, category):
    """Check if this site's notifications dict has `category` enabled.
    Missing dict or missing key defaults to True (opt-out, not opt-in)."""
    prefs = (site or {}).get('notifications') or {}
    return prefs.get(category, True)


def is_site_muted(site):
    """A site in maintenance mode has `mute_until` set to a future unix epoch.
    Muted sites still get monitored (state.json stays fresh) but no Telegram
    alert — admin or client — fires for them until the mute expires."""
    if not site:
        return False
    mute_until = site.get('mute_until')
    if not mute_until:
        return False
    try:
        return float(mute_until) > time.time()
    except (TypeError, ValueError):
        return False


# SLA tracking — append-only JSONL of state transitions. `offline_start` is
# written when a device crosses the fail-count threshold; `offline_end` is
# written when it recovers, with the duration. Reports aggregate over a window.
_SLA_LOG_PATH = Path(__file__).parent / 'outages.jsonl'


def _log_outage_event(event):
    try:
        _SLA_LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
        with open(_SLA_LOG_PATH, 'a') as f:
            f.write(json.dumps(event, ensure_ascii=False) + '\n')
    except Exception as e:
        log.error(f"outage log write failed: {e}")


def compute_sla(site_name=None, days=30, start_ts=None, end_ts=None):
    """
    Read the outage log and build an SLA report.

    If `start_ts` and `end_ts` are given, they bound the window (unix epochs).
    Otherwise the window is the last `days` days ending now.
    """
    if not _SLA_LOG_PATH.exists():
        return {'site': site_name, 'window_days': days, 'devices': {}}

    now = time.time()
    if start_ts is not None and end_ts is not None:
        cutoff_ts = float(start_ts)
        period_end = float(end_ts)
    else:
        period_end = now
        cutoff_ts = now - (days * 24 * 3600)
    period_sec = period_end - cutoff_ts

    events = []
    try:
        with open(_SLA_LOG_PATH) as f:
            for line in f:
                try:
                    e = json.loads(line)
                except (json.JSONDecodeError, ValueError):
                    continue
                if site_name and e.get('site') != site_name:
                    continue
                # Parse ts
                try:
                    t = datetime.fromisoformat(e['ts']).timestamp()
                except Exception:
                    continue
                if t < cutoff_ts or t > period_end:
                    continue
                e['_ts'] = t
                events.append(e)
    except OSError:
        return {'site': site_name, 'window_days': days, 'devices': {}}

    # pair offline_start/offline_end per device
    by_ip = {}
    for e in events:
        by_ip.setdefault(e.get('ip', '?'), []).append(e)

    devices = {}
    for ip, ev_list in by_ip.items():
        ev_list.sort(key=lambda x: x['_ts'])
        incidents = 0
        total_outage = 0
        longest = 0
        name = '?'
        open_since = None
        for e in ev_list:
            if e.get('device'):
                name = e['device']
            if e.get('event') == 'offline_start':
                open_since = e['_ts']
                incidents += 1
            elif e.get('event') == 'offline_end':
                dur = e.get('duration_sec')
                if dur is None and open_since is not None:
                    dur = int(e['_ts'] - open_since)
                if dur is not None:
                    total_outage += dur
                    longest = max(longest, dur)
                open_since = None
        # Still-ongoing outage at report time — cap at window end
        if open_since is not None:
            dur = int(min(now, period_end) - open_since)
            total_outage += dur
            longest = max(longest, dur)
        uptime_pct = max(0.0, min(100.0, (period_sec - total_outage) / period_sec * 100))
        devices[ip] = {
            'name': name,
            'incidents': incidents,
            'total_outage_sec': total_outage,
            'longest_outage_sec': longest,
            'uptime_percent': round(uptime_pct, 3),
        }

    return {
        'site': site_name,
        'window_days': int(period_sec / 86400) if period_sec else 0,
        'period_start': datetime.fromtimestamp(cutoff_ts).isoformat(timespec='seconds'),
        'period_end': datetime.fromtimestamp(period_end).isoformat(timespec='seconds'),
        'devices': devices,
    }


class AlertManager:
    def __init__(self, cooldown=300, offline_threshold=30,
                 flap_window=1800, flap_threshold=5, flap_suppress=3600):
        self.cooldown = cooldown
        # Consecutive failed pings required before we declare a device offline.
        # At PING_INTERVAL=5s, threshold=30 means ~150s (2.5 min) of solid failure
        # before an alert fires. Prevents false alarms from one dropped packet.
        self.offline_threshold = offline_threshold
        self.active_alerts = {}
        self.device_states = {}

        # ── Flap damping (anti-spam) ──────────────────────────────────────
        # A device/camera on a marginal link bounces down→up→down→up; without
        # damping each cycle re-fires an alert (state-based dedup clears on
        # recovery). Here we count how often each "flap group" (a device+symptom,
        # e.g. one camera, or one NVR's offline state) fires within a rolling
        # window. Once it exceeds the threshold we go SILENT for that group for
        # `flap_suppress` seconds and emit ONE "device is unstable" notice
        # instead. After the window passes, normal alerting resumes (and if it's
        # still flapping, at most one more notice per hour).
        self.flap_window = flap_window        # rolling window (s) to count fires
        self.flap_threshold = flap_threshold  # > this many fires in window = flapping
        self.flap_suppress = flap_suppress    # how long to stay silent once flapping
        self._flap_fires = {}                 # flap_group -> [timestamps]
        self._flap_suppressed_until = {}      # flap_group -> epoch
        self._flap_notices = []               # queued {site, label, category}

    @staticmethod
    def _flap_group(key):
        """Normalize an alert key to the 'thing' that may be flapping, so the
        down alert and its recovery, and repeated timestamped events, all count
        toward one group:
          203.0.113.10:81_cam5            ─┐
          203.0.113.10:81_cam5_recovery   ─┴─► 203.0.113.10:81_cam5
          1.2.3.4_record_recordError_2026-06-02T14:30:00 ─► 1.2.3.4_record_recordError
        """
        k = key
        if k.endswith('_recovery'):
            k = k[:-len('_recovery')]
        # strip a trailing ISO timestamp segment if present
        k = re.sub(r'_\d{4}-\d{2}-\d{2}t[\d:]+$', '', k, flags=re.IGNORECASE)
        return k

    def should_alert(self, key, label=None, site=None, category='offline'):
        """Decide whether to actually send the alert for `key`.

        Two gates:
          1. Dedup — fire ONCE when a condition is raised, stay silent until
             clear(key) is called (i.e. the condition recovers).
          2. Flap damping — if this device/symptom has fired too many times in
             the rolling window, suppress it and queue a single 'unstable'
             notice (drained by the main loop).

        Returns True only when the individual alert should be sent now.
        """
        if key in self.active_alerts:
            return False

        fg = self._flap_group(key)
        now = time.time()

        # Already in a suppression window? Mark dedup, stay silent.
        if now < self._flap_suppressed_until.get(fg, 0):
            self.active_alerts[key] = {'time': now}
            return False

        # Record this fire and prune the rolling window.
        fires = self._flap_fires.setdefault(fg, [])
        fires.append(now)
        self._flap_fires[fg] = [t for t in fires if now - t <= self.flap_window]

        self.active_alerts[key] = {'time': now}

        if len(self._flap_fires[fg]) > self.flap_threshold:
            # Crossed into flapping — go quiet for this group and emit one notice.
            self._flap_suppressed_until[fg] = now + self.flap_suppress
            self._flap_notices.append({
                'site': site,
                'label': label or fg,
                'category': category,
                'minutes': int(self.flap_suppress / 60),
            })
            return False  # suppress the individual alert; the notice covers it

        return True

    def drain_flap_notices(self):
        """Return and clear queued flap notices (one per group that just started
        flapping). The main loop sends these through the normal site filter."""
        out = self._flap_notices
        self._flap_notices = []
        return out

    def clear(self, key):
        # Only clears the dedup entry so the next genuine occurrence can fire.
        # Flap history is intentionally NOT cleared here — that memory is what
        # lets us detect a device cycling down/up repeatedly.
        self.active_alerts.pop(key, None)

    def was_offline(self, ip):
        return self.device_states.get(ip, {}).get('online') is False

    def was_online(self, ip):
        return self.device_states.get(ip, {}).get('online') is True

    def get_prev_camera_state(self, ip, cam_id):
        return self.device_states.get(ip, {}).get('cameras', {}).get(cam_id)

    def get_prev_hdd_state(self, ip, hdd_id):
        return self.device_states.get(ip, {}).get('hdds', {}).get(hdd_id)

    def update_state(self, ip, online, cameras=None, hdds=None):
        if ip not in self.device_states:
            self.device_states[ip] = {'online': None, 'cameras': {}, 'hdds': {}, 'fail_count': 0}
        self.device_states[ip]['online'] = online
        if online:
            self.device_states[ip]['fail_count'] = 0
        if cameras is not None:
            self.device_states[ip]['cameras'] = cameras
        if hdds is not None:
            self.device_states[ip]['hdds'] = hdds

    def record_ping(self, ip, success, site_name=None, device_name=None):
        """
        Record a ping result and return (just_went_offline, just_came_online).

        A device only transitions to 'offline' after `offline_threshold`
        consecutive failures — callers should only send the offline alert
        when just_went_offline is True.

        On every transition we append to the outage log for SLA reporting.
        """
        if ip not in self.device_states:
            self.device_states[ip] = {'online': None, 'cameras': {}, 'hdds': {}, 'fail_count': 0}
        s = self.device_states[ip]
        prev_online = s.get('online')
        now = time.time()

        if success:
            s['fail_count'] = 0
            if prev_online is False:
                s['online'] = True
                # outage ended — log with duration
                start = s.pop('offline_since', None)
                duration = int(now - start) if start else None
                _log_outage_event({
                    'ts': datetime.now().isoformat(timespec='seconds'),
                    'event': 'offline_end',
                    'ip': ip,
                    'site': site_name,
                    'device': device_name,
                    'duration_sec': duration,
                })
                return False, True
            if prev_online is None:
                s['online'] = True
            return False, False

        s['fail_count'] = s.get('fail_count', 0) + 1
        if s['fail_count'] >= self.offline_threshold and prev_online is not False:
            s['online'] = False
            s['offline_since'] = now
            _log_outage_event({
                'ts': datetime.now().isoformat(timespec='seconds'),
                'event': 'offline_start',
                'ip': ip,
                'site': site_name,
                'device': device_name,
            })
            return True, False
        return False, False


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_state(state):
    with open(STATE_PATH, 'w') as f:
        json.dump(state, f, indent=2, default=str)


LOG_TYPE_NAMES = {
    'motionStart': 'Motion Detected', 'lineDetectionStart': 'Line Crossing',
    'fieldDetectionStart': 'Intrusion Detected', 'faceSnapStart': 'Face Detected',
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

# Track last seen log timestamps per device to avoid duplicate notifications
_last_log_times = {}


# NVR log events that are genuinely alert-worthy ("recording stopped for some
# reason"). Mundane operations (login, config, recording start/stop schedule)
# are NOT forwarded — they were the source of past Telegram spam. HDD/SMART/
# camera/reboot are already covered by the active check_all() polling, so we
# only surface recording failures here that nothing else catches.
_CRITICAL_LOG_EVENTS = {
    'recordError': 'Recording Error',
    'recordException': 'Recording Exception',
    'recordingException': 'Recording Exception',
}


def check_nvr_logs(site_name, device, telegram, site_chat_id):
    """Pull new NVR logs; return a list of critical alert dicts (recording
    failures). Returns [] if nothing critical / not applicable. The caller
    sends them through the per-site notification filter."""
    if device.get('type') not in ('hikvision_nvr', 'auto_nvr'):
        return []

    ip = device.get('ip', '')
    port = device.get('port', 80)
    username = device.get('username', '')
    password = device.get('password', '')
    if not username:
        return []

    # Skip if the auth circuit breaker is tripped for this IP — saves us from
    # triggering the NVR's lockout when the password is wrong.
    from devices import _auth_is_blocked, _record_auth_result
    if _auth_is_blocked(ip):
        return []

    device_key = f"{site_name}:{ip}"
    # On first run, set last_seen to NOW so we don't dump all old logs
    if device_key not in _last_log_times:
        _last_log_times[device_key] = datetime.now().strftime('%Y-%m-%dT%H:%M:%S')
        return []
    last_seen = _last_log_times[device_key]
    today = datetime.now().strftime('%Y-%m-%d')
    auth = HTTPDigestAuth(username, password)

    # Fetch only Operation and Exception logs (not alarms)
    new_logs = []
    for meta_id in ['log.std-cgi.com/Operation', 'log.std-cgi.com/Exception']:
        try:
            search_id = str(uuid.uuid4())
            xml_body = (
                '<?xml version="1.0" encoding="utf-8"?>'
                '<CMSearchDescription>'
                f'<searchID>{search_id}</searchID>'
                f'<metaId>{meta_id}</metaId>'
                '<timeSpanList><timeSpan>'
                f'<startTime>{today}T00:00:00Z</startTime>'
                f'<endTime>{today}T23:59:59Z</endTime>'
                '</timeSpan></timeSpanList>'
                '<maxResults>20</maxResults>'
                '</CMSearchDescription>'
            )
            resp = requests.post(
                f"http://{ip}:{port}/ISAPI/ContentMgmt/logSearch",
                data=xml_body.encode('utf-8'), auth=auth,
                headers={"Content-Type": "application/xml"},
                timeout=8, verify=False,
            )
            # Record auth outcome so the circuit breaker can trip on repeated 401s
            _record_auth_result(ip, resp.status_code != 401)
            if resp.status_code != 200:
                continue

            root = ET.fromstring(resp.text)
            for elem in root.iter():
                tag = elem.tag.split('}')[-1] if '}' in elem.tag else elem.tag
                if tag == 'logDescriptor':
                    entry = {}
                    for child in elem:
                        ctag = child.tag.split('}')[-1] if '}' in child.tag else child.tag
                        entry[ctag] = (child.text or '').strip()

                    log_time = entry.get('StartDateTime', '')
                    if log_time > last_seen:
                        new_logs.append(entry)
        except Exception:
            pass

    if not new_logs:
        return []

    # Sort and update last seen
    new_logs.sort(key=lambda x: x.get('StartDateTime', ''))
    _last_log_times[device_key] = new_logs[-1].get('StartDateTime', last_seen)

    # Build alerts ONLY for critical recording-failure events. Everything else
    # (mundane operations, login events, etc.) is skipped — those caused the
    # old Telegram spam and are still viewable in the web UI's Device Logs tab.
    dev_name = device.get('name', ip)
    critical_alerts = []
    for entry in new_logs:
        meta = entry.get('metaId', '')
        parts = meta.replace('log.hikvision.com/', '').replace('log.std-cgi.com/', '').split('/')
        event_key = parts[1] if len(parts) > 1 else ''
        channel = parts[2] if len(parts) > 2 else ''

        if event_key not in _CRITICAL_LOG_EVENTS:
            continue  # not a recording failure — skip

        event_name = _CRITICAL_LOG_EVENTS[event_key]
        if channel:
            event_name += f' (CH{channel})'
        detail = f"\n📝 {entry.get('additionInformation', '')}" if entry.get('additionInformation') else ''
        msg = (
            f"🔴 <b>{dev_name}</b> — {event_name}\n"
            f"🏢 {site_name}\n"
            f"⚠️ ჩაწერა შეწყდა / ხარვეზი{detail}\n"
            f"🕐 {entry.get('StartDateTime', '')}"
        )
        # _record in the key routes this to the 'recording' notification category
        critical_alerts.append({
            'key': f"{ip}_record_{event_key}_{entry.get('StartDateTime','')}",
            'category': 'recording',
            'message': msg,
        })
    return critical_alerts


def main():
    log.info("NetWatch starting...")
    config = load_config()

    telegram = TelegramBot(config['telegram']['bot_token'], config['telegram']['chat_id'])
    alert_mgr = AlertManager(
        config.get('alert_cooldown', 300),
        offline_threshold=config.get('offline_threshold', 30),
        flap_window=config.get('flap_window', 1800),
        flap_threshold=config.get('flap_threshold', 5),
        flap_suppress=config.get('flap_suppress', 3600),
    )
    check_interval = config.get('check_interval', 30)
    PING_INTERVAL = 5

    monitors = []
    site_chat_ids = {}
    sites_by_name = {}
    for site in config['sites']:
        site_chat_ids[site['name']] = site.get('telegram_chat_id', '')
        sites_by_name[site['name']] = site
        for device in site['devices']:
            monitors.append((site['name'], create_monitor(device)))

    log.info(f"Monitoring {len(monitors)} devices across {len(config['sites'])} sites")

    if telegram.enabled:
        telegram.send(
            f"✅ <b>NetWatch ჩაირთო</b>\n"
            f"📡 {len(monitors)} მოწყობილობა | {len(config['sites'])} ობიექტი\n"
            f"🔄 შემოწმება ყოველ {PING_INTERVAL} წამში | სრული სკანირება ყოველ {check_interval} წამში"
        )

    last_full_check = 0
    last_log_check = 0
    NVR_LOG_INTERVAL = 30  # Check NVR logs every 30 seconds
    # Tracks when a site FIRST appeared fully offline, keyed by site name.
    # A power-outage alert only fires after the outage persists past
    # `power_outage_delay` seconds — prevents false alarms from brief
    # network blips, ISP hiccups, or our own VPN tunnel flapping (which
    # makes every device behind it look offline at once).
    power_pending = {}

    while True:
        try:
            config = load_config()
            monitors = []
            site_chat_ids = {}
            for site in config['sites']:
                site_chat_ids[site['name']] = site.get('telegram_chat_id', '')
                for device in site['devices']:
                    monitors.append((site['name'], create_monitor(device)))
        except:
            pass

        now = time.time()
        do_full_check = (now - last_full_check) >= check_interval

        state = {'last_check': datetime.now().isoformat(), 'sites': {}}

        def _site_muted(site_name):
            return is_site_muted(sites_by_name.get(site_name))

        def _send_site_alert(msg, site_name, category):
            """Deliver an alert for `site_name` respecting mute + notification prefs.
            Returns True if anything was sent (for logging callers)."""
            if _site_muted(site_name):
                return False  # maintenance mode — no admin nor client delivery
            site_obj = sites_by_name.get(site_name)
            site_chat = site_chat_ids.get(site_name)
            extras = []
            if site_chat and site_wants_category(site_obj, category):
                extras.append(site_chat)
            telegram.send(msg, extras)
            return True

        def _site_chats_for(site_name, category):
            """(Deprecated path kept for compatibility) return extras list."""
            if _site_muted(site_name):
                return []
            site_chat = site_chat_ids.get(site_name)
            if not site_chat:
                return []
            site_obj = sites_by_name.get(site_name)
            if not site_wants_category(site_obj, category):
                return []
            return [site_chat]

        for site_name, monitor in monitors:
            if site_name not in state['sites']:
                state['sites'][site_name] = []

            try:
                if do_full_check:
                    status = monitor.get_status()
                    state['sites'][site_name].append(status)
                    alerts = monitor.check_all(alert_mgr)

                    for alert in alerts:
                        category = alert.get('category') or alert_category(alert['key'])
                        # 'force' alerts (e.g. camera recovery) still respect flap damping
                        # by routing through should_alert — except we keep recovery pairing:
                        # a recovery only matters if its down-alert was sent, and the down
                        # path already gated it. Treat force as "skip dedup but keep flap".
                        if alert.get('force'):
                            should_send = True
                        else:
                            should_send = alert_mgr.should_alert(
                                alert['key'], label=f"{monitor.name}", site=site_name, category=category)
                        if should_send:
                            msg = f"🏢 <b>{site_name}</b>\n{'─' * 20}\n{alert['message']}\n\n🕐 {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
                            if _send_site_alert(msg, site_name, category):
                                log.warning(f"ALERT: {site_name} - {alert['key']}")
                            else:
                                log.info(f"muted: skipped alert for {site_name}")

                    if status.get('online'):
                        log.info(f"✓ {monitor.name} ({monitor.ip})")
                    else:
                        log.warning(f"✗ {monitor.name} ({monitor.ip}) OFFLINE")
                else:
                    is_online = monitor._ping()
                    just_offline, just_online = alert_mgr.record_ping(
                        monitor.ip, is_online,
                        site_name=site_name, device_name=monitor.name,
                    )

                    if just_offline:
                        reasons = diagnose_offline(monitor.ip, getattr(monitor, 'port', 80))
                        reason_text = '\n'.join(['• ' + r for r in reasons]) if reasons else '• მიზეზი უცნობია'

                        if alert_mgr.should_alert(f"{monitor.ip}_offline",
                                                  label=monitor.name, site=site_name, category='offline'):
                            msg = (
                                f"🏢 <b>{site_name}</b>\n{'─' * 20}\n"
                                f"🔴 <b>{monitor.name}</b> — გაითიშა!\n"
                                f"📍 IP: {monitor.ip}\n\n"
                                f"<b>სავარაუდო მიზეზი:</b>\n{reason_text}\n\n"
                                f"🕐 {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
                            )
                            if _send_site_alert(msg, site_name, 'offline'):
                                log.warning(f"FAST ALERT: {site_name} - {monitor.name} OFFLINE")
                            else:
                                log.info(f"muted: skipped offline alert for {monitor.name}")

                    elif just_online:
                        msg = (
                            f"🏢 <b>{site_name}</b>\n{'─' * 20}\n"
                            f"🟢 <b>{monitor.name}</b> — ისევ ჩაირთო!\n"
                            f"📍 IP: {monitor.ip}\n\n"
                            f"🕐 {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
                        )
                        _send_site_alert(msg, site_name, 'offline')
                        alert_mgr.clear(f"{monitor.ip}_offline")
                        log.info(f"RECOVERY: {site_name} - {monitor.name} back online")

                    state['sites'][site_name].append({
                        'name': monitor.name, 'ip': monitor.ip,
                        'type': getattr(monitor, '_detected_type', 'device') or 'device',
                        'online': is_online, 'timestamp': datetime.now().isoformat()
                    })

            except Exception as e:
                log.error(f"Error checking {monitor.name}: {e}")

        if do_full_check:
            last_full_check = now

        save_state(state)

        # Cross-site power outage detection — only alerts after a SUSTAINED outage.
        # Default delay 420s (7 min); configurable via "power_outage_delay" in config.json.
        power_delay = config.get('power_outage_delay', 420)
        for site in config['sites']:
            site_name = site['name']
            site_devices = state['sites'].get(site_name, [])
            if len(site_devices) < 2:
                continue

            offline_count = sum(1 for d in site_devices if not d.get('online'))
            total_count = len(site_devices)

            if offline_count == total_count and total_count >= 2:
                # All devices down — start (or continue) the pending timer.
                first_seen = power_pending.get(site_name)
                if first_seen is None:
                    power_pending[site_name] = now
                    log.info(f"power-pending: {site_name} all {total_count} offline — "
                             f"holding alert for {power_delay}s before confirming outage")
                elif (now - first_seen) >= power_delay:
                    # Outage has persisted past the delay → confirm and alert (once).
                    if alert_mgr.should_alert(f"site_{site_name}_power",
                                              label=f"{site_name} (power)", site=site_name,
                                              category='power_outage'):
                        down_min = int((now - first_seen) / 60)
                        msg = (
                            f"🏢 <b>{site_name}</b>\n{'─' * 20}\n"
                            f"⚡ <b>სავარაუდოდ დენი გაითიშა!</b>\n\n"
                            f"ყველა მოწყობილობა ({total_count}) გათიშულია "
                            f"{down_min}+ წუთის განმავლობაში.\n\n"
                            f"🕐 {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
                        )
                        if _send_site_alert(msg, site_name, 'power_outage'):
                            log.warning(f"POWER OUTAGE: {site_name} (sustained {down_min}min)")

            elif offline_count == 0:
                # Everything back online — clear the pending timer.
                power_pending.pop(site_name, None)
                if f"site_{site_name}_power" in alert_mgr.active_alerts:
                    msg = (
                        f"🏢 <b>{site_name}</b>\n{'─' * 20}\n"
                        f"⚡ <b>დენი აღდგა!</b>\n\n"
                        f"ყველა მოწყობილობა ისევ ჩაირთო.\n\n"
                        f"🕐 {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
                    )
                    _send_site_alert(msg, site_name, 'power_outage')
                    alert_mgr.clear(f"site_{site_name}_power")

            else:
                # Partial recovery (some up, some down) — NOT a full outage.
                # Reset the pending timer so a flapping site never accumulates
                # toward the threshold.
                power_pending.pop(site_name, None)

        # NVR log check — every NVR_LOG_INTERVAL seconds
        if now - last_log_check >= NVR_LOG_INTERVAL:
            last_log_check = now
            for site in config['sites']:
                s_name = site['name']
                s_chat = site.get('telegram_chat_id', '')
                for device in site['devices']:
                    try:
                        rec_alerts = check_nvr_logs(s_name, device, telegram, s_chat) or []
                        for a in rec_alerts:
                            # Once per unique event (timestamped key); flap damping
                            # collapses a storm of repeated recording errors into one
                            # 'unstable' notice. Routed through the site filter + mute.
                            if alert_mgr.should_alert(a['key'], label=device.get('name',''),
                                                      site=s_name, category=a['category']):
                                full = (f"🏢 <b>{s_name}</b>\n{'─' * 20}\n{a['message']}\n\n"
                                        f"🕐 {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}")
                                if _send_site_alert(full, s_name, a['category']):
                                    log.warning(f"RECORDING ALERT: {s_name} - {device.get('name','')}")
                    except Exception as e:
                        log.error(f"NVR log check error {s_name}/{device.get('name','')}: {e}")

        # Drain any flap notices accumulated this cycle — one concise "device is
        # unstable, pausing its alerts" message per group, instead of a storm.
        for n in alert_mgr.drain_flap_notices():
            fmsg = (
                f"🏢 <b>{n['site'] or 'NetWatch'}</b>\n{'─' * 20}\n"
                f"🔁 <b>{n['label']}</b> — არასტაბილურია (ხშირად ითიშება/ირთვება)\n"
                f"🔕 შეტყობინებები შეჩერებულია {n['minutes']} წუთით სპამის თავიდან ასაცილებლად.\n\n"
                f"🕐 {datetime.now().strftime('%H:%M:%S %d/%m/%Y')}"
            )
            if n['site']:
                _send_site_alert(fmsg, n['site'], n['category'])
            elif telegram.enabled:
                telegram.send(fmsg)
            log.warning(f"FLAP SUPPRESS: {n['site']} - {n['label']} (muted {n['minutes']}min)")

        time.sleep(PING_INTERVAL)


if __name__ == '__main__':
    main()
