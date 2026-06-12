#!/usr/bin/env python3
"""
UDP 514 syslog receiver for switch/router logs. Binds to the WireGuard tunnel
IP by default so it is never exposed publicly. Each message is appended as one
JSON line to a daily-dated file (YYYY-MM-DD.jsonl); a cron job prunes files
older than RETENTION_DAYS. RFC 3164 parsing is best-effort — unparseable
messages are stored raw. Runs as root for the privileged port; one blocking
recv loop.
"""

import json
import os
import re
import socket
import sys
import time
from datetime import datetime
from pathlib import Path

HERE = Path(__file__).parent
# Default location is inside project dir; override with SYSLOG_DIR env var to move it.
# Files are daily-dated (YYYY-MM-DD.jsonl). Cron at /etc/cron.daily/netwatch-syslog-retention
# deletes files older than RETENTION_DAYS.
LOG_DIR = Path(os.environ.get('SYSLOG_DIR', str(HERE / 'syslog')))
RETENTION_DAYS = int(os.environ.get('SYSLOG_RETENTION_DAYS', '90'))
BIND_HOST = os.environ.get('SYSLOG_BIND', '10.66.66.1')
BIND_PORT = int(os.environ.get('SYSLOG_PORT', '514'))

FACILITIES = ['kern', 'user', 'mail', 'daemon', 'auth', 'syslog', 'lpr', 'news',
              'uucp', 'cron', 'authpriv', 'ftp', 'ntp', 'audit', 'alert', 'clock',
              'local0', 'local1', 'local2', 'local3', 'local4', 'local5', 'local6', 'local7']
SEVERITIES = ['emerg', 'alert', 'crit', 'err', 'warn', 'notice', 'info', 'debug']
# MikroTik emits these as topic tags; map to standard severities
MIKROTIK_SEVERITY_ALIASES = {
    'critical': 'crit',
    'error': 'err',
    'warning': 'warn',
    'info': 'info',
    'debug': 'debug',
}
_BSD_TS_RE = re.compile(
    r'^([A-Z][a-z]{2})\s+(\d{1,2})\s+(\d{2}:\d{2}:\d{2})\s+(\S+)\s+(.*)$', re.S)
_TOPIC_RE = re.compile(r'^([a-z][a-z0-9,!-]*)\s+(.*)$', re.S)
_DEVICE_PREFIX_RE = re.compile(r'^([A-Z][A-Z0-9]+-[A-Z0-9]+(?:-[\w\.]+)?):\s*(.*)$', re.S)


def parse(raw):
    """
    Best-effort parse for RFC 3164 + MikroTik variants.

    Handles:
      "<PRI>Apr 21 16:17 site SITE-GW-.1: MSG"          (RouterOS 6, bsd-syslog=yes)
      "<PRI>system,info,account SITE-OUR-.55: MSG"       (RouterOS 7 default format)
      "<PRI>TIMESTAMP HOSTNAME APP: MSG"                   (standard RFC 3164)
      "topic1,topic2,severity MSG"                         (no PRI — raw MikroTik)

    Returns: facility, severity, host, device, subsystem, message.
    """
    text = raw.decode('utf-8', errors='replace').rstrip()
    out = {'facility': None, 'severity': None, 'host': None,
           'device': None, 'subsystem': None, 'message': text}

    m = re.match(r'^<(\d+)>(.*)$', text, re.S)
    if m:
        pri = int(m.group(1))
        text = m.group(2)
        out['severity'] = SEVERITIES[pri & 0x07] if (pri & 0x07) < len(SEVERITIES) else str(pri & 0x07)
        fac_idx = pri >> 3
        out['facility'] = FACILITIES[fac_idx] if fac_idx < len(FACILITIES) else f'local{fac_idx}'

    bsd = _BSD_TS_RE.match(text)
    if bsd:
        out['host'] = bsd.group(4)
        text = bsd.group(5)

    topic = _TOPIC_RE.match(text)
    if topic:
        tokens = topic.group(1).split(',')
        remaining = topic.group(2)
        sev_from_topic = None
        subsystem = []
        for tok in tokens:
            alias = MIKROTIK_SEVERITY_ALIASES.get(tok)
            if alias:
                sev_from_topic = alias
            else:
                subsystem.append(tok)
        if sev_from_topic:
            if not out['severity']:
                out['severity'] = sev_from_topic
            if subsystem:
                out['subsystem'] = ','.join(subsystem)
            text = remaining

    dev = _DEVICE_PREFIX_RE.match(text)
    if dev:
        out['device'] = dev.group(1)
        text = dev.group(2)

    out['message'] = text.rstrip()
    return out


def current_log_path():
    """Today's log file — one per day, e.g., 2026-04-21.jsonl."""
    LOG_DIR.mkdir(parents=True, exist_ok=True)
    return LOG_DIR / f'{datetime.now():%Y-%m-%d}.jsonl'


def main():
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    try:
        sock.bind((BIND_HOST, BIND_PORT))
    except OSError as e:
        print(f'ERROR: bind {BIND_HOST}:{BIND_PORT} failed: {e}', file=sys.stderr)
        sys.exit(1)

    print(f'netwatch-syslog listening on {BIND_HOST}:{BIND_PORT}', flush=True)
    print(f'writing to {LOG_DIR}/YYYY-MM-DD.jsonl (retention: {RETENTION_DAYS}d)', flush=True)

    try:
        while True:
            try:
                data, addr = sock.recvfrom(4096)
            except OSError as e:
                print(f'[recv] {e}', flush=True)
                time.sleep(1)
                continue
            src_ip = addr[0]
            parsed = parse(data)
            entry = {
                'ts': datetime.now().isoformat(timespec='seconds'),
                'src': src_ip,
                'facility': parsed['facility'],
                'severity': parsed['severity'],
                'host': parsed['host'],
                'device': parsed['device'],
                'subsystem': parsed['subsystem'],
                'message': parsed['message'],
            }
            try:
                with open(current_log_path(), 'a') as f:
                    f.write(json.dumps(entry, ensure_ascii=False) + '\n')
            except Exception as e:
                print(f'[write] {e}', flush=True)
    except KeyboardInterrupt:
        pass


if __name__ == '__main__':
    main()
