#!/usr/bin/env python3
"""
NetWatch Network Scanner - discovers and identifies all devices on a subnet.
Features: ARP scan, port scan, ONVIF discovery, SNMP auto-detect, MAC vendor lookup,
          default credential check, scan history comparison.
"""
import subprocess
import json
import re
import socket
import struct
import time
import xml.etree.ElementTree as ET
import requests
import threading
from requests.auth import HTTPDigestAuth, HTTPBasicAuth
from datetime import datetime
from pathlib import Path

SCAN_HISTORY_PATH = Path(__file__).parent / 'scan_history.json'
MAC_VENDOR_PATH = Path(__file__).parent / 'mac_vendors.json'

_mac_vendors = {}
try:
    with open(MAC_VENDOR_PATH) as f:
        _mac_vendors = json.load(f)
except:
    pass

# Common default credentials for NVRs
DEFAULT_CREDS = [
    ('admin', 'admin'),
    ('admin', '12345'),
    ('admin', 'password'),
    ('admin', ''),
    ('admin', 'admin123'),
    ('admin', '123456'),
    ('admin', '1234'),
    ('admin', '888888'),
    ('admin', '666666'),
    ('root', 'root'),
    ('root', 'pass'),
]

# Known CCTV vendor keywords for web page identification
BRAND_KEYWORDS = {
    'hikvision': ['hikvision', 'webcomponents', 'doc/page/login', 'dvrdvs', 'DNVRS'],
    'dahua': ['dahua', 'dhvideo', 'DHVideoWH', 'DahuaTech', 'loginEx'],
    'uniview': ['uniview', 'UNV', 'ezstation'],
    'hanwha': ['hanwha', 'samsung techwin', 'wisenet', 'samsungcctv'],
    'axis': ['axis communications', 'vapix', 'axis-cgi'],
    'bosch': ['bosch security', 'dinion', 'flexidome'],
    'tvt': ['tvt digital', 'tvtdisc'],
    'provision': ['provision-isr', 'provision'],
    'vivotek': ['vivotek'],
    'tiandy': ['tiandy'],
    'kedacom': ['kedacom'],
    'milesight': ['milesight'],
    'reolink': ['reolink'],
    'imou': ['imou', 'lechange'],
}


def lookup_mac_vendor(mac):
    """Look up vendor from MAC address using full IEEE database."""
    if not mac:
        return ''
    prefix = mac.lower()[:8]
    return _mac_vendors.get(prefix, '')


def identify_brand(mac_vendor_str):
    """Map MAC vendor string to a known CCTV/network brand."""
    v = mac_vendor_str.lower()

    brand_map = {
        'hikvision': 'hikvision', 'hangzhou hikvision': 'hikvision',
        'dahua': 'dahua', 'zhejiang dahua': 'dahua',
        'uniview': 'uniview',
        'hanwha': 'hanwha', 'samsung techwin': 'hanwha',
        'axis comm': 'axis',
        'bosch sec': 'bosch',
        'mikrotik': 'mikrotik', 'routerboard': 'mikrotik',
        'cisco': 'cisco',
        'ubiquiti': 'ubiquiti',
        'ruijie': 'ruijie', 'reyee': 'ruijie',
        'tp-link': 'tp-link',
        'grandstream': 'grandstream',
        'raspberry': 'raspberry_pi',
        'espressif': 'espressif',
        'dell': 'dell',
        'hewlett': 'hp', 'hp inc': 'hp',
        'american power': 'apc_ups', 'apc': 'apc_ups',
        'cyberpower': 'cyberpower_ups',
        'synology': 'synology', 'qnap': 'qnap',
        'aruba': 'aruba', 'fortinet': 'fortinet',
        'zyxel': 'zyxel', 'netgear': 'netgear',
        'd-link': 'dlink', 'huawei': 'huawei',
        'tvt': 'tvt', 'provision': 'provision',
        'vivotek': 'vivotek', 'tiandy': 'tiandy',
        'milesight': 'milesight', 'reolink': 'reolink',
    }

    for keyword, brand in brand_map.items():
        if keyword in v:
            return brand
    return None


def guess_device_type(brand, open_ports, mac_vendor=''):
    """Guess device type from brand and open ports."""
    v = (brand or '').lower()
    ports = set(open_ports)

    nvr_brands = ('hikvision', 'dahua', 'uniview', 'hanwha', 'axis', 'bosch',
                  'tvt', 'provision', 'vivotek', 'tiandy', 'milesight', 'reolink')

    if v in nvr_brands:
        if 8000 in ports or 37777 in ports or 34567 in ports:
            return 'nvr'
        if 554 in ports and 80 in ports:
            return 'camera_or_nvr'
        if 554 in ports:
            return 'ip_camera'
        return 'camera_or_nvr'

    network_brands = ('mikrotik', 'cisco', 'ubiquiti', 'ruijie', 'tp-link',
                      'aruba', 'fortinet', 'zyxel', 'netgear', 'dlink', 'huawei')
    if v in network_brands:
        if 8291 in ports:
            return 'router'
        return 'network_equipment'

    if v in ('grandstream',):
        return 'voip'
    if v in ('apc_ups', 'cyberpower_ups'):
        return 'ups'
    if v in ('synology', 'qnap'):
        return 'nas'
    if v in ('raspberry_pi',):
        return 'server'
    if v in ('hp', 'dell') and 9100 in ports:
        return 'printer'

    # Port-based guessing
    if 554 in ports:
        return 'camera_or_nvr'
    if 8000 in ports and 80 in ports:
        return 'nvr'
    if 37777 in ports:
        return 'nvr'
    if 8291 in ports:
        return 'router'
    if 9100 in ports:
        return 'printer'
    if 5060 in ports:
        return 'voip'
    if 161 in ports:
        return 'snmp_device'

    return 'unknown'


def arp_scan(subnet):
    """Fast ARP scan - finds all devices including those that block ping."""
    devices = {}
    try:
        r = subprocess.run(['arp-scan', '-l', '--interface', _get_interface(subnet), '-q'],
                          capture_output=True, text=True, timeout=30)
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n'):
                parts = line.split('\t')
                if len(parts) >= 2:
                    ip = parts[0].strip()
                    mac = parts[1].strip().lower()
                    vendor = parts[2].strip() if len(parts) > 2 else ''
                    devices[ip] = {'mac': mac, 'mac_vendor': vendor}
    except:
        pass

    # Fallback to nmap ping scan if arp-scan not available
    if not devices:
        try:
            r = subprocess.run(['nmap', '-sn', '--max-retries', '1', subnet],
                              capture_output=True, text=True, timeout=60)
            current_ip = None
            for line in r.stdout.split('\n'):
                m = re.search(r'Nmap scan report for (\S+)', line)
                if m:
                    ip = m.group(1)
                    if '(' in ip:
                        ip = re.search(r'\(([^)]+)\)', line).group(1)
                    current_ip = ip
                    devices[ip] = {'mac': '', 'mac_vendor': ''}
                m = re.search(r'MAC Address: ([0-9A-F:]+)\s*\(([^)]*)\)', line)
                if m and current_ip:
                    devices[current_ip]['mac'] = m.group(1).lower()
                    devices[current_ip]['mac_vendor'] = m.group(2)
        except:
            pass

    return devices


def _get_interface(subnet):
    """Get the network interface for a subnet."""
    try:
        r = subprocess.run(['ip', 'route', 'get', subnet.split('/')[0]],
                          capture_output=True, text=True, timeout=5)
        for part in r.stdout.split():
            if part == 'dev':
                idx = r.stdout.split().index('dev')
                return r.stdout.split()[idx + 1]
    except:
        pass
    return 'eth0'


def port_scan(ip, ports=None):
    """Scan common ports on a device."""
    if ports is None:
        ports = [22, 80, 443, 554, 8000, 8080, 8291, 37777, 34567, 9100, 5060, 161, 3389, 5000, 8443]

    open_ports = []
    threads = []
    results = []

    def check_port(ip, port):
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            sock.settimeout(1.5)
            if sock.connect_ex((ip, port)) == 0:
                results.append(port)
            sock.close()
        except:
            pass

    for port in ports:
        t = threading.Thread(target=check_port, args=(ip, port))
        threads.append(t)
        t.start()

    for t in threads:
        t.join(timeout=3)

    return sorted(results)


def snmp_detect(ip, community='public'):
    """Try SNMP to get device info."""
    try:
        r = subprocess.run(
            ['snmpget', '-v2c', '-c', community, '-t', '1', '-r', '0', ip, 'sysDescr.0', 'sysName.0'],
            capture_output=True, text=True, timeout=5
        )
        if r.returncode == 0:
            info = {}
            for line in r.stdout.strip().split('\n'):
                if 'sysDescr' in line and '=' in line:
                    info['description'] = line.split('=', 1)[1].strip().strip('"')[:100]
                if 'sysName' in line and '=' in line:
                    info['hostname'] = line.split('=', 1)[1].strip().strip('"')
            return info
    except:
        pass
    return None


def onvif_discover(subnet):
    """Send ONVIF WS-Discovery probe to find cameras/NVRs."""
    discovered = {}

    probe = '''<?xml version="1.0" encoding="UTF-8"?>
<s:Envelope xmlns:s="http://www.w3.org/2003/05/soap-envelope"
            xmlns:a="http://schemas.xmlsoap.org/ws/2004/08/addressing"
            xmlns:d="http://schemas.xmlsoap.org/ws/2005/04/discovery"
            xmlns:dn="http://www.onvif.org/ver10/network/wsdl">
    <s:Header>
        <a:Action s:mustUnderstand="1">http://schemas.xmlsoap.org/ws/2005/04/discovery/Probe</a:Action>
        <a:MessageID>uuid:netwatch-probe</a:MessageID>
        <a:ReplyTo><a:Address>http://schemas.xmlsoap.org/ws/2004/08/addressing/role/anonymous</a:Address></a:ReplyTo>
        <a:To>urn:schemas-xmlsoap-org:ws:2005:04:discovery</a:To>
    </s:Header>
    <s:Body>
        <d:Probe><d:Types>dn:NetworkVideoTransmitter</d:Types></d:Probe>
    </s:Body>
</s:Envelope>'''

    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.settimeout(3)

        # WS-Discovery multicast group/port: 239.255.255.250:3702
        sock.sendto(probe.encode(), ('239.255.255.250', 3702))

        while True:
            try:
                data, addr = sock.recvfrom(65535)
                ip = addr[0]
                response = data.decode(errors='ignore')

                info = {'onvif': True}
                m = re.search(r'XAddrs>([^<]+)<', response)
                if m:
                    info['service_url'] = m.group(1)

                # Extract scopes for model info
                m = re.search(r'Scopes>([^<]+)<', response)
                if m:
                    scopes = m.group(1)
                    for scope in scopes.split():
                        if 'name/' in scope.lower():
                            info['name'] = scope.split('/')[-1]
                        if 'hardware/' in scope.lower():
                            info['hardware'] = scope.split('/')[-1]

                discovered[ip] = info
            except socket.timeout:
                break

        sock.close()
    except:
        pass

    return discovered


def try_default_creds(ip, port=80):
    """Try common default credentials on an NVR."""
    # Try Hikvision ISAPI
    for user, passwd in DEFAULT_CREDS:
        try:
            resp = requests.get(f"http://{ip}:{port}/ISAPI/System/deviceInfo",
                              auth=HTTPDigestAuth(user, passwd), timeout=3)
            if resp.ok and 'DeviceInfo' in resp.text:
                xml = ET.fromstring(resp.text)
                ns = {'ns': 'http://www.isapi.org/ver20/XMLSchema'}
                model = xml.find('.//ns:model', ns)
                return {
                    'brand': 'Hikvision',
                    'model': model.text if model is not None else '',
                    'username': user,
                    'password': passwd,
                    'default_password': True
                }
        except:
            pass

    # Try Dahua
    for user, passwd in DEFAULT_CREDS:
        try:
            resp = requests.get(f"http://{ip}:{port}/cgi-bin/magicBox.cgi?action=getSystemInfo",
                              auth=HTTPDigestAuth(user, passwd), timeout=3)
            if resp.ok and 'deviceType' in resp.text:
                model = ''
                for line in resp.text.split('\n'):
                    if 'deviceType=' in line:
                        model = line.split('=')[1].strip()
                return {
                    'brand': 'Dahua',
                    'model': model,
                    'username': user,
                    'password': passwd,
                    'default_password': True
                }
        except:
            pass

    return None


def detect_brand_from_web(ip, port=80):
    """Detect brand by checking web interface content."""
    try:
        resp = requests.get(f"http://{ip}:{port}/", timeout=3, allow_redirects=True)
        if not resp.ok:
            return None
        content = resp.text.lower()

        for brand, keywords in BRAND_KEYWORDS.items():
            for kw in keywords:
                if kw.lower() in content:
                    return brand
    except:
        pass
    return None


def load_scan_history():
    """Load previous scan results."""
    try:
        with open(SCAN_HISTORY_PATH) as f:
            return json.load(f)
    except:
        return {}


def save_scan_history(subnet, devices):
    """Save scan results for comparison."""
    history = load_scan_history()
    history[subnet] = {
        'timestamp': datetime.now().isoformat(),
        'devices': {d['ip']: d['mac'] for d in devices}
    }
    with open(SCAN_HISTORY_PATH, 'w') as f:
        json.dump(history, f, indent=2)


def compare_with_history(subnet, current_devices):
    """Compare current scan with previous to find new/missing devices."""
    history = load_scan_history()
    prev = history.get(subnet, {}).get('devices', {})
    prev_time = history.get(subnet, {}).get('timestamp', 'never')

    current_ips = {d['ip'] for d in current_devices}
    prev_ips = set(prev.keys())

    new_devices = current_ips - prev_ips
    missing_devices = prev_ips - current_ips

    return {
        'previous_scan': prev_time,
        'new_devices': list(new_devices),
        'missing_devices': list(missing_devices),
    }


def scan_network(subnet, quick=False):
    """Full network scan with all detection methods."""
    devices = []

    arp_results = arp_scan(subnet)

    onvif_results = {}
    if not quick:
        onvif_results = onvif_discover(subnet)

    all_ips = set(arp_results.keys()) | set(onvif_results.keys())

    for ip in sorted(all_ips, key=lambda x: [int(p) for p in x.split('.')]):
        arp_info = arp_results.get(ip, {'mac': '', 'mac_vendor': ''})
        onvif_info = onvif_results.get(ip, {})

        mac = arp_info['mac']
        mac_vendor_raw = arp_info['mac_vendor']

        mac_vendor = lookup_mac_vendor(mac) or mac_vendor_raw
        brand = identify_brand(mac_vendor)

        dev = {
            'ip': ip,
            'mac': mac,
            'mac_vendor': mac_vendor,
            'brand': brand,
            'device_type': 'unknown',
            'open_ports': [],
            'device_info': {},
            'snmp_info': None,
            'onvif': onvif_info.get('onvif', False),
            'default_password': False,
        }

        if onvif_info:
            dev['device_info']['onvif_name'] = onvif_info.get('name', '')
            dev['device_info']['onvif_hardware'] = onvif_info.get('hardware', '')

        if not quick:
            dev['open_ports'] = port_scan(ip)

            snmp = snmp_detect(ip)
            if snmp:
                dev['snmp_info'] = snmp
                dev['device_info']['snmp_description'] = snmp.get('description', '')
                dev['device_info']['hostname'] = snmp.get('hostname', '')

            if not brand and 80 in dev['open_ports']:
                web_brand = detect_brand_from_web(ip)
                if web_brand:
                    dev['brand'] = web_brand
                    brand = web_brand

            if brand in ('hikvision', 'dahua', 'uniview', None) and 80 in dev['open_ports']:
                cred_info = try_default_creds(ip)
                if cred_info:
                    dev['device_info']['brand'] = cred_info['brand']
                    dev['device_info']['model'] = cred_info['model']
                    dev['brand'] = cred_info['brand'].lower()
                    dev['default_password'] = cred_info['default_password']
                    brand = dev['brand']

        dev['device_type'] = guess_device_type(brand or '', dev['open_ports'], mac_vendor)

        devices.append(dev)

    changes = compare_with_history(subnet, devices)

    save_scan_history(subnet, devices)

    for dev in devices:
        dev['is_new'] = dev['ip'] in changes['new_devices']

    return {
        'subnet': subnet,
        'timestamp': datetime.now().isoformat(),
        'device_count': len(devices),
        'devices': devices,
        'changes': changes,
    }


def quick_scan(subnet):
    """Quick scan - ARP + ONVIF only, no port scanning."""
    return scan_network(subnet, quick=True)
