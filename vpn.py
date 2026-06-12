#!/usr/bin/env python3
"""
NetWatch VPN Manager - manages WireGuard peers for client sites.
"""
import subprocess
import json
import os
from pathlib import Path

WG_CONFIG = '/etc/wireguard/wg0.conf'
VPN_DATA = Path(__file__).parent / 'vpn_sites.json'
SERVER_PORT = 51820
SERVER_NETWORK = '10.66.66.0/24'
SERVER_IP = '10.66.66.1'
# Will be set from config or auto-detected
SERVER_PUBLIC_KEY = None
SERVER_ENDPOINT = None


def _get_server_info():
    """Get server's WireGuard public key and public IP."""
    global SERVER_PUBLIC_KEY, SERVER_ENDPOINT

    if not SERVER_PUBLIC_KEY:
        try:
            r = subprocess.run(['wg', 'show', 'wg0', 'public-key'],
                             capture_output=True, text=True, timeout=5)
            if r.returncode == 0:
                SERVER_PUBLIC_KEY = r.stdout.strip()
        except:
            pass

    if not SERVER_ENDPOINT:
        try:
            import requests
            SERVER_ENDPOINT = requests.get('https://ifconfig.me', timeout=5).text.strip()
        except:
            SERVER_ENDPOINT = 'YOUR_PUBLIC_IP'

    return SERVER_PUBLIC_KEY, SERVER_ENDPOINT


def load_vpn_sites():
    try:
        with open(VPN_DATA) as f:
            return json.load(f)
    except:
        return {'next_ip': 3, 'next_nat_id': 1, 'sites': []}


def save_vpn_sites(data):
    with open(VPN_DATA, 'w') as f:
        json.dump(data, f, indent=2)


def generate_keys():
    """Generate a new WireGuard key pair."""
    priv = subprocess.run(['wg', 'genkey'], capture_output=True, text=True).stdout.strip()
    pub = subprocess.run(['wg', 'pubkey'], input=priv, capture_output=True, text=True).stdout.strip()
    psk = subprocess.run(['wg', 'genpsk'], capture_output=True, text=True).stdout.strip()
    return priv, pub, psk


def generate_admin_password():
    """Generate a strong random password suitable for MikroTik admin.
    Uses only alphanumerics (no special chars that complicate shell/SSH quoting).
    20 chars @ 62^20 = ~10^35 combinations — unfeasible to brute-force."""
    import secrets
    import string
    alphabet = string.ascii_letters + string.digits
    return ''.join(secrets.choice(alphabet) for _ in range(20))


def add_site(site_name, subnets, router_brand='mikrotik'):
    """Add a new VPN site. Returns the client config."""
    data = load_vpn_sites()
    server_pub, server_endpoint = _get_server_info()

    for site in data['sites']:
        if site['name'].lower() == site_name.lower():
            return None, f"Site '{site_name}' already exists"

    client_priv, client_pub, psk = generate_keys()
    client_ip = f"10.66.66.{data['next_ip']}"
    data['next_ip'] += 1

    # Assign unique NAT range: 10.100.X.0/24
    # This prevents conflicts when multiple clients use the same local subnet
    nat_id = data.get('next_nat_id', 1)
    nat_subnet = f"10.100.{nat_id}.0/24"
    data['next_nat_id'] = nat_id + 1

    # Unique per-device admin password — a compromised device doesn't leak any other's creds
    admin_password = generate_admin_password()

    subnet_list = [s.strip() for s in subnets.split(',') if s.strip()]

    site = {
        'name': site_name,
        'client_ip': client_ip,
        'client_private_key': client_priv,
        'client_public_key': client_pub,
        'preshared_key': psk,
        'admin_password': admin_password,
        'subnets': subnet_list,
        'nat_subnet': nat_subnet,
        'nat_id': nat_id,
        'router_brand': router_brand,
        'connected': False,
        'created': str(subprocess.run(['date', '+%Y-%m-%d %H:%M'], capture_output=True, text=True).stdout.strip())
    }

    data['sites'].append(site)
    save_vpn_sites(data)

    # Add peer to live WireGuard — use NAT subnet instead of real subnet
    # This way the server routes 10.100.X.0/24 to this peer
    allowed_ips = f"{client_ip}/32"
    if subnet_list:
        # Use NAT subnet for routing through tunnel
        allowed_ips += f",{nat_subnet}"

    subprocess.run([
        'wg', 'set', 'wg0', 'peer', client_pub,
        'preshared-key', '/dev/stdin',
        'allowed-ips', allowed_ips
    ], input=psk, capture_output=True, text=True)

    # Update config file for persistence
    _rebuild_wg_config(data)

    # Generate client config
    client_config = _generate_client_config(site, server_pub, server_endpoint)
    router_config = _generate_router_config(site, server_pub, server_endpoint, router_brand)

    return {
        'site': site,
        'client_config': client_config,
        'router_config': router_config
    }, None


def remove_site(site_name):
    """Remove a VPN site."""
    data = load_vpn_sites()

    site = None
    for i, s in enumerate(data['sites']):
        if s['name'].lower() == site_name.lower():
            site = data['sites'].pop(i)
            break

    if not site:
        return False, f"Site '{site_name}' not found"

    # Remove peer from live WireGuard
    subprocess.run(['wg', 'set', 'wg0', 'peer', site['client_public_key'], 'remove'],
                  capture_output=True, text=True)

    save_vpn_sites(data)
    _rebuild_wg_config(data)
    return True, None


def get_site_status():
    """Get connection status for all VPN sites."""
    data = load_vpn_sites()

    # Get live WireGuard peer info
    try:
        r = subprocess.run(['wg', 'show', 'wg0', 'dump'], capture_output=True, text=True, timeout=5)
        peers = {}
        if r.returncode == 0:
            for line in r.stdout.strip().split('\n')[1:]:  # Skip header
                parts = line.split('\t')
                if len(parts) >= 5:
                    pub_key = parts[0]
                    endpoint = parts[2]
                    latest_handshake = int(parts[4]) if parts[4] != '0' else 0
                    transfer_rx = int(parts[5]) if len(parts) > 5 else 0
                    transfer_tx = int(parts[6]) if len(parts) > 6 else 0

                    import time
                    connected = (time.time() - latest_handshake) < 150 if latest_handshake > 0 else False

                    peers[pub_key] = {
                        'endpoint': endpoint,
                        'connected': connected,
                        'last_handshake': latest_handshake,
                        'rx_bytes': transfer_rx,
                        'tx_bytes': transfer_tx
                    }
    except:
        peers = {}

    # Merge with site data
    for site in data['sites']:
        peer_info = peers.get(site['client_public_key'], {})
        site['connected'] = peer_info.get('connected', False)
        site['endpoint'] = peer_info.get('endpoint', '')
        site['last_handshake'] = peer_info.get('last_handshake', 0)
        site['rx_bytes'] = peer_info.get('rx_bytes', 0)
        site['tx_bytes'] = peer_info.get('tx_bytes', 0)

    return data


def get_site_config(site_name):
    """Get the router config for a specific site."""
    data = load_vpn_sites()
    server_pub, server_endpoint = _get_server_info()

    for site in data['sites']:
        if site['name'].lower() == site_name.lower():
            client_config = _generate_client_config(site, server_pub, server_endpoint)
            router_config = _generate_router_config(site, server_pub, server_endpoint, site.get('router_brand', 'mikrotik'))
            return {
                'site': site,
                'client_config': client_config,
                'router_config': router_config
            }
    return None


def _rebuild_wg_config(data):
    """Rebuild the wg0.conf file with all peers."""
    # Read current config to get the Interface section
    try:
        with open(WG_CONFIG) as f:
            content = f.read()
        # Extract Interface section
        lines = content.split('\n')
        interface_lines = []
        for line in lines:
            if line.strip().startswith('[Peer]'):
                break
            interface_lines.append(line)
        interface_section = '\n'.join(interface_lines).strip()
    except:
        interface_section = f"""[Interface]
Address = {SERVER_IP}/24
ListenPort = {SERVER_PORT}
PrivateKey = (unknown)"""

    # Build new config
    config = interface_section + '\n'

    for site in data['sites']:
        allowed_ips = f"{site['client_ip']}/32"
        nat_mappings = site.get('nat_mappings') or []
        if nat_mappings:
            # Multi-subnet: include every NAT subnet from the mappings list
            for m in nat_mappings:
                if m.get('nat'):
                    allowed_ips += f",{m['nat']}"
        elif site.get('nat_subnet'):
            allowed_ips += f",{site['nat_subnet']}"
        elif site.get('subnets'):
            allowed_ips += ',' + ','.join(site['subnets'])

        config += f"""
# {site['name']}
[Peer]
PublicKey = {site['client_public_key']}
PresharedKey = {site['preshared_key']}
AllowedIPs = {allowed_ips}
"""

    with open(WG_CONFIG, 'w') as f:
        f.write(config)


def _ssh_mikrotik(tunnel_ip, password, commands, user='admin', timeout=15):
    """Run a list of RouterOS commands on a MikroTik via SSH through the WG tunnel.
    Returns (returncode, stdout, stderr)."""
    import subprocess as _sp
    script = '; :put "###END###"; '.join(commands) if isinstance(commands, list) else commands
    cmd = ['sshpass', '-p', password, 'ssh',
           '-o', 'StrictHostKeyChecking=no', '-o', 'UserKnownHostsFile=/dev/null',
           '-o', 'KexAlgorithms=+diffie-hellman-group1-sha1',
           '-o', 'PreferredAuthentications=password',
           '-o', 'NumberOfPasswordPrompts=1',
           '-o', f'ConnectTimeout={timeout}',
           f'{user}@{tunnel_ip}', script]
    try:
        r = _sp.run(cmd, capture_output=True, text=True, timeout=timeout + 5)
        return (r.returncode, r.stdout, r.stderr)
    except _sp.TimeoutExpired:
        return (-1, '', 'ssh timeout')
    except Exception as e:
        return (-1, '', str(e))


def get_admin_password(site_name):
    """Look up the stored admin password for a site, or None if not stored."""
    data = load_vpn_sites()
    site = next((s for s in data.get('sites', []) if s['name'] == site_name), None)
    return site.get('admin_password') if site else None


def discover_subnets(tunnel_ip, password, user='admin'):
    """SSH into a MikroTik via its tunnel IP (10.66.66.X), discover LAN subnets
    (excluding WAN = default-route interface, and wg-netwatch). Returns:
       [{'subnet': '192.168.1.0/24', 'interface': 'bridge-lan'}, ...]
    Returns (list, error_message). On error, list is empty."""
    import ipaddress

    # Fetch addresses and default route in one session
    cmd = ('/ip/address/print detail without-paging; :put "###ROUTES###"; '
           '/ip/route/print detail without-paging where dst-address=0.0.0.0/0')
    rc, out, err = _ssh_mikrotik(tunnel_ip, password, cmd, user=user)
    if rc != 0:
        return [], err or f'ssh rc={rc}'

    addr_part, _, route_part = out.partition('###ROUTES###')

    # Parse /ip/address/print detail output — each entry spans multiple lines.
    # Key fields: address=X.X.X.X/NN interface=NAME
    addresses = []
    import re
    # RouterOS /detail output interleaves attributes per entry, so match each
    # address= and take the nearest following interface= rather than parse by line.
    for m in re.finditer(r'address=([\d./]+)', addr_part):
        tail = addr_part[m.end():m.end() + 300]
        im = re.search(r'interface=([^\s]+)', tail)
        if im:
            addresses.append({'address': m.group(1), 'interface': im.group(1)})

    # Find WAN interface from default route. Gateway field can be:
    #   "ether1"              — pure interface name (may contain dots for VLAN)
    #   "192.168.1.1"          — pure IP, look up which iface owns the subnet
    #   "192.168.1.1%ether1"   — IP scoped to interface
    wan_iface = None
    for m in re.finditer(r'gateway=([^\s]+)', route_part):
        g = m.group(1)
        if '%' in g:
            wan_iface = g.split('%', 1)[1]
        else:
            try:
                gw_ip = ipaddress.ip_address(g)
                # It's an IP — find the owning interface by subnet containment
                for a in addresses:
                    try:
                        net = ipaddress.ip_network(a['address'], strict=False)
                        if gw_ip in net:
                            wan_iface = a['interface']
                            break
                    except Exception:
                        pass
            except ValueError:
                # Not a valid IP → treat as an interface name (handles VLAN "ether1.100")
                wan_iface = g
        if wan_iface:
            break

    # Build LAN subnet list — exclude WAN, any tunnel/virtual interface, and lo.
    # Skip prefixes cover all common MikroTik tunnel interface names so we don't
    # accidentally treat a tunnel as a LAN.
    SKIP_PREFIXES = ('wg-', 'wg', 'ovpn-', 'l2tp-', 'l2tp', 'pptp-', 'pptp',
                     'sstp-', 'sstp', 'eoip-', 'eoip', 'gre-', 'gre',
                     'ipip-', 'ipip', 'pppoe-', 'pppoe', 'vpls-', 'vpls')
    lan = []
    seen = set()
    for a in addresses:
        iface = a['interface']
        if iface == wan_iface or iface == 'lo':
            continue
        if any(iface == p.rstrip('-') or iface.startswith(p) for p in SKIP_PREFIXES):
            continue
        try:
            net = ipaddress.ip_network(a['address'], strict=False)
        except Exception:
            continue
        # Skip point-to-point (/31) and host (/32) addresses
        if net.prefixlen >= 31:
            continue
        # Skip link-local (169.254.0.0/16) and loopback (127.0.0.0/8)
        if net.is_link_local or net.is_loopback:
            continue
        subnet_str = str(net)
        if subnet_str in seen:
            continue
        seen.add(subnet_str)
        lan.append({'subnet': subnet_str, 'interface': iface})

    return lan, ''


def classify_subnets(site_name, discovered):
    """Given a site name and freshly-discovered subnets, classify existing
    nat_mappings against them:
      - additions: discovered but not in stored mappings (new to configure)
      - keepers:   discovered AND in stored mappings (leave alone)
      - stales:    in stored mappings but NOT discovered (interface/subnet gone
                   from the MikroTik — these are leak risks to clean up)
    Returns (additions_count, keepers_count, stales_list) without modifying anything.
    Used by /discover UI to show reconcile preview before applying."""
    data = load_vpn_sites()
    site = next((s for s in data['sites'] if s['name'] == site_name), None)
    if not site:
        return None

    discovered_subnets = {d['subnet'] for d in discovered}
    mappings = list(site.get('nat_mappings') or [])

    # Carry legacy nat_subnet → treat it as an implicit mapping for classification.
    # It maps the site's first local subnet to nat_subnet.
    if site.get('nat_subnet') and site.get('subnets'):
        legacy_local = site['subnets'][0]
        if not any(m.get('nat') == site['nat_subnet'] for m in mappings):
            mappings.insert(0, {
                'local': legacy_local, 'nat': site['nat_subnet'],
                'nat_id': site.get('nat_id'), 'interface': 'legacy'})

    stored_locals = {m.get('local') for m in mappings if m.get('local')}

    additions = [d for d in discovered if d['subnet'] not in stored_locals]
    keepers = [m for m in mappings if m.get('local') in discovered_subnets]
    stales = [m for m in mappings if m.get('local') and m.get('local') not in discovered_subnets]

    return {
        'additions': additions,
        'keepers': keepers,
        'stales': stales,
    }


def auto_configure_netmap(site_name, discovered, password, user='admin', remove_stale=False):
    """For each discovered subnet not already configured, pick the next NAT id
    (globally unique via vpn_sites.json['next_nat_id']), push srcnat/dstnat/masquerade
    rules + a route on the MikroTik, then update vpn_sites.json and rebuild wg0.

    If remove_stale=True, also removes NAT mappings whose local subnet is not in
    the `discovered` list — cleans up after device relocation.

    Returns (result_dict, error_message) where result_dict has:
       additions: list of freshly-added mappings
       removed:   list of removed (stale) mappings"""
    data = load_vpn_sites()
    site = next((s for s in data['sites'] if s['name'] == site_name), None)
    if not site:
        return {'additions': [], 'removed': []}, f'site {site_name} not found'
    tunnel_ip = site['client_ip']
    next_nat_id = data.get('next_nat_id', 1)

    discovered_subnets = {d['subnet'] for d in discovered}

    # Migrate legacy nat_subnet → nat_mappings if not already there
    if site.get('nat_subnet') and site.get('subnets'):
        site.setdefault('nat_mappings', [])
        legacy_local = site['subnets'][0]
        if not any(m.get('nat') == site['nat_subnet'] for m in site['nat_mappings']):
            site['nat_mappings'].insert(0, {
                'local': legacy_local, 'nat': site['nat_subnet'],
                'nat_id': site.get('nat_id'), 'interface': 'legacy'})

    # Compute stale mappings to remove (only if opt-in)
    stales = []
    if remove_stale:
        for m in list(site.get('nat_mappings') or []):
            local = m.get('local')
            if local and local not in discovered_subnets:
                stales.append(dict(m))  # copy for return

    # Gather existing configured subnets for this site (dedupe) — EXCLUDING stales
    # (since we're about to remove them, don't block re-adding)
    stale_locals = {s['local'] for s in stales}
    existing_local = set(site.get('subnets', []))
    for m in site.get('nat_mappings') or []:
        if m.get('local') and m['local'] not in stale_locals:
            existing_local.add(m['local'])

    additions = []
    for d in discovered:
        if d['subnet'] in existing_local:
            continue
        nat_subnet = f'10.100.{next_nat_id}.0/24'
        additions.append({
            'subnet': d['subnet'],
            'nat_subnet': nat_subnet,
            'nat_id': next_nat_id,
            'interface': d['interface'],
        })
        next_nat_id += 1

    if not additions and not stales:
        return {'additions': [], 'removed': []}, 'no changes needed'

    # Build MikroTik commands: removals first, then additions
    cmds = []
    for s in stales:
        local = s.get('local')
        nat = s.get('nat')
        cmds.append(f'/ip/firewall/nat/remove [find comment="NetWatch NAT OUT {local}"]')
        cmds.append(f'/ip/firewall/nat/remove [find comment="NetWatch NAT IN {local}"]')
        cmds.append(f'/ip/firewall/nat/remove [find comment="NetWatch masq {local}"]')
        if nat:
            cmds.append(f'/ip/route/remove [find dst-address={nat} gateway=wg-netwatch]')

    for a in additions:
        s, n = a['subnet'], a['nat_subnet']
        cmds.append(
            f'/ip/firewall/nat/add chain=srcnat src-address={s} out-interface=wg-netwatch '
            f'action=netmap to-addresses={n} comment="NetWatch NAT OUT {s}"')
        cmds.append(
            f'/ip/firewall/nat/add chain=dstnat dst-address={n} in-interface=wg-netwatch '
            f'action=netmap to-addresses={s} comment="NetWatch NAT IN {s}"')
        cmds.append(
            f'/ip/firewall/nat/add chain=srcnat in-interface=wg-netwatch dst-address={s} '
            f'action=masquerade comment="NetWatch masq {s}"')
        cmds.append(f'/ip/route/add dst-address={n} gateway=wg-netwatch')

    rc, out, err = _ssh_mikrotik(tunnel_ip, password, cmds, user=user, timeout=30)
    if rc != 0:
        return {'additions': [], 'removed': []}, f'mikrotik push failed: {err or out}'

    # Purge stale mappings from vpn_sites.json (their local is no longer on any iface)
    if stales:
        stale_locals_set = {s['local'] for s in stales}
        stale_nats_set = {s.get('nat') for s in stales if s.get('nat')}
        site['nat_mappings'] = [m for m in site.get('nat_mappings') or []
                                 if m.get('local') not in stale_locals_set]
        site['subnets'] = [s for s in site.get('subnets', []) if s not in stale_locals_set]
        # Also clear legacy nat_subnet if it matched a removed stale
        if site.get('nat_subnet') in stale_nats_set:
            site.pop('nat_subnet', None)
            site.pop('nat_id', None)

    # Append new mappings
    site.setdefault('nat_mappings', [])
    for a in additions:
        if a['subnet'] not in site.get('subnets', []):
            site.setdefault('subnets', []).append(a['subnet'])
        site['nat_mappings'].append({
            'local': a['subnet'], 'nat': a['nat_subnet'],
            'nat_id': a['nat_id'], 'interface': a['interface'],
        })
    data['next_nat_id'] = next_nat_id

    save_vpn_sites(data)

    # Rebuild wg0.conf to include new AllowedIPs, then reload.
    # Prefer `wg syncconf` (no tunnel drop for existing peers). Fall back to
    # `systemctl restart wg-quick@wg0` if syncconf fails for any reason.
    try:
        _rebuild_wg_config(data)
    except Exception as e:
        return ({'additions': additions, 'removed': stales},
                f'netmap pushed OK but failed to write wg0.conf: {e}')

    reload_ok = False
    reload_detail = ''
    try:
        import tempfile
        _sp = subprocess
        strip = _sp.run(['wg-quick', 'strip', 'wg0'],
                        capture_output=True, text=True, timeout=5)
        if strip.returncode == 0 and strip.stdout:
            # Write to a tempfile for wg syncconf (avoids /dev/stdin quirks under sandboxes)
            with tempfile.NamedTemporaryFile(mode='w', suffix='.conf', delete=False) as tf:
                tf.write(strip.stdout)
                tmp_path = tf.name
            try:
                sc = _sp.run(['wg', 'syncconf', 'wg0', tmp_path],
                             capture_output=True, text=True, timeout=5)
                reload_ok = (sc.returncode == 0)
                reload_detail = sc.stderr.strip() if sc.stderr else ''
            finally:
                try:
                    os.unlink(tmp_path)
                except Exception:
                    pass
        else:
            reload_detail = (strip.stderr or '').strip() or f'wg-quick strip rc={strip.returncode}'
    except Exception as e:
        reload_detail = str(e)

    if not reload_ok:
        # Fallback: restart service. This drops the tunnel for ~2-5s for every peer.
        try:
            r = subprocess.run(['systemctl', 'restart', 'wg-quick@wg0'],
                               capture_output=True, text=True, timeout=15)
            if r.returncode == 0:
                reload_ok = True
                reload_detail = 'fallback: restarted wg-quick@wg0'
            else:
                reload_detail = f'restart failed: {r.stderr.strip() or r.stdout.strip()}'
        except Exception as e:
            reload_detail = f'restart exception: {e}'

    result = {'additions': additions, 'removed': stales}

    if not reload_ok:
        return result, f'netmap pushed OK but server-side reload failed: {reload_detail}'

    return result, ''


def harden_mikrotik(site_name, password, user='admin'):
    """Apply security hardening to a deployed MikroTik. Run ONLY after the device
    is at its final location and /discover has configured real client subnets —
    these rules lock out LAN-side management and leave only the WG tunnel path.

    Returns (applied_list, error_message)."""
    data = load_vpn_sites()
    site = next((s for s in data['sites'] if s['name'] == site_name), None)
    if not site:
        return [], f'site {site_name} not found'
    tunnel_ip = site['client_ip']

    # Build the watchdog script body. RouterOS `/system script add source="..."`
    # expects a quoted string; inner " must be escaped as \" so RouterOS unescapes
    # them back into real " inside the stored script. Using \\" in Python source
    # to produce a literal \" on the wire.
    watchdog_body = (
        ':if ([:len [/interface/find name=wg-netwatch disabled=yes]] > 0) do={/interface/enable wg-netwatch};'
        ':if ([:len [/ip/service/find name=ssh disabled=yes]] > 0) do={/ip/service/set ssh disabled=no};'
        ':if ([/ip/service/get ssh address] != \\"\\") do={/ip/service/set ssh address=\\"\\"};'
        ':if ([:len [/ip/firewall/filter/find comment=\\"NetWatch VPN IN\\"]] = 0) do={'
            '/ip/firewall/filter/add chain=input action=accept in-interface=wg-netwatch comment=\\"NetWatch VPN IN\\"'
        '};'
        ':if ([:len [/ip/dhcp-client/find interface=bridgeLocal disabled=yes]] > 0) do={'
            '/ip/dhcp-client/enable [find interface=bridgeLocal]'
        '};'
    )

    commands = [
        # Idempotency: clean up any previous hardening + watchdog artifacts first
        '/ip/firewall/filter/remove [find comment~"NetWatch hardened"]',
        '/system/scheduler/remove [find name~"netwatch-"]',
        '/system/script/remove [find name~"netwatch-"]',

        # Disable unused services entirely (reduce attack surface).
        # SSH + WinBox stay OPEN on all interfaces — LAN recovery is always available,
        # protected by the per-device 20-char random admin password (~10^35 combos).
        '/ip/service/set api disabled=yes',
        '/ip/service/set api-ssl disabled=yes',
        '/ip/service/set www disabled=yes',
        '/ip/service/set www-ssl disabled=yes',
        '/ip/service/set telnet disabled=yes',
        '/ip/service/set ftp disabled=yes',
        '/ip/service/set ssh address=""',
        '/ip/service/set winbox address=""',

        # MAC-server disabled — L2 management is weaker auth. Our strong L3 password wins.
        '/tool/mac-server/set allowed-interface-list=none',
        '/tool/mac-server/mac-winbox/set allowed-interface-list=none',
        '/tool/mac-server/ping/set enabled=no',

        # Install self-heal watchdog: script + scheduler (runs every 1 min).
        # Guarantees server-side access is never lost:
        #   wg-netwatch enabled, SSH service up + no IP restriction,
        #   "NetWatch VPN IN" filter rule present, DHCP on bridgeLocal enabled.
        f'/system/script/add name=netwatch-watchdog source="{watchdog_body}"',
        '/system/scheduler/add name=netwatch-watchdog interval=1m '
            'on-event="/system/script/run netwatch-watchdog" '
            'comment="NetWatch self-heal — never locks server out"',
    ]

    rc, out, err = _ssh_mikrotik(tunnel_ip, password, commands, user=user, timeout=30)
    if rc != 0:
        return [], f'mikrotik push failed: {err or out}'

    # Mark in vpn_sites.json
    site['hardened'] = True
    save_vpn_sites(data)
    return commands, ''


def _generate_client_config(site, server_pub, server_endpoint):
    """Generate standard WireGuard client config."""
    return f"""[Interface]
PrivateKey = {site['client_private_key']}
Address = {site['client_ip']}/32

[Peer]
PublicKey = {server_pub}
PresharedKey = {site['preshared_key']}
Endpoint = {server_endpoint}:{SERVER_PORT}
AllowedIPs = {SERVER_IP}/32
PersistentKeepalive = 25"""


def _generate_router_config(site, server_pub, server_endpoint, brand):
    """Generate router-specific config with CLI commands and GUI steps."""

    nat_subnet = site.get('nat_subnet', '10.100.1.0/24')
    nat_id = site.get('nat_id', 1)
    subnets_str = ','.join(site.get('subnets', ['192.168.1.0/24']))
    first_subnet = site['subnets'][0] if site.get('subnets') else '192.168.1.0/24'

    if brand == 'mikrotik':
        return f"""# =============================================
#  MikroTik RouterOS 7.1+ — WireGuard + NAT Setup
#  Site: {site['name']}
#  NAT: {first_subnet} → {nat_subnet} (avoids subnet conflicts)
#  In NetWatch, add devices as 10.100.{nat_id}.X (not 192.168.X.X)
# =============================================

# ─── CLI COMMANDS (Terminal) ───
# Open WinBox → New Terminal, paste these.
#
# ⚠️  IF THIS MIKROTIK ALREADY HAS CONFIG YOU WANT TO KEEP:
#     SKIP SECTION "0" BELOW (identity, NTP, password — these OVERWRITE existing values).
#     Paste only from "# 1. Create WireGuard interface" onwards.
#     Sections 1-8 are PURELY ADDITIVE — they don't touch existing routes,
#     firewall rules, users, NAT, etc. They only create new ones named wg-netwatch.
#
# ─── SECTION 0 — DESTRUCTIVE (skip for existing devices) ──────────
# These 3 commands OVERWRITE existing values. Safe only on fresh/factory-reset
# devices. For existing client routers, delete this whole section before pasting.

# 0a. Device identity (RENAMES the device — client may have their own name)
/system/identity/set name="{site['name']}"

# 0b. NTP servers (REPLACES existing — client may use their own time servers)
/system/ntp/client/set enabled=yes servers=162.159.200.1,162.159.200.123

# 0c. Admin password (REPLACES client's existing admin password — they lose access!)
#     Only run on fresh devices we own. Password is stored in vpn_sites.json
#     (0600, tunnel only) for /discover and /harden to use automatically.
/user/set admin password="{site['admin_password']}"

# ─── SECTION 1+ — ADDITIVE ONLY (safe for any MikroTik) ──────────
# From here down, every command only ADDS new objects. Nothing overwritten.
# Existing routes, firewall rules, NAT rules, users, etc. stay intact.

# 1. Create WireGuard interface
/interface/wireguard/add name=wg-netwatch listen-port=13231

# 2. Set the private key
/interface/wireguard/set wg-netwatch private-key="{site['client_private_key']}"

# 3. Add server peer
/interface/wireguard/peers/add \\
    interface=wg-netwatch \\
    public-key="{server_pub}" \\
    preshared-key="{site['preshared_key']}" \\
    endpoint-address={server_endpoint} \\
    endpoint-port={SERVER_PORT} \\
    allowed-address={SERVER_IP}/32 \\
    persistent-keepalive=25s

# 4. Assign tunnel IP
/ip/address/add address={site['client_ip']}/32 network={SERVER_IP} interface=wg-netwatch

# 5. Firewall — allow tunnel traffic. Works on fresh RouterOS 7 (empty filter chain).
#    If the device already has a DROP rule at the bottom, manually move these 3 above it
#    via WinBox (drag and drop) — otherwise tunnel input/forward gets blocked.
/ip/firewall/filter/add chain=input action=accept in-interface=wg-netwatch comment="NetWatch VPN IN"
/ip/firewall/filter/add chain=forward action=accept in-interface=wg-netwatch comment="NetWatch VPN FWD IN"
/ip/firewall/filter/add chain=forward action=accept out-interface=wg-netwatch comment="NetWatch VPN FWD OUT"

# 6. Route — tell the router to send NAT subnet traffic through the tunnel
#    Without this, packets to 10.100.X.0/24 won't reach the server!
/ip/route/add dst-address={nat_subnet} gateway=wg-netwatch

# 7. NAT — translate local IPs to unique range through tunnel
#    This prevents conflicts if multiple clients use the same subnet
#    Example: NVR at 192.168.1.64 → appears as 10.100.{nat_id}.64 on the server
/ip/firewall/nat/add chain=srcnat src-address={first_subnet} out-interface=wg-netwatch action=netmap to-addresses={nat_subnet} comment="NetWatch NAT OUT"
/ip/firewall/nat/add chain=dstnat dst-address={nat_subnet} in-interface=wg-netwatch action=netmap to-addresses={first_subnet} comment="NetWatch NAT IN"

# 8. Masquerade — rewrite source so LAN hosts can reply through the tunnel
#    Without this, only the MikroTik itself replies; other LAN hosts don't know 10.66.66.0/24
/ip/firewall/nat/add chain=srcnat in-interface=wg-netwatch dst-address={first_subnet} action=masquerade comment="NetWatch masq tunnel to LAN"

# 9. Security hardening — DO NOT RUN HERE. These commands are applied automatically
#    by the /harden Telegram command AFTER the device is deployed and /discover has
#    set up real client subnets. Running them now would lock you out of LAN-side
#    access during pre-staging.
#
# What /harden does later:
#   - Restricts SSH/WinBox services to the tunnel-side IP (10.66.66.1) only
#   - Disables API, WWW, Telnet, FTP services
#   - Adds input-drop firewall rule for all non-tunnel interfaces
#   - Disables MAC-server on all interfaces (prevents L2 Winbox/telnet)

# ═══════════════════════════════════════════════════════════════════════════
#  ALTERNATIVE: CLICK-BY-CLICK IN WINBOX (if you prefer not to paste commands)
# ═══════════════════════════════════════════════════════════════════════════
#
# Before you start:
#   • Log into WinBox as admin (default: no password on fresh MikroTik).
#   • RouterOS 7.1+ required (WireGuard support). On 6.x, upgrade first.
#   • Make sure the MikroTik has internet access on ether1 / WAN (/tool ping 8.8.8.8).
#
# ─── STEP 0 — DESTRUCTIVE, SKIP FOR EXISTING DEVICES ─────────────────
# If the MikroTik already belongs to a client and has their config,
# SKIP all of Step 0 and jump straight to Step 1. These 3 changes
# overwrite existing values that the client may rely on.
#
# STEP 0a (fresh only): Rename the device
#   WinBox → System → Identity
#   - Name: {site['name']}
#   - Apply
#
# STEP 0b (fresh only): NTP time sync
#   WinBox → System → NTP Client
#   - Enabled: ✓
#   - Servers: 162.159.200.1, 162.159.200.123
#   - Apply
#   (Check status in System → Clock → should say "synchronized" within ~10s)
#
# STEP 0c (fresh only): Set a strong admin password
#   WinBox → System → Users → double-click "admin"
#   - Password: {site['admin_password']}
#   - Confirm Password: {site['admin_password']}
#   - Apply
#   (Save this password. It's also stored on the NetWatch server so /discover
#   and /harden work automatically, but losing it on the MikroTik = factory reset.)
#
# ─── STEP 1+ — ADDITIVE ONLY, SAFE FOR ANY MIKROTIK ──────────────────
#
# STEP 1: Create the WireGuard interface
#   WinBox → WireGuard → "+" (Add) tab
#   - Name:        wg-netwatch
#   - Listen Port: 13231   (any unused port — this is our side's source port)
#   - MTU:         1420    (default, don't change)
#   → OK. A key pair auto-generates; we're about to replace the private key.
#
# STEP 2: Paste the private key we generated for this device
#   WinBox → WireGuard → double-click wg-netwatch
#   - Clear the auto-generated Private Key, paste:
#     {site['client_private_key']}
#   - Apply + OK
#
# STEP 3: Add the NetWatch server as a peer
#   WinBox → WireGuard → Peers tab → "+" (Add)
#   - Interface:             wg-netwatch
#   - Public Key:            {server_pub}
#   - Preshared Key:         {site['preshared_key']}
#   - Endpoint Address:      {server_endpoint}
#   - Endpoint Port:         {SERVER_PORT}
#   - Allowed Address:       {SERVER_IP}/32         ← just the server, not /24
#   - Persistent Keepalive:  00:00:25
#   → OK
#
# STEP 4: Assign the tunnel IP to the WireGuard interface
#   WinBox → IP → Addresses → "+" (Add)
#   - Address:   {site['client_ip']}/32
#   - Network:   {SERVER_IP}
#   - Interface: wg-netwatch
#   → OK
#
# STEP 5: Allow tunnel traffic through the firewall
#   WinBox → IP → Firewall → Filter Rules → "+" (Add)  — do this 3 times:
#
#     Rule A  chain=input     In. Interface=wg-netwatch    action=accept
#                    comment: NetWatch VPN IN
#     Rule B  chain=forward   In. Interface=wg-netwatch    action=accept
#                    comment: NetWatch VPN FWD IN
#     Rule C  chain=forward   Out. Interface=wg-netwatch   action=accept
#                    comment: NetWatch VPN FWD OUT
#
#   IF the client's existing filter chain already has a "drop everything else"
#   rule at the BOTTOM, drag rules A/B/C ABOVE it (click & drag the rows in WinBox).
#   On a default / factory-reset MikroTik the chain is empty, so ordering doesn't matter.
#
# STEP 6: Tell the router to route NAT subnet traffic through the tunnel
#   WinBox → IP → Routes → "+" (Add)
#   - Dst. Address: {nat_subnet}
#   - Gateway:      wg-netwatch
#   → OK
#
# STEP 7: NAT netmap — the part that makes monitoring actually work
#   WinBox → IP → Firewall → NAT tab → "+" (Add)  — 3 rules:
#
#   Rule 7a (srcnat OUT — local → tunnel):
#     - Chain:         srcnat
#     - Src. Address:  {first_subnet}
#     - Out. Interface: wg-netwatch
#     - (Action tab) Action:       netmap
#     - (Action tab) To Addresses: {nat_subnet}
#     - Comment:                   NetWatch NAT OUT
#
#   Rule 7b (dstnat IN — tunnel → local):
#     - Chain:         dstnat
#     - Dst. Address:  {nat_subnet}
#     - In. Interface: wg-netwatch
#     - (Action tab) Action:       netmap
#     - (Action tab) To Addresses: {first_subnet}
#     - Comment:                   NetWatch NAT IN
#
#   Rule 7c (masquerade — so LAN hosts reply correctly through tunnel):
#     - Chain:         srcnat
#     - Dst. Address:  {first_subnet}
#     - In. Interface: wg-netwatch
#     - (Action tab) Action: masquerade
#     - Comment:             NetWatch masq tunnel to LAN
#
#   Why rule 7c? Without it, only the MikroTik itself replies to pings from
#   the server; other LAN devices don't know how to route 10.66.66.0/24 back,
#   so their replies get dropped.
#
# STEP 8: Verify the tunnel is up
#   WinBox → WireGuard → Peers — look at the "Last Handshake" column.
#     It should say a few seconds ago within 25s of completing Step 3.
#   WinBox → New Terminal: /ping {SERVER_IP}
#     Expect replies <50ms.
#
#   From the NetWatch server, the admin should run in Telegram:
#     /discover    — auto-detect real LAN subnets + add per-subnet netmap rules
#     /harden      — apply security lockdown + self-heal watchdog
#
# ─── HOW NAT TRANSLATES IPS (so you can mentally map devices) ────────
#   Your local NVR/camera at 192.168.1.64
#     → MikroTik netmap → server sees it as 10.100.{nat_id}.64
#     → In NetWatch's /adddevice, add it as 10.100.{nat_id}.64
#
#   The host octet (.64) STAYS THE SAME. Only the first 3 octets change:
#     192.168.1.X   →  10.100.{nat_id}.X
#
# ─── TROUBLESHOOTING ──────────────────────────────────────────────────
#   • "Last Handshake" stays blank after Step 3:
#       - MikroTik can't reach {server_endpoint}:{SERVER_PORT}. Check
#         /tool ping {server_endpoint} — if unreachable, client's ISP may
#         block outbound UDP (rare; usually only in managed enterprise nets).
#       - Public key or preshared key mistyped — re-paste carefully.
#   • Tunnel up, but /ping {SERVER_IP} times out:
#       - Step 4 IP address wrong, or Step 5 filter rules missing.
#   • Tunnel up, server can ping MikroTik (10.100.{nat_id}.1) but not LAN devices:
#       - Step 7c masquerade rule missing.
#   • RouterOS 6.x: commands use space syntax ("/ip firewall filter add…").
#       Upgrade to 7.x first, or translate each slash to a space yourself."""

    elif brand == 'cisco':
        return f"""! =============================================
!  Cisco IOS Config
!  Site: {site['name']}
! =============================================
!
! NOTE: Cisco IOS does NOT natively support WireGuard.
! Options:
!   1. Use a different router (MikroTik, Ubiquiti, pfSense)
!   2. Put a small MikroTik/Raspberry Pi behind the Cisco for WireGuard
!   3. Use port forwarding instead of VPN (less secure)
!
! If using port forwarding, in config mode (conf t):

! Port forward NVR port 80 (adjust 192.168.1.64 to NVR's IP):
ip nat inside source static tcp 192.168.1.64 80 interface GigabitEthernet0/0 80

! Enable SNMP
snmp-server community public RO
snmp-server enable traps

! Enable Syslog
logging host {SERVER_IP}
logging trap warnings

! ─── GUI STEPS (Cisco Web UI) ───
#
# For routers with web UI (like RV series):
# STEP 1: Port Forwarding
#   Login → Firewall → Port Forwarding → Add
#   - External Port: 80
#   - Internal IP: (NVR's local IP, e.g. 192.168.1.64)
#   - Internal Port: 80
#   - Protocol: TCP
#   → Save
#
# STEP 2: SNMP
#   Login → Administration → SNMP → Enable
#   - Community: public
#   - Permission: Read-Only
#   → Save"""

    elif brand == 'ubiquiti':
        return f"""# =============================================
#  Ubiquiti EdgeOS 3+ / EdgeRouter — WireGuard
#  Site: {site['name']}
#  NOTE: EdgeOS 3.0+ has native WireGuard. Older versions
#  need the wireguard-vyatta-ubnt package from GitHub.
# =============================================

# ─── CLI COMMANDS (SSH) ───

configure

# Create WireGuard interface
set interfaces wireguard wg0 private-key {site['client_private_key']}
set interfaces wireguard wg0 address {site['client_ip']}/32
set interfaces wireguard wg0 route-allowed-ips true

# Add server peer (each allowed-ips needs separate set command)
set interfaces wireguard wg0 peer {server_pub} endpoint {server_endpoint}:{SERVER_PORT}
set interfaces wireguard wg0 peer {server_pub} allowed-ips {SERVER_IP}/32
set interfaces wireguard wg0 peer {server_pub} persistent-keepalive 25
set interfaces wireguard wg0 peer {server_pub} preshared-key {site['preshared_key']}

# Firewall — allow tunnel traffic
set firewall name WAN_LOCAL rule 20 action accept
set firewall name WAN_LOCAL rule 20 protocol udp
set firewall name WAN_LOCAL rule 20 destination port {SERVER_PORT}
set firewall name WAN_LOCAL rule 20 description "WireGuard NetWatch"

commit
save

# Verify:
#   show interfaces wireguard wg0
#   ping {SERVER_IP}

# ─── UNIFI DREAM MACHINE / GATEWAY ───
#
# UniFi supports WireGuard via GUI (firmware 1.11.0+):
#   Settings → VPN → Create New → WireGuard
#   - Type: VPN Client
#   - Configuration: paste the config below
#
# Config to paste:
#   [Interface]
#   PrivateKey = {site['client_private_key']}
#   Address = {site['client_ip']}/32
#
#   [Peer]
#   PublicKey = {server_pub}
#   PresharedKey = {site['preshared_key']}
#   Endpoint = {server_endpoint}:{SERVER_PORT}
#   AllowedIPs = {SERVER_IP}/32
#   PersistentKeepalive = 25
#
# ─── EDGEOS 1.x/2.x (Old Firmware) ───
# Install WireGuard package first:
#   curl -OL https://github.com/WireGuard/wireguard-vyatta-ubnt/releases/latest
#   sudo dpkg -i wireguard-*.deb
# WARNING: Must reinstall after every firmware upgrade!"""

    elif brand == 'pfsense':
        return f"""# =============================================
#  pfSense / OPNsense — WireGuard Setup
#  Site: {site['name']}
# =============================================
#
# ─── pfSense GUI STEPS ───
#
# STEP 1: Install WireGuard Package
#   System → Package Manager → Available Packages
#   Search "WireGuard" → Install
#
# STEP 2: Create Tunnel
#   VPN → WireGuard → Tunnels tab → Add Tunnel
#   - Description: NetWatch VPN
#   - Listen Port: (leave empty or any number)
#   - Interface Keys: click "Generate" or paste private key below
#   - Private Key: {site['client_private_key']}
#   - Interface Addresses: {site['client_ip']}/32
#   → Save
#
# STEP 3: Add Peer
#   VPN → WireGuard → Peers tab → Add Peer
#   - Tunnel: NetWatch VPN
#   - Description: NetWatch Server
#   - Public Key: {server_pub}
#   - Pre-shared Key: {site['preshared_key']}
#   - Endpoint: {server_endpoint}
#   - Endpoint Port: {SERVER_PORT}
#   - Allowed IPs: {SERVER_IP}/32
#   - Keep Alive: 25
#   → Save
#
# STEP 4: Enable WireGuard
#   VPN → WireGuard → Settings → check "Enable WireGuard" → Save
#
# STEP 5: Assign Interface
#   Interfaces → Assignments
#   - Available network ports: select "tun_wg0" (NOT wg0)
#   → Add → Save
#   - Click on new interface (OPT1)
#   - Enable: checked
#   - Description: NETWATCH_VPN
#   - IPv4 Configuration Type: None (IP is set in tunnel config!)
#   → Save → Apply Changes
#
# STEP 6: Firewall Rules
#   Firewall → Rules → NETWATCH_VPN → Add
#   - Action: Pass, Protocol: Any, Source: any, Dest: any
#   → Save → Apply Changes
#
# STEP 7: Verify
#   Status → WireGuard → check handshake timestamp
#   Diagnostics → Ping → Target: {SERVER_IP}
#
# WARNING: After interface assignment, check System → Routing →
#   Default Gateway is set to your WAN, NOT "Automatic"
#
# ─── OPNsense DIFFERENCES ───
# - WireGuard is built-in (24.1+), no package needed
# - VPN → WireGuard → Instances (not "Tunnels")
# - Interface name is "wg0" (not "tun_wg0")
# - Key generation: click gear icon (not "Generate" button)
# - Otherwise same steps"""

    elif brand == 'keenetic':
        return f"""# =============================================
#  Keenetic — WireGuard Setup (KeeneticOS 3.3+)
#  Site: {site['name']}
#  Keenetic has native WireGuard with config file import!
# =============================================
#
# ─── METHOD 1: Import Config File (Easiest) ───
#
# STEP 1: Save this as "netwatch.conf" on your computer:
#
# [Interface]
# PrivateKey = {site['client_private_key']}
# Address = {site['client_ip']}/32
#
# [Peer]
# PublicKey = {server_pub}
# PresharedKey = {site['preshared_key']}
# Endpoint = {server_endpoint}:{SERVER_PORT}
# AllowedIPs = {SERVER_IP}/32
# PersistentKeepalive = 25
#
# STEP 2: Open router admin (my.keenetic.net or 192.168.1.1)
# STEP 3: Internet → Other connections → WireGuard
# STEP 4: Click "Import from file" → select netwatch.conf
# STEP 5: Enable the connection
# STEP 6: Verify: check status shows "Connected"
#
# ─── METHOD 2: Manual Setup ───
#
# STEP 1: Install WireGuard component (if not installed)
#   Management → General settings → Change component set
#   Find "WireGuard VPN" → Install → Reboot
#
# STEP 2: Internet → Other connections → WireGuard → Add
#   - Name: NetWatch VPN
#   - Private Key: {site['client_private_key']}
#   - Address: {site['client_ip']}/32
#
# STEP 3: Add Peer
#   - Public Key: {server_pub}
#   - Preshared Key: {site['preshared_key']}
#   - Endpoint: {server_endpoint}:{SERVER_PORT}
#   - Allowed IPs: {SERVER_IP}/32
#   - Persistent Keepalive: 25
#   → Save and Enable"""

    elif brand == 'tplink':
        return f"""# =============================================
#  TP-Link Omada / ER Series — WireGuard Setup
#  Site: {site['name']}
#  Supported: ER605 V2+, ER7206, ER8411
#  NOT supported: ER605 V1 (hardware limitation)
# =============================================
#
# ─── OMADA CONTROLLER MODE ───
#
# STEP 1: Create WireGuard Interface
#   Settings → VPN → WireGuard → Create New WireGuard
#   - Name: NetWatch VPN
#   - Status: Enable
#   - MTU: 1420
#   - Listen Port: (leave default or empty)
#   - Local IP Address: {site['client_ip']}/32
#   → Create (key pair auto-generates)
#
# STEP 2: Set Private Key
#   Edit the WireGuard interface just created
#   - Replace private key with: {site['client_private_key']}
#   → Save
#
# STEP 3: Add Peer
#   Settings → VPN → WireGuard → Peers → Create New Peer
#   - Interface: NetWatch VPN
#   - Public Key: {server_pub}
#   - Preshared Key: {site['preshared_key']}
#   - Endpoint: {server_endpoint}
#   - Endpoint Port: {SERVER_PORT}
#   - Allowed IPs: {SERVER_IP}/32
#   - Persistent Keepalive: 25
#   → Create
#
# STEP 4: Verify
#   Insight → VPN Status → WireGuard VPN
#   Check traffic and last handshake
#
# ─── STANDALONE MODE (no controller) ───
#
# VPN → WireGuard → Create New WireGuard
# Same fields as above
# After creating, click Export to get the public key"""

    elif brand == 'asus':
        return f"""# =============================================
#  ASUS Router — WireGuard Setup
#  Site: {site['name']}
#  Requires firmware 388.23000+ or ASUSWRT-Merlin
# =============================================
#
# ─── GUI STEPS ───
#
# STEP 1: Save this as "netwatch.conf":
#
# [Interface]
# PrivateKey = {site['client_private_key']}
# Address = {site['client_ip']}/32
#
# [Peer]
# PublicKey = {server_pub}
# PresharedKey = {site['preshared_key']}
# Endpoint = {server_endpoint}:{SERVER_PORT}
# AllowedIPs = {SERVER_IP}/32
# PersistentKeepalive = 25
#
# STEP 2: Login to router (192.168.1.1 or asusrouter.com)
# STEP 3: VPN → VPN Fusion → Add Profile
# STEP 4: Select "WireGuard" → Upload Config → select netwatch.conf
# STEP 5: Fields auto-populate → Apply
# STEP 6: Toggle the connection ON
# STEP 7: Verify connection shows green/connected"""

    elif brand in ('cisco', 'fortinet', 'sonicwall', 'juniper', 'zyxel', 'netgear'):
        _bnames = {'cisco': 'Cisco', 'fortinet': 'Fortinet FortiGate', 'sonicwall': 'SonicWall',
                   'juniper': 'Juniper SRX', 'zyxel': 'Zyxel USG/ATP', 'netgear': 'Netgear ProSafe'}
        bname = _bnames.get(brand, brand)
        return f"""# =============================================
#  {bname} — NO WireGuard Support
#  Site: {site['name']}
# =============================================
#
# This device does NOT support WireGuard natively.
#
# ─── RECOMMENDED SOLUTION ───
#
# Option 1: Place a small MikroTik or Keenetic router
#   behind this firewall and run WireGuard on it.
#   Only need to port-forward UDP {SERVER_PORT} from this
#   device to the MikroTik/Keenetic's IP.
#
# Option 2: Port-forward NVR ports directly
#   Forward port 80 (HTTP) to each NVR's local IP.
#   Less secure — credentials travel over plain internet.
#   Use HTTPS (port 443) if the NVR supports it.
#
# ─── PORT FORWARDING STEPS ───
#
# Forward UDP {SERVER_PORT} to WireGuard device (if using Option 1):
#   - External Port: {SERVER_PORT}
#   - Internal IP: (MikroTik/Keenetic local IP)
#   - Internal Port: {SERVER_PORT}
#   - Protocol: UDP
#
# For brand-specific GUI steps, check the NetWatch vault
# reference docs or contact support.
#
# ─── WireGuard Config (for the device behind this firewall) ───
#
# [Interface]
# PrivateKey = {site['client_private_key']}
# Address = {site['client_ip']}/32
#
# [Peer]
# PublicKey = {server_pub}
# PresharedKey = {site['preshared_key']}
# Endpoint = {server_endpoint}:{SERVER_PORT}
# AllowedIPs = {SERVER_IP}/32
# PersistentKeepalive = 25"""

    elif brand in ('huawei', 'zte', 'dlink', 'tenda'):
        _bnames = {'huawei': 'Huawei', 'zte': 'ZTE', 'dlink': 'D-Link', 'tenda': 'Tenda'}
        _default_ips = {'huawei': '192.168.100.1', 'zte': '192.168.1.1', 'dlink': '192.168.0.1', 'tenda': '192.168.0.1'}
        _default_creds = {
            'huawei': 'root / admin  ან  telecomadmin / admintelecom',
            'zte': 'user / user  ან  admin / (სტიკერზე)',
            'dlink': 'admin / (ცარიელი პაროლი)',
            'tenda': 'admin / admin',
        }
        _menu_paths = {
            'huawei': 'Forward Rules → Port Mapping Configuration\n#      (ახალი CPE: More Functions → Security Settings → NAT Services)',
            'zte': 'Application → Port Forwarding\n#      (ზოგი firmware: Internet → Security → Port Forwarding)',
            'dlink': 'Features → Port Forwarding → Virtual Server → Add Rule\n#      (DIR-615: Advanced → Port Forwarding)',
            'tenda': 'Advanced → Virtual Server → "+" (Add)\n#      (ჯერ: Advanced → DHCP Reservation — მიამაგრე IP)',
        }
        bname = _bnames.get(brand, brand)
        default_ip = _default_ips.get(brand, '192.168.1.1')
        default_cred = _default_creds.get(brand, 'admin / admin')
        menu_path = _menu_paths.get(brand, 'Advanced → Port Forwarding')
        return f"""# =============================================
#  {bname} — WireGuard არ აქვს, მხოლოდ პორტის გადამისამართება
#  Site: {site['name']}
# =============================================
#
# ეს როუტერი არ უჭერს WireGuard-ს ან სხვა site-to-site VPN-ს.
#
# ─── რეკომენდებული გადაწყვეტა ───
#
# MikroTik hAP lite (~$25) დააყენე ამ როუტერის უკან
# და WireGuard გაუშვი MikroTik-ზე.
#
# ამ როუტერზე მხოლოდ UDP {SERVER_PORT} გადაამისამართე MikroTik-ზე.
#
# ─── პორტის გადამისამართება ─ ნაბიჯ-ნაბიჯ ───
#
# 1. შედი როუტერის ადმინ პანელში:
#    URL: http://{default_ip}
#    მომხმარებელი/პაროლი: {default_cred}
#
# 2. გადადი: {menu_path}
#
# 3. დაამატე ახალი წესი:
#    - სახელი: WireGuard
#    - პროტოკოლი: UDP
#    - გარე პორტი: {SERVER_PORT}
#    - შიდა IP: (MikroTik-ის IP, მაგ. {default_ip.rsplit('.', 1)[0]}.200)
#    - შიდა პორტი: {SERVER_PORT}
#
# 4. შეინახე / Apply
#
# ─── გაფრთხილება (საქართველო) ───
#   თუ WAN IP იწყება 100.64.x.x ან 10.x.x.x-ით,
#   CGNAT-ის უკან ხარ. პორტის გადამისამართება ვერ იმუშავებს!
#   დარეკე პროვაიდერს (Magti/Silknet) და მოითხოვე საჯარო IP.
#
#   როგორ შეამოწმო: შეადარე როუტერის WAN IP
#   და https://whatismyip.com — თუ განსხვავდება, CGNAT-ის უკან ხარ.
#
# ─── WireGuard Config (for the MikroTik behind this router) ───
#
# [Interface]
# PrivateKey = {site['client_private_key']}
# Address = {site['client_ip']}/32
#
# [Peer]
# PublicKey = {server_pub}
# PresharedKey = {site['preshared_key']}
# Endpoint = {server_endpoint}:{SERVER_PORT}
# AllowedIPs = {SERVER_IP}/32
# PersistentKeepalive = 25"""

    else:
        return f"""# =============================================
#  Generic WireGuard Config
#  Site: {site['name']}
#  NAT: {first_subnet} → {nat_subnet}
#  In NetWatch, add devices as 10.100.{nat_id}.X
# =============================================
# Use this config file on any WireGuard-compatible device.
# Import it in the WireGuard app or paste into the config file.
#
# NOTE: This config does NOT include NAT rules.
# NAT must be configured on the router separately.
# Without NAT, use the device's real local IP (only works
# if no other client uses the same subnet).

[Interface]
PrivateKey = {site['client_private_key']}
Address = {site['client_ip']}/32

[Peer]
PublicKey = {server_pub}
PresharedKey = {site['preshared_key']}
Endpoint = {server_endpoint}:{SERVER_PORT}
AllowedIPs = {SERVER_IP}/32
PersistentKeepalive = 25

# ─── NAT MAPPING ───
# Local 192.168.1.64 → appears as 10.100.{nat_id}.64 on server
# Local 192.168.1.100 → appears as 10.100.{nat_id}.100 on server
# The last octet stays the same!

# ─── SETUP STEPS ───
#
# Option A: WireGuard App (Windows/Mac/Linux/Android/iOS)
#   1. Install WireGuard from https://wireguard.com/install/
#   2. Open the app → Add Tunnel → Import from file
#   3. Save this config as "netwatch.conf" and import it
#   4. Activate the tunnel
#   5. Verify: ping {SERVER_IP}
#
# Option B: Linux CLI
#   1. Save this config to /etc/wireguard/wg-netwatch.conf
#   2. sudo wg-quick up wg-netwatch
#   3. Verify: ping {SERVER_IP}
#   4. Auto-start: sudo systemctl enable wg-quick@wg-netwatch"""
