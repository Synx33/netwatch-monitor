#!/usr/bin/env python3
"""
new-mikrotik.py — Create a new MikroTik site without Claude/Telegram.

Does exactly what the bot's /newclient command does:
  1. Generates unique WireGuard keys (priv, pub, preshared)
  2. Assigns unique tunnel IP (10.66.66.X) and NAT subnet (10.100.Y.0/24) via the counters
  3. Generates a unique 20-char alphanumeric admin password
  4. Appends the site to vpn_sites.json
  5. Adds the peer to the live WireGuard interface
  6. Rebuilds /etc/wireguard/wg0.conf for persistence across reboots
  7. Prints the ready-to-paste MikroTik setup script + the admin password

Usage:
  sudo ./new-mikrotik.py <site-name> [lan-subnets-comma-separated]

Examples:
  sudo ./new-mikrotik.py bank-isani-1
  sudo ./new-mikrotik.py bank-isani-1 192.168.1.0/24
  sudo ./new-mikrotik.py rustaveli-branch 192.168.1.0/24,192.168.10.0/24

Notes:
  - Must run as root (writes /etc/wireguard/wg0.conf and live WG peer state)
  - The "lan-subnets" argument is a HINT only — the real subnets get auto-discovered
    later via the /discover Telegram command after the device is deployed
  - The admin password is printed ONCE here. It's also saved in
    the vpn_sites.json peer store (kept 0600).
    /discover and /harden read it automatically; you only need it for manual SSH.

After this script runs:
  1. Paste the MikroTik setup script into WinBox → New Terminal (or save to .rsc
     and /import it)
  2. Plug the MikroTik into any internet-connected port
  3. Within ~25 seconds the tunnel comes up, banner + Telegram notification fires
  4. Run /discover in Telegram to auto-detect real LAN subnets + configure netmap
  5. Run /harden in Telegram to disable unused services + install self-heal watchdog
"""

import os
import sys


def main():
    if len(sys.argv) < 2 or sys.argv[1] in ('-h', '--help'):
        print(__doc__, file=sys.stderr)
        sys.exit(0 if sys.argv[1:] == ['--help'] or sys.argv[1:] == ['-h'] else 1)

    # Ensure we can import vpn.py from the project dir regardless of cwd
    here = os.path.dirname(os.path.abspath(__file__))
    sys.path.insert(0, here)

    # Refuse to run as non-root — we can't modify /etc/wireguard otherwise
    if os.geteuid() != 0:
        print("ERROR: must run as root (sudo). Writes to /etc/wireguard/wg0.conf.",
              file=sys.stderr)
        sys.exit(1)

    from vpn import add_site

    site_name = sys.argv[1].strip()
    subnets = sys.argv[2].strip() if len(sys.argv) >= 3 else ''

    if not site_name or any(c in site_name for c in ' \t\n;|&$`'):
        print(f"ERROR: invalid site name {site_name!r}. Use alphanumerics + dashes.",
              file=sys.stderr)
        sys.exit(1)

    print(f"\nCreating site '{site_name}'...")
    result, err = add_site(site_name, subnets, router_brand='mikrotik')
    if err:
        print(f"ERROR: {err}", file=sys.stderr)
        sys.exit(1)

    site = result['site']
    bar = '═' * 72

    print(f"""
{bar}
  ✅ SITE CREATED: {site['name']}
{bar}
  Tunnel IP:      {site['client_ip']}
  NAT subnet:     {site.get('nat_subnet', '-')}
  Router brand:   {site['router_brand']}
  LAN subnets:    {', '.join(site.get('subnets') or []) or '(none yet — set by /discover)'}

  🔑 ADMIN PASSWORD: {site['admin_password']}
  ⚠️  Save it. Also stored in vpn_sites.json (root 0600).
{bar}
  📋 MIKROTIK SETUP SCRIPT (paste into WinBox → New Terminal)
{bar}
{result['router_config']}

{bar}
  🚀 NEXT STEPS
{bar}
  1. Paste the script above into WinBox terminal (or save to .rsc and /import).
  2. Plug MikroTik into any internet-connected ether port.
  3. Wait ~25s. Tunnel auto-connects.
  4. Telegram: /discover → bot auto-adds netmap rules for real LAN subnets.
  5. Telegram: /harden → locks down services + installs 1-minute self-heal watchdog.
{bar}
""")


if __name__ == '__main__':
    main()
