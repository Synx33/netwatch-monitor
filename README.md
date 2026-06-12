# NetWatch

Monitoring for camera/network fleets that **doesn't cry wolf**.

NetWatch watches NVRs, routers, switches, and UPS units across dozens of remote sites from one server. It pings everything on a tight loop and deep-polls each NVR over its vendor API for camera, disk, recording, and clock health — then it sends a Telegram message *only when something is actually wrong*.

That last part is the whole game. Anyone can write a script that pings a box and shouts when a packet drops. The hard problem is **not shouting** — at the dropped packet, the camera blinking during a reboot, the disk that's "100% full" because that's how surveillance recording works. A monitor that cries wolf gets muted, and a muted monitor is useless. Most of the engineering here is about earning the operator's trust.

> Source-available portfolio sample — see [LICENSE](LICENSE). Built to run unattended for months across real client sites.

## The interesting part: making alerts trustworthy

A device is only "offline" after it fails **30 pings in a row** (~2.5 min), so one bad packet never wakes anyone. Alerts are **state-machine driven** — they fire once when a condition appears and stay quiet until it clears, instead of repeating every few minutes. A flaky link that flaps up/down/up/down gets **one** "this device is unstable, muting it for an hour" notice instead of forty alerts. When an NVR reboots, every camera on it drops for a couple minutes while it reconnects — so there's a **grace window** that swallows that storm and lets the single "NVR rebooted" alert through. A site-wide power cut waits **7 minutes** before it's called an outage, because the building's internet hiccups too.

And it knows surveillance gear: a recorder running its disks at 100% on a loop isn't broken, a disk reporting "idle" isn't broken, so neither fires an alert. Only genuine faults — a failed drive, a dead camera, a clock that's drifted — get through.

Each site/client gets a chat that only receives the categories they care about, with a mute switch for planned maintenance. Operators see everything; clients see a filtered, IP-free view.

## What it monitors

- **NVRs** — Hikvision (ISAPI), Dahua, Uniview, Hanwha, Axis, Bosch, ONVIF, plus an auto-detecting fallback. Pulls per-camera status, HDD/RAID/SMART, uptime, recording state, clock drift.
- **Network gear** — switches/routers/APs over SNMP, UPS battery and load.
- Anything else with an IP gets ping + port monitoring.

## How it's built

Four independent processes (run as systemd services) so a crash in one can't take down the rest:

```
bot.py        Telegram command handler + scheduled reports
netwatch.py   the engine: 5s ping loop, 30s deep checks, the alert logic
web.py        dashboard + REST API on :7700 (session auth)
syslog_*.py   UDP 514 receiver, tunnel-bound
```

Supporting modules: `devices.py` (one monitor class per vendor), `vpn.py` (generates WireGuard configs for new client sites and auto-discovers their LAN subnets), `scanner.py` (ARP/port/ONVIF discovery), `clock_fix.py` (the opt-in NVR clock repair).

Python 3, standard library for the core (`requests` for device APIs), JSON files for state — no database, no build step. The dashboard is hand-written HTML/CSS/JS. The operator-facing UI is localized (the deployed build runs in Georgian).

## Remote sites & the lockout problem

Client devices sit behind their own firewalls, so NetWatch provisions a **WireGuard** tunnel per site and reaches them over a private overlay, with cross-peer isolation so one client can never see another's network. Routers get a self-healing watchdog config — because the fastest way to turn a monitoring tool into an incident is to push a config that locks you out of the thing you were monitoring.

That same caution shows up in the one place NetWatch *writes* to a device (an optional NVR clock fix): it's off by default behind a kill-switch, human-triggered, dry-run-first, refuses any device that shares a public IP with another, verifies the write by reading it back, and rolls back on mismatch. A monitor should never be the thing that breaks the device.

## Running it

```bash
python3 -m venv venv && source venv/bin/activate
pip install requests
cp config.example.json config.json     # add your Telegram token + devices
python3 netwatch.py                     # engine
python3 web.py                          # dashboard → http://localhost:7700
python3 bot.py                          # Telegram bot
```

`config.json` and all state/log files are git-ignored — nothing with credentials is committed.

## Telegram, briefly

`/status` for the whole fleet, `/site <name>` / `/device <name>` to drill in, `/sla <site>` for an uptime report, `/mute <site> 2h` during maintenance, `/syslog` to tail collected logs. Client chats get a smaller command set than the admin chat.

## License

Source-available, all rights reserved ([LICENSE](LICENSE)) — published to read, not to deploy. Ask if you want to use it.
