#!/usr/bin/env python3
"""
NetWatch Telegram Bot - responds to commands in chat.
"""
import json
import time
import threading
import subprocess
import re
import html
import requests
from pathlib import Path
from datetime import datetime

CONFIG_PATH = Path(__file__).parent / 'config.json'
STATE_PATH = Path(__file__).parent / 'state.json'
LOG_PATH = Path(__file__).parent / 'netwatch.log'
ADMINS_PATH = Path(__file__).parent / 'admins.json'


def load_config():
    with open(CONFIG_PATH) as f:
        return json.load(f)


def save_config(config):
    with open(CONFIG_PATH, 'w') as f:
        json.dump(config, f, indent=2, ensure_ascii=False)


def load_admins():
    try:
        with open(ADMINS_PATH) as f:
            return json.load(f)
    except:
        return {'super_admin': None, 'admins': []}


def save_admins(data):
    with open(ADMINS_PATH, 'w') as f:
        json.dump(data, f, indent=2)


def load_state():
    try:
        with open(STATE_PATH) as f:
            return json.load(f)
    except:
        return {}


BRAND_LIST = [
    ('mikrotik', 'MikroTik (RouterOS 7)'),
    ('keenetic', 'Keenetic'),
    ('ubiquiti', 'Ubiquiti (EdgeOS 3+)'),
    ('pfsense', 'pfSense / OPNsense'),
    ('tplink', 'TP-Link (Omada/ER V2+)'),
    ('asus', 'ASUS'),
    ('cisco', 'Cisco (IPsec, WireGuard არ აქვს)'),
    ('fortinet', 'Fortinet FortiGate'),
    ('sonicwall', 'SonicWall'),
    ('juniper', 'Juniper SRX'),
    ('zyxel', 'Zyxel USG/ATP'),
    ('netgear', 'Netgear ProSafe'),
    ('huawei', 'Huawei (მხოლოდ პორტის გადამისამართება)'),
    ('zte', 'ZTE (მხოლოდ პორტის გადამისამართება)'),
    ('dlink', 'D-Link (მხოლოდ პორტის გადამისამართება)'),
    ('tenda', 'Tenda (მხოლოდ პორტის გადამისამართება)'),
    ('generic', 'სხვა / Generic WireGuard'),
]

DEVICE_TYPES = [
    ('hikvision_nvr', 'Hikvision NVR/DVR'),
    ('dahua_nvr', 'Dahua NVR/DVR'),
    ('uniview_nvr', 'Uniview NVR/DVR'),
    ('auto_nvr', 'NVR/DVR (ავტო-გამოვლენა)'),
    ('switch', 'სვიჩი (SNMP)'),
    ('router', 'როუტერი (SNMP)'),
    ('access_point', 'წვდომის წერტილი (SNMP)'),
    ('ups', 'UPS'),
    ('ip_camera', 'IP კამერა'),
    ('http_device', 'ვებ სერვისი (HTTP)'),
    ('network_device', 'სხვა (მხოლოდ პინგი)'),
]


class NetWatchBot:
    def __init__(self):
        config = load_config()
        self.token = config['telegram']['bot_token']
        self.chat_id = config['telegram']['chat_id']
        self.last_update_id = 0
        # Conversation state: user_id -> {step, data}
        self._conversations = {}

    def send(self, chat_id, text):
        try:
            # Split long messages (Telegram limit is 4096 chars)
            while text:
                chunk = text[:4000]
                text = text[4000:]
                requests.post(
                    f"https://api.telegram.org/bot{self.token}/sendMessage",
                    json={"chat_id": chat_id, "text": chunk, "parse_mode": "HTML"},
                    timeout=10
                )
        except Exception as e:
            print(f"Send error: {e}")

    def get_updates(self):
        try:
            resp = requests.get(
                f"https://api.telegram.org/bot{self.token}/getUpdates",
                params={"offset": self.last_update_id + 1, "timeout": 30},
                timeout=35
            )
            if resp.ok:
                return resp.json().get('result', [])
        except:
            pass
        return []

    def _is_admin_chat(self, chat_id):
        """Check if message is from the main admin chat."""
        return str(chat_id) == str(self.chat_id)

    def _is_authorized(self, user_id):
        """Check if user is authorized (super admin or admin)."""
        admins = load_admins()
        uid = str(user_id)
        return uid == str(admins.get('super_admin')) or uid in [str(a) for a in admins.get('admins', [])]

    def _is_super_admin(self, user_id):
        admins = load_admins()
        return str(user_id) == str(admins.get('super_admin'))

    def handle_message(self, msg):
        chat_id = msg['chat']['id']
        user_id = msg['from']['id']
        user_name = msg['from'].get('first_name', '') + ' ' + msg['from'].get('last_name', '')
        text = msg.get('text', '').strip()
        text_lower = text.lower()

        # Check if user is in an active conversation flow
        if user_id in self._conversations and not text.startswith('/') or \
           (user_id in self._conversations and text_lower == '/cancel'):
            if text_lower == '/cancel':
                del self._conversations[user_id]
                self.send(chat_id, "❌ გაუქმდა.")
                return
            self._handle_conversation(chat_id, user_id, text)
            return

        if text_lower in ('/chatid', 'chatid'):
            chat_type = msg['chat'].get('type', 'private')
            self.send(chat_id,
                f"📋 <b>Chat ID:</b> <code>{chat_id}</code>\n"
                f"Type: {chat_type}\n\n"
                f"Copy this ID and paste it in NetWatch when adding a site."
            )
            return

        # /myid — show your Telegram user ID + auto-register super admin
        elif text_lower in ('/myid', 'myid'):
            admins = load_admins()
            role = "super admin" if str(user_id) == str(admins.get('super_admin')) else \
                   "admin" if str(user_id) in [str(a) for a in admins.get('admins', [])] else \
                   "არაავტორიზებული"
            # Auto-register first user as super admin
            if admins.get('super_admin') is None and self._is_admin_chat(chat_id):
                admins['super_admin'] = user_id
                save_admins(admins)
                role = "super admin (ახლახან დარეგისტრირდა)"
            self.send(chat_id,
                f"👤 <b>შენი Telegram ID:</b> <code>{user_id}</code>\n"
                f"📛 სახელი: {user_name.strip()}\n"
                f"🔑 როლი: {role}"
            )
            return

        # === ADMIN-ONLY COMMANDS (only in admin chat, only authorized users) ===

        elif text_lower.startswith('/adduser '):
            if not self._is_admin_chat(chat_id):
                return
            if not self._is_super_admin(user_id):
                self.send(chat_id, "❌ მხოლოდ მთავარ ადმინისტრატორს შეუძლია მომხმარებლების დამატება.")
                return
            try:
                new_id = int(text.split(' ', 1)[1].strip())
                admins = load_admins()
                if new_id not in admins['admins'] and str(new_id) != str(admins['super_admin']):
                    admins['admins'].append(new_id)
                    save_admins(admins)
                    self.send(chat_id, f"✅ მომხმარებელი <code>{new_id}</code> დაემატა ადმინისტრატორებში.")
                else:
                    self.send(chat_id, f"ℹ️ მომხმარებელი <code>{new_id}</code> უკვე ადმინისტრატორია.")
            except ValueError:
                self.send(chat_id, "❌ არასწორი ID. გამოიყენე: /adduser 123456789")
            return

        elif text_lower.startswith('/removeuser '):
            if not self._is_admin_chat(chat_id):
                return
            if not self._is_super_admin(user_id):
                self.send(chat_id, "❌ მხოლოდ მთავარ ადმინისტრატორს შეუძლია მომხმარებლების წაშლა.")
                return
            try:
                rm_id = int(text.split(' ', 1)[1].strip())
                admins = load_admins()
                if rm_id in admins['admins']:
                    admins['admins'].remove(rm_id)
                    save_admins(admins)
                    self.send(chat_id, f"✅ მომხმარებელი <code>{rm_id}</code> წაიშალა ადმინისტრატორებიდან.")
                else:
                    self.send(chat_id, f"❌ მომხმარებელი <code>{rm_id}</code> არ არის ადმინისტრატორი.")
            except ValueError:
                self.send(chat_id, "❌ არასწორი ID. გამოიყენე: /removeuser 123456789")
            return

        elif text_lower == '/admins':
            if not self._is_admin_chat(chat_id):
                return
            admins = load_admins()
            msg_text = "👥 <b>ადმინისტრატორები:</b>\n\n"
            msg_text += f"👑 მთავარი: <code>{admins.get('super_admin', 'არ არის')}</code>\n"
            for a in admins.get('admins', []):
                msg_text += f"👤 <code>{a}</code>\n"
            if not admins.get('admins'):
                msg_text += "სხვა ადმინისტრატორები არ არის."
            self.send(chat_id, msg_text)
            return

        elif text_lower in ('/newclient', '/adddevice'):
            if not self._is_admin_chat(chat_id):
                return
            if not self._is_authorized(user_id):
                self.send(chat_id, "❌ არ გაქვს ამ ბრძანების გამოყენების უფლება. სთხოვე ადმინისტრატორს /adduser.")
                return
            if text_lower == '/newclient':
                # Check for unlinked VPN sites (have VPN but no monitoring site)
                from vpn import load_vpn_sites
                vpn_data = load_vpn_sites()
                config = load_config()
                existing_site_names = [s['name'].lower() for s in config['sites']]
                unlinked = [s for s in vpn_data.get('sites', []) if s['name'].lower() not in existing_site_names]

                if unlinked:
                    menu = "📝 <b>ახალი კლიენტის დამატება</b>\n\n"
                    menu += "🔐 <b>არსებული VPN ობიექტები (მონიტორინგის გარეშე):</b>\n\n"
                    for i, site in enumerate(unlinked, 1):
                        connected = "🟢" if site.get('connected') else "🔴"
                        menu += f"  <b>{i}.</b> {connected} {site['name']} (VPN: {site['client_ip']})\n"
                    menu += f"\n  <b>{len(unlinked) + 1}.</b> ➕ ახალი ობიექტის შექმნა\n"
                    menu += "\nჩაწერე ნომერი:"
                    self._conversations[user_id] = {'flow': 'newclient', 'step': 'pick_vpn', 'data': {'unlinked': unlinked}}
                else:
                    self._conversations[user_id] = {'flow': 'newclient', 'step': 'name', 'data': {}}
                    self.send(chat_id, "📝 <b>ახალი კლიენტის დამატება</b>\n\nჩაწერე ობიექტის სახელი:")
            else:
                config = load_config()
                if not config['sites']:
                    self.send(chat_id, "❌ ობიექტები ჯერ არ არის. ჯერ დაამატე: /newclient")
                    return
                menu = "🏢 <b>აირჩიე ობიექტი:</b>\n\n"
                for i, site in enumerate(config['sites'], 1):
                    dev_count = len(site.get('devices', []))
                    menu += f"  <b>{i}.</b> {site['name']} ({dev_count} მოწყობილობა)\n"
                menu += "\nჩაწერე ნომერი:"
                self._conversations[user_id] = {'flow': 'adddevice', 'step': 'site', 'data': {}}
                self.send(chat_id, menu)
            return

        elif text_lower == '/cancel':
            if user_id in self._conversations:
                del self._conversations[user_id]
                self.send(chat_id, "❌ გაუქმდა.")
            return

        # === REGULAR COMMANDS (anyone in any chat) ===

        elif text_lower in ('/status', 'status', 'სტატუსი'):
            self.cmd_status(chat_id)
        elif text_lower.startswith('/logs') or text_lower.startswith('logs'):
            self.cmd_logs(chat_id, text)
        elif text_lower.startswith('/syslog') or text_lower.startswith('syslog'):
            self.cmd_syslog(chat_id, text)
        elif text_lower.startswith('/mute '):
            self.cmd_mute(chat_id, text)
        elif text_lower.startswith('/unmute '):
            self.cmd_unmute(chat_id, text)
        elif text_lower.startswith('/sla '):
            self.cmd_sla(chat_id, text)
        elif text_lower.startswith('/monthlyreport'):
            self.cmd_monthlyreport(chat_id, text)
        elif text_lower.startswith('/fixclock'):
            self.cmd_fixclock(chat_id, text)
        elif text_lower.startswith('/alerts') or text_lower.startswith('alerts'):
            self.cmd_alerts(chat_id, text)
        elif text_lower in ('/sites', 'sites', 'საიტები', 'ობიექტები'):
            self.cmd_sites(chat_id)
        elif text_lower in ('/scansubnets', '/scansubnet', 'scansubnets'):
            self.cmd_scansubnets(chat_id, user_id)
        elif text_lower in ('/discover', '/discoversubnets', 'discover'):
            self.cmd_discover(chat_id, user_id)
        elif text_lower in ('/harden', 'harden'):
            self.cmd_harden(chat_id, user_id)
        elif text_lower in ('/help', 'help', 'დახმარება'):
            self.cmd_help(chat_id)
        elif text_lower.startswith('/site ') or text_lower.startswith('site '):
            site_name = text.split(' ', 1)[1].strip()
            self.cmd_site_detail(chat_id, site_name)
        elif text_lower.startswith('/device ') or text_lower.startswith('device '):
            self.cmd_device_detail(chat_id, text.split(' ', 1)[1].strip())
        else:
            self.cmd_help(chat_id)

    def _handle_conversation(self, chat_id, user_id, text):
        """Handle multi-step conversation flows."""
        conv = self._conversations[user_id]
        flow = conv['flow']
        step = conv['step']
        data = conv['data']

        try:
            # ===== NEW CLIENT FLOW =====
            if flow == 'newclient':
                if step == 'pick_vpn':
                    try:
                        idx = int(text) - 1
                        unlinked = data.get('unlinked', [])
                        if idx == len(unlinked):
                            # User chose "create new"
                            conv['step'] = 'name'
                            data.pop('unlinked', None)
                            self.send(chat_id, "📝 ჩაწერე ობიექტის სახელი:")
                        elif 0 <= idx < len(unlinked):
                            # User chose an existing VPN site — use its name and skip VPN setup
                            vpn_site = unlinked[idx]
                            data['name'] = vpn_site['name']
                            data['skip_vpn'] = True
                            data.pop('unlinked', None)
                            conv['step'] = 'chat_id'
                            self.send(chat_id,
                                f"🔐 VPN ობიექტი: <b>{vpn_site['name']}</b> (IP: {vpn_site['client_ip']})\n\n"
                                f"💬 Telegram ჯგუფის Chat ID?\n\n"
                                f"<i>ჯგუფში ჩაწერე /chatid რომ გაიგო. თუ ჯერ არ გაქვს ჯგუფი, ჩაწერე</i> <b>0</b>")
                        else:
                            self.send(chat_id, f"❌ აირჩიე 1-დან {len(unlinked) + 1}-მდე:")
                    except ValueError:
                        self.send(chat_id, "❌ ჩაწერე ნომერი:")

                elif step == 'name':
                    config = load_config()
                    for s in config['sites']:
                        if s['name'].lower() == text.lower():
                            self.send(chat_id, f"❌ ობიექტი \"{text}\" უკვე არსებობს. სცადე სხვა სახელი:")
                            return
                    data['name'] = text
                    conv['step'] = 'chat_id'
                    self.send(chat_id, "💬 Telegram ჯგუფის Chat ID?\n\n<i>ჯგუფში ჩაწერე /chatid რომ გაიგო. თუ ჯერ არ გაქვს ჯგუფი, ჩაწერე</i> <b>0</b>")

                elif step == 'chat_id':
                    data['chat_id'] = text if text != '0' else ''

                    if data.get('skip_vpn'):
                        # Linking existing VPN — skip brand and subnet, go straight to creating the site
                        conv['step'] = 'finish'
                        self._finish_newclient(chat_id, user_id, data)
                        return

                    conv['step'] = 'brand'
                    menu = "📡 <b>როუტერის ბრენდი:</b>\n\n"
                    for i, (key, name) in enumerate(BRAND_LIST, 1):
                        menu += f"  <b>{i}.</b> {name}\n"
                    menu += "\nჩაწერე ნომერი:"
                    self.send(chat_id, menu)

                elif step == 'brand':
                    try:
                        idx = int(text) - 1
                        if 0 <= idx < len(BRAND_LIST):
                            data['brand'] = BRAND_LIST[idx][0]
                            conv['step'] = 'subnets'
                            self.send(chat_id,
                                "🌐 <b>კლიენტის ქვექსელი:</b>\n\n"
                                "მაგ: <code>192.168.1.0/24</code>\n"
                                "მრავალი: <code>192.168.1.0/24,10.0.0.0/24</code>\n"
                                "დიდი ქსელი: <code>10.0.0.0/8</code>"
                            )
                        else:
                            self.send(chat_id, f"❌ აირჩიე 1-დან {len(BRAND_LIST)}-მდე:")
                    except ValueError:
                        self.send(chat_id, "❌ ჩაწერე ნომერი:")

                elif step == 'subnets':
                    data['subnets'] = text
                    self._finish_newclient(chat_id, user_id, data)

            # ===== ADD DEVICE FLOW =====
            elif flow == 'adddevice':
                if step == 'site':
                    try:
                        idx = int(text) - 1
                        config = load_config()
                        if 0 <= idx < len(config['sites']):
                            data['site_idx'] = idx
                            data['site_name'] = config['sites'][idx]['name']
                            conv['step'] = 'dev_name'
                            self.send(chat_id, f"🏢 ობიექტი: <b>{data['site_name']}</b>\n\n📹 მოწყობილობის სახელი?")
                        else:
                            self.send(chat_id, f"❌ აირჩიე 1-დან {len(config['sites'])}-მდე:")
                    except ValueError:
                        self.send(chat_id, "❌ ჩაწერე ნომერი:")

                elif step == 'dev_name':
                    data['dev_name'] = text
                    conv['step'] = 'dev_type'
                    menu = "📋 <b>მოწყობილობის ტიპი:</b>\n\n"
                    for i, (key, name) in enumerate(DEVICE_TYPES, 1):
                        menu += f"  <b>{i}.</b> {name}\n"
                    menu += "\nჩაწერე ნომერი:"
                    self.send(chat_id, menu)

                elif step == 'dev_type':
                    try:
                        idx = int(text) - 1
                        if 0 <= idx < len(DEVICE_TYPES):
                            data['dev_type'] = DEVICE_TYPES[idx][0]
                            conv['step'] = 'dev_ip'
                            self.send(chat_id, "📍 IP მისამართი?\n\nმაგ: <code>192.168.1.64</code>")
                        else:
                            self.send(chat_id, f"❌ აირჩიე 1-დან {len(DEVICE_TYPES)}-მდე:")
                    except ValueError:
                        self.send(chat_id, "❌ ჩაწერე ნომერი:")

                elif step == 'dev_ip':
                    data['dev_ip'] = text
                    conv['step'] = 'dev_port'
                    self.send(chat_id, "🔌 პორტი?\n\nნაგულისხმევი 80. ჩაწერე ნომერი ან <b>80</b>:")

                elif step == 'dev_port':
                    try:
                        data['dev_port'] = int(text)
                    except ValueError:
                        data['dev_port'] = 80
                    # Check if this device type needs credentials
                    needs_creds = data['dev_type'] in ('hikvision_nvr', 'dahua_nvr', 'uniview_nvr', 'auto_nvr', 'ip_camera', 'http_device')
                    if needs_creds:
                        conv['step'] = 'dev_user'
                        self.send(chat_id, "👤 მომხმარებელი?\n\nმაგ: <code>admin</code>")
                    else:
                        data['dev_user'] = ''
                        data['dev_pass'] = ''
                        self._finish_adddevice(chat_id, user_id, data)

                elif step == 'dev_user':
                    data['dev_user'] = text
                    conv['step'] = 'dev_pass'
                    self.send(chat_id, "🔑 პაროლი?")

                elif step == 'dev_pass':
                    data['dev_pass'] = text
                    self._finish_adddevice(chat_id, user_id, data)

            elif flow == 'scansubnets':
                if step == 'pick_site':
                    try:
                        idx = int(text) - 1
                        scannable = data.get('scannable', [])
                        if 0 <= idx < len(scannable):
                            site = scannable[idx]
                            del self._conversations[user_id]
                            # Run scan in background so user gets instant feedback
                            threading.Thread(
                                target=self._run_subnet_scan,
                                args=(chat_id, site),
                                daemon=True
                            ).start()
                        else:
                            self.send(chat_id, f"❌ აირჩიე 1-დან {len(scannable)}-მდე:")
                    except ValueError:
                        self.send(chat_id, "❌ ჩაწერე ნომერი:")

            elif flow == 'discover':
                if step == 'pick_site':
                    try:
                        idx = int(text) - 1
                        online = data.get('online', [])
                        if 0 <= idx < len(online):
                            site = online[idx]
                            # If we have a stored per-device password, skip the prompt
                            stored_pw = site.get('admin_password')
                            if stored_pw:
                                conv['data'] = {'site': site}
                                threading.Thread(
                                    target=self._run_discover,
                                    args=(chat_id, user_id, site, stored_pw),
                                    daemon=True
                                ).start()
                            else:
                                conv['step'] = 'password'
                                conv['data'] = {'site': site}
                                self.send(chat_id,
                                    f"🔑 <b>{site['name']}</b>-ის admin პაროლი:\n\n"
                                    f"<i>(პაროლი არ არის შენახული — ერთხელ ჩაწერე. მერე შეგიძლია მესიჯი წაშალო.)</i>")
                        else:
                            self.send(chat_id, f"❌ აირჩიე 1-დან {len(online)}-მდე:")
                    except ValueError:
                        self.send(chat_id, "❌ ჩაწერე ნომერი:")
                elif step == 'password':
                    site = data['site']
                    password = text
                    # Keep the conversation live; _run_discover will transition it to confirm_apply
                    threading.Thread(
                        target=self._run_discover,
                        args=(chat_id, user_id, site, password),
                        daemon=True
                    ).start()
                elif step == 'confirm_apply':
                    choice = text.strip()
                    if choice in ('1', '2'):
                        site = data['site']
                        subnets = data['subnets']
                        password = data['password']
                        remove_stale = (choice == '1')  # full sync = also remove stales
                        del self._conversations[user_id]
                        threading.Thread(
                            target=self._apply_discover,
                            args=(chat_id, site, subnets, password, remove_stale),
                            daemon=True
                        ).start()
                    elif choice == '3':
                        del self._conversations[user_id]
                        self.send(chat_id, "👌 კარგი, არაფერი არ შევცვალე.")
                    else:
                        self.send(chat_id, "❌ ჩაწერე <b>1</b>, <b>2</b> ან <b>3</b>:")

            elif flow == 'harden':
                if step == 'pick_site':
                    try:
                        idx = int(text) - 1
                        online = data.get('online', [])
                        if 0 <= idx < len(online):
                            site = online[idx]
                            stored_pw = site.get('admin_password')
                            if stored_pw:
                                del self._conversations[user_id]
                                threading.Thread(
                                    target=self._run_harden,
                                    args=(chat_id, user_id, site, stored_pw),
                                    daemon=True
                                ).start()
                            else:
                                conv['step'] = 'password'
                                conv['data'] = {'site': site}
                                self.send(chat_id,
                                    f"🔑 <b>{site['name']}</b>-ის admin პაროლი:\n\n"
                                    f"<i>(მერე შეგიძლია მესიჯი წაშალო ჩატიდან.)</i>")
                        else:
                            self.send(chat_id, f"❌ აირჩიე 1-დან {len(online)}-მდე:")
                    except ValueError:
                        self.send(chat_id, "❌ ჩაწერე ნომერი:")
                elif step == 'password':
                    site = data['site']
                    password = text
                    del self._conversations[user_id]
                    threading.Thread(
                        target=self._run_harden,
                        args=(chat_id, user_id, site, password),
                        daemon=True
                    ).start()

        except Exception as e:
            del self._conversations[user_id]
            self.send(chat_id, f"❌ შეცდომა: {str(e)}")

    def _finish_newclient(self, chat_id, user_id, data):
        """Final step — create the monitoring site (and VPN if needed)."""
        if user_id in self._conversations:
            del self._conversations[user_id]

        self.send(chat_id, f"⏳ იქმნება <b>{data['name']}</b>...")

        config = load_config()
        config['sites'].append({
            'name': data['name'],
            'telegram_chat_id': data.get('chat_id', ''),
            'devices': []
        })
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)

        if data.get('skip_vpn'):
            # Linking existing VPN site — no VPN creation needed
            self.send(chat_id,
                f"✅ <b>ობიექტი შეიქმნა!</b>\n"
                f"{'─' * 28}\n\n"
                f"📍 სახელი: <b>{data['name']}</b>\n"
                f"💬 Telegram: <code>{data.get('chat_id', 'არ არის')}</code>\n"
                f"🔐 VPN: უკვე დაკავშირებული\n\n"
                f"შემდეგი ნაბიჯი: /adddevice"
            )
            return

        from vpn import add_site
        vpn_result, vpn_error = add_site(data['name'], data['subnets'], data['brand'])

        if vpn_error:
            self.send(chat_id,
                f"✅ ობიექტი <b>{data['name']}</b> შეიქმნა.\n"
                f"⚠️ VPN: {vpn_error}")
            return

        client_ip = vpn_result.get('site', {}).get('client_ip', '?')
        router_config = vpn_result.get('router_config', '')

        self.send(chat_id,
            f"✅ <b>ობიექტი შეიქმნა!</b>\n"
            f"{'─' * 28}\n\n"
            f"📍 სახელი: <b>{data['name']}</b>\n"
            f"💬 Telegram: <code>{data.get('chat_id', 'არ არის')}</code>\n"
            f"🔐 VPN IP: <code>{client_ip}</code>\n"
            f"🌐 ქვექსელი: <code>{data.get('subnets', '')}</code>\n"
            f"📡 ბრენდი: {data.get('brand', '')}\n\n"
            f"შემდეგი ნაბიჯი: /adddevice"
        )

        if router_config:
            self.send(chat_id, f"📋 <b>როუტერის კონფიგურაცია:</b>\n\n<pre>{router_config[:3500]}</pre>")

    def _finish_adddevice(self, chat_id, user_id, data):
        """Final step of adddevice flow — save to config."""
        del self._conversations[user_id]

        config = load_config()
        device = {
            'name': data['dev_name'],
            'type': data['dev_type'],
            'ip': data['dev_ip'],
            'port': data['dev_port'],
            'username': data.get('dev_user', ''),
            'password': data.get('dev_pass', ''),
            'monitor': {'ping': True, 'hdd_health': True, 'camera_status': True, 'uptime': True}
        }

        config['sites'][data['site_idx']]['devices'].append(device)
        with open(CONFIG_PATH, 'w') as f:
            json.dump(config, f, indent=2)

        dev_type_name = dict(DEVICE_TYPES).get(data['dev_type'], data['dev_type'])
        self.send(chat_id,
            f"✅ <b>მოწყობილობა დაემატა!</b>\n\n"
            f"🏢 ობიექტი: {data['site_name']}\n"
            f"📹 სახელი: {data['dev_name']}\n"
            f"📋 ტიპი: {dev_type_name}\n"
            f"📍 IP: {data['dev_ip']}:{data['dev_port']}\n"
            f"{'👤 მომხმარებელი: ' + data['dev_user'] if data.get('dev_user') else ''}\n\n"
            f"მონიტორინგი დაიწყება 30 წამში.\n"
            f"კიდევ დასამატებელია? /adddevice"
        )

    def cmd_help(self, chat_id):
        msg = (
            "📋 <b>NetWatch — ბრძანებები:</b>\n\n"
            "<b>მდგომარეობა:</b>\n"
            "/status — ყველა მოწყობილობის მდგომარეობა\n"
            "/sites — ობიექტების სია\n"
            "/site Office — კონკრეტული ობიექტის დეტალები\n"
            "/device NVR Office — კონკრეტული მოწყობილობის ინფორმაცია\n\n"
            "<b>ჩანაწერები:</b>\n"
            "/logs — ბოლო 30 ჩანაწერი\n"
            "/logs NVR Office — კონკრეტული მოწყობილობის ჩანაწერები\n"
            "/syslog — MikroTik-ების syslog ბოლო 20\n"
            "/syslog crit — მხოლოდ კრიტიკული\n"
            "/syslog wireguard — საძიებო სიტყვით ფილტრი\n\n"
            "<b>შეტყობინებები:</b>\n"
            "/alerts — ბოლო 20 შეტყობინება\n"
            "/alerts NVR Office — მოწყობილობის შეტყობინებები\n\n"
        )
        if self._is_admin_chat(chat_id):
            msg += (
                "<b>ადმინისტრაცია (მხოლოდ ადმინ ჩატში):</b>\n"
                "/mute SITE 2h — შეტყობინებების დადუმება (მაგ: 30m / 2h / 1d)\n"
                "/unmute SITE — დადუმების გაუქმება\n"
                "/sla SITE 30 — uptime რეპორტი ბოლო N დღე\n"
                "/monthlyreport [SITE] [YYYY-MM] — ყოველთვიური რეპორტი (ავტომატურად 1-ში 09:00)\n"
                "/newclient [სახელი] [ChatID] [ბრენდი] [ქვექსელი] — ახალი კლიენტის დამატება\n"
                "/adddevice [ობიექტი] [სახელი] [IP] [მომხ.] [პაროლი] — მოწყობილობის დამატება\n"
                "/scansubnets — კლიენტის ქვექსელის სკანირება ტუნელის გავლით\n"
                "/discover — MikroTik-ის ქვექსელების აღმოჩენა + ავტო NAT კონფიგურაცია\n"
                "/harden — MikroTik-ის უსაფრთხო ჩაკეტვა (მხოლოდ ტუნელიდან წვდომა)\n"
                "/myid — შენი Telegram ID\n"
                "/adduser [ID] — ადმინისტრატორის დამატება\n"
                "/removeuser [ID] — ადმინისტრატორის წაშლა\n"
                "/admins — ადმინისტრატორების სია\n\n"
            )
        msg += "/help — ბრძანებების სია"
        self.send(chat_id, msg)

    def cmd_status(self, chat_id):
        state = load_state()
        config = load_config()
        last_check = state.get('last_check', 'Unknown')
        show_ips = self._is_admin_chat(chat_id)

        msg = f"📊 <b>NetWatch — მდგომარეობა</b>\n🕐 {last_check}\n\n"

        for site in config.get('sites', []):
            site_name = site['name']
            site_state = state.get('sites', {}).get(site_name, [])

            online = sum(1 for d in site_state if d.get('online'))
            total = len(site_state)
            icon = "🟢" if online == total else "🔴" if online == 0 else "🟡"

            msg += f"{icon} <b>{site_name}</b> — {online}/{total} ხელმისაწვდომი\n"

            for dev in site_state:
                status_icon = "✅" if dev.get('online') else "❌"
                name = dev.get('name', 'Unknown')
                ip = dev.get('ip', '')

                details = []
                if dev.get('device_info', {}).get('model'):
                    details.append(dev['device_info']['model'])
                if dev.get('uptime'):
                    h = dev['uptime'] // 3600
                    m = (dev['uptime'] % 3600) // 60
                    details.append(f"Up {h}h{m}m")
                if dev.get('cameras'):
                    cam_on = sum(1 for c in dev['cameras'] if c.get('online'))
                    cam_total = len(dev['cameras'])
                    if cam_on < cam_total:
                        details.append(f"📷 {cam_on}/{cam_total}")
                if dev.get('hdds'):
                    for h in dev['hdds']:
                        if h.get('status', '').lower() not in ('ok', 'normal'):
                            details.append(f"💾 HDD#{h['id']}: {h['status']}")

                detail_str = ' | '.join(details) if details else ''
                ip_str = f" ({ip})" if show_ips and ip else ''
                msg += f"  {status_icon} {name}{ip_str} {detail_str}\n"

            msg += "\n"

        self.send(chat_id, msg)

    def cmd_sites(self, chat_id):
        config = load_config()
        msg = "🏢 <b>ობიექტები:</b>\n\n"
        for i, site in enumerate(config.get('sites', []), 1):
            device_count = len(site.get('devices', []))
            msg += f"{i}. <b>{site['name']}</b> — {device_count} მოწყობილობა\n"
        if not config.get('sites'):
            msg += "ობიექტები ჯერ არ არის დამატებული."
        self.send(chat_id, msg)

    def cmd_site_detail(self, chat_id, site_name):
        state = load_state()
        config = load_config()

        # Find site (case insensitive)
        site = None
        for s in config.get('sites', []):
            if s['name'].lower() == site_name.lower():
                site = s
                break

        if not site:
            self.send(chat_id, f"❌ ობიექტი \"{site_name}\" ვერ მოიძებნა.")
            return

        site_state = state.get('sites', {}).get(site['name'], [])
        msg = f"🏢 <b>{site['name']}</b>\n{'─' * 25}\n\n"

        for dev in site_state:
            online = dev.get('online', False)
            msg += f"{'🟢' if online else '🔴'} <b>{dev.get('name', 'Unknown')}</b>\n"
            msg += f"   IP: {dev.get('ip', '')}\n"

            if dev.get('device_info', {}).get('model'):
                msg += f"   მოდელი: {dev['device_info']['model']}\n"
                msg += f"   Firmware: {dev['device_info'].get('firmware', '')}\n"

            if dev.get('uptime'):
                h = dev['uptime'] // 3600
                m = (dev['uptime'] % 3600) // 60
                msg += f"   Uptime: {h} საათი {m} წუთი\n"

            if dev.get('hdds'):
                msg += f"   💾 დისკები:\n"
                for h in dev['hdds']:
                    cap_gb = h.get('capacity_mb', 0) / 1024
                    free_gb = h.get('free_mb', 0) / 1024
                    msg += f"      #{h['id']}: {h.get('status', '?')} — {cap_gb:.0f}GB ({h.get('model', '')})\n"

            if dev.get('cameras'):
                cam_on = sum(1 for c in dev['cameras'] if c.get('online'))
                cam_total = len(dev['cameras'])
                msg += f"   📷 კამერები: {cam_on}/{cam_total} ხელმისაწვდომი\n"
                for c in dev['cameras']:
                    icon = "✅" if c.get('online') else "❌"
                    msg += f"      {icon} CH{c['id']} ({c.get('ip', '')}) — {c.get('status', '')}\n"

            msg += "\n"

        self.send(chat_id, msg)

    def _parse_filter_args(self, text):
        """Parse command args: /logs [device_name] [count]"""
        parts = text.split(None, 1)
        if len(parts) < 2:
            return None, 30

        args = parts[1].strip()

        # Check if it's just a number
        if args.isdigit():
            return None, int(args)

        # Check if last word is a number (count)
        words = args.rsplit(None, 1)
        if len(words) == 2 and words[1].isdigit():
            return words[0], int(words[1])

        return args, 30

    def cmd_logs(self, chat_id, text):
        device_filter, count = self._parse_filter_args(text)
        count = min(count, 100)

        try:
            with open(LOG_PATH) as f:
                lines = f.readlines()

            if device_filter:
                lines = [l for l in lines if device_filter.lower() in l.lower()]

            lines = lines[-count:]

            if lines:
                header = f"📜 <b>ბოლო {len(lines)} ჩანაწერი"
                if device_filter:
                    header += f" ({device_filter})"
                header += ":</b>\n\n<pre>"
                msg = header + ''.join(lines) + "</pre>"
            else:
                msg = f"❌ ჩანაწერები ვერ მოიძებნა."
                if device_filter:
                    msg += f" \"{device_filter}\"-სთვის"
            self.send(chat_id, msg)
        except:
            self.send(chat_id, "❌ ჩანაწერები ვერ მოიძებნა.")

    def cmd_syslog(self, chat_id, text):
        """Show recent syslog entries from syslog.jsonl. Optional: severity filter (crit/warn/err/info) or search term."""
        import json as _json
        from pathlib import Path as _Path
        parts = text.split()[1:]
        severity_filter = None
        search = None
        count = 20
        for p in parts:
            if p in ('crit', 'critical', 'err', 'error', 'warn', 'warning', 'info', 'debug'):
                severity_filter = {'critical': 'crit', 'error': 'err', 'warning': 'warn'}.get(p, p)
            elif p.isdigit():
                count = min(int(p), 50)
            else:
                search = p
        from syslog_collector import LOG_DIR as _SYSLOG_DIR
        entries = []
        # Walk newest → oldest until we have enough matches
        for file in sorted(_SYSLOG_DIR.glob('*.jsonl'), reverse=True):
            with open(file, 'rb') as f:
                f.seek(0, 2)
                size = f.tell()
                pos = max(0, size - 256 * 1024)
                f.seek(pos)
                lines = f.read().decode('utf-8', errors='replace').splitlines()
            file_entries = []
            for line in lines:
                if not line.strip():
                    continue
                try:
                    e = _json.loads(line)
                except _json.JSONDecodeError:
                    continue
                if severity_filter and e.get('severity') != severity_filter:
                    continue
                if search and search.lower() not in (e.get('message') or '').lower():
                    continue
                file_entries.append(e)
            entries = file_entries + entries
            if len(entries) >= count:
                break
        entries = entries[-count:]
        if not entries:
            self.send(chat_id, "❌ syslog ჩანაწერები ვერ მოიძებნა.")
            return
        header = f"📡 <b>syslog — ბოლო {len(entries)}"
        if severity_filter:
            header += f" [{severity_filter}]"
        if search:
            header += f" «{search}»"
        header += "</b>\n\n<pre>"
        formatted = []
        for e in entries:
            ts = (e.get('ts') or '')[-8:]
            dev = e.get('device') or e.get('src') or '?'
            sev = e.get('severity') or '-'
            msg = (e.get('message') or '')[:90]
            formatted.append(f"{ts} [{sev:4}] {dev}: {msg}")
        full = header + '\n'.join(formatted) + "</pre>"
        if len(full) > 4000:
            full = full[:3990] + "…</pre>"
        self.send(chat_id, full)

    def _parse_duration_minutes(self, token):
        """Accept '30m', '2h', '1d', or bare number (minutes). Returns int minutes or None."""
        if not token:
            return None
        token = token.strip().lower()
        try:
            if token.endswith('m'):
                return int(token[:-1])
            if token.endswith('h'):
                return int(token[:-1]) * 60
            if token.endswith('d'):
                return int(token[:-1]) * 60 * 24
            return int(token)
        except ValueError:
            return None

    def _find_site(self, needle):
        """Find a site by name (exact or substring, case-insensitive). Returns (index, site) or (None, None)."""
        cfg = load_config()
        needle = needle.strip().lower()
        for i, s in enumerate(cfg.get('sites', [])):
            if s['name'].lower() == needle:
                return i, s
        for i, s in enumerate(cfg.get('sites', [])):
            if needle in s['name'].lower():
                return i, s
        return None, None

    def _all_nvr_devices(self):
        """Yield (site, device, monitor) for every Hikvision/auto NVR with creds."""
        import devices as _dev
        cfg = load_config()
        for site in cfg.get('sites', []):
            for d in site.get('devices', []):
                if d.get('type') in ('hikvision_nvr', 'auto_nvr') and d.get('password') and d.get('username'):
                    yield site, d, _dev.create_monitor(d)

    def cmd_fixclock(self, chat_id, text):
        """NVR clock auto-fix (human-triggered, admin-only).

          /fixclock                 — list NVRs + drift + opt-in/kill-switch
          /fixclock <name>          — DRY RUN one NVR: show the exact PUT bodies
          /fixclock <name> GO       — LIVE write (NTP) on that one NVR + verify

        Default is always dry-run; nothing writes without the explicit GO token.
        """
        if not self._is_admin_chat(chat_id):
            self.send(chat_id, "❌ მხოლოდ ადმინ ჩატში.")
            return
        import clock_fix as cf
        import devices as _dev

        parts = text.split()
        cfg = load_config()
        kill = cfg.get('clock_fix_enabled', False)

        # No args → status list
        if len(parts) < 2:
            lines = [f"🕐 <b>NVR Clock Fix</b>  (global: {'ON' if kill else 'OFF — set clock_fix_enabled'})\n"]
            for site, d, mon in self._all_nvr_devices():
                if not isinstance(mon, _dev.GenericNVR) and not isinstance(mon, _dev.HikvisionNVR):
                    pass
                uid = f"{d['ip']}:{d.get('port',80)}"
                opt = '✅' if d.get('auto_fix_clock') else '⬜'
                st = cf.get_uid_state(uid)
                done = ' (fixed)' if st.get('verified') else ''
                lines.append(f"{opt} {d['name']} <code>{uid}</code>{done}")
            lines.append("\nგამოყენება: <code>/fixclock NAME</code> (dry-run) → <code>/fixclock NAME GO</code> (live)")
            self.send(chat_id, '\n'.join(lines))
            return

        go = parts[-1].upper() == 'GO'
        query = ' '.join(parts[1:-1]) if go else ' '.join(parts[1:])
        query = query.strip().lower()

        # Match a single NVR by name substring
        match = None
        for site, d, mon in self._all_nvr_devices():
            if query in d['name'].lower():
                if match is not None:
                    self.send(chat_id, f"❌ \"{query}\" ემთხვევა ბევრ NVR-ს. დააკონკრეტე.")
                    return
                match = (site, d, mon)
        if not match:
            self.send(chat_id, f"❌ ვერ ვიპოვე NVR \"{query}\".")
            return
        site, d, mon = match
        uid = f"{d['ip']}:{d.get('port',80)}"

        # Resolve the concrete HikvisionNVR (auto_nvr wraps it in GenericNVR)
        target = mon
        if isinstance(mon, _dev.GenericNVR):
            target = mon._detect()
        if not isinstance(target, _dev.HikvisionNVR):
            self.send(chat_id, f"❌ {d['name']} არ არის Hikvision-თავსებადი (ვერ მოხერხდა აღმოჩენა).")
            return

        # SHARED-IP GUARD: refuse to act if ANY other auth-using device sits behind
        # this public IP. The auth breaker is keyed by BARE IP at threshold 1 and
        # blinds EVERY authenticated request to that IP — regardless of vendor or
        # whether the sibling currently has credentials saved. So count siblings by
        # bare IP across ALL devices that do authenticated polling (any NVR/HTTP-API
        # type), not just credentialed Hikvision ones — otherwise a credential-less
        # sibling (e.g. some NVRs awaiting passwords) is invisible to the
        # guard yet still gets blinded by a write-401.
        AUTH_TYPES = ('hikvision_nvr', 'auto_nvr', 'dahua_nvr', 'uniview_nvr',
                      'hanwha_nvr', 'axis', 'bosch', 'http')
        cfg_all = load_config()
        same_ip_names = [dd['name'] for s2 in cfg_all.get('sites', [])
                         for dd in s2.get('devices', [])
                         if dd.get('ip') == d['ip'] and dd.get('type') in AUTH_TYPES]
        if len(same_ip_names) > 1:
            others = [n for n in same_ip_names if n != d['name']]
            self.send(chat_id, f"⛔ {d['name']} იზიარებს IP-ს <code>{d['ip']}</code>-ს {len(same_ip_names)} მოწყობილობასთან "
                               f"({', '.join(others[:4])}{'…' if len(others)>4 else ''}). "
                               f"გაზიარებულ IP-ზე წერისას ერთი 401 დაბლოკავს ყველა მათგანის მონიტორინგს — "
                               f"უარი ვთქვი უსაფრთხოებისთვის. (გამოიყენე მხოლოდ ცალკე-IP-ზე მყოფ NVR-ზე.)")
            return

        # Read the device's clock so we pick the RIGHT fix (NTP vs DST/timezone).
        snap = target.read_clock_state()
        if not snap:
            self.send(chat_id, f"❌ {d['name']} — ვერ წავიკითხე საათის მდგომარეობა (auth-block ან მიუწვდომელი).")
            return
        mode = (snap.get('timeMode') or '').upper()
        cur_tz = snap.get('timeZone') or ''
        clean_tz = cf.strip_dst(cur_tz)
        needs_tz = clean_tz != cur_tz          # has a DST clause that shouldn't be there
        needs_ntp = mode != 'NTP'

        # NTP server: tunnel-reachable (10.x) → our server; else regional pool.
        if d['ip'].startswith('10.100.') or d['ip'].startswith('10.66.') or d['ip'].startswith('192.168.'):
            ntp_server, addressing = '10.66.66.1', 'ipaddress'
        else:
            ntp_server, addressing = 'ge.pool.ntp.org', 'hostname'

        if not needs_ntp and not needs_tz:
            self.send(chat_id, f"✅ {d['name']} — საათი წესრიგშია (timeMode=NTP, tz=<code>{cur_tz}</code>). არაფერია გასაკეთებელი.")
            return

        action = 'ntp' if needs_ntp else 'timezone'   # NTP fix takes priority if in manual mode

        # ── helper to run + report a result uniformly ──
        def _run(dry):
            if action == 'ntp':
                return target.fix_clock_via_ntp(ntp_server, addressing=addressing, dry_run=dry)
            return target.fix_timezone(clean_tz, dry_run=dry)

        if go:
            if not kill:
                self.send(chat_id, "❌ გლობალური ჩამრთველი გამორთულია. ჯერ: config.json → \"clock_fix_enabled\": true")
                return
            if cf.recently_attempted(uid):
                self.send(chat_id, f"⏳ {d['name']} — ცოტა ხნის წინ უკვე იყო მცდელობა (24სთ დაცვა). გამოტოვება.")
                return
            self.send(chat_id, f"⚙️ <b>{d['name']}</b> — ვწერ ({action}) live…")
            cf.update_uid_state(uid, last_attempt_epoch=time.time())
            res = _run(False)
            cf.log_event({'action': f'fixclock_live_{action}', 'uid': uid, 'site': site['name'],
                          'ntp_server': ntp_server if action == 'ntp' else None, 'new_tz': clean_tz if action == 'timezone' else None,
                          'result_ok': res.get('ok'), 'config_verified': res.get('config_verified'),
                          'skipped': res.get('skipped'), 'error': res.get('error'), 'steps': res.get('steps')})
            # B2 fix: a skip is NOT a successful write.
            if res.get('skipped'):
                self.send(chat_id, f"ℹ️ {d['name']} — ცვლილება საჭირო არ იყო ({res.get('skipped')}). არაფერი დაიწერა.")
                return
            if res.get('ok') and res.get('config_verified'):
                cf.update_uid_state(uid, result=f'{action}_verified', verified=True, written_epoch=time.time())
                after = res.get('after', {})
                if action == 'ntp':
                    self.send(chat_id, f"✅ <b>{d['name']}</b> — NTP ჩაიწერა და დადასტურდა (read-back: timeMode={after.get('timeMode')}).\n"
                                       f"⏱ საათი ფიზიკურად დასინქრონდება ~60 წთ-ში; დრიფტს მონიტორინგი დაიჭერს.\n"
                                       f"🔋 <b>ბატარეა მაინც შესაცვლელია</b> — NTP სიმპტომს ფარავს.")
                else:
                    self.send(chat_id, f"✅ <b>{d['name']}</b> — timezone გასწორდა → <code>{after.get('timeZone')}</code> (read-back დადასტურდა).\n"
                                       f"🕐 localTime ახლა: <code>{after.get('localTime')}</code>")
            else:
                # write failed OR applied-but-not-verified → report honestly, incl. restore status
                extra = ''
                if 'restore_ok' in res:
                    extra = f"\nrestore: {'ok' if res.get('restore_ok') else '⚠️ ALSO FAILED — შესაძლოა ნახევრად ჩაწერილი'}"
                self.send(chat_id, f"❌ <b>{d['name']}</b> — ვერ მოხერხდა/ვერ დადასტურდა.\n<code>{res.get('error')}</code>{extra}")
            return

        # DRY RUN (default) — show exactly what would be sent, write nothing
        self.send(chat_id, f"🔍 <b>{d['name']}</b> <code>{uid}</code> — DRY RUN ({action}, არაფერი იწერება)…")
        res = _run(True)
        cf.log_event({'action': f'fixclock_dryrun_{action}', 'uid': uid, 'site': site['name'],
                      'result_ok': res.get('ok'), 'error': res.get('error')})
        if not res.get('ok'):
            self.send(chat_id, f"❌ dry-run ჩავარდა: <code>{res.get('error')}</code>\nsteps: <code>{res.get('steps')}</code>")
            return
        if res.get('skipped'):
            self.send(chat_id, f"ℹ️ {d['name']} — ცვლილება საჭირო არ არის ({res.get('skipped')}).")
            return
        before = res.get('before', {})
        if action == 'ntp':
            ntp_put = res.get('ntp_put', {}); time_put = res.get('time_put', {})
            bodies = (f"<b>PUT 1</b> <code>{ntp_put.get('path')}</code>\n<pre>{html.escape(ntp_put.get('body',''))}</pre>\n"
                      f"<b>PUT 2</b> <code>{time_put.get('path')}</code>\n<pre>{html.escape(time_put.get('body',''))}</pre>\n")
            head = f"მოქმედება: <b>manual → NTP</b> (<code>{ntp_server}</code>)"
        else:
            time_put = res.get('time_put', {})
            bodies = (f"<b>PUT</b> <code>{time_put.get('path')}</code>\n<pre>{html.escape(time_put.get('body',''))}</pre>\n")
            head = f"მოქმედება: <b>timezone fix</b> — DST მოშორება → <code>{clean_tz}</code> (−1სთ)"
        msg = (
            f"📋 <b>{d['name']}</b> — dry-run:\n{head}\n"
            f"მიმდინარე: timeMode=<code>{before.get('timeMode')}</code> "
            f"localTime=<code>{before.get('localTime')}</code> tz=<code>{before.get('timeZone')}</code>\n\n"
            f"{bodies}"
            f"✅ დასადასტურებლად: <code>/fixclock {d['name']} GO</code>"
        )
        self.send(chat_id, msg)

    def cmd_mute(self, chat_id, text):
        """/mute SITE 1h — suppress all alerts for SITE for the given duration."""
        if not self._is_admin_chat(chat_id):
            self.send(chat_id, "❌ მხოლოდ ადმინ ჩატში.")
            return
        parts = text.split(maxsplit=2)
        if len(parts) < 3:
            self.send(chat_id, "📝 გამოყენება: <code>/mute SITE DURATION</code>\n"
                               "მაგ: <code>/mute SiteA 2h</code> ან <code>/mute SiteA 90m</code>")
            return
        minutes = self._parse_duration_minutes(parts[2])
        if not minutes or minutes < 1 or minutes > 10080:
            self.send(chat_id, "❌ არასწორი ხანგრძლივობა. მიუთითე 15m / 2h / 1d (მაქს 7d).")
            return
        idx, site = self._find_site(parts[1])
        if idx is None:
            self.send(chat_id, f"❌ ვერ ვიპოვე ობიექტი \"{parts[1]}\".")
            return
        cfg = load_config()
        cfg['sites'][idx]['mute_until'] = time.time() + minutes * 60
        save_config(cfg)
        until = datetime.fromtimestamp(cfg['sites'][idx]['mute_until']).strftime('%H:%M %d/%m')
        self.send(chat_id, f"🔕 <b>{site['name']}</b> — დადუმდა {minutes} წუთით\n"
                           f"🕐 აღდგება: {until}")

    def cmd_unmute(self, chat_id, text):
        if not self._is_admin_chat(chat_id):
            self.send(chat_id, "❌ მხოლოდ ადმინ ჩატში.")
            return
        parts = text.split(maxsplit=1)
        if len(parts) < 2:
            self.send(chat_id, "📝 გამოყენება: <code>/unmute SITE</code>")
            return
        idx, site = self._find_site(parts[1])
        if idx is None:
            self.send(chat_id, f"❌ ვერ ვიპოვე ობიექტი \"{parts[1]}\".")
            return
        cfg = load_config()
        cfg['sites'][idx].pop('mute_until', None)
        save_config(cfg)
        self.send(chat_id, f"🔔 <b>{site['name']}</b> — აღდგა შეტყობინებები")

    def cmd_sla(self, chat_id, text):
        """/sla SITE [days=30] — return uptime report."""
        parts = text.split()
        if len(parts) < 2:
            self.send(chat_id, "📝 გამოყენება: <code>/sla SITE [days]</code>\n"
                               "მაგ: <code>/sla SiteA 30</code>")
            return
        site_query = parts[1]
        days = 30
        if len(parts) >= 3:
            try:
                days = max(1, min(int(parts[2]), 365))
            except ValueError:
                pass
        idx, site = self._find_site(site_query)
        if idx is None:
            self.send(chat_id, f"❌ ვერ ვიპოვე ობიექტი \"{site_query}\".")
            return
        from netwatch import compute_sla
        rep = compute_sla(site_name=site['name'], days=days)
        devs = rep.get('devices', {})
        if not devs:
            self.send(chat_id, f"📊 <b>{site['name']}</b> — {days}d\n"
                               f"ინციდენტები არ დაფიქსირდა (ან მონიტორინგი უფრო ახალია).")
            return
        avg_pct = sum(d['uptime_percent'] for d in devs.values()) / len(devs)
        incidents = sum(d['incidents'] for d in devs.values())
        longest = max(d['longest_outage_sec'] for d in devs.values())
        def _fmt(s):
            if s < 60: return f"{s}s"
            if s < 3600: return f"{s//60}m"
            h = s//3600; m = (s % 3600)//60
            return f"{h}h{m}m"
        msg = (f"📊 <b>{site['name']}</b> — ბოლო {days} დღე\n"
               f"━━━━━━━━━━━━━━━━━━━━\n"
               f"🟢 <b>{avg_pct:.2f}%</b> საშუალო uptime\n"
               f"🔴 ინციდენტები: <b>{incidents}</b>\n"
               f"⏱ ყველაზე გრძელი: {_fmt(longest)}\n\n"
               f"<b>მოწყობილობების მიხედვით:</b>\n<pre>")
        for ip, d in sorted(devs.items(), key=lambda kv: kv[1]['uptime_percent']):
            msg += f"{d['name'][:22]:<22} {d['uptime_percent']:6.2f}%  {d['incidents']:>2} inc\n"
        msg += "</pre>"
        self.send(chat_id, msg)

    def cmd_alerts(self, chat_id, text):
        device_filter, count = self._parse_filter_args(text)
        count = min(count, 100)

        try:
            with open(LOG_PATH) as f:
                lines = f.readlines()

            alerts = [l for l in lines if 'ALERT' in l or 'WARNING' in l]

            if device_filter:
                alerts = [l for l in alerts if device_filter.lower() in l.lower()]

            alerts = alerts[-count:]

            if alerts:
                header = f"⚠️ <b>ბოლო {len(alerts)} გაფრთხილება"
                if device_filter:
                    header += f" ({device_filter})"
                header += ":</b>\n\n<pre>"
                msg = header + ''.join(alerts) + "</pre>"
            else:
                msg = "✅ გაფრთხილებები არ მოიძებნა."
                if device_filter:
                    msg += f" \"{device_filter}\"-სთვის"
            self.send(chat_id, msg)
        except:
            self.send(chat_id, "❌ ჩანაწერები ვერ მოიძებნა.")

    def cmd_device_detail(self, chat_id, device_name):
        state = load_state()
        config = load_config()

        # Find device across all sites
        found_dev = None
        found_site = None
        for site in config.get('sites', []):
            site_state = state.get('sites', {}).get(site['name'], [])
            for dev in site_state:
                if dev.get('name', '').lower() == device_name.lower():
                    found_dev = dev
                    found_site = site['name']
                    break
            if found_dev:
                break

        if not found_dev:
            # Try partial match
            for site in config.get('sites', []):
                site_state = state.get('sites', {}).get(site['name'], [])
                for dev in site_state:
                    if device_name.lower() in dev.get('name', '').lower():
                        found_dev = dev
                        found_site = site['name']
                        break
                if found_dev:
                    break

        if not found_dev:
            self.send(chat_id, f"❌ მოწყობილობა \"{device_name}\" ვერ მოიძებნა.")
            return

        online = found_dev.get('online', False)
        msg = f"{'🟢' if online else '🔴'} <b>{found_dev.get('name')}</b>\n"
        msg += f"🏢 ობიექტი: {found_site}\n"
        msg += f"{'─' * 25}\n\n"
        msg += f"📍 IP: {found_dev.get('ip')}\n"
        msg += f"📶 მდგომარეობა: {'ხელმისაწვდომი' if online else 'მიუწვდომელი'}\n"

        if found_dev.get('device_info', {}).get('model'):
            msg += f"\n📱 <b>მოწყობილობის ინფო:</b>\n"
            msg += f"   მოდელი: {found_dev['device_info']['model']}\n"
            msg += f"   Firmware: {found_dev['device_info'].get('firmware', '?')}\n"
            msg += f"   სერიალი: {found_dev['device_info'].get('serial', '?')}\n"

        if found_dev.get('uptime') is not None:
            d = found_dev['uptime'] // 86400
            h = (found_dev['uptime'] % 86400) // 3600
            m = (found_dev['uptime'] % 3600) // 60
            msg += f"\n⏱ <b>Uptime:</b> {d} დღე {h} საათი {m} წუთი\n"

        if found_dev.get('hdds'):
            msg += f"\n💾 <b>დისკები ({len(found_dev['hdds'])}):</b>\n"
            for h in found_dev['hdds']:
                cap_gb = h.get('capacity_mb', 0) / 1024
                free_gb = h.get('free_mb', 0) / 1024
                used_pct = ((cap_gb - free_gb) / cap_gb * 100) if cap_gb > 0 else 0
                status_icon = "✅" if h.get('status', '').lower() in ('ok', 'normal') else "⚠️"
                msg += f"   {status_icon} #{h['id']}: {h.get('status')} — {cap_gb:.0f}GB ({h.get('model', '')})\n"
                msg += f"      თავისუფალი: {free_gb:.0f}GB | გამოყენებული: {used_pct:.0f}%\n"

        if found_dev.get('cameras'):
            cam_on = sum(1 for c in found_dev['cameras'] if c.get('online'))
            cam_total = len(found_dev['cameras'])
            msg += f"\n📷 <b>კამერები ({cam_on}/{cam_total} ხელმისაწვდომი):</b>\n"
            for c in found_dev['cameras']:
                icon = "✅" if c.get('online') else "❌"
                msg += f"   {icon} CH{c['id']} — {c.get('ip', '?')} — {c.get('status', '?')}\n"

        # Recent alerts for this device
        try:
            with open(LOG_PATH) as f:
                lines = f.readlines()
            dev_alerts = [l for l in lines if ('ALERT' in l or 'WARNING' in l) and found_dev.get('ip', 'xxx') in l][-5:]
            if dev_alerts:
                msg += f"\n⚠️ <b>ბოლო გაფრთხილებები:</b>\n<pre>"
                msg += ''.join(dev_alerts)
                msg += "</pre>"
        except:
            pass

        self.send(chat_id, msg)

    def send_hourly_report(self):
        """Send a clean site overview to the main chat."""
        state = load_state()
        config = load_config()
        now = datetime.now().strftime('%Y-%m-%d %H:%M')

        # Build per-site reports
        full_msg = f"📊 <b>NetWatch — {now}</b>\n{'─' * 28}\n\n"

        for site in config.get('sites', []):
            site_name = site['name']
            site_chat_id = site.get('telegram_chat_id', '')
            site_state = state.get('sites', {}).get(site_name, [])
            if not site_state:
                continue

            online = sum(1 for d in site_state if d.get('online'))
            total = len(site_state)

            if online == total:
                icon = "🟢"
                status_text = "All OK"
            elif online == 0:
                icon = "🔴"
                status_text = "ALL DOWN"
            else:
                icon = "🟡"
                status_text = f"{total - online} issue(s)"

            site_msg = f"{icon} <b>{site_name}</b> — {status_text}\n"

            for dev in site_state:
                s_icon = "✅" if dev.get('online') else "❌"
                name = dev.get('name', '?')
                parts = []

                if dev.get('device_info', {}).get('model'):
                    parts.append(dev['device_info']['model'])
                if dev.get('uptime'):
                    d = dev['uptime'] // 86400
                    h = (dev['uptime'] % 86400) // 3600
                    if d > 0:
                        parts.append(f"Up {d}d {h}h")
                    else:
                        parts.append(f"Up {h}h")
                if dev.get('cameras'):
                    cam_on = sum(1 for c in dev['cameras'] if c.get('online'))
                    cam_total = len(dev['cameras'])
                    parts.append(f"📷 {cam_on}/{cam_total}")
                if dev.get('hdds'):
                    bad = [h for h in dev['hdds'] if h.get('status', '').lower() not in ('ok', 'normal')]
                    if bad:
                        parts.append(f"💾 ⚠️ {len(bad)} HDD issue(s)")
                    else:
                        parts.append(f"💾 {len(dev['hdds'])} OK")

                detail = ' · '.join(parts) if parts else ''
                site_msg += f"  {s_icon} {name}"
                if detail:
                    site_msg += f"\n       {detail}"
                site_msg += "\n"

            # Add to full report for main chat
            full_msg += site_msg + "\n"

            # Periodic status reports go ONLY to the admin chat. Client site chats
            # receive messages only when something goes wrong (handled by alert_mgr
            # in netwatch.py — device offline, HDD fail, recording stopped, etc).
            # All-OK pings would be noise for clients.

        # Send full report to main admin chat
        self.send(self.chat_id, full_msg)

    def cmd_scansubnets(self, chat_id, user_id):
        """List every scannable NAT subnet across VPN sites (one entry per nat_mapping,
        with live connected status from wg show wg0)."""
        if not self._is_admin_chat(chat_id):
            return
        if not self._is_authorized(user_id):
            self.send(chat_id, "❌ არ გაქვს ამ ბრძანების გამოყენების უფლება.")
            return

        from vpn import get_site_status
        vpn_data = get_site_status()

        # Flatten to one row per scannable NAT subnet — prefer nat_mappings, fall back
        # to legacy nat_subnet.
        scannable = []
        for s in vpn_data.get('sites', []):
            mappings = s.get('nat_mappings') or []
            seen_nats = set()
            if mappings:
                for m in mappings:
                    nat = m.get('nat')
                    if not nat or nat in seen_nats:
                        continue
                    seen_nats.add(nat)
                    label = s['name']
                    if m.get('interface') and m['interface'] != 'legacy':
                        label += f" / {m['interface']}"
                    scannable.append({
                        'label': label,
                        'nat_subnet': nat,
                        'local_subnet': m.get('local') or '',
                        'connected': s.get('connected', False),
                    })
            if s.get('nat_subnet') and s['nat_subnet'] not in seen_nats:
                scannable.append({
                    'label': s['name'],
                    'nat_subnet': s['nat_subnet'],
                    'local_subnet': (s.get('subnets') or [''])[0],
                    'connected': s.get('connected', False),
                })

        if not scannable:
            self.send(chat_id, "❌ არ არის VPN ობიექტი NAT ქვექსელით. ჯერ შექმენი VPN ობიექტი /newclient-ით.")
            return

        menu = "🔍 <b>რომელი ქვექსელი გავასკანერიროთ?</b>\n\n"
        for i, item in enumerate(scannable, 1):
            dot = "🟢" if item['connected'] else "🔴"
            local = f" ← <code>{item['local_subnet']}</code>" if item['local_subnet'] else ''
            menu += f"  <b>{i}.</b> {dot} {item['label']} — <code>{item['nat_subnet']}</code>{local}\n"
        menu += "\nჩაწერე ნომერი (ან /cancel გასაუქმებლად):"

        self._conversations[user_id] = {'flow': 'scansubnets', 'step': 'pick_site', 'data': {'scannable': scannable}}
        self.send(chat_id, menu)

    def _run_subnet_scan(self, chat_id, site):
        """Run quick scan against site's NAT subnet and report results."""
        nat_subnet = site['nat_subnet']
        # Accept either 'label' (new flat format) or 'name' (legacy) for backward compat
        name = site.get('label') or site.get('name') or '?'
        self.send(chat_id, f"⏳ სკანირება: <b>{name}</b> — <code>{nat_subnet}</code>...\n(შეიძლება ~30-60 წამი დასჭირდეს)")

        try:
            from scanner import quick_scan
            result = quick_scan(nat_subnet)
            devices = result.get('devices', []) if isinstance(result, dict) else []
        except Exception as e:
            self.send(chat_id, f"❌ სკანირების შეცდომა: {e}")
            return

        if not devices:
            self.send(chat_id, f"⚠️ ქვექსელში <code>{nat_subnet}</code> არაფერი ვიპოვე.\n\n"
                               f"შეამოწმე:\n"
                               f"• ტუნელი ცოცხალია თუ არა\n"
                               f"• MikroTik NAT წესები მართებულია\n"
                               f"• კლიენტის LAN-ში ცოცხალი ჰოსტებია")
            return

        msg = f"✅ <b>{name}</b> — {len(devices)} ცოცხალი ჰოსტი\n"
        msg += f"ქვექსელი: <code>{nat_subnet}</code>\n{'─' * 25}\n\n"
        for d in devices:
            ip = d.get('ip', '?')
            brand = d.get('brand') or ''
            dtype = d.get('device_type', 'unknown')
            mac = d.get('mac', '')
            # Make IP clickable — opens http://IP on the device that taps it.
            # Works if the viewer has network routing to NAT subnet (LAN or Tailscale with subnet routes).
            line = f"• <a href=\"http://{ip}\">{ip}</a>"
            if brand:
                line += f" — {brand}"
            if dtype and dtype != 'unknown':
                line += f" ({dtype})"
            if mac:
                line += f"\n    MAC: <code>{mac}</code>"
            msg += line + "\n"

        # Telegram message length limit is 4096; chunk if needed
        if len(msg) > 3800:
            chunks = []
            cur = f"✅ <b>{name}</b> — {len(devices)} ცოცხალი ჰოსტი\n{'─' * 25}\n"
            for d in devices:
                line = f"• <code>{d.get('ip','?')}</code>"
                if d.get('brand'): line += f" — {d['brand']}"
                if d.get('mac'): line += f" [{d['mac']}]"
                line += "\n"
                if len(cur) + len(line) > 3800:
                    chunks.append(cur)
                    cur = ""
                cur += line
            if cur:
                chunks.append(cur)
            for c in chunks:
                self.send(chat_id, c)
        else:
            self.send(chat_id, msg)

    def cmd_discover(self, chat_id, user_id):
        """Start discovery flow — pick a connected VPN site, enter admin password,
        bot SSHs in, finds LAN subnets, asks user to confirm auto-configuring netmap."""
        if not self._is_admin_chat(chat_id):
            return
        if not self._is_authorized(user_id):
            self.send(chat_id, "❌ არ გაქვს ამ ბრძანების გამოყენების უფლება.")
            return

        from vpn import get_site_status
        data = get_site_status()
        # Only MikroTik sites — RouterOS-specific CLI is required for discovery
        online = [s for s in data.get('sites', [])
                  if s.get('connected') and s.get('router_brand', '').lower() == 'mikrotik']
        if not online:
            non_mt = [s for s in data.get('sites', [])
                      if s.get('connected') and s.get('router_brand', '').lower() != 'mikrotik']
            if non_mt:
                self.send(chat_id, "❌ /discover მხოლოდ MikroTik-ზე მუშაობს. სხვა ბრენდები ჯერ არ არის მხარდაჭერილი.")
            else:
                self.send(chat_id, "❌ ონლაინ MikroTik ობიექტი არ არის. ჯერ ჩართე MikroTik და დარწმუნდი, რომ ტუნელი მუშაობს.")
            return

        menu = "🔎 <b>ქვექსელების აღმოჩენა</b>\n\nრომელ ობიექტზე?\n\n"
        for i, s in enumerate(online, 1):
            lock = " 🔑" if s.get('admin_password') else ""
            menu += f"  <b>{i}.</b> 🟢 {s['name']} — <code>{s['client_ip']}</code>{lock}\n"
        menu += "\nჩაწერე ნომერი (ან /cancel):"
        self._conversations[user_id] = {'flow': 'discover', 'step': 'pick_site',
                                        'data': {'online': online}}
        self.send(chat_id, menu)

    def _run_discover(self, chat_id, user_id, site, password):
        """Background: SSH to MikroTik, discover LAN subnets, then preview the
        add/keep/remove plan and prompt user to apply."""
        from vpn import discover_subnets, classify_subnets, load_vpn_sites
        self.send(chat_id, f"⏳ ვუკავშირდები MikroTik-ს (<code>{site['client_ip']}</code>)...")
        subnets, err = discover_subnets(site['client_ip'], password)
        if err:
            self._conversations.pop(user_id, None)
            self.send(chat_id, f"❌ შეცდომა: <code>{err}</code>\n\nშეამოწმე პაროლი და ტუნელი.")
            return
        if not subnets:
            self._conversations.pop(user_id, None)
            self.send(chat_id, f"⚠️ <b>{site['name']}</b>-ზე LAN ქვექსელი ვერ ვიპოვე.\n\n"
                               f"სხვა ინტერფეისებზე სტატიკური IP არ არის — ყველაფერი WAN-ზე ან ბრიჯშია.")
            return

        plan = classify_subnets(site['name'], subnets)
        if plan is None:
            self._conversations.pop(user_id, None)
            self.send(chat_id, "❌ ობიექტი ვერ ვიპოვე vpn_sites.json-ში.")
            return

        vpn_data = load_vpn_sites()
        next_nat_id = vpn_data.get('next_nat_id', 1)

        msg = f"🔍 <b>{site['name']}</b>\n\n"
        if plan['additions']:
            msg += f"➕ <b>დაემატება ({len(plan['additions'])}):</b>\n"
            for i, s in enumerate(plan['additions']):
                nat = f"10.100.{next_nat_id + i}.0/24"
                msg += f"  <code>{s['subnet']}</code> ({s['interface']}) → <code>{nat}</code>\n"
            msg += "\n"
        if plan['keepers']:
            msg += f"✓ <b>უცვლელად ({len(plan['keepers'])}):</b>\n"
            for m in plan['keepers']:
                msg += f"  <code>{m.get('local')}</code> → <code>{m.get('nat')}</code>\n"
            msg += "\n"
        if plan['stales']:
            msg += f"🗑 <b>წაიშლება ({len(plan['stales'])}) — ინტერფეისზე აღარ არის:</b>\n"
            for m in plan['stales']:
                msg += f"  <code>{m.get('local')}</code> → <code>{m.get('nat')}</code>\n"
            msg += "\n"

        if not plan['additions'] and not plan['stales']:
            self._conversations.pop(user_id, None)
            self.send(chat_id, msg + "✅ უკვე სინქრონიზირებულია — არაფერი საცვლელი.")
            return

        msg += "<b>რა გავაკეთო?</b>\n"
        msg += "  <b>1.</b> ✅ მომარჯებულად (დაამატე ახლები, წაშალე ძველები)\n"
        msg += "  <b>2.</b> ➕ მხოლოდ ახლები დაემატოს (ძველები დარჩეს)\n"
        msg += "  <b>3.</b> ❌ არა — გააუქმე\n\nჩაწერე ნომერი:"

        self._conversations[user_id] = {
            'flow': 'discover', 'step': 'confirm_apply',
            'data': {'site': site, 'subnets': subnets, 'password': password, 'plan': plan}
        }
        self.send(chat_id, msg)

    def _apply_discover(self, chat_id, site, subnets, password, remove_stale=False):
        """Background: run auto_configure_netmap and report add/remove result."""
        from vpn import auto_configure_netmap
        mode = "ავტო-სინქი" if remove_stale else "მხოლოდ დამატება"
        self.send(chat_id, f"⏳ ვმუშაობ ({mode})...")
        result, err = auto_configure_netmap(site['name'], subnets, password, remove_stale=remove_stale)
        additions = result.get('additions') or []
        removed = result.get('removed') or []
        if err and not additions and not removed:
            self.send(chat_id, f"❌ შეცდომა: <code>{err}</code>")
            return
        if not additions and not removed:
            self.send(chat_id, "✅ უკვე სინქრონიზირებულია — არაფერი არ შეცვლილა.")
            return
        msg = "✅ <b>შესრულდა!</b>\n\n"
        if additions:
            msg += f"➕ <b>დაემატა ({len(additions)}):</b>\n"
            for a in additions:
                msg += f"  <code>{a['subnet']}</code> ({a['interface']}) → <code>{a['nat_subnet']}</code>\n"
            msg += "\n"
        if removed:
            msg += f"🗑 <b>წაიშალა ({len(removed)}):</b>\n"
            for r in removed:
                msg += f"  <code>{r.get('local')}</code> → <code>{r.get('nat')}</code>\n"
            msg += "\n"
        if err:
            msg += f"⚠️ <i>{err}</i>\n"
        msg += "💡 ახლა შეგიძლია ქვექსელის სკანირება: /scansubnets"
        self.send(chat_id, msg)

    def cmd_harden(self, chat_id, user_id):
        """Start hardening flow — pick a deployed MikroTik site, enter admin password,
        bot locks the device down (SSH/WinBox tunnel-only, input drop, services disabled).

        Should be run AFTER /discover has configured real client subnets and the
        device is at its final location."""
        if not self._is_admin_chat(chat_id):
            return
        if not self._is_authorized(user_id):
            self.send(chat_id, "❌ არ გაქვს ამ ბრძანების გამოყენების უფლება.")
            return

        from vpn import get_site_status
        data = get_site_status()
        online = [s for s in data.get('sites', [])
                  if s.get('connected') and s.get('router_brand', '').lower() == 'mikrotik']
        if not online:
            self.send(chat_id, "❌ არ არის ონლაინ MikroTik ობიექტი.")
            return

        menu = ("🔐 <b>MikroTik უსაფრთხოდ ჩაკეტვა</b>\n\n"
                "⚠️ <b>ყურადღება:</b> ამის შემდეგ მხოლოდ ტუნელის IP-ით (10.66.66.1)-დან "
                "შეძლებ SSH/WinBox-ით შესვლას. LAN-იდან წვდომა დაიბლოკება.\n\n"
                "გაუშვი მხოლოდ მას მერე, რაც:\n"
                "  ✓ მოწყობილობა საბოლოო ადგილზეა\n"
                "  ✓ /discover-ი გაკეთდა\n"
                "  ✓ ტუნელი მუშაობს\n\n"
                "რომელი ობიექტი ჩავკეტო?\n\n")
        for i, s in enumerate(online, 1):
            already = " 🔒 (უკვე ჩაკეტილი)" if s.get('hardened') else ""
            menu += f"  <b>{i}.</b> 🟢 {s['name']} — <code>{s['client_ip']}</code>{already}\n"
        menu += "\nჩაწერე ნომერი (ან /cancel):"

        self._conversations[user_id] = {'flow': 'harden', 'step': 'pick_site',
                                        'data': {'online': online}}
        self.send(chat_id, menu)

    def _run_harden(self, chat_id, user_id, site, password):
        """Background: push hardening commands to MikroTik via SSH."""
        from vpn import harden_mikrotik
        self.send(chat_id, f"⏳ ვამყარებ უსაფრთხოებას <b>{site['name']}</b>-ზე...")
        applied, err = harden_mikrotik(site['name'], password)
        if err:
            self.send(chat_id, f"❌ შეცდომა: <code>{err}</code>\n\nშეამოწმე პაროლი და ტუნელი.")
            return
        msg = (f"🔐 <b>{site['name']}</b> ჩაკეტილია!\n\n"
               f"გატარდა {len(applied)} ბრძანება:\n"
               f"  ✓ SSH/WinBox მხოლოდ ტუნელიდან (10.66.66.1)\n"
               f"  ✓ API/WWW/Telnet/FTP გამორთულია\n"
               f"  ✓ Input firewall drops everything except tunnel\n"
               f"  ✓ MAC-server გამორთულია ყველა ინტერფეისზე\n\n"
               f"⚠️ ახლა LAN-იდან ამ MikroTik-ს ვერ მიუდგები — მხოლოდ ტუნელის გავლით.")
        self.send(chat_id, msg)

    def vpn_watch_loop(self):
        """Detect newly-online VPN peers (pre-staged MikroTiks plugged in for the first time)
        and notify admin chat. Tracks state in memory; transitions offline→online for an
        unlinked site fire a notification."""
        from vpn import get_site_status
        previously_online = set()
        # Seed with currently-online so we don't dump everything on first run
        try:
            seed = get_site_status()
            for s in seed.get('sites', []):
                if s.get('connected'):
                    previously_online.add(s['client_public_key'])
        except Exception:
            pass

        while True:
            try:
                time.sleep(30)
                cfg = load_config()
                monitored = {s['name'].lower() for s in cfg.get('sites', [])}
                vpn_data = get_site_status()
                now_online = set()
                for s in vpn_data.get('sites', []):
                    pk = s.get('client_public_key')
                    if not pk:
                        continue
                    if s.get('connected'):
                        now_online.add(pk)
                        # Newly-online + not linked to monitoring → notify
                        if pk not in previously_online and s['name'].lower() not in monitored:
                            sub = s.get('nat_subnet', '')
                            sub_line = f"\n🌐 NAT ქვექსელი: <code>{sub}</code>" if sub else ""
                            msg = (
                                f"🟢 <b>ახალი VPN ობიექტი ონლაინია!</b>\n"
                                f"━━━━━━━━━━━━━━━━━━━━━━━━━\n"
                                f"📛 სახელი: <b>{s['name']}</b>\n"
                                f"🔐 VPN IP: <code>{s.get('client_ip','?')}</code>{sub_line}\n\n"
                                f"💡 დაამატე მონიტორინგში: /newclient"
                            )
                            try:
                                self.send(self.chat_id, msg)
                            except Exception as e:
                                print(f"vpn_watch notify error: {e}")
                previously_online = now_online
            except Exception as e:
                print(f"vpn_watch error: {e}")
                time.sleep(60)

    # =================================================================
    # Monthly SLA report — calendar-month uptime sent to each client chat
    # =================================================================

    MONTHLY_STATE_PATH = Path(__file__).parent / '.monthly_report_state.json'

    _MONTH_NAMES_KA = [
        '', 'იანვარი', 'თებერვალი', 'მარტი', 'აპრილი', 'მაისი', 'ივნისი',
        'ივლისი', 'აგვისტო', 'სექტემბერი', 'ოქტომბერი', 'ნოემბერი', 'დეკემბერი',
    ]

    def _load_monthly_state(self):
        try:
            with open(self.MONTHLY_STATE_PATH) as f:
                return json.load(f)
        except (FileNotFoundError, json.JSONDecodeError):
            return {}

    def _save_monthly_state(self, state):
        try:
            with open(self.MONTHLY_STATE_PATH, 'w') as f:
                json.dump(state, f)
        except OSError as e:
            print(f"monthly state write failed: {e}")

    def _format_duration_short(self, sec):
        if sec < 60:
            return f"{int(sec)}s"
        if sec < 3600:
            return f"{int(sec // 60)}m"
        h = int(sec // 3600)
        m = int((sec % 3600) // 60)
        return f"{h}h {m}m" if m else f"{h}h"

    def build_monthly_report(self, site, year, month):
        """Build a Telegram-ready monthly SLA report for one site, or None if empty."""
        from datetime import datetime as _dt
        from calendar import monthrange
        from netwatch import compute_sla

        start = _dt(year, month, 1, 0, 0, 0)
        last_day = monthrange(year, month)[1]
        end = _dt(year, month, last_day, 23, 59, 59)
        rep = compute_sla(
            site_name=site['name'],
            start_ts=start.timestamp(),
            end_ts=end.timestamp(),
        )
        devs = rep.get('devices', {})

        month_label = f"{self._MONTH_NAMES_KA[month]} {year}"

        if not devs:
            return (
                f"📊 <b>{site['name']}</b>\n"
                f"📅 {month_label} — ყოველთვიური რეპორტი\n"
                f"━━━━━━━━━━━━━━━━━━━━\n"
                f"🟢 100.00% uptime — ინციდენტები არ დაფიქსირდა\n\n"
                f"<i>ყოველი მოწყობილობა მთელი თვის განმავლობაში ხელმისაწვდომი იყო.</i>"
            )

        avg_pct = sum(d['uptime_percent'] for d in devs.values()) / len(devs)
        total_inc = sum(d['incidents'] for d in devs.values())
        longest = max(d['longest_outage_sec'] for d in devs.values())
        total_down = sum(d['total_outage_sec'] for d in devs.values())

        if avg_pct >= 99.5:
            banner = '🟢'
        elif avg_pct >= 98:
            banner = '🟡'
        else:
            banner = '🔴'

        header = (
            f"📊 <b>{site['name']}</b>\n"
            f"📅 {month_label} — ყოველთვიური რეპორტი\n"
            f"━━━━━━━━━━━━━━━━━━━━\n"
            f"{banner} საერთო uptime: <b>{avg_pct:.2f}%</b>\n"
            f"🔴 ინციდენტები: <b>{total_inc}</b>\n"
            f"⏱ ყველაზე გრძელი გათიშვა: {self._format_duration_short(longest)}\n"
            f"📉 ჯამში გათიშული: {self._format_duration_short(total_down)}\n\n"
            f"<b>მოწყობილობების მიხედვით:</b>\n<pre>"
        )
        body = ''
        for ip, d in sorted(devs.items(), key=lambda kv: kv[1]['uptime_percent']):
            body += f"{d['name'][:22]:<22} {d['uptime_percent']:6.2f}%  {d['incidents']:>2}\n"
        return header + body + "</pre>"

    def send_monthly_reports(self, year, month):
        """Run once per month: generate + send reports for every configured site."""
        cfg = load_config()
        sent_to_admin = False
        for site in cfg.get('sites', []):
            try:
                msg = self.build_monthly_report(site, year, month)
                if not msg:
                    continue
                # Client chat gets their own report (if configured)
                client_chat = site.get('telegram_chat_id', '')
                if client_chat:
                    self._send_to(client_chat, msg)
                # Admin gets every site's report too
                self.send(self.chat_id, msg)
                sent_to_admin = True
            except Exception as e:
                print(f"monthly report failed for {site.get('name','?')}: {e}")
        if sent_to_admin:
            print(f"Monthly reports sent for {year}-{month:02d}")

    def monthly_report_loop(self):
        """Fires once per calendar month on the 1st at 09:00 local. Covers prior month.

        Survives restarts: uses a state file ({"last_sent": "YYYY-MM"}) so we never
        double-send and never miss a month. Polls every 30 min.
        """
        from datetime import datetime as _dt
        while True:
            try:
                now = _dt.now()
                # Determine which month we'd be reporting on (previous full month)
                if now.month == 1:
                    report_year, report_month = now.year - 1, 12
                else:
                    report_year, report_month = now.year, now.month - 1
                key = f"{report_year:04d}-{report_month:02d}"

                state = self._load_monthly_state()
                already_sent = state.get('last_sent') == key

                # Fire only on/after 09:00 on the 1st (or later if we were down)
                should_fire = (
                    not already_sent
                    and (now.day > 1 or (now.day == 1 and now.hour >= 9))
                )
                if should_fire:
                    self.send_monthly_reports(report_year, report_month)
                    state['last_sent'] = key
                    self._save_monthly_state(state)
            except Exception as e:
                print(f"monthly report loop error: {e}")
            time.sleep(1800)  # check twice an hour — cheap

    def cmd_monthlyreport(self, chat_id, text):
        """/monthlyreport [SITE] [YYYY-MM] — manual trigger for testing or re-sending.
        Always replies to the invoking chat only. Does NOT update last_sent state."""
        if not self._is_admin_chat(chat_id):
            self.send(chat_id, "❌ მხოლოდ ადმინ ჩატში.")
            return
        parts = text.split()
        from datetime import datetime as _dt
        now = _dt.now()
        # Default: last full month
        if now.month == 1:
            year, month = now.year - 1, 12
        else:
            year, month = now.year, now.month - 1
        site_filter = None
        for tok in parts[1:]:
            if '-' in tok and len(tok) == 7:
                try:
                    year, month = map(int, tok.split('-'))
                except ValueError:
                    pass
            else:
                site_filter = tok
        cfg = load_config()
        sites = cfg.get('sites', [])
        if site_filter:
            idx, site = self._find_site(site_filter)
            if idx is None:
                self.send(chat_id, f"❌ ვერ ვიპოვე ობიექტი \"{site_filter}\".")
                return
            sites = [site]
        for site in sites:
            try:
                msg = self.build_monthly_report(site, year, month)
                if msg:
                    self.send(chat_id, msg)
            except Exception as e:
                self.send(chat_id, f"❌ {site.get('name','?')}: {e}")

    def run(self):
        print("NetWatch Bot listening for commands...")

        # Start VPN watch thread (detect newly-online pre-staged routers)
        threading.Thread(target=self.vpn_watch_loop, daemon=True).start()

        # Periodic status report — every 4 hours on the 4-hour marks
        # (00:00, 04:00, 08:00, 12:00, 16:00, 20:00 local time)
        def periodic_report_loop():
            from datetime import timedelta
            while True:
                try:
                    now = datetime.now()
                    # Round down to the current hour, then advance to the next 4-hour mark
                    base = now.replace(minute=0, second=0, microsecond=0)
                    next_hr = base.hour - (base.hour % 4) + 4  # 0→4, 1→4, 4→8, 5→8, ...
                    if next_hr >= 24:
                        next_slot = base.replace(hour=0) + timedelta(days=1)
                    else:
                        next_slot = base.replace(hour=next_hr)
                    wait = (next_slot - now).total_seconds()
                    time.sleep(wait)
                    self.send_hourly_report()
                except Exception as e:
                    print(f"Periodic report error: {e}")
                    time.sleep(60)

        t = threading.Thread(target=periodic_report_loop, daemon=True)
        t.start()

        # Monthly SLA report — first of each month at 09:00 local time,
        # covering the previous full calendar month.
        threading.Thread(target=self.monthly_report_loop, daemon=True).start()

        while True:
            try:
                updates = self.get_updates()
                for update in updates:
                    self.last_update_id = update['update_id']
                    if 'message' in update and 'text' in update['message']:
                        self.handle_message(update['message'])
            except Exception as e:
                print(f"Bot error: {e}")
                time.sleep(5)


if __name__ == '__main__':
    bot = NetWatchBot()
    bot.run()
