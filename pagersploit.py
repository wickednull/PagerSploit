#!/usr/bin/env python3
"""
PagerSploit v2.9.1 - Stability Edition
Thread-Safe Hardware Access for WiFi Pineapple Pager
"""

import os, sys, json, re, time, threading, subprocess, argparse
import socket, base64, urllib.request, urllib.parse, shutil
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse, unquote_plus

# ── Global State & Locks ──────────────────────────────────────────────────
STATE = {
    'active_module': 'idle', 'module_status': 'Standing by',
    'loot_count': 0, 'server_ip': '172.16.52.1', 'server_port': '8080',
    'payload_dir': '', 'log': [], 'scan_results': [], 'hosts': [],
    'jobs': {}, 'stop_events': {}, 'module_data': {},
    'cwd': os.getcwd(),
}
STATE_LOCK = threading.Lock()
HW_LOCK = threading.Lock() # CRITICAL: Prevents kernel panic on dual hardware access

# Lazy imports for stability
try: import sqlite3
except ImportError: sqlite3 = None

try: 
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from pagerctl import Pager
except ImportError: Pager = None

# Standard paths
RECON_DB = '/etc/pineapple/recon.db'
PINEAP_FUNCTIONS = '/etc/pineapple/functions'

def log(msg, level='info'):
    entry = {'time': datetime.now().strftime('%H:%M:%S'), 'level': level, 'msg': str(msg)}
    with STATE_LOCK:
        STATE['log'].append(entry)
        if len(STATE['log']) > 100: STATE['log'] = STATE['log'][-100:]
    print(f"[{entry['time']}] {msg}", flush=True)

def set_module(name, status='Running'):
    with STATE_LOCK:
        STATE['active_module'] = name
        STATE['module_status'] = status

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

def loot_path(*parts): return os.path.join(STATE['payload_dir'], 'loot', *parts)

def save_loot(subdir, filename, content):
    path = loot_path(subdir, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb' if isinstance(content, bytes) else 'w') as f: f.write(content)
    with STATE_LOCK: STATE['loot_count'] += 1
    return path

def _pineapple(*args):
    cmd_str = ' '.join(f'"{a}"' for a in args)
    full_cmd = f'source {PINEAP_FUNCTIONS} && {cmd_str}'
    try:
        r = subprocess.run(['bash', '-c', full_cmd], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return ''

# ── Hardware Feedback (Thread-Safe) ───────────────────────────────────────

def alert_success(p_instance=None):
    """Vibrate and Flash LED. Use existing Pager instance if available."""
    def _do_alert(p):
        try:
            p.set_led(0, 255, 0); p.set_vibration(True)
            time.sleep(0.3)
            p.set_vibration(False); p.set_led(0, 0, 0)
        except: pass

    if p_instance:
        _do_alert(p_instance)
    else:
        # If no instance provided, we must lock and open a temporary one
        if not Pager: return
        with HW_LOCK:
            try:
                with Pager() as p: _do_alert(p)
            except: pass

# ── WiFi Core (Native) ────────────────────────────────────────────────────

def wifi_scan(band='abg', duration=5):
    log(f'WiFi scan ({band})...'); set_module('WiFi Scan', 'Scanning...')
    _pineapple('PINEAPPLE_RECON_START')
    time.sleep(int(duration))
    results = []
    if not sqlite3: return []
    try:
        conn = sqlite3.connect(f'file:{RECON_DB}?mode=ro', uri=True)
        cur = conn.cursor()
        cur.execute("SELECT ssid, mac, channel, signal, encryption FROM wifi_ap_view ORDER BY signal DESC LIMIT 50")
        for row in cur.fetchall():
            ssid, bssid, channel, signal, encryption = row
            results.append({'ssid': ssid or '<hidden>', 'bssid': bssid.upper(), 'channel': int(channel), 
                           'signal': int(signal), 'encryption': str(encryption)})
        conn.close()
    except Exception as e: log(f'Scan error: {e}', 'error')
    with STATE_LOCK: STATE['scan_results'] = results
    set_module('idle', f'{len(results)} APs'); return results

# ── API Handler (Standard/Lean) ───────────────────────────────────────────

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
        elif p == '/api/state':
            with STATE_LOCK: s = {k: v for k, v in STATE.items() if k != 'module_data'}; s['jobs'] = list(STATE['jobs'].keys())
            self.send_json(s)
        elif p == '/api/log':
            with STATE_LOCK: self.send_json(STATE['log'])
        elif p == '/api/scans':
            with STATE_LOCK: self.send_json(STATE['scan_results'])
        else: self.send_json({'error': 'not found'}, 404)

    def do_POST(self):
        p = urlparse(self.path).path; length = int(self.headers.get('Content-Length', 0))
        b = json.loads(self.rfile.read(length).decode('utf-8', errors='ignore')) if length else {}
        
        if p == '/api/wifi/scan': start_job('wifi_scan', wifi_scan, b.get('band', 'abg'))
        elif p == '/api/wifi/deauth': 
            _pineapple('PINEAPPLE_DEAUTH_CLIENT', b.get('bssid'), 'FF:FF:FF:FF:FF:FF', str(b.get('channel', '6')))
        elif p == '/api/stop_all':
            with STATE_LOCK:
                for ev in STATE['stop_events'].values(): ev.set()
            self.send_json({'status': 'stopped'}); return
        self.send_json({'status': 'started'})

# ── Pager Display (Locked) ────────────────────────────────────────────────

def rgb(r, g, b): return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
C_BG, C_TITLE, C_GREEN = rgb(4, 4, 12), rgb(0, 255, 180), rgb(0, 255, 80)

def pager_display_loop(p, stop_event):
    p.set_rotation(270); BTN_B = Pager.BTN_B
    while not stop_event.is_set():
        with HW_LOCK: # Only one thread touches hardware at a time
            try:
                with STATE_LOCK: mod, sts, loot, ip = STATE['active_module'], STATE['module_status'], STATE['loot_count'], STATE['server_ip']
                p.fill_rect(0, 0, 480, 222, C_BG); p.fill_rect(0, 0, 480, 18, rgb(0, 30, 20))
                p.draw_text(4, 2, 'PAGERSPLOIT v2.9.1 (SAFE)', C_TITLE, 1)
                p.draw_text(10, 40, f"IP: {ip}", C_GREEN, 2); p.draw_text(10, 80, f"MOD: {mod}", rgb(255, 220, 0), 2)
                p.draw_text(10, 110, f"STS: {sts}", rgb(200, 200, 200), 1)
                p.flip()
                _, pressed, _ = p.poll_input()
                if pressed & BTN_B: stop_event.set()
            except: pass
        time.sleep(0.5)

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--payload-dir', required=True)
    args = parser.parse_args()
    with STATE_LOCK: STATE['payload_dir'] = args.payload_dir
    
    # Standard server (Lean)
    server = HTTPServer(('0.0.0.0', 8080), APIHandler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    
    log('System Stable. Starting UI...')
    time.sleep(2) # Give hardware time to settle
    
    if Pager:
        stop_event = threading.Event()
        with Pager() as p: 
            pager_display_loop(p, stop_event)
    else:
        log('Pager hardware not found. Running in headless mode.')
        while True: time.sleep(1)

if __name__ == '__main__': run()
