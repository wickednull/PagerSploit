#!/usr/bin/env python3
"""
PagerSploit v3.0 - Professional Orchestrator Edition
Zero-Crash Architecture for WiFi Pineapple Pager
"""

import os, sys, json, time, threading, subprocess, argparse, sqlite3
import socket, base64, shutil, signal
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import urlparse

# ── Infrastructure ────────────────────────────────────────────────────────

class SharedState:
    def __init__(self):
        self.active_module = 'idle'
        self.status = 'Standing by'
        self.loot_count = 0
        self.scan_results = []
        self.log = []
        self.jobs = {}
        self.stop_events = {}
        self.payload_dir = ''
        self.running = True

state = SharedState()

try:
    sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
    from pagerctl import Pager
except ImportError:
    Pager = None

RECON_DB = '/etc/pineapple/recon.db'
PINEAP_FUNCTIONS = '/etc/pineapple/functions'

def log(msg, level='info'):
    entry = {'time': time.strftime('%H:%M:%S'), 'level': level, 'msg': str(msg)}
    state.log.append(entry)
    if len(state.log) > 50: state.log.pop(0)
    print(f"[{entry['time']}] {msg}", flush=True)

# ── Native Engine ─────────────────────────────────────────────────────────

def _pineapple(*args):
    cmd = f'source {PINEAP_FUNCTIONS} && ' + ' '.join(f'"{a}"' for a in args)
    try:
        return subprocess.check_output(['bash', '-c', cmd], text=True).strip()
    except: return ''

def wifi_scan_task():
    state.active_module = 'Scanning'
    state.status = 'Querying DB...'
    _pineapple('PINEAPPLE_RECON_START')
    time.sleep(5)
    try:
        conn = sqlite3.connect(f'file:{RECON_DB}?mode=ro', uri=True)
        cur = conn.cursor()
        cur.execute("SELECT ssid, mac, channel, signal, encryption FROM wifi_ap_view ORDER BY signal DESC LIMIT 30")
        state.scan_results = [{'ssid': r[0] or '<hidden>', 'bssid': r[1].upper(), 'ch': r[2], 'sig': r[3]} for r in cur.fetchall()]
        conn.close()
    except: pass
    state.active_module = 'idle'
    state.status = f'{len(state.scan_results)} APs found'

# ── Web UI Orchestrator ───────────────────────────────────────────────────

class PSHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def send_json(self, data):
        self.send_response(200); self.send_header('Content-Type', 'application/json')
        self.send_header('Access-Control-Allow-Origin', '*'); self.end_headers()
        self.wfile.write(json.dumps(data).encode())

    def do_GET(self):
        p = urlparse(self.path).path
        if p == '/api/state':
            self.send_json({
                'module': state.active_module,
                'status': state.status,
                'loot': state.loot_count,
                'aps': state.scan_results
            })
        elif p == '/api/log': self.send_json(state.log)
        elif p in ('/', '/index.html'):
            try:
                with open(os.path.join(state.payload_dir, 'pagersploit_ui.html'), 'rb') as f:
                    self.send_response(200); self.end_headers(); self.wfile.write(f.read())
            except: self.send_error(404)
        elif p == '/pagersploit.js':
            try:
                with open(os.path.join(state.payload_dir, 'pagersploit.js'), 'rb') as f:
                    self.send_response(200); self.send_header('Content-Type', 'application/javascript')
                    self.end_headers(); self.wfile.write(f.read())
            except: self.send_error(404)

    def do_POST(self):
        p = urlparse(self.path).path
        if p == '/api/wifi/scan':
            threading.Thread(target=wifi_scan_task, daemon=True).start()
            self.send_json({'status': 'started'})
        elif p == '/api/stop_all':
            state.active_module = 'idle'
            state.status = 'Stopped'
            self.send_json({'status': 'ok'})

# ── Hardware Main Loop (The "Pager" Way) ──────────────────────────────────

def rgb(r, g, b): return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)

def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--payload-dir', required=True)
    args = parser.parse_args()
    state.payload_dir = args.payload_dir

    # 1. Start Web Server (Background)
    server = HTTPServer(('0.0.0.0', 8080), PSHandler)
    web_thread = threading.Thread(target=server.serve_forever, daemon=True)
    web_thread.start()
    log(f"Web UI active at 172.16.52.1:8080", "success")

    # 2. Hardware Signal Handling
    def graceful_exit(s, f):
        log("Shutting down..."); state.running = False
        server.shutdown(); sys.exit(0)
    
    signal.signal(signal.SIGINT, graceful_exit)
    signal.signal(signal.SIGTERM, graceful_exit)

    # 3. Main Hardware/UI Loop (Primary Thread)
    if Pager:
        with Pager() as p:
            p.set_rotation(270)
            C_BG = rgb(4,4,12); C_TITLE = rgb(0,255,180)
            
            while state.running:
                try:
                    p.fill_rect(0, 0, 480, 222, C_BG)
                    p.fill_rect(0, 0, 480, 18, rgb(0, 30, 20))
                    p.draw_text(4, 2, 'PAGERSPLOIT v3.0 (ORCHESTRATOR)', C_TITLE, 1)
                    
                    p.draw_text(10, 40, f"IP: 172.16.52.1", rgb(0, 255, 80), 2)
                    p.draw_text(10, 80, f"MOD: {state.active_module}", rgb(255, 220, 0), 2)
                    p.draw_text(10, 110, f"STS: {state.status[:30]}", rgb(200, 200, 200), 1)
                    p.draw_text(10, 140, f"LOOT: {state.loot_count}", rgb(255, 40, 40), 2)
                    
                    p.flip()
                    
                    # Poll buttons
                    _, pressed, _ = p.poll_input()
                    if pressed & Pager.BTN_B:
                        state.running = False
                        
                except Exception as e:
                    print(f"UI Error: {e}")
                
                time.sleep(0.1) # 10Hz refresh
    else:
        log("Headless mode (No Pager Hardware detected)")
        while state.running: time.sleep(1)

    server.shutdown()

if __name__ == '__main__':
    main()
