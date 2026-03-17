
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
  try{if(event&&event.target&&event.target.classList)event.target.classList.add('active');}catch(e){}
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

// Basic OUI vendor lookup from MAC prefix
const OUI={
  '02:13:37':'Hak5','00:13:37':'Hak5',
  'F0:9F:C2':'Ubiquiti','DC:9F:DB':'Ubiquiti','44:D9:E7':'Ubiquiti',
  'B8:27:EB':'Raspberry Pi','DC:A6:32':'Raspberry Pi','E4:5F:01':'Raspberry Pi',
  '00:50:56':'VMware','00:0C:29':'VMware',
  '00:1A:11':'Google','F4:F5:D8':'Google','54:60:09':'Google',
  '18:FE:34':'Espressif','24:6F:28':'Espressif','A4:CF:12':'Espressif',
  'AC:91:A1':'Apple','3C:22:FB':'Apple','F0:D1:A9':'Apple','A8:BB:CF':'Apple',
  '00:17:F2':'Apple','00:23:12':'Apple',
  '60:57:18':'Apple','70:56:81':'Apple',
  'C8:69:CD':'Apple','F4:37:B7':'Apple',
  '00:26:BB':'Apple','28:CF:DA':'Apple',
  'CC:08:8D':'Apple',
  'FC:65:DE':'Samsung','50:32:37':'Samsung','78:59:5E':'Samsung',
  '54:BD:79':'Netgear','C0:3F:0E':'Netgear','20:4E:7F':'Netgear',
  '00:0F:66':'Netgear','1C:1B:0D':'Netgear',
  '4C:C5:3E':'CenturyLink/Zyxel','00:A0:C5':'Zyxel',
  'C8:D3:A3':'Linksys','C4:41:1E':'Linksys','00:14:BF':'Linksys',
  '00:18:39':'Cisco','00:1B:D5':'Cisco','58:AC:78':'Cisco',
  '00:E0:4C':'Realtek','00:E0:F0':'Netopia',
  'E8:94:F6':'TP-Link','C4:E9:84':'TP-Link','50:C7:BF':'TP-Link',
  'EC:08:6B':'TP-Link','54:A7:03':'TP-Link','18:D6:C7':'TP-Link',
  'B0:BE:76':'TP-Link','84:16:F9':'TP-Link',
};
function ouiLookup(mac){
  if(!mac)return'';
  const p6=mac.substring(0,8).toUpperCase();
  return OUI[p6]||'';}
function sigBar(dbm){const p=Math.max(0,Math.min(100,(dbm+100)*2));
  const c=p>60?'#00ff50':p>30?'#ffdc00':'#ff2828';
  return '<div class="sig"><div class="sig-fill" style="width:'+p+'%;background:'+c+'"></div></div> '+dbm;}
function renderScan(aps){
  const sb=document.getElementById('scan-body');
  const db=document.getElementById('d-ap-body');
  const sc=document.getElementById('scan-count');
  const dc=document.getElementById('d-ap-count');
  if(!aps||!aps.length){
    const empty='<tr><td colspan="7" style="color:var(--dim)">No APs</td></tr>';
    if(sb)sb.innerHTML=empty; if(db)db.innerHTML=empty; return;}
  function mkRow(a){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(a.ssid||'<hidden>')+'</td>'+
      '<td style="font-size:11px;color:var(--dim);cursor:pointer" title="Click to copy" onclick="navigator.clipboard&&navigator.clipboard.writeText('+JSON.stringify(a.bssid)+').then(()=>toast('+JSON.stringify('Copied: '+a.bssid)+',\'#00ffb4\'))">'+esc(a.bssid)+'</td>'+
      '<td>'+esc(a.channel)+'</td>'+
      '<td><span class="tag '+((a.encryption==='Open'||a.encryption==='?')?'tag-red':'tag-green')+'">'+esc(a.encryption||'?')+'</span></td>'+
      '<td style="font-size:10px;color:var(--dim)">'+esc(ouiLookup(a.bssid))+'</td>'+
      '<td>'+sigBar(a.signal)+'</td>'+
      '<td></td>';
    const td=tr.lastElementChild;
    const bd=document.createElement('button');
    bd.className='btn btn-red btn-sm'; bd.textContent='Deauth';
    bd.addEventListener('click',function(){quickDeauth(a.bssid,a.channel);});
    const bc=document.createElement('button');
    bc.className='btn btn-orange btn-sm'; bc.textContent='Cap'; bc.style.marginLeft='3px';
    bc.addEventListener('click',function(){quickCap(a.bssid,a.channel,a.ssid);});
    const bt=document.createElement('button');
    bt.className='btn btn-blue btn-sm'; bt.textContent='Twin'; bt.style.marginLeft='3px';
    bt.addEventListener('click',function(){quickTwin(a.ssid,a.channel);});
    td.appendChild(bd); td.appendChild(bc); td.appendChild(bt);
    return tr;}
  [sb,db].forEach(function(tbody){
    if(!tbody)return;
    tbody.innerHTML='';
    aps.forEach(function(a){tbody.appendChild(mkRow(a));});});
  if(sc)sc.textContent='('+aps.length+')';
  if(dc)dc.textContent='('+aps.length+')';}
function renderArp(hosts){
  const tbody=document.getElementById('arp-body');if(!tbody)return;
  tbody.innerHTML='';
  hosts.forEach(function(h){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(h.ip)+'</td>'+
      '<td style="font-size:11px;color:var(--dim)">'+esc(h.mac||'')+'</td>'+
      '<td style="color:var(--dim)">'+esc(h.vendor||'')+'</td>'+
      '<td></td>';
    const td=tr.lastElementChild;
    const bs=document.createElement('button');
    bs.className='btn btn-blue btn-sm'; bs.textContent='Scan';
    bs.addEventListener('click',function(){g('ps-target').value=h.ip;show('lan-portscan');});
    const bc=document.createElement('button');
    bc.className='btn btn-orange btn-sm'; bc.textContent='Creds'; bc.style.marginLeft='3px';
    bc.addEventListener('click',function(){g('cred-target').value=h.ip;show('lan-creds');});
    const bg=document.createElement('button');
    bg.className='btn btn-purple btn-sm'; bg.textContent='Geo'; bg.style.marginLeft='3px';
    bg.addEventListener('click',function(){g('geo-ip').value=h.ip;show('osint-ipgeo');doGeo();});
    td.appendChild(bs); td.appendChild(bc); td.appendChild(bg);
    tbody.appendChild(tr);});
  const c=document.getElementById('arp-count');if(c)c.textContent='('+hosts.length+')';}
function g(id){return document.getElementById(id);}
function gv(id){const el=g(id);return el?el.value:'';}
async function doScan(){
  const band=gv('scan-band')||'abg';
  const dur=parseInt(gv('scan-dur'))||20;
  g('scan-status').textContent='Scanning '+band+' ('+dur+'s)...';
  g('scan-body').innerHTML='<tr><td colspan="7" style="color:var(--dim)">Scanning...</td></tr>';
  await api('/api/wifi/scan','POST',{band:band,duration:dur});
  pollUntilIdle(async()=>{const sc=await api('/api/scans');
    if(sc&&Array.isArray(sc)){scanResults=sc;renderScan(sc);g('scan-status').textContent='Done ('+sc.length+' APs)';}
    else g('scan-status').textContent='Done';},dur+15);}
async function doDeauth(){const b=gv('da-bssid');if(!b)return alert('BSSID required');
  await api('/api/wifi/deauth','POST',{bssid:b,channel:gv('da-ch'),count:gv('da-count'),client:gv('da-client')});}
function quickDeauth(b,c){show('wifi-deauth');g('da-bssid').value=b;g('da-ch').value=c;doDeauth();}
async function doCapture(){const b=gv('cap-bssid');if(!b)return alert('BSSID required');
  const r=await api('/api/wifi/capture','POST',{bssid:b,ssid:gv('cap-ssid'),channel:gv('cap-ch')});
  if(r.error){g('cap-status').textContent='Error: '+r.error;return;}
  g('cap-status').textContent='Capturing... → '+(r.handshake_dir||'/root/loot/handshakes');
  // Poll loot for new handshake files
  let lastCount=0;
  const t=setInterval(async()=>{
    const loot=await api('/api/loot');
    const hs=loot.filter(l=>l.category==='handshakes');
    if(hs.length>lastCount){lastCount=hs.length;g('cap-status').textContent='✓ Handshake captured! ('+hs.length+' total) → check Loot';}
    const s=await api('/api/state');
    if(!s||s.active_module==='idle'||s.active_module!=='Capture'){clearInterval(t);}
  },3000);}
async function doCapDeauth(){await doCapture();const b=gv('cap-bssid');
  if(b)await api('/api/wifi/deauth','POST',{bssid:b,channel:gv('cap-ch'),count:'10'});}
function quickCap(b,c,s){show('wifi-capture');g('cap-bssid').value=b;g('cap-ch').value=c;g('cap-ssid').value=s;}
function quickTwin(s,c){show('wifi-evil-twin');g('et-ssid').value=s;g('et-ch').value=c;}
async function loadCrackSelects(){const loot=await api('/api/loot');
  const capExts=['.cap','.pcap','.22000','.hc22000','.hccapx'];
  const caps=loot.filter(l=>capExts.some(e=>l.name.endsWith(e)));
  g('crack-cap').innerHTML=caps.map(c=>'<option value="'+c.path+'">'+esc(c.category+'/'+c.name)+'</option>').join('')||'<option>No cap files found</option>';
  const wls=await api('/api/wordlists');
  g('crack-wl').innerHTML=wls.map(w=>'<option value="'+w.path+'">'+esc(w.name)+' ('+(w.size/1024/1024).toFixed(1)+'MB)</option>').join('')||'<option>No wordlists found</option>';}
async function doCrack(){
  const c=gv('crack-cap-manual').trim()||gv('crack-cap');
  const w=gv('crack-wl');
  if(!c||c.includes('No cap')||c.includes('No files'))return alert('Select or enter a cap file');
  if(!w||w.includes('No wordlist'))return alert('Select a wordlist');
  const out=g('crack-out');if(out)out.textContent='Starting crack...';
  await api('/api/wifi/crack','POST',{cap_file:c,wordlist:w});
  // Live output polling while crack runs
  const liveT=setInterval(async()=>{
    const d=await api('/api/data/crack_output');
    if(d&&Array.isArray(d)&&d.length&&out)out.textContent=d.slice(-80).join('\n');
  },2000);
  pollUntilIdle(async(s)=>{
    clearInterval(liveT);
    // Prefer final loot file (always saved now); fallback to in-memory output
    const loot=await api('/api/loot');
    const f=loot.find?.(l=>l.name.startsWith('crack_hit_')||l.name.startsWith('crack_done_'));
    if(f){const r=await fetch('/api/loot/download/'+encodeURIComponent(f.name));
      if(out)out.textContent=await r.text();}
    else{const d=await api('/api/data/crack_output');
      if(out)out.textContent=(d&&Array.isArray(d)&&d.length?d.join('\n'):null)||
        (s&&s.module_status)||'Crack complete';}
  },600);}
async function doPmkid(){const b=gv('pmkid-bssid');if(!b)return alert('BSSID required');
  const st=g('pmkid-status');if(st)st.textContent='Running...';
  await api('/api/wifi/pmkid','POST',{bssid:b,channel:gv('pmkid-ch')});
  pollUntilIdle(async(s)=>{
    if(st)st.textContent=s?s.module_status:'Done';
    const loot=await api('/api/loot');
    const hs=loot.filter(l=>l.category==='handshakes');
    if(hs.length&&st)st.textContent='Done — '+hs.length+' handshake(s) in loot';
  },130);}
async function loadPortals(){const p=await api('/api/portals');
  g('et-portal').innerHTML='<option value="">-- None --</option>'+p.map(x=>'<option value="'+x+'">'+x+'</option>').join('');}
async function doEvilTwin(){const s=gv('et-ssid');if(!s)return alert('SSID required');
  const st=g('et-status');if(st)st.textContent='Starting evil twin for: '+s;
  const r=await api('/api/wifi/evil_twin','POST',{ssid:s,channel:gv('et-ch'),portal:gv('et-portal')});
  if(st)st.textContent=r.error?'Error: '+r.error:'Active — AP broadcasting as "'+s+'" on ch '+gv('et-ch');}
async function doKarma(){
  const st=g('karma-status');if(st)st.textContent='Active — responding to all probes...';
  await api('/api/wifi/karma','POST',{channel:gv('karma-ch')});}
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
    if(d&&d.length)g('wps-body').innerHTML=d.map(w=>'<tr><td>'+esc(w.bssid)+'</td><td>'+(w.channel||'?')+'</td><td>'+(w.rssi||'?')+'</td><td><span class="tag tag-'+(w.wps_info&&w.wps_info!=='unknown'?'green':'yellow')+'">'+esc(w.wps_info||'?')+'</span></td><td>'+esc(w.ssid)+'</td></tr>').join('');
    else g('wps-body').innerHTML='<tr><td colspan="6">None found</td></tr>';},35);}
async function loadCachedScan(){
  const sc=await api('/api/scans');
  if(sc&&Array.isArray(sc)&&sc.length){scanResults=sc;renderScan(sc);g('scan-status').textContent='Cached ('+sc.length+' APs)';}
  else{g('scan-status').textContent='No cached scan — run a scan first';}}
async function doChanHop(){await api('/api/wifi/channel_hop','POST',{band:gv('hop-band')});}
async function doArp(){const subnet=gv('arp-subnet')||'172.16.52.0/24';
  const tbody=g('arp-body');if(tbody)tbody.innerHTML='<tr><td colspan="4" style="color:var(--dim)">Scanning...</td></tr>';
  await api('/api/lan/arp_scan','POST',{subnet});
  pollUntilIdle(async()=>{const h=await api('/api/hosts');if(h&&Array.isArray(h)){renderArp(h);const c=g('arp-count');if(c)c.textContent='('+h.length+')';}},60);}
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
  const cs=g('cred-status');if(cs)cs.textContent='Spraying...';
  if(g('cred-results'))g('cred-results').textContent='Running...';
  await api('/api/lan/default_creds','POST',{target:t});
  pollUntilIdle(async(s)=>{
    if(cs)cs.textContent=s?s.module_status:'';
    const loot=await api('/api/loot');
    const f=loot.find?.(l=>l.name.startsWith('creds_'+t));
    if(f){const r=await fetch('/api/loot/download/'+encodeURIComponent(f.name));
      const txt=await r.text();
      if(g('cred-results'))g('cred-results').textContent=txt||'No credentials found';}
    else if(g('cred-results'))g('cred-results').textContent='No credentials found';},90);}
async function doSsh(){const t=gv('ssh-target');if(!t)return alert('Target required');
  const ss=g('ssh-status');if(ss)ss.textContent='Running...';
  if(g('ssh-results'))g('ssh-results').textContent='Brute forcing...';
  await api('/api/lan/ssh_brute','POST',{target:t,port:gv('ssh-port')});
  pollUntilIdle(async(s)=>{
    if(ss)ss.textContent=s?s.module_status:'';
    // Try in-memory result first (set_data), then loot file
    const d=await api('/api/data/ssh_scan');
    if(d&&d.raw){
      const txt=d.creds&&d.creds.length?'CREDENTIALS FOUND:\n'+JSON.stringify(d.creds,null,2)+'\n\n'+d.raw:
        (d.banner?'Banner: '+d.banner+'\n\n'+d.raw:d.raw);
      if(g('ssh-results'))g('ssh-results').textContent=txt;
    } else {
      const loot=await api('/api/loot');
      const f=loot.find?.(l=>l.name.startsWith('ssh_'+t)||l.name.startsWith('ssh_scan_'+t));
      if(f){const r=await fetch('/api/loot/download/'+encodeURIComponent(f.name));
        if(g('ssh-results'))g('ssh-results').textContent=await r.text();}
      else if(g('ssh-results'))g('ssh-results').textContent='No results';}},90);}
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
  g('mac-result').textContent='Looking up vendors...';
  const bssids=scanResults.slice(0,8).map(a=>a.bssid);
  // Sequential to avoid mac_lookup state being overwritten between POST and GET
  const lines=[];
  for(const mac of bssids){
    const r=await api('/api/osint/mac','POST',{mac});
    if(r.error)continue;
    // Small delay then read — the module runs synchronously server-side so result is immediate
    await new Promise(res=>setTimeout(res,200));
    const d=await api('/api/data/mac_lookup');
    if(d&&d.vendor&&d.vendor!=='Unknown')lines.push(mac+': '+d.vendor);
  }
  g('mac-result').textContent=lines.join('\n')||'No vendors found in local OUI database';}
async function doGeo(){const ip=gv('geo-ip');if(!ip)return alert('IP required');
  g('geo-result').textContent='Looking up... (requires internet on Pager)';await api('/api/osint/ipgeo','POST',{ip});
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
  g('wgeo-result').textContent='Querying Mozilla Location Service... (requires internet on Pager)';
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
async function deleteLoot(name){
  if(!confirm('Delete '+name+'?'))return;
  const r=await fetch(API+'/api/loot/delete/'+encodeURIComponent(name),{method:'DELETE'});
  const d=await r.json();
  if(d.status==='deleted'){toast('Deleted: '+name,'#00ff50');loadLoot();}
  else toast('Error: '+(d.error||'unknown'),'#ff2828');}
async function deleteAllLoot(){
  if(!confirm('Delete ALL loot files? This cannot be undone.'))return;
  const r=await fetch(API+'/api/loot/delete_all',{method:'DELETE'});
  const d=await r.json();
  toast('Deleted '+d.count+' files','#ff8c00');loadLoot();}
let _lootFilter='';
async function loadLoot(){
  const loot=await api('/api/loot');const tbody=g('loot-body');
  if(!Array.isArray(loot)||!loot.length){tbody.innerHTML='<tr><td colspan="6" style="color:var(--dim)">No loot</td></tr>';return;}
  // Render filter buttons
  const cats={handshakes:'tag-blue',credentials:'tag-red',scans:'tag-green',pmkid:'tag-yellow'};
  const allCats=[...new Set(loot.map(l=>l.category))].sort();
  const fb=g('loot-filter-bar');
  if(fb){
    fb.innerHTML='<button class="btn btn-sm '+ (!_lootFilter?'btn-blue':'btn-yellow')+'" onclick="_lootFilter=\'\';loadLoot()">All</button> '+
      allCats.map(c=>'<button class="btn btn-sm '+(_lootFilter===c?'btn-blue':'btn-yellow')+'" onclick="_lootFilter='+JSON.stringify(c)+';loadLoot()">'+esc(c)+'</button>').join(' ');
  }
  const filtered=_lootFilter?loot.filter(l=>l.category===_lootFilter):loot;
  if(!filtered.length){tbody.innerHTML='<tr><td colspan="6" style="color:var(--dim)">No files in this category</td></tr>';return;}
  tbody.innerHTML=filtered.map(l=>'<tr>'+
    '<td style="font-size:11px;word-break:break-all">'+esc(l.name)+'</td>'+
    '<td><span class="tag '+(cats[l.category]||'tag-blue')+'">'+esc(l.category)+'</span></td>'+
    '<td style="white-space:nowrap">'+(l.size<1024?l.size+'B':(l.size/1024).toFixed(1)+'KB')+'</td>'+
    '<td style="color:var(--dim);font-size:11px;white-space:nowrap">'+l.modified+'</td>'+
    '<td><a href="/api/loot/download/'+encodeURIComponent(l.name)+'" style="color:var(--blue);font-size:11px">↓ DL</a></td>'+
    '<td><button class="btn btn-red btn-sm" onclick="deleteLoot('+JSON.stringify(l.name)+')">✕</button></td>'+
    '</tr>').join('');}

async function loadCapLoot(){
  const loot=await api('/api/loot');
  const el=g('cap-loot');if(!el)return;
  const hs=loot.filter(l=>l.category==='handshakes');
  if(!hs.length){el.textContent='No handshakes captured yet';el.style.color='var(--dim)';return;}
  el.style.color='var(--green)';
  el.innerHTML=hs.map(h=>'<div>'+esc(h.name)+' <span style="color:var(--dim)">('+h.modified+')</span> '+
    '<a href="/api/loot/download/'+encodeURIComponent(h.name)+'" style="color:var(--blue);margin-left:8px">↓</a></div>').join('');}

// ── Terminal ──────────────────────────────────────────────────────────────
let termLive=true, termLastLog=0;
let _cmdHistory=[],_cmdHistIdx=-1;
function termEl(){return document.getElementById('term-out');}
function termWrite(text, col){
  const el=termEl(); if(!el)return;
  const span=document.createElement('span');
  if(col)span.style.color=col;
  span.textContent=text+'\n';
  el.appendChild(span);
  el.scrollTop=el.scrollHeight;
}
function termClear(){const el=termEl();if(el)el.innerHTML='';termLastLog=0;_termLastMsg='';}
function termToggleLive(){termLive=!termLive;const s=document.getElementById('term-live-status');if(s)s.textContent=termLive?'ON':'OFF';}
async function termKillAll(){await api('/api/stop_all','POST',{});termWrite('[killed all jobs]','#ff8c00');}
async function termRun(){
  const inp=document.getElementById('term-input');
  const cmd=inp?inp.value.trim():'';
  if(!cmd)return;
  if(inp)inp.value='';
  // Add to history (avoid duplicates at end)
  if(!_cmdHistory.length||_cmdHistory[_cmdHistory.length-1]!==cmd)_cmdHistory.push(cmd);
  if(_cmdHistory.length>100)_cmdHistory.shift();
  _cmdHistIdx=-1;
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
// termInjectLog tracks by last-seen entry time string to avoid index drift
let termLastTime='';
let _termLastMsg='';
function termInjectLog(entries){
  if(!termLive||!entries||!entries.length)return;
  // Use last message content+time as dedup key — handles same-second entries
  let startIdx=0;
  const lastKey=_termLastMsg;
  if(lastKey){
    for(let i=entries.length-1;i>=0;i--){
      const key=entries[i].time+'|'+entries[i].msg;
      if(key===lastKey){startIdx=i+1;break;}
    }
  }
  const newEntries=entries.slice(startIdx);
  if(!newEntries.length)return;
  const last=entries[entries.length-1];
  _termLastMsg=last.time+'|'+last.msg;
  const cols={success:'#00ff50',error:'#ff2828',warn:'#ff8c00',info:'#555'};
  newEntries.forEach(e=>termWrite('['+e.time+'] '+e.msg,cols[e.level]||'#aaa'));
}
// Adaptive poll — fast when active, slow when idle
let _pollActive=false, _pollInterval=2000;
async function pollState(){
  if(_pollActive)return; // debounce: skip if previous call still running
  _pollActive=true;
  try{
    const s=await api('/api/state');
    if(s&&!s.error){
      const busy=s.active_module!=='idle';
      // Adaptive interval: 1s when busy, 3s when idle
      const want=busy?1000:3000;
      if(want!==_pollInterval){_pollInterval=want;clearInterval(_pollTimer);_pollTimer=setInterval(pollState,_pollInterval);}
      document.getElementById('sb-mod').textContent=s.active_module;
      document.getElementById('sb-status').textContent=s.module_status;
      document.getElementById('tb-loot').textContent=s.loot_count;
      document.getElementById('d-mod').textContent=s.active_module;
      document.getElementById('d-status').textContent=s.module_status;
      document.getElementById('d-loot').textContent=s.loot_count;
      document.getElementById('d-jobs').textContent=(s.jobs||[]).length;
      document.getElementById('d-ip').textContent='http://'+s.server_ip+':'+s.server_port;
      document.getElementById('tb-ip').textContent=s.server_ip+':'+s.server_port;
    }
    const lg=await api('/api/log');
    if(lg&&!lg.error){
      const el=document.getElementById('log-entries');
      el.innerHTML=lg.slice(-60).map(l=>'<span class="log-'+l.level+'">['+l.time+'] '+esc(l.msg)+'</span><br>').join('');
      el.scrollTop=el.scrollHeight;
      termInjectLog(lg);
    }
    // Only re-render scan/host tables if those pages are visible
    const scanPage=document.getElementById('page-wifi-scan');
    const dashPage=document.getElementById('page-dashboard');
    const arpPage=document.getElementById('page-lan-arp');
    const scanVisible=scanPage&&!scanPage.classList.contains('hidden');
    const dashVisible=dashPage&&!dashPage.classList.contains('hidden');
    const arpVisible=arpPage&&!arpPage.classList.contains('hidden');
    if(scanVisible||dashVisible){
      const sc=await api('/api/scans');
      if(sc&&Array.isArray(sc)&&sc.length){scanResults=sc;renderScan(sc);}
    }
    if(arpVisible){
      const hosts=await api('/api/hosts');
      if(hosts&&Array.isArray(hosts)&&hosts.length)renderArp(hosts);
    }
  }finally{_pollActive=false;}
}
let _pollTimer=setInterval(pollState,_pollInterval);pollState();
