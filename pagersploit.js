
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
  const sb=document.getElementById('scan-body');
  const db=document.getElementById('d-ap-body');
  const sc=document.getElementById('scan-count');
  const dc=document.getElementById('d-ap-count');
  if(!aps||!aps.length){
    const empty='<tr><td colspan="7" style="color:var(--dim)">No APs</td></tr>';
    if(sb)sb.innerHTML=empty; if(db)db.innerHTML=empty; return;}
  function mkRow(a){
    const tr=document.createElement('tr');
    tr.innerHTML='<td>'+esc(a.ssid)+'</td>'+
      '<td style="font-size:11px;color:var(--dim)">'+esc(a.bssid)+'</td>'+
      '<td>'+esc(a.channel)+'</td>'+
      '<td><span class="tag '+(a.enc==='Open'?'tag-red':'tag-green')+'">'+esc(a.enc)+'</span></td>'+
      '<td>'+(a.clients||0)+'</td>'+
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
setInterval(pollState,2000);pollState();
