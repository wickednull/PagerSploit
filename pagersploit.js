
const API=window.location.origin;let scanResults=[];let _pollActive=false;let _cmdHistory=[];let _cmdHistIdx=-1;

async function api(path,method='GET',body=null){
  try{const o={method,headers:{'Content-Type':'application/json'}};if(body)o.body=JSON.stringify(body);
  const r=await fetch(API+path,o);if(!r.ok)return null;return await r.json();}catch(e){return null;}
}

function show(pageId){
  document.querySelectorAll('.page').forEach(p=>p.classList.add('hidden'));
  document.getElementById('page-'+pageId).classList.remove('hidden');
  document.querySelectorAll('.nav-item').forEach(i=>i.classList.remove('active'));
  const nav=document.querySelector(`.nav-item[onclick*="'${pageId}'"]`);if(nav)nav.classList.add('active');
  document.getElementById('page-title').innerText=pageId.replace(/-/g,' ').toUpperCase();
  if(pageId==='loot')loadLoot();
  if(pageId==='wifi-crack')loadCrackSelects();
  if(pageId==='wifi-evil-twin')loadPortals();
}

async function pollState(){
  if(_pollActive)return; _pollActive=true;
  try{
    const s=await api('/api/state');if(!s)return;
    document.getElementById('sb-mod').innerText=s.active_module;
    document.getElementById('sb-status').innerText=s.module_status;
    document.getElementById('tb-loot').innerText=s.loot_count;
    document.getElementById('d-mod').innerText=s.active_module;
    document.getElementById('d-status').innerText=s.module_status;
    document.getElementById('d-loot').innerText=s.loot_count;
    document.getElementById('d-ip').innerText=s.server_ip;
    document.getElementById('d-jobs').innerText=s.jobs?s.jobs.length:0;

    // Health
    const h=await api('/api/sys/stats');
    if(h) document.getElementById('d-health').innerText=`T: ${h.temp} | U: ${h.uptime}`;

    // Logs
    const logs=await api('/api/log');
    if(logs){
      const container=document.getElementById('log-entries');
      const isScrolled=(container.scrollHeight-container.scrollTop)<=container.clientHeight+20;
      container.innerHTML=logs.map(l=>`<div class="log-${l.level}">[${l.time}] ${l.msg}</div>`).join('');
      if(isScrolled)container.scrollTop=container.scrollHeight;
    }

    // Creds for Dashboard
    const credData=await api('/api/data/creds');
    if(credData&&Array.isArray(credData)){
       const dashboardCreds = document.getElementById('cred-results');
       if(dashboardCreds) dashboardCreds.innerHTML = credData.map(c=>`<div>[${c.time}] [${c.src}] ${c.data}</div>`).join('');
    }
  }finally{_pollActive=false;}
}

// System
let walkActive=false;
async function toggleWalk(){
  walkActive=!walkActive;
  const btn=document.getElementById('btn-walk');
  btn.innerText=walkActive?'STOP WALK-MODE':'WALK-MODE (AUTO-PWN)';
  btn.className=walkActive?'btn btn-orange':'btn btn-red';
  await api('/api/walkmode','POST',{active:walkActive});
}

async function genReport(){
  const r=await api('/api/report','POST');
  if(r&&r.path) alert("Report generated in loot/reports/");
}

async function stopAll(){ 
  walkActive=false;
  const btn=document.getElementById('btn-walk');
  btn.innerText='WALK-MODE (AUTO-PWN)'; btn.className='btn btn-red';
  await api('/api/stop_all','POST'); 
}

  const band=document.getElementById('scan-band').value;
  document.getElementById('scan-status').innerText='Scanning...';
  await api('/api/wifi/scan','POST',{band,duration:10});
  setTimeout(loadCachedScan, 11000);
}

async function loadCachedScan(){
  const r=await api('/api/scans');if(!r)return;
  scanResults=r;
  const body=document.getElementById('scan-body');
  const dBody=document.getElementById('d-ap-body');
  const html=r.map(ap=>`<tr>
    <td>${ap.ssid}</td><td>${ap.bssid}</td><td>${ap.channel}</td>
    <td><span class="tag tag-blue">${ap.encryption}</span></td>
    <td style="color:var(--dim);font-size:10px">${ap.vendor||'Unknown'}</td>
    <td><div class="sig"><div class="sig-fill" style="width:${Math.max(10,100+ap.signal)}%;background:var(--green)"></div></div></td>
    <td>
      <button class="btn btn-red btn-sm" onclick="quickTarget('${ap.bssid}','${ap.channel}','${ap.ssid}')">Target</button>
    </td>
  </tr>`).join('');
  body.innerHTML=html||'<tr><td colspan="7">No APs found</td></tr>';
  if(dBody) dBody.innerHTML=html;
  document.getElementById('scan-status').innerText='';
  document.getElementById('scan-count').innerText=`(${r.length})`;
}

function quickTarget(bssid,ch,ssid){
  document.getElementById('da-bssid').value=bssid; document.getElementById('da-ch').value=ch;
  document.getElementById('cap-bssid').value=bssid; document.getElementById('cap-ch').value=ch; document.getElementById('cap-ssid').value=ssid;
  document.getElementById('pmkid-bssid').value=bssid; document.getElementById('pmkid-ch').value=ch;
  show('wifi-deauth');
}

async function doDeauth(){
  const bssid=document.getElementById('da-bssid').value;
  const ch=document.getElementById('da-ch').value;
  const client=document.getElementById('da-client').value;
  const count=document.getElementById('da-count').value;
  await api('/api/wifi/deauth','POST',{bssid,channel:ch,count,client});
}

async function doCapture(){
  const bssid=document.getElementById('cap-bssid').value;
  const ch=document.getElementById('cap-ch').value;
  const ssid=document.getElementById('cap-ssid').value;
  await api('/api/wifi/capture','POST',{bssid,channel:ch,ssid});
}

async function doCrack(){
  const cap_file=document.getElementById('crack-cap').value||document.getElementById('crack-cap-manual').value;
  const wordlist=document.getElementById('crack-wl').value;
  await api('/api/wifi/crack','POST',{cap_file,wordlist});
  // Poll crack output
  const timer=setInterval(async()=>{
     const d=await api('/api/data/crack_output');
     if(d) document.getElementById('crack-out').innerText=d.join('\n');
     const s=await api('/api/state');
     if(s.active_module!=='Cracking') clearInterval(timer);
  },2000);
}

// MDK4 & Advanced
async function doMdk4(mode){
  const ch=prompt("Channel to target?", "6");
  if(ch) await api('/api/wifi/mdk4','POST',{mode,channel:ch});
}

async function doMacRandom(){
  const r=await api('/api/wifi/mac_random','POST');
  if(r&&r.mac) alert("New MAC: " + r.mac);
}

// LAN
async function doArp(){
  const subnet=document.getElementById('arp-subnet').value;
  await api('/api/lan/arp_scan','POST',{subnet});
  setTimeout(async()=>{
    const r=await api('/api/hosts');
    if(r) document.getElementById('arp-body').innerHTML=r.map(h=>`<tr>
      <td>${h.ip}</td><td>${h.mac}</td><td>${h.vendor}</td>
      <td><button class="btn btn-blue btn-sm" onclick="show('lan-portscan');document.getElementById('ps-target').value='${h.ip}'">Scan</button></td>
    </tr>`).join('');
  }, 5000);
}

// Terminal
let _currentPrompt = 'root@pineapple:~# ';

async function termRun(){
  const inp=document.getElementById('term-input');
  const cmd=inp.value.trim(); if(!cmd)return;
  _cmdHistory.push(cmd); _cmdHistIdx=-1;
  const out=document.getElementById('term-out');
  out.innerHTML+=`<div style="color:var(--title)">${_currentPrompt}${cmd}</div>`;
  inp.value='';
  const r=await api('/api/term/exec','POST',{cmd});
  if(r&&r.output) out.innerHTML+=`<div>${r.output}</div>`;
  else if(r&&r.error) out.innerHTML+=`<div style="color:var(--red)">${r.error}</div>`;
  if(r&&r.prompt) _currentPrompt = r.prompt;
  out.scrollTop=out.scrollHeight;
}

function termClear(){
  document.getElementById('term-out').innerHTML = `<div>PagerSploit Terminal Session Started...</div><div>Current Prompt: ${_currentPrompt}</div>`;
}

// System
async function stopAll(){ await api('/api/stop_all','POST'); }
async function stop(module){ await api('/api/stop','POST',{module}); }

setInterval(pollState,3000); pollState();
show('dashboard');
