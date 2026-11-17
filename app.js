(() => {
  const $ = (id) => document.getElementById(id);
  const source = $('email-source');
  let latestReport = null;
  let activeFile = null;
  const sample = `From: Microsoft Account <security@micros0ft-alert.example>
Reply-To: account-help@random-mail.example
Return-Path: <bounce@random-mail.example>
To: employee@example.org
Subject: Urgent: Your account will be suspended
Date: Tue, 17 Nov 2026 08:20:00 +0000
Received: from unknown-host.example (unknown-host.example [203.0.113.42])
Authentication-Results: mx.example.org; spf=fail smtp.mailfrom=random-mail.example; dkim=none; dmarc=fail
MIME-Version: 1.0
Content-Type: text/plain; charset=UTF-8

Your Microsoft account will be suspended today. Verify immediately:
http://198.51.100.24/login
https://account-microsoft.example.security-check.example/verify
`;
  $('paste-tab').addEventListener('click', () => setMode('paste'));
  $('file-tab').addEventListener('click', () => setMode('file'));
  function setMode(mode) {
    const paste = mode === 'paste';
    $('paste-view').classList.toggle('hidden', !paste);
    $('file-view').classList.toggle('hidden', paste);
    $('paste-tab').classList.toggle('active', paste);
    $('file-tab').classList.toggle('active', !paste);
    $('paste-tab').setAttribute('aria-selected', String(paste));
    $('file-tab').setAttribute('aria-selected', String(!paste));
  }
  source.addEventListener('input', () => $('char-count').textContent = source.value.length.toLocaleString() + ' characters');
  $('sample-button').addEventListener('click', () => { source.value = sample; source.dispatchEvent(new Event('input')); });
  $('eml-file').addEventListener('change', async (e) => {
    const file = e.target.files && e.target.files[0]; if (!file) return;
    activeFile = file; source.value = await file.text(); source.dispatchEvent(new Event('input')); $('file-name').textContent = file.name + ' · ' + file.size.toLocaleString() + ' bytes';
  });
  const drop = document.querySelector('.drop-zone');
  ['dragenter','dragover'].forEach(evt => drop.addEventListener(evt, e => {e.preventDefault();drop.style.borderColor='var(--cyan)';}));
  ['dragleave','drop'].forEach(evt => drop.addEventListener(evt, e => {e.preventDefault();drop.style.borderColor='';}));
  drop.addEventListener('drop', async e => {const f=e.dataTransfer.files[0];if(!f)return;activeFile=f;source.value=await f.text();source.dispatchEvent(new Event('input'));$('file-name').textContent=f.name+' · '+f.size.toLocaleString()+' bytes';});
  $('clear-button').addEventListener('click', () => {source.value='';source.dispatchEvent(new Event('input'));$('eml-file').value='';$('file-name').textContent='';activeFile=null;latestReport=null;$('results').classList.add('hidden');$('empty-state').classList.remove('hidden');});
  $('analyze-button').addEventListener('click', analyze);
  $('export-json').addEventListener('click', () => download('phishing-analysis.json', JSON.stringify(latestReport,null,2), 'application/json'));
  $('export-html').addEventListener('click', () => window.print());
  function headerMap(raw) {
    const unfolded = raw.replace(/\r?\n[ \t]+/g, ' ');
    const map = {};
    for (const line of unfolded.split(/\r?\n/)) { const i=line.indexOf(':'); if(i>0){const k=line.slice(0,i).trim().toLowerCase();(map[k]??=[]).push(line.slice(i+1).trim());} }
    return map;
  }
  const first = (h,k) => (h[k]||[])[0] || 'Not provided';
  function extractUrls(text) {
    const matches = text.match(/https?:\/\/[^\s<>"'\])}]+/gi) || [];
    return [...new Set(matches.map(x=>x.replace(/[.,;!?]+$/,'')))].slice(0,100);
  }
  function safeHost(value) { try { return new URL(value).hostname.toLowerCase(); } catch { return ''; } }
  function analyze() {
    const raw=source.value.trim(); if(!raw){source.focus();source.placeholder='Paste an email source first, or load the sample email.';return;}
    const h=headerMap(raw), urls=extractUrls(raw), findings=[];let score=0;
    const add=(severity,title,detail,points)=>{findings.push({severity,title,detail,points});score+=points;};
    const from=first(h,'from'), reply=first(h,'reply-to'), ret=first(h,'return-path'), subject=first(h,'subject');
    const emailOf = s => (s.match(/[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}/i)||[])[0]||'';
    const fromEmail=emailOf(from), replyEmail=emailOf(reply), returnEmail=emailOf(ret);
    const fromDomain=fromEmail.split('@')[1]||'', replyDomain=replyEmail.split('@')[1]||'', returnDomain=returnEmail.split('@')[1]||'';
    if(!fromEmail)add('medium','Sender address missing','No parseable email address was found in the From header.',12);
    if(replyEmail&&fromDomain&&replyDomain&&fromDomain!==replyDomain)add('high','Reply-To domain differs','The Reply-To address uses a different domain from the visible sender. This can be legitimate, but deserves verification.',22);
    if(returnDomain&&fromDomain&&returnDomain!==fromDomain)add('medium','Return-Path domain differs','The envelope return-path domain differs from the visible From domain.',12);
    if(/urgent|suspend|suspended|immediately|act now|verify|password|payment|invoice|expire|locked|unusual activity/i.test(subject+' '+raw.slice(raw.indexOf('\n\n')+2,raw.length).slice(0,2500)))add('medium','Urgency or credential language','The subject or message body contains urgency, account, payment or verification language often used in social engineering.',12);
    const auth=(h['authentication-results']||[]).join('; ')+' '+(h['received-spf']||[]).join('; ');
    const authStatus={spf:readAuth(auth,'spf'),dkim:readAuth(auth,'dkim'),dmarc:readAuth(auth,'dmarc')};
    for(const [name,status] of Object.entries(authStatus)){if(status==='fail')add('high',name.toUpperCase()+' reported failure','The supplied Authentication-Results / Received-SPF header reports '+name+'=fail. The header itself is not authenticated by this tool.',15);else if(status==='none')add('low',name.toUpperCase()+' result not found','No clear '+name.toUpperCase()+' result was found in the supplied authentication headers.',3);}
    const ipUrl=urls.filter(u=>/^https?:\/\/(?:\d{1,3}\.){3}\d{1,3}(?::\d+)?(?:\/|$)/i.test(u));
    if(ipUrl.length)add('high','Link uses an IP address',ipUrl.length+' URL(s) use a raw IP address instead of a recognizable domain.',18);
    const shorteners=['bit.ly','tinyurl.com','t.co','goo.gl','is.gd','cutt.ly','rb.gy','ow.ly'];
    const shortUrls=urls.filter(u=>shorteners.includes(safeHost(u)));
    if(shortUrls.length)add('medium','URL shortener detected',shortUrls.length+' shortened link(s) conceal the final destination.',10);
    const nonHttps=urls.filter(u=>u.toLowerCase().startsWith('http://'));
    if(nonHttps.length)add('medium','Unencrypted HTTP links',nonHttps.length+' link(s) use HTTP rather than HTTPS. HTTPS alone does not guarantee safety.',8);
    const suspiciousHosts=urls.filter(u=>{const host=safeHost(u);return host.includes('xn--')||host.split('.').length>5||/\d{1,3}(?:-\d{1,3}){2,}/.test(host);});
    if(suspiciousHosts.length)add('medium','Unusual URL hostname','One or more URLs contain an internationalized/punycode hostname, an unusually deep subdomain chain or IP-like hostname text.',12);
    const received=(h['received']||[]).join(' ');
    if(!received)add('low','No Received trace found','No Received header was found. A complete message normally contains mail-routing trace headers.',4);
    if(/\.(?:exe|scr|js|vbs|bat|cmd|ps1|iso|img|hta)(?:[\s;"']|$)/i.test(raw))add('high','Potentially executable attachment reference','The raw message contains a reference to a potentially executable file extension. Attachment content is not inspected.',18);
    if(!findings.length)add('low','No obvious heuristic indicators','No high-signal patterns matched the current rule set. This does not establish that the email is safe.',0);
    score=Math.min(100,score);
    const level=score>=60?'HIGH RISK':score>=30?'SUSPICIOUS':score>0?'LOW SIGNAL':'NO FLAGS';
    const summary=score>=60?'Multiple warning signs were detected. Treat this message as potentially malicious.':score>=30?'Several indicators deserve investigation before you trust this message.':score>0?'A few indicators were found. Verify the sender and links independently.':'No configured indicators matched. This is not a guarantee of safety.';
    const report={tool:'VAIB Free Phishing Email Analyzer',version:'1.0.0',analyzedAt:new Date().toISOString(),fileName:activeFile?.name||null,riskScore:score,riskLevel:level,sender:{from,replyTo:reply,returnPath:ret,subject},authentication:authStatus,urls,findings,limitations:'Authentication results are parsed from untrusted supplied headers and are not independently verified. Heuristic analysis can produce false positives and false negatives.'};
    latestReport=report;render(report,summary);$('empty-state').classList.add('hidden');$('results').classList.remove('hidden');$('results').scrollIntoView({behavior:'smooth',block:'start'});
  }
  function readAuth(text,name){const re=new RegExp('(?:^|[;\\s])'+name+'\\s*=\\s*(pass|fail|softfail|neutral|none|temperror|permerror)', 'i');const m=text.match(re);return m?m[1].toLowerCase():'not found';}
  function render(r,summary){
    $('risk-score').textContent=r.riskScore;$('risk-level').textContent=r.riskLevel;$('risk-summary').textContent=summary;
    const gauge=$('gauge-value');gauge.style.strokeDashoffset=String(308-(308*r.riskScore/100));gauge.style.stroke=r.riskScore>=60?'var(--red)':r.riskScore>=30?'var(--amber)':'var(--green)';
    $('sender-details').innerHTML='';[['From',r.sender.from],['Reply-To',r.sender.replyTo],['Return-Path',r.sender.returnPath],['Subject',r.sender.subject]].forEach(([k,v])=>{const dt=document.createElement('dt'),dd=document.createElement('dd');dt.textContent=k;dd.textContent=v;$('sender-details').append(dt,dd);});
    $('auth-details').innerHTML='';Object.entries(r.authentication).forEach(([k,v])=>{const row=document.createElement('div');row.className='auth-row';const a=document.createElement('span'),b=document.createElement('span');a.textContent=k.toUpperCase();b.className='auth-status '+(v==='pass'?'pass':v==='fail'?'fail':'neutral');b.textContent=v.toUpperCase();row.append(a,b);$('auth-details').append(row);});
    $('finding-count').textContent=r.findings.length+' finding(s)';$('findings-list').innerHTML='';
    r.findings.forEach(f=>{const item=document.createElement('div');item.className='finding';const dot=document.createElement('i');dot.className='severity '+(f.severity==='high'?'high':f.severity==='low'?'low':'');const body=document.createElement('div'),title=document.createElement('strong'),desc=document.createElement('p');title.textContent=f.title;desc.textContent=f.detail;body.append(title,desc);item.append(dot,body);$('findings-list').append(item);});
    $('url-count').textContent=r.urls.length+' URL(s)';$('url-list').innerHTML='';
    if(!r.urls.length){const p=document.createElement('p');p.className='url-empty';p.textContent='No HTTP or HTTPS links were found in the supplied source.';$('url-list').append(p);}
    r.urls.forEach(u=>{const item=document.createElement('div');item.className='url-item';const code=document.createElement('code');code.textContent=u;const p=document.createElement('p');const host=safeHost(u);p.textContent='Host: '+host+' · '+(u.startsWith('https:')?'HTTPS':'HTTP');item.append(code,p);$('url-list').append(item);});
  }
  function download(name,content,type){const blob=new Blob([content],{type}),url=URL.createObjectURL(blob),a=document.createElement('a');a.href=url;a.download=name;a.click();URL.revokeObjectURL(url);}
})();