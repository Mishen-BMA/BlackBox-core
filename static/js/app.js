// =========================
// API HELPERS
// =========================

async function apiPost(endpoint, data){
    try{
        const r = await fetch(endpoint, {
            method:  'POST',
            headers: { 'Content-Type': 'application/json' },
            body:    JSON.stringify(data),
        });
        return await r.json();
    } catch(e){
        return { status: 'error', error: e.message };
    }
}

async function apiUpload(endpoint, file){
    const fd = new FormData();
    fd.append('file', file);
    try{
        const r = await fetch(endpoint, { method: 'POST', body: fd });
        return await r.json();
    } catch(e){
        return { status: 'error', error: e.message };
    }
}

async function apiUploadForm(endpoint, formData){
    try{
        const r = await fetch(endpoint, { method: 'POST', body: formData });
        return await r.json();
    } catch(e){
        return { status: 'error', error: e.message };
    }
}

// =========================
// OUTPUT HELPERS
// =========================

function createOutput(id, label='Output'){
    return `
    <div class="output-label">${label}</div>
    <div class="output-box" id="${id}">
        <span style="color:var(--muted)">Result will appear here...</span>
        <div class="output-actions">
            <button class="output-action-btn" onclick="copyOutput('${id}',this)"> Copy</button>
            <button class="output-action-btn" onclick="exportOutput('${id}')"> Save</button>
        </div>
    </div>`;
}

function setOutput(id, content, isHTML=false){
    const el = document.getElementById(id);
    if(!el) return;
    if(isHTML){
        el.innerHTML = content + `<div class="output-actions">
            <button class="output-action-btn" onclick="copyOutput('${id}',this)"> Copy</button>
            <button class="output-action-btn" onclick="exportOutput('${id}')"> Save</button>
        </div>`;
    } else {
        el.textContent = content;
        el.innerHTML += `<div class="output-actions">
            <button class="output-action-btn" onclick="copyOutput('${id}',this)"> Copy</button>
            <button class="output-action-btn" onclick="exportOutput('${id}')"> Save</button>
        </div>`;
    }
}

function setLoading(id){
    const el = document.getElementById(id);
    if(el) el.innerHTML = '<div class="spinner"></div> <span style="color:var(--muted);margin-left:10px;">Processing...</span>';
}

function resetOutput(id){
    const el = document.getElementById(id);
    if(el) el.innerHTML = '<span style="color:var(--muted)">Result will appear here...</span>';
}

function copyOutput(id, btn){
    const el = document.getElementById(id);
    if(!el) return;
    const text = el.innerText || el.textContent;
    navigator.clipboard.writeText(text).then(() => {
        if(btn){ btn.textContent='OK Copied'; setTimeout(()=>btn.textContent=' Copy',2000); }
        showToast('Copied!');
    });
}

function exportOutput(id){
    const el = document.getElementById(id);
    if(!el) return;
    const text = el.innerText;
    const blob = new Blob([text], {type:'text/plain'});
    const a    = document.createElement('a');
    a.href     = URL.createObjectURL(blob);
    a.download = `blackbox-core-${id}-${Date.now()}.txt`;
    a.click();
}

function copyText(text, btn){
    navigator.clipboard.writeText(text).then(() => {
        showToast('Copied!');
        if(btn){ const orig=btn.textContent; btn.textContent='OK'; setTimeout(()=>btn.textContent=orig,2000); }
    });
}

// =========================
// TOAST
// =========================

function showToast(msg, type='success'){
    const c     = document.getElementById('toastContainer');
    if(!c) return;
    const toast = document.createElement('div');
    toast.className = `toast ${type}`;
    toast.textContent = msg;
    c.appendChild(toast);
    setTimeout(() => toast.remove(), 3000);
}

// =========================
// NAVIGATION
// =========================

let currentView = 'dashboard';
let currentTool = null;

function showView(viewId){
    document.querySelectorAll('.view').forEach(v => v.classList.remove('active'));
    document.querySelectorAll('.tool-panel').forEach(p => p.style.display='none');
    document.querySelectorAll('.card-grid').forEach(g => g.style.display='grid');
    const target = document.getElementById(viewId);
    if(target) target.classList.add('active');
    currentView = viewId; currentTool = null;
    document.querySelectorAll('.nav-btn').forEach(btn => btn.classList.remove('active'));
    const activeBtn = [...document.querySelectorAll('.nav-btn')]
        .find(b => b.getAttribute('onclick')?.includes(`'${viewId}'`));
    if(activeBtn) activeBtn.classList.add('active');
    window.scrollTo({top:0,behavior:'smooth'});
}

function showTool(toolId){
    document.querySelectorAll('.card-grid').forEach(g => g.style.display='none');
    document.querySelectorAll('.tool-panel').forEach(p => p.style.display='none');
    const panel = document.getElementById(toolId);
    if(!panel) return;
    panel.style.display = 'block';
    buildTool(toolId, panel);
    currentTool = toolId;
    window.scrollTo({top:0,behavior:'smooth'});
}

function goBack(){
    if(currentTool){
        document.querySelectorAll('.tool-panel').forEach(p => p.style.display='none');
        document.querySelectorAll('.card-grid').forEach(g => g.style.display='grid');
        currentTool = null;
    } else {
        showView('dashboard');
    }
}

function toolHeader(icon, name, desc){
    return `
    <button class="back-btn" onclick="goBack()"><- Back</button>
    <div class="view-header"><h2>${icon} ${name}</h2><p>${desc}</p></div>`;
}

// =========================
// SEARCH
// =========================

const ALL_TOOLS = [
    {id:'rsaFactor',      name:'RSA Large N Factor',       section:'crypto',    icon:'', desc:'Factor RSA modulus sympy'},
    {id:'rsaWiener',      name:'RSA Wiener Attack',         section:'crypto',    icon:'', desc:'Recover small private exponent'},
    {id:'rsaDecrypt',     name:'RSA Decrypt p q known',     section:'crypto',    icon:'', desc:'Decrypt given p q e ciphertext'},
    {id:'rsaHastad',      name:'RSA Hastad Broadcast',      section:'crypto',    icon:'', desc:'Broadcast attack e=3'},
    {id:'rsaKeyParser',   name:'RSA Key Parser',            section:'crypto',    icon:'', desc:'Parse PEM key extract components'},
    {id:'dnsLookup',      name:'DNS Lookup',                section:'network',   icon:'', desc:'A AAAA MX TXT NS CNAME records'},
    {id:'whoisLookup',    name:'WHOIS Lookup',              section:'network',   icon:'', desc:'Domain registration data'},
    {id:'portScan',       name:'Port Scanner',              section:'network',   icon:'', desc:'TCP scan banner grabbing'},
    {id:'geoIp',          name:'GeoIP Lookup',              section:'network',   icon:'', desc:'IP geolocation ISP ASN'},
    {id:'subdomainRecon', name:'Subdomain Recon',           section:'network',   icon:'', desc:'Find subdomains crt.sh DNS'},
    {id:'sslInfo',        name:'SSL Certificate',           section:'network',   icon:'', desc:'SSL cert details expiry SANs'},
    {id:'headerCheck',    name:'Security Headers',          section:'network',   icon:'', desc:'HTTP security header analysis'},
    {id:'fileAnalysis',   name:'Full File Analysis',        section:'forensics', icon:'', desc:'Magic bytes hashes entropy strings'},
    {id:'stringsExtract', name:'Strings Extractor',         section:'forensics', icon:'', desc:'Extract strings from binary'},
    {id:'hexDumpTool',    name:'Hex Dump',                  section:'forensics', icon:'', desc:'Full hex dump with ASCII'},
    {id:'zipCrack',       name:'ZIP Password Cracker',      section:'forensics', icon:'', desc:'Crack ZIP password wordlist'},
    {id:'lsbStego',       name:'LSB Steganography',         section:'forensics', icon:'', desc:'Server-side LSB extraction Pillow'},
    {id:'entropyTool',    name:'Entropy Analysis',          section:'forensics', icon:'', desc:'Shannon entropy byte frequency'},
    {id:'httpTester',     name:'HTTP Request Tester',       section:'webtools',  icon:'', desc:'Make HTTP requests inspect response'},
    {id:'sqliScanner',    name:'SQLi Scanner',              section:'webtools',  icon:'', desc:'Test SQL injection'},
    {id:'xssScanner',     name:'XSS Tester',               section:'webtools',  icon:'', desc:'Test reflected XSS'},
    {id:'corsTester',     name:'CORS Tester',               section:'webtools',  icon:'', desc:'Test CORS misconfiguration'},
    {id:'ssrfGen',        name:'SSRF Payload Generator',    section:'webtools',  icon:'', desc:'Generate SSRF payloads'},
    {id:'encodeDecode',   name:'Encode Decode',             section:'utils',     icon:'', desc:'Base64 Base32 hex URL HTML binary'},
    {id:'hashTool',       name:'Hash Generator',            section:'utils',     icon:'', desc:'MD5 SHA Blake2 hash generation'},
    {id:'baseConvert',    name:'Base Converter',            section:'utils',     icon:'', desc:'Convert numbers between bases'},
    {id:'regexTool',      name:'Regex Search',              section:'utils',     icon:'', desc:'Search text with regex patterns'},
    {id:'jsonFormat',     name:'JSON Formatter',            section:'utils',     icon:'', desc:'Validate and format JSON'},
    {id:'urlParse',       name:'URL Parser',                section:'utils',     icon:'', desc:'Parse URL components and query'},
    {id:'flagExtract',    name:'Flag Extractor',            section:'utils',     icon:'', desc:'Extract CTF flags from text'},
];

const SECTIONS = {
    crypto:    ' Cryptography',
    network:   ' Network Recon',
    forensics: ' Forensics',
    webtools:  ' Web Testing',
    utils:     ' Utilities',
};

const globalSearch  = document.getElementById('globalSearch');
const sidebarSearch = document.getElementById('sidebarSearch');
const searchResults = document.getElementById('searchResults');

function searchTools(query){
    const q = query.trim().toLowerCase();
    if(!q) return [];
    return ALL_TOOLS.filter(t =>
        t.name.toLowerCase().includes(q) || t.desc.toLowerCase().includes(q)
    );
}

if(globalSearch){
globalSearch.addEventListener('input', function(){
    const q = this.value.trim().toLowerCase();
    if(!q){ searchResults.classList.remove('open'); return; }
    const matches = searchTools(q);
    if(!matches.length){
        searchResults.innerHTML = `<div class="search-no-results">No tools found</div>`;
        searchResults.classList.add('open');
        return;
    }
    searchResults.innerHTML = matches.slice(0,8).map(t => `
    <div class="search-result-item" onclick="openFromSearch('${t.id}','${t.section}')">
        <span class="result-icon">${t.icon}</span>
        <div>
            <div class="result-name">${t.name}</div>
            <div class="result-section">${SECTIONS[t.section]}</div>
        </div>
    </div>`).join('');
    searchResults.classList.add('open');
});
}

if(sidebarSearch){
sidebarSearch.addEventListener('input', function(){
    const matches = searchTools(this.value);
    document.querySelectorAll('.card').forEach(card => {
        const text = card.innerText.toLowerCase();
        card.style.display = !this.value || text.includes(this.value.toLowerCase()) ? '' : 'none';
    });
    if(matches.length === 1 && this.value.trim().length > 2){
        showView(matches[0].section);
    }
});
}

function openFromSearch(toolId, section){
    if(globalSearch) globalSearch.value = '';
    if(searchResults) searchResults.classList.remove('open');
    showView(section);
    setTimeout(() => showTool(toolId), 50);
}

document.addEventListener('click', e => {
    if(searchResults && !e.target.closest('.topbar-search')) searchResults.classList.remove('open');
});

document.addEventListener('keydown', e => {
    if(e.key==='/' && document.activeElement.tagName!=='INPUT' && document.activeElement.tagName!=='TEXTAREA'){
        if(globalSearch){ e.preventDefault(); globalSearch.focus(); }
    }
    if(e.key==='Escape'){
        if(searchResults && searchResults.classList.contains('open')){
            searchResults.classList.remove('open');
            if(globalSearch) globalSearch.blur();
        } else if(currentTool){ goBack(); }
    }
});

// =========================
// THEME
// =========================

function setTheme(theme){
    document.documentElement.setAttribute('data-theme', theme);
    document.querySelectorAll('.theme-dot').forEach(d => d.classList.remove('active'));
    const dot = document.querySelector(`.theme-dot.${theme}`);
    if(dot) dot.classList.add('active');
    try{ localStorage.setItem('bc_theme', theme); } catch(e){}
}
try{ const t=localStorage.getItem('bc_theme'); if(t) setTheme(t); } catch(e){}

// =========================
// TOOL ROUTER
// =========================

function buildTool(toolId, panel){
    if(panel.dataset.built) return;
    const builders = {
        rsaFactor:      buildRsaFactor,
        rsaWiener:      buildRsaWiener,
        rsaDecrypt:     buildRsaDecrypt,
        rsaHastad:      buildRsaHastad,
        rsaKeyParser:   buildRsaKeyParser,
        dnsLookup:      buildDnsLookup,
        whoisLookup:    buildWhoisLookup,
        portScan:       buildPortScan,
        geoIp:          buildGeoIp,
        subdomainRecon: buildSubdomainRecon,
        sslInfo:        buildSslInfo,
        headerCheck:    buildHeaderCheck,
        fileAnalysis:   buildFileAnalysis,
        stringsExtract: buildStringsExtract,
        hexDumpTool:    buildHexDumpTool,
        zipCrack:       buildZipCrack,
        lsbStego:       buildLsbStego,
        entropyTool:    buildEntropyTool,
        httpTester:     buildHttpTester,
        sqliScanner:    buildSqliScanner,
        xssScanner:     buildXssScanner,
        corsTester:     buildCorsTester,
        ssrfGen:        buildSsrfGen,
        encodeDecode:   buildEncodeDecode,
        hashTool:       buildHashTool,
        baseConvert:    buildBaseConvert,
        regexTool:      buildRegexTool,
        jsonFormat:     buildJsonFormat,
        urlParse:       buildUrlParse,
        flagExtract:    buildFlagExtract,
    };
    const builder = builders[toolId];
    if(builder){ builder(panel); panel.dataset.built = 'true'; }
}

// =========================
// SERVER STATUS CHECK
// =========================

async function checkServer(){
    try{
        const r   = await fetch('/api/ping');
        const data = await r.json();
        const el  = document.getElementById('serverStatus');
        if(el) el.innerHTML = `<span style="color:var(--success);"> Server Online</span>`;
    } catch(e){
        const el = document.getElementById('serverStatus');
        if(el) el.innerHTML = `<span style="color:var(--danger);"> Server Offline</span>`;
    }
}

checkServer();
setInterval(checkServer, 30000);
