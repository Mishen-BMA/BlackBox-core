function buildHttpTester(panel){
    panel.innerHTML = `
    ${toolHeader('','HTTP Request Tester','Make any HTTP request and inspect full response')}
    <div class="tool-wrap">
        <div class="tool-title"> HTTP Request Tester</div>
        <label>URL</label>
        <input type="text" id="httpUrl" placeholder="https://example.com/api/endpoint">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div>
                <label>Method</label>
                <select id="httpMethod">
                    <option>GET</option><option>POST</option><option>PUT</option>
                    <option>DELETE</option><option>PATCH</option><option>HEAD</option><option>OPTIONS</option>
                </select>
            </div>
            <div>
                <label>Timeout (s)</label>
                <input type="number" id="httpTimeout" value="10" min="1" max="60">
            </div>
        </div>
        <label>Headers (JSON object)</label>
        <textarea id="httpHeaders" style="min-height:80px;"
            placeholder='{"Content-Type":"application/json","Authorization":"Bearer token"}'></textarea>
        <label>Body</label>
        <textarea id="httpBody" style="min-height:80px;" placeholder='{"key":"value"}'></textarea>
        <label style="display:flex;align-items:center;gap:8px;margin-bottom:12px;">
            <input type="checkbox" id="httpFollow" checked> Follow redirects
        </label>
        <div class="button-group">
            <button class="btn btn-run" onclick="runHttpTester()">Send Request</button>
            <button class="btn btn-outline" onclick="clearHttpTester()">Clear</button>
        </div>
        ${createOutput('httpOutput','Response')}
    </div>`;
}

async function runHttpTester(){
    const url     = document.getElementById('httpUrl').value.trim();
    const method  = document.getElementById('httpMethod').value;
    const timeout = parseInt(document.getElementById('httpTimeout').value);
    const follow  = document.getElementById('httpFollow').checked;
    const body    = document.getElementById('httpBody').value.trim();
    let headers   = {};
    try{
        const h = document.getElementById('httpHeaders').value.trim();
        if(h) headers = JSON.parse(h);
    } catch(e){ showToast('Invalid headers JSON','error'); return; }

    if(!url){ showToast('Enter a URL','error'); return; }
    setLoading('httpOutput');

    const res = await apiPost('/api/web/request',{ url, method, headers, body, follow_redirects: follow, timeout });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Status: ${d.status_code} ${d.reason}\n`;
        out += `URL: ${d.url}\n`;
        out += `Time: ${d.elapsed_ms}ms\n`;
        out += `Body length: ${d.body_length.toLocaleString()} bytes\n`;
        if(d.redirects.length) out += `Redirects: ${d.redirects.join(' -> ')}\n`;
        out += `\nRESPONSE HEADERS:\n`;
        Object.entries(d.headers).forEach(([k,v]) => out += `  ${k}: ${v}\n`);
        out += `\nBODY (first 5000 chars):\n${d.body}`;
        setOutput('httpOutput', out);
    } else {
        setOutput('httpOutput', `Error: ${res.error}`);
    }
}

function clearHttpTester(){
    ['httpUrl','httpHeaders','httpBody'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
    resetOutput('httpOutput');
}

function buildSqliScanner(panel){
    panel.innerHTML = `
    ${toolHeader('','SQLi Scanner','Test URL parameter for SQL injection indicators')}
    <div class="tool-wrap">
        <div class="warn-box">WARN Only use on systems you own or have permission to test.</div>
        <div class="tool-title"> SQLi Scanner</div>
        <label>Target URL</label>
        <input type="text" id="sqliUrl" placeholder="https://example.com/search">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div><label>Parameter name</label><input type="text" id="sqliParam" value="id"></div>
            <div><label>Baseline value</label><input type="text" id="sqliValue" value="1"></div>
        </div>
        <div class="button-group">
            <button class="btn btn-run" onclick="runSqliScanner()">Test for SQLi</button>
            <button class="btn btn-outline" onclick="clearSqliScanner()">Clear</button>
        </div>
        ${createOutput('sqliOutput','Scan Results')}
    </div>`;
}

async function runSqliScanner(){
    const url   = document.getElementById('sqliUrl').value.trim();
    const param = document.getElementById('sqliParam').value.trim();
    const value = document.getElementById('sqliValue').value.trim();
    if(!url){ showToast('Enter a URL','error'); return; }
    setLoading('sqliOutput');
    const res = await apiPost('/api/web/sqli_test',{ url, param, value });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `URL: ${d.url}\nParameter: ${d.param}\n`;
        out += `Potentially vulnerable: ${d.potentially_vulnerable ? ' YES' : 'OK No'}\n`;
        out += `Tests: ${d.tests_run} | Suspicious: ${d.vulnerable_count}\n\n`;
        d.results.forEach(r => {
            out += `${r.potentially_vulnerable ? '' : 'OK'} ${r.test}\n`;
            out += `   Payload: ${r.payload}\n`;
            if(r.sql_errors?.length) out += `   Errors: ${r.sql_errors.join(', ')}\n`;
            if(r.diff_from_baseline) out += `   Response diff: ${r.diff_from_baseline} bytes\n`;
            out += '\n';
        });
        setOutput('sqliOutput', out);
    } else {
        setOutput('sqliOutput', `Error: ${res.error}`);
    }
}
function clearSqliScanner(){
    document.getElementById('sqliUrl').value='';
    resetOutput('sqliOutput');
}

function buildXssScanner(panel){
    panel.innerHTML = `
    ${toolHeader('','XSS Tester','Test for reflected XSS vulnerability')}
    <div class="tool-wrap">
        <div class="warn-box">WARN Only use on systems you own or have permission to test.</div>
        <div class="tool-title"> XSS Tester</div>
        <label>Target URL</label>
        <input type="text" id="xssUrl" placeholder="https://example.com/search">
        <label>Parameter name</label>
        <input type="text" id="xssParam" value="q">
        <div class="button-group">
            <button class="btn btn-run" onclick="runXssScanner()">Test for XSS</button>
            <button class="btn btn-outline" onclick="clearXssScanner()">Clear</button>
        </div>
        ${createOutput('xssOutput','XSS Test Results')}
    </div>`;
}

async function runXssScanner(){
    const url   = document.getElementById('xssUrl').value.trim();
    const param = document.getElementById('xssParam').value.trim();
    if(!url){ showToast('Enter a URL','error'); return; }
    setLoading('xssOutput');
    const res = await apiPost('/api/web/xss_test',{ url, param });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `URL: ${d.url}\nParameter: ${d.param}\n`;
        out += `Vulnerable: ${d.vulnerable ? ' POSSIBLY YES' : 'OK No reflections found'}\n\n`;
        d.results.forEach(r => {
            const icon = r.vulnerable ? '' : r.reflected ? 'WARN' : 'OK';
            out += `${icon} ${r.payload}\n`;
            if(r.reflected) out += `   Reflected: YES ${r.encoded ? '(encoded - possibly safe)' : '(UNENCODED - vulnerable!)'}\n`;
            out += '\n';
        });
        setOutput('xssOutput', out);
    } else {
        setOutput('xssOutput', `Error: ${res.error}`);
    }
}
function clearXssScanner(){
    document.getElementById('xssUrl').value='';
    resetOutput('xssOutput');
}

function buildCorsTester(panel){
    panel.innerHTML = `
    ${toolHeader('','CORS Tester','Test CORS misconfiguration on a URL')}
    <div class="tool-wrap">
        <div class="warn-box">WARN Only use on systems you own or have permission to test.</div>
        <div class="tool-title"> CORS Tester</div>
        <label>Target URL</label>
        <input type="text" id="corsUrl" placeholder="https://api.example.com/data">
        <div class="button-group">
            <button class="btn btn-run" onclick="runCorsTester()">Test CORS</button>
            <button class="btn btn-outline" onclick="clearCorsTester()">Clear</button>
        </div>
        ${createOutput('corsTestOutput','CORS Test Results')}
    </div>`;
}

async function runCorsTester(){
    const url = document.getElementById('corsUrl').value.trim();
    if(!url){ showToast('Enter a URL','error'); return; }
    setLoading('corsTestOutput');
    const res = await apiPost('/api/web/cors_test',{ url });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `URL: ${d.url}\nVulnerable: ${d.vulnerable ? ' YES' : 'OK No'}\n\n`;
        d.results.forEach(r => {
            const icon = r.vulnerable ? '' : 'OK';
            out += `${icon} Origin: ${r.origin}\n`;
            out += `   ACAO: ${r.acao || '(not set)'}\n`;
            out += `   Credentials: ${r.credentials || '(not set)'}\n\n`;
        });
        setOutput('corsTestOutput', out);
    } else {
        setOutput('corsTestOutput', `Error: ${res.error}`);
    }
}
function clearCorsTester(){
    document.getElementById('corsUrl').value='';
    resetOutput('corsTestOutput');
}

function buildSsrfGen(panel){
    panel.innerHTML = `
    ${toolHeader('','SSRF Payload Generator','Generate SSRF test payloads for a target endpoint')}
    <div class="tool-wrap">
        <div class="tool-title"> SSRF Payload Generator</div>
        <label>Target URL (endpoint that fetches URLs)</label>
        <input type="text" id="ssrfTarget" placeholder="https://example.com/fetch?url=">
        <label>Your callback server (optional)</label>
        <input type="text" id="ssrfCallback" placeholder="http://your-server.com/ssrf">
        <div class="button-group">
            <button class="btn btn-run" onclick="runSsrfGen()">Generate Payloads</button>
            <button class="btn btn-outline" onclick="clearSsrfGen()">Clear</button>
        </div>
        ${createOutput('ssrfOutput','SSRF Payloads')}
    </div>`;
}

async function runSsrfGen(){
    const target   = document.getElementById('ssrfTarget').value.trim();
    const callback = document.getElementById('ssrfCallback').value.trim();
    const res = await apiPost('/api/web/ssrf_payloads',{ target, callback });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Target: ${d.target}\n\nSSRF TEST PAYLOADS:\n\n`;
        d.payloads.forEach(p => {
            out += `${p.desc}\n  ${p.url}\n  Full: ${p.full_url}\n\n`;
        });
        setOutput('ssrfOutput', out);
    } else {
        setOutput('ssrfOutput', `Error: ${res.error}`);
    }
}
function clearSsrfGen(){
    document.getElementById('ssrfTarget').value='';
    resetOutput('ssrfOutput');
}