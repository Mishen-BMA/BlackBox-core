function buildDnsLookup(panel){
    panel.innerHTML = `
    ${toolHeader('','DNS Lookup','Full DNS record lookup - A, AAAA, MX, TXT, NS, CNAME, SOA')}
    <div class="tool-wrap">
        <div class="tool-title"> DNS Lookup</div>
        <label>Domain or IP</label>
        <input type="text" id="dnsTarget" placeholder="example.com or 8.8.8.8">
        <div class="button-group">
            <button class="btn btn-run" onclick="runDnsLookup()">Lookup</button>
            <button class="btn btn-outline" onclick="clearDns()">Clear</button>
        </div>
        ${createOutput('dnsOutput','DNS Records')}
    </div>`;
}

async function runDnsLookup(){
    const target = document.getElementById('dnsTarget').value.trim();
    if(!target){ showToast('Enter a domain or IP','error'); return; }
    setLoading('dnsOutput');
    const res = await apiPost('/api/network/dns',{ target });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Target: ${d.target}\n\n`;
        const records = d.records || {};
        Object.entries(records).forEach(([type, vals]) => {
            out += `${type}:\n`;
            vals.forEach(v => out += `  ${v}\n`);
            out += '\n';
        });
        if(d.reverse_dns) out += `Reverse DNS:\n  ${d.reverse_dns.join(', ')}`;
        setOutput('dnsOutput', out);
    } else {
        setOutput('dnsOutput', `Error: ${res.error}`);
    }
}
function clearDns(){ document.getElementById('dnsTarget').value=''; resetOutput('dnsOutput'); }

function buildWhoisLookup(panel){
    panel.innerHTML = `
    ${toolHeader('','WHOIS Lookup','Full WHOIS registration data for domain or IP')}
    <div class="tool-wrap">
        <div class="tool-title"> WHOIS Lookup</div>
        <label>Domain or IP</label>
        <input type="text" id="whoisTarget" placeholder="example.com">
        <div class="button-group">
            <button class="btn btn-run" onclick="runWhois()">WHOIS</button>
            <button class="btn btn-outline" onclick="clearWhois()">Clear</button>
        </div>
        ${createOutput('whoisOutput','WHOIS Data')}
    </div>`;
}

async function runWhois(){
    const target = document.getElementById('whoisTarget').value.trim();
    if(!target){ showToast('Enter a domain','error'); return; }
    setLoading('whoisOutput');
    const res = await apiPost('/api/network/whois',{ target });
    if(res.status === 'ok'){
        let out = '';
        Object.entries(res.data).forEach(([k,v]) => {
            out += `${k.replace(/_/g,' ').toUpperCase()}: ${Array.isArray(v)?v.join(', '):v}\n`;
        });
        setOutput('whoisOutput', out || 'No data returned');
    } else {
        setOutput('whoisOutput', `Error: ${res.error}`);
    }
}
function clearWhois(){ document.getElementById('whoisTarget').value=''; resetOutput('whoisOutput'); }

function buildPortScan(panel){
    panel.innerHTML = `
    ${toolHeader('','Port Scanner','TCP port scan with service detection and banner grabbing')}
    <div class="tool-wrap">
        <div class="tool-title"> Port Scanner</div>
        <label>Target (IP or domain)</label>
        <input type="text" id="portTarget" placeholder="192.168.1.1 or example.com">
        <label>Ports (comma separated, or leave for top 20)</label>
        <input type="text" id="portList" placeholder="21,22,80,443,3306,8080">
        <label>Timeout (seconds)</label>
        <input type="number" id="portTimeout" value="0.8" min="0.1" max="5" step="0.1">
        <div class="button-group">
            <button class="btn btn-run" onclick="runPortScan()">Scan Ports</button>
            <button class="btn btn-outline" onclick="clearPortScan()">Clear</button>
        </div>
        ${createOutput('portOutput','Scan Results')}
    </div>`;
}

async function runPortScan(){
    const target  = document.getElementById('portTarget').value.trim();
    const portsRaw = document.getElementById('portList').value.trim();
    const timeout = parseFloat(document.getElementById('portTimeout').value) || 0.8;
    if(!target){ showToast('Enter a target','error'); return; }

    const ports = portsRaw
        ? portsRaw.split(',').map(p => parseInt(p.trim())).filter(p => !isNaN(p))
        : [];

    setLoading('portOutput');
    const res = await apiPost('/api/network/portscan',{ target, ports, timeout });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Target: ${d.target} (${d.ip})\nOpen ports: ${d.total_open}\n\n`;
        if(d.open_ports.length){
            d.open_ports.forEach(p => {
                out += `PORT ${p.port}/tcp  OPEN  ${p.service}`;
                if(p.banner) out += `\n  Banner: ${p.banner}`;
                out += '\n';
            });
        } else {
            out += 'No open ports found.';
        }
        setOutput('portOutput', out);
        showToast(`Found ${d.total_open} open port(s)`);
    } else {
        setOutput('portOutput', `Error: ${res.error}`);
    }
}
function clearPortScan(){
    ['portTarget','portList'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
    resetOutput('portOutput');
}

function buildGeoIp(panel){
    panel.innerHTML = `
    ${toolHeader('','GeoIP Lookup','IP geolocation, ISP, ASN and timezone information')}
    <div class="tool-wrap">
        <div class="tool-title"> GeoIP Lookup</div>
        <label>IP Address</label>
        <input type="text" id="geoIpInput" placeholder="8.8.8.8">
        <div class="button-group">
            <button class="btn btn-run" onclick="runGeoIp()">Lookup</button>
            <button class="btn btn-outline" onclick="clearGeoIp()">Clear</button>
        </div>
        ${createOutput('geoIpOutput','Geolocation Data')}
    </div>`;
}

async function runGeoIp(){
    const ip = document.getElementById('geoIpInput').value.trim();
    if(!ip){ showToast('Enter an IP address','error'); return; }
    setLoading('geoIpOutput');
    const res = await apiPost('/api/network/geoip',{ ip });
    if(res.status === 'ok'){
        const d = res.data;
        const out = Object.entries(d)
            .filter(([k]) => k !== 'status')
            .map(([k,v]) => `${k.padEnd(16)} ${v}`)
            .join('\n');
        setOutput('geoIpOutput', out);
    } else {
        setOutput('geoIpOutput', `Error: ${res.error}`);
    }
}
function clearGeoIp(){ document.getElementById('geoIpInput').value=''; resetOutput('geoIpOutput'); }

function buildSubdomainRecon(panel){
    panel.innerHTML = `
    ${toolHeader('','Subdomain Recon','Find subdomains via certificate transparency logs + DNS resolution')}
    <div class="tool-wrap">
        <div class="tool-title"> Subdomain Recon</div>
        <label>Domain</label>
        <input type="text" id="subdomainInput" placeholder="example.com">
        <div class="button-group">
            <button class="btn btn-run" onclick="runSubdomainRecon()">Find Subdomains</button>
            <button class="btn btn-outline" onclick="clearSubdomain()">Clear</button>
        </div>
        ${createOutput('subdomainOutput','Subdomains Found')}
    </div>`;
}

async function runSubdomainRecon(){
    const domain = document.getElementById('subdomainInput').value.trim();
    if(!domain){ showToast('Enter a domain','error'); return; }
    setLoading('subdomainOutput');
    const res = await apiPost('/api/network/subdomains',{ domain });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Domain: ${d.domain}\nTotal found: ${d.total}\n\n`;
        d.subdomains.forEach(s => {
            const status = s.alive ? `ALIVE  ${s.ip}` : 'DEAD';
            out += `${s.subdomain.padEnd(40)} ${status}\n`;
        });
        setOutput('subdomainOutput', out);
        showToast(`Found ${d.total} subdomains`);
    } else {
        setOutput('subdomainOutput', `Error: ${res.error}`);
    }
}
function clearSubdomain(){ document.getElementById('subdomainInput').value=''; resetOutput('subdomainOutput'); }

function buildSslInfo(panel){
    panel.innerHTML = `
    ${toolHeader('','SSL Certificate','Full SSL certificate details including expiry and SANs')}
    <div class="tool-wrap">
        <div class="tool-title"> SSL Certificate Info</div>
        <label>Domain</label>
        <input type="text" id="sslDomain" placeholder="example.com">
        <div class="button-group">
            <button class="btn btn-run" onclick="runSslInfo()">Get SSL Info</button>
            <button class="btn btn-outline" onclick="clearSsl()">Clear</button>
        </div>
        ${createOutput('sslOutput','SSL Certificate')}
    </div>`;
}

async function runSslInfo(){
    const domain = document.getElementById('sslDomain').value.trim();
    if(!domain){ showToast('Enter a domain','error'); return; }
    setLoading('sslOutput');
    const res = await apiPost('/api/network/ssl',{ domain });
    if(res.status === 'ok'){
        const d = res.data;
        const exp = d.expired ? 'WARN EXPIRED' : `OK Valid (${d.days_left} days left)`;
        let out = `Domain:      ${d.domain}\n`;
        out += `Status:      ${exp}\n`;
        out += `Expires:     ${d.not_after}\n`;
        out += `Issued By:   ${d.issuer?.organizationName || 'N/A'}\n`;
        out += `Common Name: ${d.subject?.commonName || 'N/A'}\n`;
        out += `Serial:      ${d.serial}\n`;
        if(d.sans?.length) out += `\nSANs:\n${d.sans.map(s=>'  '+s).join('\n')}`;
        setOutput('sslOutput', out);
    } else {
        setOutput('sslOutput', `Error: ${res.error}`);
    }
}
function clearSsl(){ document.getElementById('sslDomain').value=''; resetOutput('sslOutput'); }

function buildHeaderCheck(panel){
    panel.innerHTML = `
    ${toolHeader('','Security Headers','Fetch and analyze HTTP security headers from any URL')}
    <div class="tool-wrap">
        <div class="tool-title"> Security Headers Analyzer</div>
        <label>URL</label>
        <input type="text" id="headerUrl" placeholder="https://example.com">
        <div class="button-group">
            <button class="btn btn-run" onclick="runHeaderCheck()">Analyze Headers</button>
            <button class="btn btn-outline" onclick="clearHeaderCheck()">Clear</button>
        </div>
        ${createOutput('headerCheckOutput','Header Analysis')}
    </div>`;
}

async function runHeaderCheck(){
    const url = document.getElementById('headerUrl').value.trim();
    if(!url){ showToast('Enter a URL','error'); return; }
    setLoading('headerCheckOutput');
    const res = await apiPost('/api/network/headers',{ url });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `URL: ${d.final_url}\nStatus: ${d.status_code}\nSecurity Score: ${d.security_score}\n\n`;
        out += 'SECURITY HEADERS:\n';
        d.security_analysis.forEach(h => {
            const icon = h.present ? 'OK' : 'NO';
            out += `${icon} ${h.header}\n`;
            if(h.value) out += `   Value: ${h.value}\n`;
        });
        out += '\nALL HEADERS:\n';
        Object.entries(d.all_headers).forEach(([k,v]) => {
            out += `  ${k}: ${v}\n`;
        });
        setOutput('headerCheckOutput', out);
    } else {
        setOutput('headerCheckOutput', `Error: ${res.error}`);
    }
}
function clearHeaderCheck(){ document.getElementById('headerUrl').value=''; resetOutput('headerCheckOutput'); }