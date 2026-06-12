function buildRsaFactor(panel){
    panel.innerHTML = `
    ${toolHeader('','RSA Large N Factor','Factor RSA modulus using server-side sympy')}
    <div class="tool-wrap">
        <div class="tool-title"> RSA Large N Factoring</div>
        <div class="info-box">Factors N using sympy on the server. Works for most CTF RSA challenges.</div>
        <label>Modulus N</label>
        <textarea id="rsaFactorN" placeholder="Paste RSA modulus N here (any size)..."></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runRsaFactor()">Factor N</button>
            <button class="btn btn-outline" onclick="clearRsaFactor()">Clear</button>
        </div>
        ${createOutput('rsaFactorOutput','Factoring Result')}
    </div>`;
}

async function runRsaFactor(){
    const n = document.getElementById('rsaFactorN').value.trim();
    if(!n){ showToast('Enter modulus N','error'); return; }
    setOutput('rsaFactorOutput','<span style="color:var(--muted)">Factoring... this may take a moment.</span>',true);
    const res = await apiPost('/api/crypto/rsa/factor',{ n });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `N = ${d.n}\n\nFactors:\n`;
        Object.entries(d.factors).forEach(([k,v]) => out += `  ${k}^${v}\n`);
        if(d.p) out += `\np = ${d.p}\nq = ${d.q}\nphi(n) = ${d.phi}`;
        setOutput('rsaFactorOutput', out);
        showToast('Factoring complete!');
    } else {
        setOutput('rsaFactorOutput', `Error: ${res.error}`);
    }
}

function clearRsaFactor(){
    document.getElementById('rsaFactorN').value = '';
    resetOutput('rsaFactorOutput');
}

function buildRsaWiener(panel){
    panel.innerHTML = `
    ${toolHeader('','RSA Wiener Attack','Recover private key when d is small')}
    <div class="tool-wrap">
        <div class="tool-title"> RSA Wiener Attack</div>
        <div class="info-box">Works when private exponent d &lt; N^0.25. Common in CTF RSA challenges with large e.</div>
        <label>Public Exponent e</label>
        <textarea id="wienerE" placeholder="Paste e here..."></textarea>
        <label>Modulus N</label>
        <textarea id="wienerN" placeholder="Paste N here..."></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runWiener()">Run Wiener Attack</button>
            <button class="btn btn-outline" onclick="clearWiener()">Clear</button>
        </div>
        ${createOutput('wienerOutput','Attack Result')}
    </div>`;
}

async function runWiener(){
    const e = document.getElementById('wienerE').value.trim();
    const n = document.getElementById('wienerN').value.trim();
    if(!e || !n){ showToast('Enter e and N','error'); return; }
    setOutput('wienerOutput','<span style="color:var(--muted)">Running Wiener attack...</span>',true);
    const res = await apiPost('/api/crypto/rsa/wiener',{ e, n });
    if(res.status === 'ok'){
        const d = res.data;
        if(d.vulnerable){
            setOutput('wienerOutput',
                `OK VULNERABLE!\n\np = ${d.p}\nq = ${d.q}\nd = ${d.d}\nphi(n) = ${d.phi}\n\n${d.message}`
            );
            showToast('Wiener attack succeeded!');
        } else {
            setOutput('wienerOutput', `NO Not vulnerable\n\n${d.message}`);
        }
    } else {
        setOutput('wienerOutput', `Error: ${res.error}`);
    }
}

function clearWiener(){
    document.getElementById('wienerE').value = '';
    document.getElementById('wienerN').value = '';
    resetOutput('wienerOutput');
}

function buildRsaDecrypt(panel){
    panel.innerHTML = `
    ${toolHeader('','RSA Decrypt (p,q known)','Decrypt RSA ciphertext when p and q are known')}
    <div class="tool-wrap">
        <div class="tool-title"> RSA Decrypt</div>
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div><label>Prime p</label><textarea id="rsaP" style="min-height:80px;" placeholder="p..."></textarea></div>
            <div><label>Prime q</label><textarea id="rsaQ" style="min-height:80px;" placeholder="q..."></textarea></div>
        </div>
        <label>Public exponent e</label>
        <input type="text" id="rsaE" value="65537">
        <label>Ciphertext c (integer)</label>
        <textarea id="rsaC" placeholder="Paste ciphertext integer here..."></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runRsaDecrypt()">Decrypt</button>
            <button class="btn btn-outline" onclick="clearRsaDecrypt()">Clear</button>
        </div>
        ${createOutput('rsaDecOutput','Plaintext')}
    </div>`;
}

async function runRsaDecrypt(){
    const p = document.getElementById('rsaP').value.trim();
    const q = document.getElementById('rsaQ').value.trim();
    const e = document.getElementById('rsaE').value.trim();
    const c = document.getElementById('rsaC').value.trim();
    if(!p||!q||!c){ showToast('Fill all fields','error'); return; }
    const res = await apiPost('/api/crypto/rsa/decrypt',{ p, q, e, c });
    if(res.status === 'ok'){
        const d = res.data;
        setOutput('rsaDecOutput',
            `Plaintext: ${d.plaintext}\n\nn = ${d.n}\nphi(n) = ${d.phi}\nd = ${d.d}\nm (int) = ${d.m_int}\nm (hex) = ${d.m_hex}`
        );
        showToast('Decryption complete!');
    } else {
        setOutput('rsaDecOutput', `Error: ${res.error}`);
    }
}

function clearRsaDecrypt(){
    ['rsaP','rsaQ','rsaE','rsaC'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
    resetOutput('rsaDecOutput');
}

function buildRsaHastad(panel){
    panel.innerHTML = `
    ${toolHeader('','RSA Hastad Broadcast Attack','Attack when same message is encrypted with e public keys')}
    <div class="tool-wrap">
        <div class="tool-title"> Hastad Broadcast Attack</div>
        <div class="info-box">Requires e ciphertext/modulus pairs. Most common: e=3 (need 3 pairs).</div>
        <label>Public Exponent e</label>
        <input type="number" id="hastadE" value="3" min="2" max="17">
        <label>Ciphertexts (one per line)</label>
        <textarea id="hastadC" placeholder="c1&#10;c2&#10;c3" style="min-height:100px;"></textarea>
        <label>Moduli N (one per line)</label>
        <textarea id="hastadN" placeholder="n1&#10;n2&#10;n3" style="min-height:100px;"></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runHastad()">Run Hastad Attack</button>
            <button class="btn btn-outline" onclick="clearHastad()">Clear</button>
        </div>
        ${createOutput('hastadOutput','Attack Result')}
    </div>`;
}

async function runHastad(){
    const e  = document.getElementById('hastadE').value;
    const cs = document.getElementById('hastadC').value.trim().split('\n').map(s=>s.trim()).filter(Boolean);
    const ns = document.getElementById('hastadN').value.trim().split('\n').map(s=>s.trim()).filter(Boolean);
    if(!cs.length || !ns.length){ showToast('Enter ciphertexts and moduli','error'); return; }
    setOutput('hastadOutput','<span style="color:var(--muted)">Running Hastad attack...</span>',true);
    const res = await apiPost('/api/crypto/rsa/hastad',{ e: parseInt(e), ciphertexts: cs, moduli: ns });
    if(res.status === 'ok'){
        const d = res.data;
        setOutput('hastadOutput',
            `Plaintext: ${d.plaintext}\n\nm (int): ${d.message}\nm (hex): ${d.hex}`
        );
        showToast('Hastad attack complete!');
    } else {
        setOutput('hastadOutput', `Error: ${res.error}`);
    }
}

function clearHastad(){
    ['hastadC','hastadN'].forEach(id => { const el=document.getElementById(id); if(el) el.value=''; });
    resetOutput('hastadOutput');
}

function buildRsaKeyParser(panel){
    panel.innerHTML = `
    ${toolHeader('','RSA Key Parser','Extract n, e, d, p, q from PEM key')}
    <div class="tool-wrap">
        <div class="tool-title"> RSA Key Parser</div>
        <label>PEM Key (public or private)</label>
        <textarea id="rsaPem" style="min-height:150px;"
            placeholder="-----BEGIN PUBLIC KEY-----&#10;...&#10;-----END PUBLIC KEY-----"></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runRsaKeyParser()">Parse Key</button>
            <button class="btn btn-outline" onclick="clearRsaKeyParser()">Clear</button>
        </div>
        ${createOutput('rsaKeyOutput','Key Components')}
    </div>`;
}

async function runRsaKeyParser(){
    const pem = document.getElementById('rsaPem').value.trim();
    if(!pem){ showToast('Paste a PEM key','error'); return; }
    const res = await apiPost('/api/crypto/rsa/parse_key',{ pem });
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Key Size: ${d.key_size} bits\nHas Private Key: ${d.has_private}\n\ne = ${d.e}\nn = ${d.n}`;
        if(d.has_private) out += `\nd = ${d.d}\np = ${d.p}\nq = ${d.q}`;
        setOutput('rsaKeyOutput', out);
    } else {
        setOutput('rsaKeyOutput', `Error: ${res.error}`);
    }
}

function clearRsaKeyParser(){
    document.getElementById('rsaPem').value = '';
    resetOutput('rsaKeyOutput');
}