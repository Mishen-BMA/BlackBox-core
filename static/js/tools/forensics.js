function buildFileAnalysis(panel){
    panel.innerHTML = `
    ${toolHeader('','Full File Analysis','Magic bytes, hashes, entropy, strings - all in one shot')}
    <div class="tool-wrap">
        <div class="tool-title"> Full File Analysis</div>
        <label>Upload File</label>
        <input type="file" id="analysisFile">
        <label>Flag format (optional)</label>
        <input type="text" id="analysisFlagFormat" placeholder="flag{} or picoCTF{...}">
        <div class="button-group">
            <button class="btn btn-run" onclick="runFileAnalysis()">Analyze</button>
            <button class="btn btn-outline" onclick="clearFileAnalysis()">Clear</button>
        </div>
        ${createOutput('analysisOutput','Analysis Results')}
    </div>`;
}

async function runFileAnalysis(){
    const file = document.getElementById('analysisFile').files[0];
    const flagFormat = document.getElementById('analysisFlagFormat').value.trim();
    if(!file){ showToast('Upload a file','error'); return; }
    setLoading('analysisOutput');
    const res = await apiUpload('/api/forensics/analyze', file);
    if(res.status === 'ok'){
        const d = res.data;
        let out = `File: ${d.filename}\nSize: ${d.size.toLocaleString()} bytes\n`;
        out += `Type: ${d.file_type}\n`;
        out += `Entropy: ${d.entropy} bits/byte\n`;
        out += `Text file: ${d.is_text}\nEncrypted/Compressed: ${d.is_encrypted}\n\n`;
        out += `HASHES:\n  MD5:    ${d.hashes.md5}\n  SHA1:   ${d.hashes.sha1}\n  SHA256: ${d.hashes.sha256}\n\n`;
        out += `HEX PREVIEW (first 256 bytes):\n${d.hex_preview}\n\n`;
        out += `STRINGS (first 50):\n${d.strings.slice(0,50).map(s=>'  '+s).join('\n')}`;
        if(d.string_count > 50) out += `\n  ... and ${d.string_count-50} more strings`;
        if(flagFormat){
            const stringsText = d.strings.join('\n');
            const flagRes = await findFlags(stringsText, flagFormat);
            if(flagRes.status === 'ok'){
                setOutput('analysisOutput',
                    `<div class="plain-output-block">${escapeHtml(out)}</div>` +
                    flagResultsHtml(stringsText, flagRes.data, {
                        title: 'Flags found in strings',
                        sourceLabel: 'Extracted Strings'
                    }),
                    true
                );
            } else {
                setOutput('analysisOutput', `${out}\n\nFlag search error: ${flagRes.error}`);
            }
        } else {
            setOutput('analysisOutput', out);
        }
        showToast('Analysis complete!');
    } else {
        setOutput('analysisOutput', `Error: ${res.error}`);
    }
}
function clearFileAnalysis(){
    document.getElementById('analysisFile').value='';
    document.getElementById('analysisFlagFormat').value='';
    resetOutput('analysisOutput');
}

function buildStringsExtract(panel){
    panel.innerHTML = `
    ${toolHeader('','Strings Extractor','Extract printable strings with filter support')}
    <div class="tool-wrap">
        <div class="tool-title"> Strings Extractor</div>
        <label>Upload File</label>
        <input type="file" id="stringsFile">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div><label>Min Length</label><input type="number" id="stringsMin" value="4" min="1"></div>
            <div><label>Filter keyword (optional)</label><input type="text" id="stringsFilter" placeholder="flag, pass, key..."></div>
        </div>
        <label>Flag format (optional)</label>
        <input type="text" id="stringsFlagFormat" placeholder="flag{} or picoCTF{...}">
        <div class="button-group">
            <button class="btn btn-run" onclick="runStringsExtract()">Extract</button>
            <button class="btn btn-outline" onclick="clearStrings()">Clear</button>
        </div>
        ${createOutput('stringsOutput','Strings')}
    </div>`;
}

async function runStringsExtract(){
    const file   = document.getElementById('stringsFile').files[0];
    const minLen = document.getElementById('stringsMin').value;
    const filter = document.getElementById('stringsFilter').value;
    const flagFormat = document.getElementById('stringsFlagFormat').value.trim();
    if(!file){ showToast('Upload a file','error'); return; }
    setLoading('stringsOutput');
    const fd = new FormData();
    fd.append('file', file);
    fd.append('min_len', minLen);
    fd.append('filter', filter);
    const res = await apiUploadForm('/api/forensics/strings', fd);
    if(res.status === 'ok'){
        const d = res.data;
        const header = `Total strings: ${d.total}${d.filter ? ` (filtered by "${d.filter}")` : ''}\n\n`;
        const stringsText = d.strings.join('\n');
        if(flagFormat){
            const flagRes = await findFlags(stringsText, flagFormat);
            if(flagRes.status === 'ok'){
                setOutput('stringsOutput',
                    `<div class="plain-output-block">${escapeHtml(header)}</div>` +
                    flagResultsHtml(stringsText, flagRes.data, {
                        title: 'Flags found',
                        sourceLabel: 'Strings'
                    }),
                    true
                );
            } else {
                setOutput('stringsOutput', `${header}${stringsText}\n\nFlag search error: ${flagRes.error}`);
            }
        } else {
            setOutput('stringsOutput', header + stringsText);
        }
    } else {
        setOutput('stringsOutput', `Error: ${res.error}`);
    }
}
function clearStrings(){
    document.getElementById('stringsFile').value='';
    document.getElementById('stringsFlagFormat').value='';
    resetOutput('stringsOutput');
}

function buildHexDumpTool(panel){
    panel.innerHTML = `
    ${toolHeader('','Hex Dump','Full hex dump with offset and ASCII representation')}
    <div class="tool-wrap">
        <div class="tool-title"> Hex Dump</div>
        <label>Upload File</label>
        <input type="file" id="hexDumpFile">
        <label>Max bytes to show</label>
        <select id="hexDumpMax">
            <option value="512">512</option>
            <option value="1024">1 KB</option>
            <option value="4096" selected>4 KB</option>
            <option value="16384">16 KB</option>
            <option value="0">All</option>
        </select>
        <div class="button-group">
            <button class="btn btn-run" onclick="runHexDumpTool()">Dump</button>
            <button class="btn btn-outline" onclick="clearHexDump()">Clear</button>
        </div>
        ${createOutput('hexDumpOutput','Hex Dump')}
    </div>`;
}

async function runHexDumpTool(){
    const file = document.getElementById('hexDumpFile').files[0];
    const max  = document.getElementById('hexDumpMax').value;
    if(!file){ showToast('Upload a file','error'); return; }
    setLoading('hexDumpOutput');
    const fd = new FormData();
    fd.append('file', file);
    fd.append('max_bytes', max);
    const res = await apiUploadForm('/api/forensics/hexdump', fd);
    if(res.status === 'ok'){
        const d = res.data;
        let header = `File size: ${d.total_size.toLocaleString()} bytes | Showing: ${d.shown_bytes.toLocaleString()} bytes\n\n`;
        setOutput('hexDumpOutput', header + d.hex_dump);
    } else {
        setOutput('hexDumpOutput', `Error: ${res.error}`);
    }
}
function clearHexDump(){ document.getElementById('hexDumpFile').value=''; resetOutput('hexDumpOutput'); }

function buildZipCrack(panel){
    panel.innerHTML = `
    ${toolHeader('','ZIP Password Cracker','Crack password-protected ZIP files using wordlist')}
    <div class="tool-wrap">
        <div class="tool-title"> ZIP Password Cracker</div>
        <label>Upload ZIP File</label>
        <input type="file" id="zipFile" accept=".zip">
        <label>Wordlist (one password per line)</label>
        <textarea id="zipWordlist" style="min-height:120px;"
            placeholder="password&#10;123456&#10;admin&#10;secret&#10;..."></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runZipCrack()">Crack ZIP</button>
            <button class="btn btn-outline" onclick="clearZipCrack()">Clear</button>
        </div>
        ${createOutput('zipOutput','Crack Result')}
    </div>`;
}

async function runZipCrack(){
    const file     = document.getElementById('zipFile').files[0];
    const wordlist = document.getElementById('zipWordlist').value.trim();
    if(!file){ showToast('Upload a ZIP file','error'); return; }
    if(!wordlist){ showToast('Enter a wordlist','error'); return; }
    setLoading('zipOutput');
    const fd = new FormData();
    fd.append('file', file);
    fd.append('wordlist', wordlist);
    const res = await apiUploadForm('/api/forensics/zip_crack', fd);
    if(res.status === 'ok'){
        const d = res.data;
        if(d.found){
            setOutput('zipOutput', `OK PASSWORD FOUND!\n\nPassword: ${d.password}\nTried: ${d.tried} passwords`);
            showToast(`Password found: ${d.password}`);
        } else if(d.protected === false){
            setOutput('zipOutput', 'ZIP is not password protected');
        } else {
            setOutput('zipOutput', `NO Not found\nTried: ${d.tried} passwords\n\n${d.message || ''}`);
        }
    } else {
        setOutput('zipOutput', `Error: ${res.error}`);
    }
}
function clearZipCrack(){
    document.getElementById('zipFile').value='';
    document.getElementById('zipWordlist').value='';
    resetOutput('zipOutput');
}

function buildLsbStego(panel){
    panel.innerHTML = `
    ${toolHeader('','LSB Steganography','Server-side LSB extraction using Pillow')}
    <div class="tool-wrap">
        <div class="tool-title"> LSB Stego Extractor</div>
        <label>Upload Image (PNG recommended)</label>
        <input type="file" id="lsbFile" accept="image/*">
        <label>Bits per channel</label>
        <select id="lsbBits">
            <option value="1">1 bit</option>
            <option value="2">2 bits</option>
            <option value="4">4 bits</option>
        </select>
        <label>Flag format (optional)</label>
        <input type="text" id="lsbFlagFormat" placeholder="flag{} or picoCTF{...}">
        <div class="button-group">
            <button class="btn btn-run" onclick="runLsbStego()">Extract LSB</button>
            <button class="btn btn-outline" onclick="clearLsb()">Clear</button>
        </div>
        ${createOutput('lsbOutput','Extracted Data')}
    </div>`;
}

async function runLsbStego(){
    const file = document.getElementById('lsbFile').files[0];
    const bits = document.getElementById('lsbBits').value;
    const flagFormat = document.getElementById('lsbFlagFormat').value.trim();
    if(!file){ showToast('Upload an image','error'); return; }
    setLoading('lsbOutput');
    const fd = new FormData();
    fd.append('file', file);
    fd.append('bits', bits);
    const res = await apiUploadForm('/api/forensics/lsb', fd);
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Image: ${d.image_size} | Bits/channel: ${d.bits_per_channel}\n`;
        out += `Printable ratio: ${(d.printable_ratio*100).toFixed(1)}%\n`;
        out += `Flag detected: ${d.has_flag ? ' YES' : 'No'}\n\n`;
        out += `Hex preview: ${d.hex_preview}\n\n`;
        out += `ASCII text:\n${d.extracted_text || '(no printable text found)'}`;
        if(flagFormat){
            const text = d.extracted_text || '';
            const flagRes = await findFlags(text, flagFormat);
            if(flagRes.status === 'ok'){
                setOutput('lsbOutput',
                    `<div class="plain-output-block">${escapeHtml(out)}</div>` +
                    flagResultsHtml(text, flagRes.data, {
                        title: 'Flags found',
                        sourceLabel: 'Extracted Text'
                    }),
                    true
                );
            } else {
                setOutput('lsbOutput', `${out}\n\nFlag search error: ${flagRes.error}`);
            }
        } else {
            setOutput('lsbOutput', out);
        }
        if(d.has_flag) showToast(' Flag detected in LSB!');
    } else {
        setOutput('lsbOutput', `Error: ${res.error}`);
    }
}
function clearLsb(){
    document.getElementById('lsbFile').value='';
    document.getElementById('lsbFlagFormat').value='';
    resetOutput('lsbOutput');
}

function buildEntropyTool(panel){
    panel.innerHTML = `
    ${toolHeader('','Entropy Analysis','Shannon entropy and byte frequency analysis')}
    <div class="tool-wrap">
        <div class="tool-title"> Entropy Analyzer</div>
        <label>Upload File</label>
        <input type="file" id="entropyFile">
        <div class="button-group">
            <button class="btn btn-run" onclick="runEntropyTool()">Analyze</button>
            <button class="btn btn-outline" onclick="clearEntropy()">Clear</button>
        </div>
        ${createOutput('entropyOutput','Entropy Results')}
    </div>`;
}

async function runEntropyTool(){
    const file = document.getElementById('entropyFile').files[0];
    if(!file){ showToast('Upload a file','error'); return; }
    setLoading('entropyOutput');
    const res = await apiUpload('/api/forensics/entropy', file);
    if(res.status === 'ok'){
        const d = res.data;
        let out = `Entropy: ${d.entropy} / 8.0 bits/byte\n`;
        out += `Interpretation: ${d.interpretation}\n\n`;
        out += `File size: ${d.file_size.toLocaleString()} bytes\n`;
        out += `Unique bytes: ${d.unique_bytes} / 256\n`;
        out += `Null bytes: ${d.null_bytes}\n\n`;
        out += `TOP 20 BYTES:\n`;
        d.top_bytes.forEach(b => {
            out += `  0x${b.byte.toString(16).padStart(2,'0')} (${b.byte.toString().padStart(3)})  ${b.count.toLocaleString().padStart(8)}  ${b.pct}%\n`;
        });
        setOutput('entropyOutput', out);
    } else {
        setOutput('entropyOutput', `Error: ${res.error}`);
    }
}
function clearEntropy(){ document.getElementById('entropyFile').value=''; resetOutput('entropyOutput'); }
