function buildEncodeDecode(panel){
    panel.innerHTML = `
    ${toolHeader('', 'Encode / Decode', 'Base, URL, HTML, and binary transformations')}
    <div class="tool-wrap">
        <div class="tool-title">Encode / Decode</div>
        <label>Operation</label>
        <select id="encodeOperation">
            <option value="base64_encode">Base64 Encode</option>
            <option value="base64_decode">Base64 Decode</option>
            <option value="base32_encode">Base32 Encode</option>
            <option value="base32_decode">Base32 Decode</option>
            <option value="hex_encode">Hex Encode</option>
            <option value="hex_decode">Hex Decode</option>
            <option value="url_encode">URL Encode</option>
            <option value="url_decode">URL Decode</option>
            <option value="html_encode">HTML Encode</option>
            <option value="html_decode">HTML Decode</option>
            <option value="binary_encode">Binary Encode</option>
            <option value="binary_decode">Binary Decode</option>
        </select>
        <label>Input</label>
        <textarea id="encodeInput" placeholder="Paste text here..."></textarea>
        <label>Flag format (optional)</label>
        <input type="text" id="encodeFlagFormat" placeholder="flag{} or picoCTF{...}">
        <div class="button-group">
            <button class="btn btn-run" onclick="runEncodeDecode()">Run</button>
            <button class="btn btn-outline" onclick="clearEncodeDecode()">Clear</button>
        </div>
        ${createOutput('encodeOutput', 'Result')}
    </div>`;
}

async function runEncodeDecode(){
    const operation = document.getElementById('encodeOperation').value;
    const text = document.getElementById('encodeInput').value;
    const flagFormat = document.getElementById('encodeFlagFormat').value.trim();
    setLoading('encodeOutput');
    const res = await apiPost('/api/utils/encode-decode', {operation, text});
    if(res.status === 'ok'){
        if(flagFormat){
            const flagRes = await findFlags(res.data.result, flagFormat);
            if(flagRes.status === 'ok'){
                setOutput('encodeOutput', flagResultsHtml(res.data.result, flagRes.data, {
                    title: 'Flags found',
                    sourceLabel: 'Decoded Result'
                }), true);
            } else {
                setOutput('encodeOutput', `${res.data.result}\n\nFlag search error: ${flagRes.error}`);
            }
        } else {
            setOutput('encodeOutput', res.data.result);
        }
    } else {
        setOutput('encodeOutput', `Error: ${res.error}`);
    }
}

function clearEncodeDecode(){
    document.getElementById('encodeInput').value = '';
    document.getElementById('encodeFlagFormat').value = '';
    resetOutput('encodeOutput');
}

function buildHashTool(panel){
    panel.innerHTML = `
    ${toolHeader('', 'Hash Generator', 'Generate common hashes from text')}
    <div class="tool-wrap">
        <div class="tool-title">Hash Generator</div>
        <label>Algorithm</label>
        <select id="hashAlgorithm">
            <option value="sha256">SHA256</option>
            <option value="sha512">SHA512</option>
            <option value="sha1">SHA1</option>
            <option value="md5">MD5</option>
            <option value="sha224">SHA224</option>
            <option value="sha384">SHA384</option>
            <option value="blake2b">BLAKE2b</option>
            <option value="blake2s">BLAKE2s</option>
        </select>
        <label>Input</label>
        <textarea id="hashInput" placeholder="Text to hash..."></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runHashTool()">Generate</button>
            <button class="btn btn-outline" onclick="clearHashTool()">Clear</button>
        </div>
        ${createOutput('hashOutput', 'Hash')}
    </div>`;
}

async function runHashTool(){
    const algorithm = document.getElementById('hashAlgorithm').value;
    const text = document.getElementById('hashInput').value;
    setLoading('hashOutput');
    const res = await apiPost('/api/utils/hash', {algorithm, text});
    if(res.status === 'ok'){
        setOutput('hashOutput', `${res.data.algorithm.toUpperCase()}\n${res.data.hash}\n\nLength: ${res.data.length}`);
    } else {
        setOutput('hashOutput', `Error: ${res.error}`);
    }
}

function clearHashTool(){
    document.getElementById('hashInput').value = '';
    resetOutput('hashOutput');
}

function buildBaseConvert(panel){
    panel.innerHTML = `
    ${toolHeader('', 'Base Converter', 'Convert numbers between bases 2 through 36')}
    <div class="tool-wrap">
        <div class="tool-title">Base Converter</div>
        <label>Number</label>
        <input type="text" id="baseNumber" placeholder="ff">
        <div style="display:grid;grid-template-columns:1fr 1fr;gap:12px;">
            <div><label>From base</label><input type="number" id="fromBase" min="2" max="36" value="16"></div>
            <div><label>To base</label><input type="number" id="toBase" min="2" max="36" value="10"></div>
        </div>
        <div class="button-group">
            <button class="btn btn-run" onclick="runBaseConvert()">Convert</button>
            <button class="btn btn-outline" onclick="clearBaseConvert()">Clear</button>
        </div>
        ${createOutput('baseOutput', 'Conversion')}
    </div>`;
}

async function runBaseConvert(){
    const number = document.getElementById('baseNumber').value.trim();
    const from_base = document.getElementById('fromBase').value;
    const to_base = document.getElementById('toBase').value;
    if(!number){ showToast('Enter a number', 'error'); return; }
    setLoading('baseOutput');
    const res = await apiPost('/api/utils/base-convert', {number, from_base, to_base});
    if(res.status === 'ok'){
        setOutput('baseOutput', `Input: ${res.data.input} (base ${res.data.from_base})\nOutput: ${res.data.output} (base ${res.data.to_base})\nDecimal: ${res.data.decimal}`);
    } else {
        setOutput('baseOutput', `Error: ${res.error}`);
    }
}

function clearBaseConvert(){
    document.getElementById('baseNumber').value = '';
    resetOutput('baseOutput');
}

function buildRegexTool(panel){
    panel.innerHTML = `
    ${toolHeader('', 'Regex Search', 'Find matches in pasted text')}
    <div class="tool-wrap">
        <div class="tool-title">Regex Search</div>
        <label>Pattern</label>
        <input type="text" id="regexPattern" placeholder="[A-Za-z0-9_]+\\{[^\\}]+\\}">
        <label>Text</label>
        <textarea id="regexText" style="min-height:180px;" placeholder="Paste logs, decoded text, or page source..."></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runRegexTool()">Search</button>
            <button class="btn btn-outline" onclick="clearRegexTool()">Clear</button>
        </div>
        ${createOutput('regexOutput', 'Matches')}
    </div>`;
}

async function runRegexTool(){
    const pattern = document.getElementById('regexPattern').value.trim();
    const text = document.getElementById('regexText').value;
    if(!pattern){ showToast('Enter a regex pattern', 'error'); return; }
    setLoading('regexOutput');
    const res = await apiPost('/api/utils/regex', {pattern, text});
    if(res.status === 'ok'){
        setOutput('regexOutput', `Matches: ${res.data.count}\n\n${res.data.matches.map(m => Array.isArray(m) ? m.join(' | ') : m).join('\n')}`);
    } else {
        setOutput('regexOutput', `Error: ${res.error}`);
    }
}

function clearRegexTool(){
    document.getElementById('regexPattern').value = '';
    document.getElementById('regexText').value = '';
    resetOutput('regexOutput');
}

function buildJsonFormat(panel){
    panel.innerHTML = `
    ${toolHeader('', 'JSON Formatter', 'Validate and pretty-print JSON')}
    <div class="tool-wrap">
        <div class="tool-title">JSON Formatter</div>
        <label>JSON</label>
        <textarea id="jsonInput" style="min-height:220px;" placeholder='{"flag":"blackbox{example}"}'></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runJsonFormat()">Format</button>
            <button class="btn btn-outline" onclick="clearJsonFormat()">Clear</button>
        </div>
        ${createOutput('jsonOutput', 'Formatted JSON')}
    </div>`;
}

async function runJsonFormat(){
    const text = document.getElementById('jsonInput').value;
    setLoading('jsonOutput');
    const res = await apiPost('/api/utils/json-format', {text});
    if(res.status === 'ok'){
        if(res.data.valid){
            setOutput('jsonOutput', res.data.formatted);
        } else {
            setOutput('jsonOutput', `Invalid JSON: ${res.data.error}`);
        }
    } else {
        setOutput('jsonOutput', `Error: ${res.error}`);
    }
}

function clearJsonFormat(){
    document.getElementById('jsonInput').value = '';
    resetOutput('jsonOutput');
}

function buildUrlParse(panel){
    panel.innerHTML = `
    ${toolHeader('', 'URL Parser', 'Break a URL into components')}
    <div class="tool-wrap">
        <div class="tool-title">URL Parser</div>
        <label>URL</label>
        <input type="text" id="urlParseInput" placeholder="https://example.com/path?id=1#top">
        <div class="button-group">
            <button class="btn btn-run" onclick="runUrlParse()">Parse</button>
            <button class="btn btn-outline" onclick="clearUrlParse()">Clear</button>
        </div>
        ${createOutput('urlParseOutput', 'URL Components')}
    </div>`;
}

async function runUrlParse(){
    const url = document.getElementById('urlParseInput').value.trim();
    if(!url){ showToast('Enter a URL', 'error'); return; }
    setLoading('urlParseOutput');
    const res = await apiPost('/api/utils/url-parse', {url});
    if(res.status === 'ok'){
        setOutput('urlParseOutput', JSON.stringify(res.data, null, 2));
    } else {
        setOutput('urlParseOutput', `Error: ${res.error}`);
    }
}

function clearUrlParse(){
    document.getElementById('urlParseInput').value = '';
    resetOutput('urlParseOutput');
}

function buildFlagExtract(panel){
    panel.innerHTML = `
    ${toolHeader('', 'Flag Extractor', 'Find flags by format or regex')}
    <div class="tool-wrap">
        <div class="tool-title">Flag Extractor</div>
        <label>Flag format</label>
        <input type="text" id="flagFormat" placeholder="flag{} or picoCTF{...}">
        <label>Regex override (optional)</label>
        <input type="text" id="flagPattern" placeholder="[A-Za-z0-9_]+\\{[^\\}]+\\}">
        <label>Known keys / passwords (optional, one per line)</label>
        <textarea id="flagKeys" style="min-height:80px;" placeholder="Paste candidate keys here, or let the scanner extract them from text..."></textarea>
        <label>Text</label>
        <textarea id="flagText" style="min-height:200px;" placeholder="Paste decoded output, logs, source, or strings..."></textarea>
        <div class="button-group">
            <button class="btn btn-run" onclick="runFlagExtract()">Extract Flags</button>
            <button class="btn btn-outline" onclick="runDeepFlagExtract()">Deep Scan</button>
            <button class="btn btn-outline" onclick="clearFlagExtract()">Clear</button>
        </div>
        ${createOutput('flagOutput', 'Flags')}
    </div>`;
}

async function runFlagExtract(){
    const flagFormat = document.getElementById('flagFormat').value.trim();
    const pattern = document.getElementById('flagPattern').value.trim();
    const text = document.getElementById('flagText').value;
    setLoading('flagOutput');
    const res = await findFlags(text, flagFormat, pattern);
    if(res.status === 'ok'){
        setOutput('flagOutput', flagResultsHtml(text, res.data, {
            title: 'Flags found',
            sourceLabel: 'Input Text'
        }), true);
    } else {
        setOutput('flagOutput', `Error: ${res.error}`);
    }
}

async function runDeepFlagExtract(){
    const flagFormat = document.getElementById('flagFormat').value.trim();
    const pattern = document.getElementById('flagPattern').value.trim();
    const keys = document.getElementById('flagKeys').value;
    const text = document.getElementById('flagText').value;
    setLoading('flagOutput');
    const res = await deepFindFlags(text, flagFormat, pattern, keys);
    if(res.status === 'ok'){
        setOutput('flagOutput', deepFlagResultsHtml(text, res.data), true);
    } else {
        setOutput('flagOutput', `Error: ${res.error}`);
    }
}

function clearFlagExtract(){
    document.getElementById('flagFormat').value = '';
    document.getElementById('flagPattern').value = '';
    document.getElementById('flagKeys').value = '';
    document.getElementById('flagText').value = '';
    resetOutput('flagOutput');
}
