# BlackBox-Core CTF Manual

This manual is tuned for HACK KAP CTF 2026 / Operation Heist style tasks, but it also works as a general workflow for Jeopardy CTFs.

Use BlackBox only on challenge targets and files you are authorized to test. Do not attack the CTF platform itself, brute force the flag submit form, or scan infrastructure outside the challenge scope.

## 1. Start BlackBox

From the repo root:

```powershell
python -m venv .venv
.\.venv\Scripts\Activate.ps1
python -m pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

Check health:

```powershell
Invoke-RestMethod http://127.0.0.1:5000/api/status
```

If port 5000 is busy, edit `.env`:

```text
PORT=5001
```

Then run `python app.py` and open `http://127.0.0.1:5001`.

## 2. Fast CTF Workflow

For every challenge:

1. Read the title, category, description, attachments, and hints.
2. Write down the expected flag format. For this event, use:

```text
K4P{...}
```

3. Start with the lightest inspection:

```text
For any new prompt: Utilities -> Challenge Flow Advisor
For files: Forensics -> Full File Analysis
For text blobs: Utilities -> Deep Flag Scan
For URLs: Web Testing -> HTTP Request Tester
For domains/IPs: Network Recon -> DNS, Headers, SSL, Port Scanner
For RSA numbers/keys: Cryptography -> RSA tools
```

4. Whenever you decode, extract, crack, or fetch anything, paste the result into:

```text
Utilities -> Flag Extractor -> Deep Scan
```

5. Keep a notes file with: challenge name, inputs, commands/tools used, discoveries, candidate flags, and final submitted flag.

## 3. UI Navigation

The web UI has five main sections:

- `Cryptography`: RSA factoring, Wiener, Hastad, RSA decrypt, RSA key parsing.
- `Network Recon`: DNS, WHOIS, port scan, GeoIP, subdomain recon, SSL certs, security headers.
- `Forensics`: file analysis, strings, hex dump, ZIP cracking, LSB extraction, entropy.
- `Web Testing`: HTTP tester, SQLi, XSS, CORS, SSRF payload generation.
- `Utilities`: challenge flow advisor, encode/decode, hash generation, base conversion, regex, JSON formatting, URL parsing, flag extraction.

Use the search bar for quick access. Press `/` in the UI to focus search.

## 4. API Usage Pattern

All JSON endpoints return:

```json
{
  "status": "ok",
  "data": {}
}
```

or:

```json
{
  "status": "error",
  "error": "message"
}
```

PowerShell JSON example:

```powershell
$body = @{ text = "S0RQe2V4YW1wbGV9"; operation = "base64_decode" } | ConvertTo-Json
Invoke-RestMethod http://127.0.0.1:5000/api/utils/encode-decode -Method Post -ContentType "application/json" -Body $body
```

PowerShell file upload example:

```powershell
curl.exe -F "file=@challenge.png" http://127.0.0.1:5000/api/forensics/analyze
```

## 5. Utility Tools

### Challenge Flow Advisor

Use this first when you receive a fresh challenge and are not sure where to begin. Paste the challenge title, category, description, hints, filenames, URLs, and any visible text. It ranks likely categories, extracts clues, and gives you a step-by-step BlackBox tool flow.

Endpoint:

```text
POST /api/utils/challenge-flow
```

Body:

```json
{
  "description": "The Front Door - Web - Bypass the Mint's public login portal. URL: https://challenge.example/login",
  "format": "K4P{...}",
  "category_hint": "web"
}
```

The response includes:

- `primary_category`
- `ranked_categories`
- `recommended_tools`
- `flow`
- `clues`
- `external_tools`
- `safety`

### Encode / Decode

Use for Base64, Base32, hex, URL, HTML, and binary transformations.

Good clues:

- Base64 often looks like `S0RQe...`, `eyJ...`, or ends in `=`.
- Hex is only `0-9a-f`, often even-length.
- Binary is groups of 8 bits.
- URL encoding contains `%7B`, `%7D`, `%20`, etc.
- HTML encoding contains `&amp;`, `&#123;`, `&lt;`.

Endpoint:

```text
POST /api/utils/encode-decode
```

Body:

```json
{
  "operation": "base64_decode",
  "text": "S0RQe2V4YW1wbGV9"
}
```

Operations:

```text
base64_encode, base64_decode
base32_encode, base32_decode
hex_encode, hex_decode
url_encode, url_decode
html_encode, html_decode
binary_encode, binary_decode
```

### Deep Flag Scan

Use this constantly. It tries plaintext, URL/HTML decoding, Base64/Base32/hex/binary decoding, reverse text, ROT13, Caesar shifts, and XOR against candidate keys.

Endpoint:

```text
POST /api/utils/deep-flag-scan
```

Body:

```json
{
  "text": "paste logs, strings, decoded data, source, etc.",
  "format": "K4P{...}",
  "keys": "optionalKey1\noptionalKey2"
}
```

Use `format` as `K4P{...}` for this event. Use `pattern` only if the flag format differs.

### Flag Extractor

Use when you only want direct regex matching.

Endpoint:

```text
POST /api/utils/extract-flags
```

Body:

```json
{
  "text": "text containing K4P{maybe_this}",
  "format": "K4P{...}"
}
```

### JSON Formatter

Use for API responses, dumped config, JWT header/payload after Base64URL decoding, and logs.

Endpoint:

```text
POST /api/utils/json-format
```

### URL Parser

Use on web challenge URLs to separate path, query params, fragments, ports, and hosts.

Endpoint:

```text
POST /api/utils/url-parse
```

### Base Converter

Use for number puzzles, ASCII codes, RSA values, weird base encodings, and binary/decimal/hex conversion.

Endpoint:

```text
POST /api/utils/base-convert
```

## 6. Forensics Workflow

Use this order for unknown files:

1. `Forensics -> Full File Analysis`
2. Check file type, magic bytes, entropy, hashes, strings.
3. If strings contain readable text, paste them into `Utilities -> Deep Flag Scan`.
4. If magic bytes disagree with extension, rename mentally and analyze as the detected type.
5. If high entropy, suspect compression, encryption, archive, image/video/audio payload, or packed data.
6. If ZIP, use `ZIP Password Cracker` or `Deep Scan ZIP`.
7. If image, use strings, hex dump, PNG chunk analysis if needed, and LSB extraction.

### Full File Analysis

Endpoint:

```text
POST /api/forensics/analyze
```

Upload field:

```text
file
```

Returns:

- MD5/SHA hashes.
- Detected magic type.
- Entropy.
- Hex preview.
- First strings.

PowerShell:

```powershell
curl.exe -F "file=@evidence.bin" http://127.0.0.1:5000/api/forensics/analyze
```

### Strings Extractor

Use filters like:

```text
K4P
flag
key
pass
secret
token
admin
password
```

Endpoint:

```text
POST /api/forensics/strings
```

PowerShell:

```powershell
curl.exe -F "file=@sample.bin" -F "min_len=4" -F "filter=K4P" http://127.0.0.1:5000/api/forensics/strings
```

### Hex Dump

Use when:

- The file extension may be wrong.
- There is hidden data before/after normal file sections.
- You need offsets.
- Strings are not enough.

Endpoint:

```text
POST /api/forensics/hexdump
```

### Entropy

Interpretation:

- `0-4.5`: likely plain text or structured.
- `4.5-6.5`: mixed data.
- `6.5-7.5`: compressed/binary.
- `7.5-8.0`: encrypted, compressed, or random-looking.

Endpoint:

```text
POST /api/forensics/entropy
```

### ZIP Password Cracker

Built-in wordlists live in:

```text
assets/wordlists/
```

Current built-ins:

```text
rockyou-mini.txt
ctf-common.txt
```

Add more `.txt` files there if you have challenge-specific words.

Good custom wordlist candidates:

- Challenge title words.
- Story names: professor, berlin, tokyo, rio, nairobi, denver, murillo, sistema, mint.
- Dates: 2026, 13062026, 14062026.
- Organizer names and sponsor names.
- Words found in strings, metadata, comments, page source, and filenames.

Endpoint:

```text
POST /api/forensics/zip_crack
```

PowerShell:

```powershell
curl.exe -F "file=@archive.zip" -F "builtin_wordlist=ctf-common" http://127.0.0.1:5000/api/forensics/zip_crack
```

### ZIP Deep Scan

Use when you know or can guess the ZIP password and want BlackBox to open files and scan all extracted text for flags.

Endpoint:

```text
POST /api/forensics/zip_deep_scan
```

PowerShell:

```powershell
curl.exe -F "file=@archive.zip" -F "password=professor" -F "format=K4P{...}" http://127.0.0.1:5000/api/forensics/zip_deep_scan
```

### LSB Steganography

Use for image steg tasks, especially PNG.

Try:

- 1 bit per channel first.
- Then 2 bits.
- Then 4 bits.

Endpoint:

```text
POST /api/forensics/lsb
```

PowerShell:

```powershell
curl.exe -F "file=@hidden.png" -F "bits=1" http://127.0.0.1:5000/api/forensics/lsb
```

## 7. Cryptography Workflow

Use this triage:

1. If you have PEM key text, use `RSA Key Parser`.
2. If you have RSA `n`, try `RSA Large N Factor`.
3. If you have `e` and `n`, and `e` is large or challenge hints at small `d`, try `RSA Wiener Attack`.
4. If you have `p`, `q`, `e`, `c`, use `RSA Decrypt`.
5. If same plaintext was encrypted to multiple moduli with small `e`, use `RSA Hastad Broadcast`.
6. For encodings, Caesar/ROT13/XOR-like clues, use `Deep Flag Scan`.
7. For AES, use the AES tool only when the challenge gives enough details.

### RSA Key Parser

Endpoint:

```text
POST /api/crypto/rsa/parse_key
```

Body:

```json
{
  "pem": "-----BEGIN PUBLIC KEY-----\n...\n-----END PUBLIC KEY-----"
}
```

Returns `n`, `e`, key size, and private values if present.

### RSA Factor

Endpoint:

```text
POST /api/crypto/rsa/factor
```

Body:

```json
{
  "n": "123456789..."
}
```

If BlackBox finds `p` and `q`, feed them into RSA Decrypt.

### RSA Wiener

Endpoint:

```text
POST /api/crypto/rsa/wiener
```

Body:

```json
{
  "e": "12345...",
  "n": "67890..."
}
```

Works when the private exponent `d` is unusually small.

### RSA Decrypt

Endpoint:

```text
POST /api/crypto/rsa/decrypt
```

Body:

```json
{
  "p": "prime1",
  "q": "prime2",
  "e": "65537",
  "c": "ciphertext_integer"
}
```

The output includes plaintext, integer, and hex. Paste plaintext and hex-decoded variants into Deep Flag Scan.

### RSA Hastad

Endpoint:

```text
POST /api/crypto/rsa/hastad
```

Body:

```json
{
  "e": 3,
  "ciphertexts": ["c1", "c2", "c3"],
  "moduli": ["n1", "n2", "n3"]
}
```

Requires at least `e` ciphertext/modulus pairs for the same message.

### Hash Crack

There is a backend endpoint:

```text
POST /api/crypto/hash/crack
```

Body:

```json
{
  "hash": "5f4dcc3b5aa765d61d8327deb882cf99",
  "wordlist": ["password", "admin", "professor"]
}
```

It tests MD5, SHA1, SHA224, SHA256, SHA384, and SHA512 against the provided words.

## 8. Web Challenge Workflow

Stay inside the challenge host/path. Do not scan the scoreboard or CTF platform.

Use this order:

1. `HTTP Request Tester`: fetch the page or API endpoint.
2. Look at status code, headers, redirects, cookies, and first 5000 body chars.
3. Paste source/body into `Deep Flag Scan`.
4. Use `URL Parser` to identify parameters.
5. Use `SQLi Scanner` only on challenge parameters.
6. Use `XSS Tester` for reflected parameters.
7. Use `CORS Tester` for API endpoints.
8. Use `SSRF Payload Generator` only when the challenge has a URL-fetching feature.

### HTTP Request Tester

Endpoint:

```text
POST /api/web/request
```

Body:

```json
{
  "url": "https://challenge.example/path",
  "method": "GET",
  "headers": {},
  "body": "",
  "follow_redirects": true,
  "timeout": 10
}
```

For APIs:

```json
{
  "url": "https://challenge.example/api/login",
  "method": "POST",
  "headers": {
    "Content-Type": "application/json"
  },
  "body": "{\"username\":\"admin\",\"password\":\"admin\"}"
}
```

### SQLi Scanner

Endpoint:

```text
POST /api/web/sqli_test
```

Body:

```json
{
  "url": "https://challenge.example/item",
  "param": "id",
  "value": "1"
}
```

Read results carefully. This is a quick indicator, not a full exploit engine. False positives happen when pages have unstable content lengths.

### XSS Tester

Endpoint:

```text
POST /api/web/xss_test
```

Body:

```json
{
  "url": "https://challenge.example/search",
  "param": "q"
}
```

It checks whether payloads are reflected unencoded. Use it to confirm likely reflected XSS tasks.

### CORS Tester

Endpoint:

```text
POST /api/web/cors_test
```

Body:

```json
{
  "url": "https://challenge.example/api/profile"
}
```

Look for reflected arbitrary origins plus credential support.

### SSRF Payload Generator

Endpoint:

```text
POST /api/web/ssrf_payloads
```

Body:

```json
{
  "target": "https://challenge.example/fetch?url=",
  "callback": "http://your-callback-host/ssrf"
}
```

Use only when the challenge provides an explicit URL fetcher/proxy/import feature.

## 9. Network Recon Workflow

Use network tools only for challenge-provided domains/IPs.

Good order:

1. DNS Lookup.
2. Security Headers.
3. SSL Certificate.
4. Subdomain Recon, if OSINT/recon category allows it.
5. Port Scan with a small explicit port list.
6. WHOIS/GeoIP only if useful for OSINT clues.

### DNS Lookup

Endpoint:

```text
POST /api/network/dns
```

Body:

```json
{
  "target": "example.com"
}
```

Check TXT records. CTF flags and hints often hide there.

### Security Headers

Endpoint:

```text
POST /api/network/headers
```

Body:

```json
{
  "url": "https://challenge.example"
}
```

Useful for web recon and hints about framework/proxy behavior.

### SSL Certificate

Endpoint:

```text
POST /api/network/ssl
```

Body:

```json
{
  "domain": "challenge.example",
  "port": 443
}
```

Check SANs for hidden subdomains.

### Subdomain Recon

Endpoint:

```text
POST /api/network/subdomains
```

Body:

```json
{
  "domain": "example.com"
}
```

Uses certificate transparency via `crt.sh`. It is passive-ish but still resolves up to 50 names.

### Port Scanner

Endpoint:

```text
POST /api/network/portscan
```

Body:

```json
{
  "target": "challenge.example",
  "ports": "80,443,8080,8443",
  "timeout": 0.8
}
```

Keep it small. The backend enforces a maximum of 200 ports, but CTF rules may be stricter.

## 10. OSINT Tasks

BlackBox helps with technical OSINT:

- DNS TXT/MX/NS records.
- WHOIS registration clues.
- SSL SAN subdomains.
- Subdomain recon from certificate transparency.
- URL parsing.
- Hashing/encoding/regex.

Manual OSINT still matters:

- Search exact names, usernames, handles, email addresses, and filenames.
- Check page source and robots/sitemap if in scope.
- Look at image/video metadata using file analysis and strings.
- Try story-specific words as passwords or keys.

Use Deep Flag Scan on every copied profile bio, page source, JSON response, metadata blob, and certificate value.

## 11. Steganography Tasks

For images:

1. Full File Analysis.
2. Strings Extractor.
3. Hex Dump.
4. LSB with 1, 2, then 4 bits.
5. Deep Flag Scan on all outputs.

For audio/video:

BlackBox can identify magic bytes, entropy, strings, and hashes, but it does not do spectrograms or audio decoding. Use external tools for spectrogram/audio channels if needed, then paste discovered text back into Deep Flag Scan.

For archives hidden inside images:

- Look for `PK` in strings/hex.
- Look for extra bytes after PNG `IEND` or JPEG EOF markers.
- BlackBox can show clues, but extraction may need external tools.

## 12. Programming Tasks

BlackBox is useful for:

- Base conversions.
- Regex extraction.
- JSON formatting.
- Hash generation.
- Decoding sample outputs.
- Flag extraction.

For actual scripts, write small Python locally. Typical flow:

1. Decode/parse samples with BlackBox.
2. Understand transformation.
3. Script the repeated work.
4. Paste output to Deep Flag Scan.

## 13. Tasks BlackBox Does Not Fully Cover

Switch tools when you see these categories:

- `Pwn / Binary Exploitation`: use Ghidra, pwndbg/gdb, checksec, ROPgadget, pwntools.
- `Reverse Engineering`: use Ghidra, Binary Ninja, IDA Free, strings, ltrace/strace, jadx for Java/APK.
- `Malware Analysis`: use isolated VM/sandbox, strings, PE tools, Ghidra, Procmon-style tooling. Do not run unknown malware on your main system.
- `Mobile`: use jadx, apktool, adb, MobSF, SQLite viewers.
- `Blockchain/Web3`: use Foundry, Hardhat, cast, ethers/web3, block explorer tools.
- `Cloud Security`: use AWS/GCP/Azure CLIs only against provided challenge accounts/resources.
- `Active Directory`: use BloodHound, Impacket, CrackMapExec/NetExec only in the provided lab network.
- `AI/ML Security`: BlackBox can help parse JSON/logs and extract flags, but prompt-injection/adversarial tasks need manual model interaction.

## 14. Operation Heist Challenge Mapping

### Act 1

- `The Invitation` / Sanity Check: inspect the overview, page source, copied text, and obvious strings. Use `Flag Extractor`.
- `Red Jumpsuit` / Linux Basics: BlackBox may help decode outputs, but terminal basics are primary.
- `The Blueprints` / OSINT: use DNS, WHOIS, SSL, Subdomain Recon, URL Parser.
- `Bella Ciao` / Steganography: use Full File Analysis, Strings, Hex Dump, LSB; external spectrogram if audio.
- `The Front Door` / Web: use HTTP Tester, URL Parser, SQLi, XSS, CORS as relevant.
- `Camera Blind Spot` / Forensics: use Full File Analysis, Strings, Entropy, Hex Dump.
- `The Guard's Frequency` / Network: if PCAP is provided, BlackBox has limited PCAP support; use Wireshark/tshark, then paste extracted payloads into Deep Flag Scan.
- `Hostage Protocol` / Crypto: use Encode/Decode, Deep Flag Scan, RSA/AES if applicable.
- `Rio's Toolkit` / Programming: use Utilities to decode samples and verify output.
- `The Janitor` / Misc: use regex, URL parser, hashes, encoders, and Deep Flag Scan.

### Act 2 and Side Stories

- Web/API tasks: HTTP Tester, SQLi, XSS, CORS, SSRF payloads.
- Crypto tasks: RSA parser/factor/Wiener/Hastad/decrypt, AES if enough details are supplied.
- Forensics tasks: Full File Analysis, ZIP Crack, ZIP Deep Scan, Strings, Hex Dump, Entropy.
- OSINT tasks: DNS, WHOIS, SSL SANs, subdomain recon.
- Blockchain/mobile/cloud/pwn/rev/AD: use external specialist tools, then bring discovered text/keys/files back into BlackBox for decoding and flag extraction.

## 15. Practical Checklist During The CTF

Before submitting:

- Confirm the flag starts with `K4P{` and ends with `}`.
- Check for whitespace/newlines copied from output.
- If the content looks encoded inside the braces, try decoding only the inner value.
- If multiple candidate flags appear, prefer the one produced by the final challenge-specific step.
- Record how you solved it, because later challenges may reuse keys, usernames, paths, or story words.

When stuck:

- Reread title and story for exact words that could be keys/passwords.
- Search output for `K4P`, `flag`, `key`, `pass`, `secret`, `token`, `admin`, `debug`, `backup`.
- Run Deep Flag Scan with known keys.
- Try the same data in reverse, ROT13, Base64, Base32, hex, URL decode, and binary.
- For files, compare extension vs magic bytes.
- For web, inspect redirects, cookies, hidden inputs, comments, JavaScript, and API JSON.

## 16. Safety Notes

- Do not scan broad ranges.
- Do not brute force logins unless the challenge explicitly permits it.
- Do not brute force the flag submission system.
- Keep port scans small and challenge-specific.
- Do not use SSRF payloads on non-challenge systems.
- Treat malware samples as hostile and do not execute them on your host.
- Keep team communication private and do not share flags with other teams.
