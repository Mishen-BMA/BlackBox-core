import base64
import binascii
import hashlib
import html
import json
import re
import string
import urllib.parse

from flask import Blueprint, jsonify, request


utils_bp = Blueprint("utils", __name__)


def success(data):
    return jsonify({"status": "ok", "data": data})


def error(msg, code=400):
    return jsonify({"status": "error", "error": msg}), code


def safe_decode(data):
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("latin-1", errors="replace")


def is_valid_ip(ip):
    pattern = re.compile(r"^(\d{1,3}\.){3}\d{1,3}$")
    if not pattern.match(ip):
        return False
    return all(0 <= int(part) <= 255 for part in ip.split("."))


def is_valid_domain(domain):
    pattern = re.compile(
        r"^(?:[a-zA-Z0-9](?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)+[a-zA-Z]{2,}$"
    )
    return bool(pattern.match(domain))


def hash_string(text, algo="md5"):
    digest = hashlib.new(algo)
    digest.update(text.encode())
    return digest.hexdigest()


def _decode_with_padding(value, decoder, block_size):
    cleaned = re.sub(r"\s+", "", value)
    padding = (-len(cleaned)) % block_size
    return decoder(cleaned + ("=" * padding)).decode("utf-8", errors="replace")


def encode_decode(operation, text):
    operations = {
        "base64_encode": lambda: base64.b64encode(text.encode()).decode(),
        "base64_decode": lambda: _decode_with_padding(text, base64.b64decode, 4),
        "base32_encode": lambda: base64.b32encode(text.encode()).decode(),
        "base32_decode": lambda: _decode_with_padding(text.upper(), base64.b32decode, 8),
        "hex_encode": lambda: text.encode().hex(),
        "hex_decode": lambda: bytes.fromhex(text.replace(" ", "").replace("0x", "")).decode("utf-8", errors="replace"),
        "url_encode": lambda: urllib.parse.quote(text),
        "url_decode": lambda: urllib.parse.unquote(text),
        "html_encode": lambda: html.escape(text, quote=True),
        "html_decode": lambda: html.unescape(text),
        "binary_encode": lambda: " ".join(format(ord(char), "08b") for char in text),
        "binary_decode": lambda: "".join(chr(int(bits, 2)) for bits in text.split()),
    }
    if operation not in operations:
        raise ValueError(f"Unknown operation: {operation}")
    return {"operation": operation, "result": operations[operation]()}


def base_convert(number, from_base, to_base):
    from_base = int(from_base)
    to_base = int(to_base)
    if from_base < 2 or from_base > 36 or to_base < 2 or to_base > 36:
        raise ValueError("Bases must be between 2 and 36")

    decimal = int(str(number), from_base)
    digits = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    if decimal == 0:
        converted = "0"
    else:
        value = abs(decimal)
        output = ""
        while value:
            output = digits[value % to_base] + output
            value //= to_base
        converted = ("-" if decimal < 0 else "") + output

    return {
        "input": str(number),
        "from_base": from_base,
        "to_base": to_base,
        "decimal": decimal,
        "output": converted,
    }


def generate_hash(text, algorithm="sha256"):
    allowed = {
        "md5": hashlib.md5,
        "sha1": hashlib.sha1,
        "sha224": hashlib.sha224,
        "sha256": hashlib.sha256,
        "sha384": hashlib.sha384,
        "sha512": hashlib.sha512,
        "blake2b": hashlib.blake2b,
        "blake2s": hashlib.blake2s,
    }
    if algorithm not in allowed:
        raise ValueError(f"Unknown algorithm: {algorithm}")
    digest = allowed[algorithm](text.encode()).hexdigest()
    return {"algorithm": algorithm, "hash": digest, "length": len(digest)}


def flag_format_to_regex(flag_format):
    """Convert a simple flag shape into a regex."""
    flag_format = (flag_format or "").strip()
    if not flag_format:
        return r"[A-Za-z0-9_]+\{[^\r\n\}]+\}"

    token = "\0"
    pattern = flag_format
    pattern = pattern.replace("{...}", "{" + token + "}")
    pattern = pattern.replace("{}", "{" + token + "}")
    pattern = pattern.replace("...", token)
    pattern = pattern.replace("*", token)

    escaped = []
    for char in pattern:
        if char == token:
            escaped.append(r"[^\r\n\}]+")
        elif char == "?":
            escaped.append(r"[^\r\n\}]")
        else:
            escaped.append(re.escape(char))
    return "".join(escaped)


def extract_flag_matches(text, pattern):
    matches = []
    for match in re.finditer(pattern, text, re.MULTILINE | re.DOTALL):
        value = match.group(0)
        if value == "":
            continue
        matches.append({
            "text": value,
            "start": match.start(),
            "end": match.end(),
        })
        if len(matches) >= 200:
            break
    return matches


def printable_ratio(text):
    if not text:
        return 0
    printable = set(string.printable)
    return sum(1 for char in text if char in printable) / len(text)


def limited_text(value, limit=2000):
    value = value or ""
    return value[:limit] + ("..." if len(value) > limit else "")


def decode_bytes(data):
    try:
        return data.decode("utf-8")
    except Exception:
        return data.decode("latin-1", errors="replace")


def maybe_add_variant(variants, seen, method, text, source="input"):
    text = text or ""
    if len(text) < 3 or text in seen:
        return
    if printable_ratio(text) < 0.65:
        return
    seen.add(text)
    variants.append({"method": method, "source": source, "text": text})


def caesar_shift(text, shift):
    out = []
    for char in text:
        if "a" <= char <= "z":
            out.append(chr((ord(char) - 97 + shift) % 26 + 97))
        elif "A" <= char <= "Z":
            out.append(chr((ord(char) - 65 + shift) % 26 + 65))
        else:
            out.append(char)
    return "".join(out)


def xor_decrypt(data, key):
    key_bytes = key.encode("utf-8", errors="ignore")
    if not key_bytes:
        return ""
    return decode_bytes(bytes(byte ^ key_bytes[i % len(key_bytes)] for i, byte in enumerate(data)))


def extract_key_candidates(text):
    candidates = []
    patterns = [
        r"(?i)\b(?:key|password|passwd|pass|pwd|secret|token)\b\s*[:=]\s*['\"]?([A-Za-z0-9_\-@#$%!.]{3,64})",
        r"(?i)\b(?:xor|aes|vigenere|zip)\s+key\s*[:=]\s*['\"]?([A-Za-z0-9_\-@#$%!.]{3,64})",
    ]
    for pattern in patterns:
        candidates.extend(re.findall(pattern, text))

    quoted = re.findall(r"['\"]([A-Za-z0-9_\-@#$%!.]{4,32})['\"]", text)
    candidates.extend(quoted[:50])

    output = []
    seen = set()
    for value in candidates:
        value = value.strip().strip("'\"")
        if value and value not in seen:
            seen.add(value)
            output.append(value)
        if len(output) >= 100:
            break
    return output


def extract_encoded_chunks(text):
    chunks = []
    base64_re = r"(?<![A-Za-z0-9+/=])([A-Za-z0-9+/]{12,}={0,2})(?![A-Za-z0-9+/=])"
    base32_re = r"(?<![A-Z2-7=])([A-Z2-7]{16,}={0,6})(?![A-Z2-7=])"
    hex_re = r"(?<![A-Fa-f0-9])((?:0x)?[A-Fa-f0-9]{16,})(?![A-Fa-f0-9])"
    binary_re = r"((?:[01]{8}\s*){3,})"

    for label, pattern in [
        ("base64", base64_re),
        ("base32", base32_re),
        ("hex", hex_re),
        ("binary", binary_re),
    ]:
        for match in re.finditer(pattern, text):
            chunks.append({"type": label, "value": match.group(1), "start": match.start(1), "end": match.end(1)})
            if len(chunks) >= 200:
                return chunks
    return chunks


def decode_chunk(chunk):
    value = chunk["value"]
    try:
        if chunk["type"] == "base64":
            cleaned = re.sub(r"\s+", "", value)
            return base64.b64decode(cleaned + ("=" * ((-len(cleaned)) % 4)), validate=False)
        if chunk["type"] == "base32":
            cleaned = re.sub(r"\s+", "", value.upper())
            return base64.b32decode(cleaned + ("=" * ((-len(cleaned)) % 8)))
        if chunk["type"] == "hex":
            cleaned = value.lower().replace("0x", "")
            if len(cleaned) % 2:
                return b""
            return bytes.fromhex(cleaned)
        if chunk["type"] == "binary":
            bits = re.sub(r"\s+", "", value)
            return bytes(int(bits[i:i+8], 2) for i in range(0, len(bits), 8))
    except (ValueError, binascii.Error):
        return b""
    return b""


def build_decode_variants(text):
    variants = []
    seen = {text}

    for method, decoded in [
        ("url decode", urllib.parse.unquote(text)),
        ("html decode", html.unescape(text)),
        ("reverse", text[::-1]),
        ("rot13", caesar_shift(text, 13)),
    ]:
        maybe_add_variant(variants, seen, method, decoded)

    for shift in range(1, 26):
        maybe_add_variant(variants, seen, f"caesar {shift}", caesar_shift(text, shift))

    for chunk in extract_encoded_chunks(text):
        raw = decode_chunk(chunk)
        if not raw:
            continue
        decoded = decode_bytes(raw)
        maybe_add_variant(variants, seen, f"{chunk['type']} decode", decoded, chunk["value"][:80])

        for method, nested in [
            ("nested url decode", urllib.parse.unquote(decoded)),
            ("nested html decode", html.unescape(decoded)),
            ("nested rot13", caesar_shift(decoded, 13)),
        ]:
            maybe_add_variant(variants, seen, method, nested, chunk["value"][:80])

    return variants[:300]


def deep_flag_scan(text, flag_format="", pattern="", keys=None):
    text = text or ""
    keys = keys or []
    pattern = (pattern or "").strip() or flag_format_to_regex(flag_format)

    direct_matches = extract_flag_matches(text, pattern)
    key_candidates = []
    for key in list(keys) + extract_key_candidates(text):
        key = (key or "").strip()
        if key and key not in key_candidates:
            key_candidates.append(key)
        if len(key_candidates) >= 100:
            break

    discoveries = []
    for variant in build_decode_variants(text):
        matches = extract_flag_matches(variant["text"], pattern)
        if matches:
            discoveries.append({
                "method": variant["method"],
                "source": variant["source"],
                "text": limited_text(variant["text"]),
                "matches": matches[:50],
                "count": len(matches),
            })

    decryptions = []
    chunks = extract_encoded_chunks(text)
    for chunk in chunks[:80]:
        raw = decode_chunk(chunk)
        if not raw:
            continue
        for key in key_candidates[:40]:
            plain = xor_decrypt(raw, key)
            if printable_ratio(plain) < 0.7:
                continue
            matches = extract_flag_matches(plain, pattern)
            if matches:
                decryptions.append({
                    "method": f"xor with {chunk['type']} blob",
                    "key": key,
                    "source": chunk["value"][:80],
                    "text": limited_text(plain),
                    "matches": matches[:50],
                    "count": len(matches),
                })
                if len(decryptions) >= 100:
                    break

    return {
        "pattern": pattern,
        "format": flag_format,
        "direct": {
            "count": len(direct_matches),
            "matches": direct_matches[:100],
            "flags": [match["text"] for match in direct_matches[:100]],
        },
        "decoded": discoveries[:100],
        "decryptions": decryptions[:100],
        "key_candidates": key_candidates[:100],
        "notes": [
            "Auto scan tries plaintext, URL/HTML, Base64/Base32/hex/binary, ROT13, Caesar shifts, and XOR against extracted/provided keys.",
            "Strong encryption such as AES needs the exact key, mode, IV, and ciphertext format.",
        ],
    }


@utils_bp.post("/encode-decode")
def encode_decode_route():
    data = request.get_json(silent=True) or {}
    try:
        return success(encode_decode(data.get("operation", ""), data.get("text", "")))
    except Exception as exc:
        return error(str(exc))


@utils_bp.post("/base-convert")
def base_convert_route():
    data = request.get_json(silent=True) or {}
    try:
        return success(base_convert(data.get("number", "0"), data.get("from_base", 10), data.get("to_base", 16)))
    except Exception as exc:
        return error(str(exc))


@utils_bp.post("/hash")
def hash_route():
    data = request.get_json(silent=True) or {}
    try:
        return success(generate_hash(data.get("text", ""), data.get("algorithm", "sha256")))
    except Exception as exc:
        return error(str(exc))


@utils_bp.post("/regex")
def regex_route():
    data = request.get_json(silent=True) or {}
    pattern = data.get("pattern", "")
    text = data.get("text", "")
    try:
        matches = re.findall(pattern, text, re.MULTILINE | re.DOTALL)
        return success({"pattern": pattern, "count": len(matches), "matches": matches[:100]})
    except re.error as exc:
        return error(f"Invalid regex: {exc}")


@utils_bp.post("/json-format")
def json_format_route():
    data = request.get_json(silent=True) or {}
    try:
        parsed = json.loads(data.get("text", ""))
        return success({
            "valid": True,
            "type": type(parsed).__name__,
            "formatted": json.dumps(parsed, indent=2),
            "keys": list(parsed.keys()) if isinstance(parsed, dict) else [],
        })
    except json.JSONDecodeError as exc:
        return success({"valid": False, "error": str(exc)})


@utils_bp.post("/url-parse")
def url_parse_route():
    data = request.get_json(silent=True) or {}
    parsed = urllib.parse.urlparse(data.get("url", ""))
    query_params = urllib.parse.parse_qs(parsed.query)
    return success({
        "scheme": parsed.scheme,
        "netloc": parsed.netloc,
        "path": parsed.path,
        "params": parsed.params,
        "query": parsed.query,
        "fragment": parsed.fragment,
        "hostname": parsed.hostname,
        "port": parsed.port,
        "query_params": {key: values[0] if len(values) == 1 else values for key, values in query_params.items()},
    })


@utils_bp.post("/extract-flags")
def extract_flags_route():
    data = request.get_json(silent=True) or {}
    text = data.get("text", "")
    flag_format = data.get("format", "")
    pattern = data.get("pattern", "").strip() or flag_format_to_regex(flag_format)
    try:
        matches = extract_flag_matches(text, pattern)
        flags = [match["text"] for match in matches]
        return success({
            "count": len(matches),
            "flags": flags[:100],
            "matches": matches[:100],
            "pattern": pattern,
            "format": flag_format,
        })
    except re.error as exc:
        return error(f"Invalid regex: {exc}")


@utils_bp.post("/deep-flag-scan")
def deep_flag_scan_route():
    data = request.get_json(silent=True) or {}
    keys_raw = data.get("keys", "")
    keys = keys_raw if isinstance(keys_raw, list) else keys_raw.splitlines()
    try:
        return success(deep_flag_scan(
            data.get("text", ""),
            data.get("format", ""),
            data.get("pattern", ""),
            keys,
        ))
    except re.error as exc:
        return error(f"Invalid regex: {exc}")
