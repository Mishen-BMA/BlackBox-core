import base64
import hashlib
import html
import json
import re
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
