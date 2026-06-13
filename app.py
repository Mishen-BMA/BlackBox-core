from collections import defaultdict, deque
from datetime import datetime
from functools import wraps
import time

from flask import Flask, jsonify, render_template, request
from flask_cors import CORS
from dotenv import load_dotenv
import os

from core.crypto import crypto_bp
from core.forensics import forensics_bp
from core.network import network_bp
from core.utils import utils_bp
from core.web import web_bp


load_dotenv()

app = Flask(__name__)
CORS(app, resources={r"/api/*": {"origins": "*"}})
app.config["SECRET_KEY"] = os.getenv("SECRET_KEY", "blackbox-core-dev")
app.config["MAX_CONTENT_LENGTH"] = int(os.getenv("MAX_CONTENT_LENGTH", str(50 * 1024 * 1024)))
app.config["UPLOAD_FOLDER"] = os.getenv("UPLOAD_FOLDER", "temp/uploads")
app.config["REQUIRE_API_KEY"] = os.getenv("REQUIRE_API_KEY", "false").lower() == "true"
app.config["API_KEYS"] = {key.strip() for key in os.getenv("API_KEYS", "").split(",") if key.strip()}
app.config["ENABLE_RATE_LIMIT"] = os.getenv("ENABLE_RATE_LIMIT", "true").lower() == "true"
app.config["RATE_LIMIT_PER_MINUTE"] = int(os.getenv("RATE_LIMIT_PER_MINUTE", "60"))

os.makedirs(app.config["UPLOAD_FOLDER"], exist_ok=True)

app.register_blueprint(crypto_bp, url_prefix="/api/crypto")
app.register_blueprint(network_bp, url_prefix="/api/network")
app.register_blueprint(forensics_bp, url_prefix="/api/forensics")
app.register_blueprint(utils_bp, url_prefix="/api/utils")
app.register_blueprint(web_bp, url_prefix="/api/web")

_rate_limit_cache = defaultdict(deque)


def _json_error(message, code):
    return jsonify({"status": "error", "error": message}), code


def api_guard(route_handler):
    @wraps(route_handler)
    def wrapped(*args, **kwargs):
        if request.method != "OPTIONS" and request.path.startswith("/api/") and request.endpoint not in {"ping", "status"}:
            if app.config["REQUIRE_API_KEY"]:
                api_key = request.headers.get("X-API-Key") or request.args.get("api_key")
                if not api_key:
                    return _json_error("API key required", 401)
                if api_key not in app.config["API_KEYS"]:
                    return _json_error("Invalid API key", 403)

            if app.config["ENABLE_RATE_LIMIT"]:
                client_id = request.headers.get("X-Forwarded-For", request.remote_addr or "unknown").split(",")[0].strip()
                now = time.time()
                window = 60
                requests_for_client = _rate_limit_cache[client_id]
                while requests_for_client and now - requests_for_client[0] > window:
                    requests_for_client.popleft()
                if len(requests_for_client) >= app.config["RATE_LIMIT_PER_MINUTE"]:
                    return _json_error("Rate limit exceeded. Please wait.", 429)
                requests_for_client.append(now)

        return route_handler(*args, **kwargs)

    return wrapped


@app.before_request
def apply_api_guard():
    guarded = api_guard(lambda: None)
    response = guarded()
    if response is not None:
        return response
    return None


@app.get("/")
def index():
    return render_template("index.html")


@app.get("/api/ping")
def ping():
    return jsonify({"status": "ok", "tool": "BlackBox-Core v1.0"})


@app.get("/api/status")
def status():
    return jsonify({
        "status": "ok",
        "version": "1.1.0",
        "timestamp": datetime.utcnow().isoformat() + "Z",
        "limits": {
            "max_content_length": app.config["MAX_CONTENT_LENGTH"],
            "rate_limit_enabled": app.config["ENABLE_RATE_LIMIT"],
            "rate_limit_per_minute": app.config["RATE_LIMIT_PER_MINUTE"],
            "api_key_required": app.config["REQUIRE_API_KEY"],
        },
        "modules": {
            "crypto": ["rsa_factor", "rsa_wiener", "rsa_decrypt", "hastad", "key_parser", "hash_crack", "aes"],
            "network": ["dns", "whois", "portscan", "geoip", "subdomains", "ssl", "headers"],
            "forensics": ["analyze", "strings", "hexdump", "entropy", "zip_crack", "zip_deep_scan", "lsb"],
            "web": ["request", "sqli_test", "xss_test", "cors_test", "ssrf_payloads", "open_redirect"],
            "utils": ["challenge_flow", "encode_decode", "base_convert", "hash", "regex", "json_format", "url_parse", "extract_flags", "deep_flag_scan"],
        },
    })


@app.errorhandler(404)
def not_found(_error):
    return jsonify({"status": "error", "error": "Endpoint not found"}), 404


@app.errorhandler(413)
def too_large(_error):
    return jsonify({"status": "error", "error": "File too large (max 50MB)"}), 413


@app.errorhandler(500)
def server_error(error):
    return jsonify({"status": "error", "error": "Internal server error", "detail": str(error)}), 500


if __name__ == "__main__":
    debug = os.getenv("FLASK_ENV", "production").lower() == "development"
    port = int(os.getenv("PORT", "5000"))
    print("BlackBox-Core v1.0")
    print("CTF Backend Engine")
    print(f"http://127.0.0.1:{port}")
    app.run(debug=debug, host="0.0.0.0", port=port)
