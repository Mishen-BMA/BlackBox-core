import base64
import hashlib


def hash_text(value: str, algorithm: str = "sha256") -> str:
    hasher = hashlib.new(algorithm)
    hasher.update(value.encode())
    return hasher.hexdigest()


def b64_decode(value: str) -> str:
    return base64.b64decode(value).decode(errors="replace")

