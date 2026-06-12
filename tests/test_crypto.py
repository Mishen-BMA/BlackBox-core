from modules.crypto_helper import b64_decode, hash_text


def test_hash_text_sha256() -> None:
    assert hash_text("blackbox") == "12708c45a93e4d6e11ad468168fd0469d1208152fed4563e7ace8857fba11ff4"


def test_b64_decode() -> None:
    assert b64_decode("SzRQe3Rlc3R9") == "K4P{test}"
