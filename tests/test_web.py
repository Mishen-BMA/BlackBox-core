from modules.web_exploit import build_url


def test_build_url() -> None:
    assert build_url("https://example.com/app", "/admin") == "https://example.com/app/admin"

