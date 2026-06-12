from collections.abc import Iterable


def build_fuzz_targets(base_url: str, words: Iterable[str]) -> list[str]:
    return [f"{base_url.rstrip('/')}/{word.strip().lstrip('/')}" for word in words if word.strip()]

