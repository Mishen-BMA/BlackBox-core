from pathlib import Path


def dictionary_crack(hash_value: str, wordlist_path: str | Path) -> str | None:
    import hashlib

    for word in Path(wordlist_path).read_text(errors="ignore").splitlines():
        if hashlib.sha256(word.encode()).hexdigest() == hash_value:
            return word
    return None

