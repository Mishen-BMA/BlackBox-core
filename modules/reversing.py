from pathlib import Path


def extract_ascii_strings(path: str | Path, min_length: int = 4) -> list[str]:
    data = Path(path).read_bytes()
    strings: list[str] = []
    current = bytearray()
    for byte in data:
        if 32 <= byte <= 126:
            current.append(byte)
        else:
            if len(current) >= min_length:
                strings.append(current.decode())
            current.clear()
    if len(current) >= min_length:
        strings.append(current.decode())
    return strings

