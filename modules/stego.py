from pathlib import Path


def read_trailing_bytes(path: str | Path, size: int = 256) -> bytes:
    file_path = Path(path)
    with file_path.open("rb") as handle:
        handle.seek(max(file_path.stat().st_size - size, 0))
        return handle.read()

