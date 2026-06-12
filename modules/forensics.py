from pathlib import Path


def file_signature(path: str | Path, size: int = 16) -> bytes:
    with Path(path).open("rb") as handle:
        return handle.read(size)

