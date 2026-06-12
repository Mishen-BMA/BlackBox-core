from pathlib import Path


def is_apk(path: str | Path) -> bool:
    file_path = Path(path)
    return file_path.suffix.lower() == ".apk"

