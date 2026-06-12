from pathlib import Path


def validate_upload_path(path: str | Path, upload_root: str | Path = "uploads") -> Path:
    root = Path(upload_root).resolve()
    target = Path(path).resolve()
    if root not in target.parents and target != root:
        raise ValueError("Path is outside upload directory")
    return target

