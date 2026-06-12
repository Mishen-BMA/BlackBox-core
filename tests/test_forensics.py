from modules.forensics import file_signature


def test_file_signature(tmp_path) -> None:
    sample = tmp_path / "sample.bin"
    sample.write_bytes(b"ABCDEF")
    assert file_signature(sample, 3) == b"ABC"

