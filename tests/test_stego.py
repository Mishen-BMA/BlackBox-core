from modules.stego import read_trailing_bytes


def test_read_trailing_bytes(tmp_path) -> None:
    sample = tmp_path / "image.png"
    sample.write_bytes(b"1234567890")
    assert read_trailing_bytes(sample, 4) == b"7890"

