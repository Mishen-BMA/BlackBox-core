from modules.pwn_helper import cyclic


def test_cyclic_length() -> None:
    assert len(cyclic(32)) == 32

