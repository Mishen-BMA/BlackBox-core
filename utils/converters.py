import base64


def bytes_to_hex(data: bytes) -> str:
    return data.hex()


def bytes_to_b64(data: bytes) -> str:
    return base64.b64encode(data).decode()

