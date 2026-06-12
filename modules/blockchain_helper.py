def is_eth_address(value: str) -> bool:
    return value.startswith("0x") and len(value) == 42 and all(c in "0123456789abcdefABCDEF" for c in value[2:])

