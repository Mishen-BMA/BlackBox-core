def cyclic(length: int, alphabet: str = "abcdefghijklmnopqrstuvwxyz") -> str:
    return "".join(alphabet[index % len(alphabet)] for index in range(length))

