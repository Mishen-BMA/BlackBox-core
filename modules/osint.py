def normalize_domain(domain: str) -> str:
    return domain.strip().lower().removeprefix("http://").removeprefix("https://").strip("/")

