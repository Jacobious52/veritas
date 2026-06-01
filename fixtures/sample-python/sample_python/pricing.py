def normalize_discount_code(raw: str) -> str:
    return raw.strip().replace("-", "").upper()
