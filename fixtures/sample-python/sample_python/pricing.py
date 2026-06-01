def normalize_discount_code(raw: str) -> str:
    return raw.strip().replace("-", "").upper()


def normalized_discount_tags(raw: str) -> list[str]:
    return sorted(tag.strip().lower() for tag in raw.split(",") if tag.strip())
