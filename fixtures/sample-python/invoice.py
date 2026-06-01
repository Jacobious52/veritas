def parse_invoice_total(raw: str) -> tuple[int, bool]:
    normalized = raw.strip().replace("_", "")
    try:
        value = int(normalized)
    except ValueError:
        return 0, False
    if value <= 1_000_000:
        return value, True
    return 0, False


def authorize_refund(role: str, amount_cents: int) -> bool:
    return role == "admin" or (role == "support" and amount_cents <= 25_000)


def normalized_invoice_tags(raw: str) -> list[str]:
    return sorted(tag.strip().lower() for tag in raw.split(",") if tag.strip())
