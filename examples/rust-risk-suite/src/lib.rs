pub fn authorize_transfer(role: &str, amount_cents: u64) -> bool {
    role == "admin" || (role == "support" && amount_cents <= 10_000)
}

pub fn parse_discount_percent(input: &str) -> Option<u8> {
    let value = input.trim().parse::<u8>().ok()?;
    if value <= 50 {
        Some(value)
    } else {
        None
    }
}

pub fn serialize_status(code: u16) -> &'static str {
    if code >= 500 {
        "retry"
    } else if code >= 400 {
        "fail"
    } else {
        "ok"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_transfer_threshold_is_covered() {
        assert!(authorize_transfer("support", 10_000));
        assert!(!authorize_transfer("support", 10_001));
        assert!(authorize_transfer("admin", 999_999));
    }

    #[test]
    fn discount_parser_rejects_large_values() {
        assert_eq!(parse_discount_percent(" 50 "), Some(50));
        assert_eq!(parse_discount_percent("51"), None);
    }
}
