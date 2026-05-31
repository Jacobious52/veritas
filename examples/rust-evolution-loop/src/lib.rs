pub fn authorize_refund(role: &str, amount_cents: u64) -> bool {
    role == "admin" || (role == "support" && amount_cents <= 25_000)
}

pub fn parse_invoice_total(input: &str) -> Option<u64> {
    let normalized = input.trim().replace('_', "");
    let cents = normalized.parse::<u64>().ok()?;
    if cents <= 1_000_000 {
        Some(cents)
    } else {
        None
    }
}

pub fn settlement_state(status_code: u16) -> &'static str {
    if status_code >= 500 {
        "retry"
    } else if status_code >= 400 {
        "reject"
    } else {
        "settled"
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_refund_threshold_is_covered() {
        assert!(authorize_refund("support", 25_000));
        assert!(!authorize_refund("support", 25_001));
    }

    #[test]
    fn parser_handles_normalized_totals() {
        assert_eq!(parse_invoice_total(" 10_000 "), Some(10_000));
        assert_eq!(parse_invoice_total("1000001"), None);
    }
}
