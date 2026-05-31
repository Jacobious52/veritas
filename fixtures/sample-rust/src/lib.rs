pub fn parse_invoice_total(input: &str) -> u32 {
    input
        .trim()
        .parse::<u32>()
        .unwrap_or(0)
}

pub fn apply_discount_cents(cents: u32, percent: u8) -> u32 {
    let bounded = percent.min(100) as u32;
    cents.saturating_sub(cents.saturating_mul(bounded) / 100)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_invoice_total() {
        assert_eq!(parse_invoice_total("42"), 42);
    }

    #[test]
    fn invalid_invoice_total_defaults_to_zero() {
        assert_eq!(parse_invoice_total("not-a-number"), 0);
    }

    #[test]
    fn discounts_cents() {
        assert_eq!(apply_discount_cents(1000, 10), 900);
    }
}
