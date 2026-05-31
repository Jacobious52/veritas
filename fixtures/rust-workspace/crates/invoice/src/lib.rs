#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Invoice {
    pub account_id: String,
    pub cents: u32,
    pub currency: String,
}

impl Invoice {
    pub fn total_cents(&self) -> u32 {
        self.cents
    }

    pub fn is_usd(&self) -> bool {
        self.currency == "USD"
    }
}

pub fn parse_invoice_total(input: &str) -> u32 {
    input
        .trim()
        .strip_prefix("total=")
        .and_then(|value| value.parse::<u32>().ok())
        .unwrap_or(0)
}

pub fn apply_discount_cents(cents: u32, percent: u8) -> u32 {
    let bounded = percent.min(100) as u32;
    cents.saturating_sub(cents.saturating_mul(bounded) / 100)
}

pub fn serialize_invoice(cents: u32, paid: bool) -> String {
    let state = if paid { "paid" } else { "open" };
    format!("total={cents};state={state}")
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_total_prefix() {
        assert_eq!(parse_invoice_total("total=4200"), 4200);
    }

    #[test]
    fn malformed_totals_default_to_zero() {
        assert_eq!(parse_invoice_total("not-total"), 0);
    }

    #[test]
    fn discounts_are_capped() {
        assert_eq!(apply_discount_cents(1000, 250), 0);
    }

    #[test]
    fn serializes_paid_state() {
        assert_eq!(serialize_invoice(42, true), "total=42;state=paid");
    }
}
