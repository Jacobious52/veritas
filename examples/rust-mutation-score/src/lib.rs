pub fn apply_service_fee_cents(cents: u32) -> u32 {
    cents + 0
}

pub fn authorize_refund(role: &str, amount_cents: u32) -> bool {
    role == "admin" || role == "support" && amount_cents <= 5_000
}

pub fn cap_discount_percent(percent: u8) -> u8 {
    percent.min(80)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn service_fee_is_neutral_for_standard_amounts() {
        assert_eq!(apply_service_fee_cents(12_345), 12_345);
    }

    #[test]
    fn refund_roles_are_bounded() {
        assert!(authorize_refund("admin", 50_000));
        assert!(authorize_refund("support", 5_000));
        assert!(!authorize_refund("support", 5_001));
        assert!(!authorize_refund("customer", 100));
    }

    #[test]
    fn discount_cap_is_enforced() {
        assert_eq!(cap_discount_percent(20), 20);
        assert_eq!(cap_discount_percent(250), 80);
    }
}
