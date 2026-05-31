#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundRequest {
    pub user_role: String,
    pub cents: u32,
    pub original_charge_cents: u32,
}

pub fn parse_invoice_total(input: &str) -> u32 {
    let total = input
        .strip_prefix("total=")
        .expect("invoice total must start with total=");
    total.parse::<u32>().expect("invoice total must be numeric")
}

pub fn apply_discount_cents(cents: u32, percent: u8) -> u32 {
    let bounded = percent.min(100) as u32;
    cents.saturating_sub(cents.saturating_mul(bounded) / 100)
}

pub fn authorize_refund(request: RefundRequest) -> bool {
    request.user_role == "admin" || request.cents <= request.original_charge_cents
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_valid_invoice_total() {
        assert_eq!(parse_invoice_total("total=4200"), 4200);
    }

    #[test]
    fn caps_discount_at_full_value() {
        assert_eq!(apply_discount_cents(1000, 250), 0);
    }

    #[test]
    fn applies_partial_discount_without_over_capping() {
        assert_eq!(apply_discount_cents(1_000, 25), 750);
    }

    #[test]
    fn admins_can_refund_more_than_original_charge() {
        let request = RefundRequest {
            user_role: "admin".to_string(),
            cents: 1_001,
            original_charge_cents: 1_000,
        };

        assert!(authorize_refund(request));
    }

    #[test]
    fn regular_users_cannot_refund_more_than_original_charge() {
        let request = RefundRequest {
            user_role: "support".to_string(),
            cents: 1_001,
            original_charge_cents: 1_000,
        };

        assert!(!authorize_refund(request));
    }
}
