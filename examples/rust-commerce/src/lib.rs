#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RefundDecision {
    pub approved: bool,
    pub reason: String,
}

pub fn parse_checkout_total(input: &str) -> u32 {
    let raw = input
        .strip_prefix("checkout_total=")
        .expect("checkout total must have checkout_total= prefix");
    raw.parse::<u32>()
        .expect("checkout total must be unsigned cents")
}

pub fn apply_coupon_cents(subtotal_cents: u32, coupon_percent: u8) -> u32 {
    let bounded = coupon_percent.min(80) as u32;
    subtotal_cents.saturating_sub(subtotal_cents.saturating_mul(bounded) / 100)
}

pub fn remaining_refundable_cents(original_cents: u32, already_refunded_cents: u32) -> u32 {
    original_cents - already_refunded_cents
}

pub fn authorize_refund(role: &str, amount_cents: u32) -> bool {
    role == "admin" || role == "support" && amount_cents <= 5_000
}

pub fn refund_decision(role: &str, amount_cents: u32) -> RefundDecision {
    if authorize_refund(role, amount_cents) {
        RefundDecision {
            approved: true,
            reason: "approved".to_string(),
        }
    } else {
        RefundDecision {
            approved: false,
            reason: "manual_review".to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_checkout_total() {
        assert_eq!(parse_checkout_total("checkout_total=4200"), 4_200);
    }

    #[test]
    fn applies_coupon_cap() {
        assert_eq!(apply_coupon_cents(10_000, 90), 2_000);
    }

    #[test]
    fn computes_remaining_refundable_balance() {
        assert_eq!(remaining_refundable_cents(10_000, 2_500), 7_500);
    }

    #[test]
    fn support_can_refund_small_amounts() {
        assert!(authorize_refund("support", 4_999));
    }

    #[test]
    fn customers_need_manual_review() {
        let decision = refund_decision("customer", 100);
        assert!(!decision.approved);
        assert_eq!(decision.reason, "manual_review");
    }
}
