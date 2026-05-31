use auth::{has_permission, Policy};
use invoice::{apply_discount_cents, parse_invoice_total};

pub fn can_issue_discounted_refund(role: &str, total: &str, discount: u8) -> bool {
    let cents = parse_invoice_total(total);
    let discounted = apply_discount_cents(cents, discount);
    let policy = Policy {
        max_refund_cents: 10_000,
    };
    has_permission(role, "refund:create") && policy.authorize_refund(role, discounted)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn support_can_issue_small_discounted_refund() {
        assert!(can_issue_discounted_refund("support", "total=500", 10));
    }

    #[test]
    fn unknown_role_cannot_issue_refund() {
        assert!(!can_issue_discounted_refund("guest", "total=500", 10));
    }
}
