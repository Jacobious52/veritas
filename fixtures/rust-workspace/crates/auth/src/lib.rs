#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Policy {
    pub max_refund_cents: u32,
}

impl Policy {
    pub fn authorize_refund(&self, role: &str, amount_cents: u32) -> bool {
        role == "admin" || (role == "support" && amount_cents <= self.max_refund_cents)
    }
}

pub fn normalize_token(input: &str) -> String {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        "anonymous".to_string()
    } else {
        trimmed.to_ascii_lowercase()
    }
}

pub fn has_permission(role: &str, permission: &str) -> bool {
    matches!(
        (role.trim(), permission.trim()),
        ("admin", _) | ("support", "refund:read") | ("support", "refund:create")
    )
}

pub fn validate_token(input: &str) -> bool {
    let token = normalize_token(input);
    token != "anonymous" && token.len() >= 8 && token.chars().all(|ch| ch.is_ascii_alphanumeric())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn admin_has_all_permissions() {
        assert!(has_permission("admin", "billing:delete"));
    }

    #[test]
    fn support_write_scope_is_limited() {
        assert!(has_permission("support", "refund:create"));
        assert!(!has_permission("support", "billing:delete"));
    }

    #[test]
    fn token_validation_rejects_short_tokens() {
        assert!(!validate_token("abc"));
        assert!(validate_token("token1234"));
    }

    #[test]
    fn policy_caps_support_refunds() {
        let policy = Policy {
            max_refund_cents: 500,
        };
        assert!(policy.authorize_refund("support", 500));
        assert!(!policy.authorize_refund("support", 501));
    }
}
