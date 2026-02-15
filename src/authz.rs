#[derive(Debug)]
pub struct PolicyDecisionRequest<'a> {
    pub principal: &'a str,
    pub action: &'a str,
    pub resource: &'a str,
    pub scopes: &'a [&'a str],
}

#[derive(Debug, PartialEq, Eq)]
pub struct PolicyDecision {
    pub allowed: bool,
    pub required_scope: Option<&'static str>,
    pub reason: &'static str,
}

pub fn evaluate_policy(request: &PolicyDecisionRequest<'_>) -> PolicyDecision {
    let required_scope = match (request.action, request.resource) {
        ("read", "account") => Some("api:read"),
        ("write", "account") => Some("api:write"),
        _ => None,
    };

    let Some(required_scope) = required_scope else {
        return PolicyDecision {
            allowed: false,
            required_scope: None,
            reason: "deny_by_default",
        };
    };

    let has_required_scope = request.scopes.contains(&required_scope);
    if has_required_scope {
        return PolicyDecision {
            allowed: true,
            required_scope: Some(required_scope),
            reason: "allowed",
        };
    }

    PolicyDecision {
        allowed: false,
        required_scope: Some(required_scope),
        reason: "missing_required_scope",
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_policy_decision_allows_known_action_with_required_scope() {
        let scopes = ["api:read"];
        let request = PolicyDecisionRequest {
            principal: "machine-client-1",
            action: "read",
            resource: "account",
            scopes: &scopes,
        };

        let decision = evaluate_policy(&request);
        assert!(decision.allowed);
        assert_eq!(decision.required_scope, Some("api:read"));
        assert_eq!(decision.reason, "allowed");
    }

    #[test]
    fn test_policy_decision_denies_unknown_action_by_default() {
        let scopes = ["api:read", "api:write"];
        let request = PolicyDecisionRequest {
            principal: "machine-client-1",
            action: "delete",
            resource: "account",
            scopes: &scopes,
        };

        let decision = evaluate_policy(&request);
        assert!(!decision.allowed);
        assert_eq!(decision.required_scope, None);
        assert_eq!(decision.reason, "deny_by_default");
    }
}
