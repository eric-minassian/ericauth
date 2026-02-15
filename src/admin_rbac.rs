#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum AdminPermission {
    ReadAuditEvents,
    WriteAuditEvents,
}

pub fn has_admin_permission(scopes: &[String], permission: AdminPermission) -> bool {
    if scopes.iter().any(|scope| scope == "admin") {
        return true;
    }

    match permission {
        AdminPermission::ReadAuditEvents => scopes.iter().any(|scope| scope == "audit:read"),
        AdminPermission::WriteAuditEvents => scopes.iter().any(|scope| scope == "audit:write"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scopes(values: &[&str]) -> Vec<String> {
        values.iter().map(|value| (*value).to_string()).collect()
    }

    #[test]
    fn test_allow_deny_matrix_for_admin_roles_and_permissions() {
        let matrix = [
            (scopes(&["admin"]), AdminPermission::ReadAuditEvents, true),
            (scopes(&["admin"]), AdminPermission::WriteAuditEvents, true),
            (
                scopes(&["audit:read"]),
                AdminPermission::ReadAuditEvents,
                true,
            ),
            (
                scopes(&["audit:read"]),
                AdminPermission::WriteAuditEvents,
                false,
            ),
            (
                scopes(&["audit:write"]),
                AdminPermission::ReadAuditEvents,
                false,
            ),
            (
                scopes(&["audit:write"]),
                AdminPermission::WriteAuditEvents,
                true,
            ),
            (
                scopes(&["profile"]),
                AdminPermission::ReadAuditEvents,
                false,
            ),
            (
                scopes(&["profile"]),
                AdminPermission::WriteAuditEvents,
                false,
            ),
        ];

        for (scopes, permission, expected) in matrix {
            assert_eq!(
                has_admin_permission(&scopes, permission),
                expected,
                "expected scope set {:?} to {:?}={expected}",
                scopes,
                permission
            );
        }
    }
}
