use crate::db::client::ClientTable;
use crate::password::verify_password_hash;

const FORBIDDEN_USER_SCOPES: [&str; 3] = ["openid", "email", "profile"];

pub fn authenticate_client_secret_post(
    client: &ClientTable,
    provided_secret: Option<&str>,
) -> Result<bool, &'static str> {
    if client.token_endpoint_auth_method != "client_secret_post" {
        return Ok(false);
    }

    let client_secret = match provided_secret {
        Some(secret) if !secret.is_empty() => secret,
        _ => return Ok(false),
    };

    let secret_hash = match client.client_secret_hash.as_deref() {
        Some(hash) => hash,
        None => return Ok(false),
    };

    verify_password_hash(client_secret, secret_hash)
}

pub fn resolve_scope(
    client: &ClientTable,
    requested_scope: Option<&str>,
) -> Result<String, &'static str> {
    let allowed = client.allowed_scope_set();

    match requested_scope {
        Some(scope) => {
            if scope.trim().is_empty() {
                return Err("scope must not be empty");
            }

            for item in scope.split_whitespace() {
                if FORBIDDEN_USER_SCOPES.contains(&item) {
                    return Err("requested scope is not allowed for client_credentials");
                }
                if !allowed.contains(item) {
                    return Err("requested scope is not allowed for this client");
                }
            }

            Ok(scope.to_string())
        }
        None => {
            for item in &client.allowed_scopes {
                if FORBIDDEN_USER_SCOPES.contains(&item.as_str()) {
                    return Err("requested scope is not allowed for client_credentials");
                }
            }
            Ok(client.allowed_scopes.join(" "))
        }
    }
}
