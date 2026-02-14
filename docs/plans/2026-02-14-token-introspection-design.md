# Token Introspection (RFC 7662) + Confidential Client Support

## Summary

Add an RFC 7662-compliant Token Introspection endpoint (`POST /token/introspect`)
that allows confidential OAuth2 clients to validate access tokens. This requires
adding `client_secret` support to the client model, distinguishing between public
and confidential clients.

## Motivation

Token introspection is a core OAuth2 endpoint that every industry-standard auth
provider supports. Resource servers need a reliable way to validate tokens
server-side, especially for checking revocation status or when they can't perform
local JWT verification. Adding confidential client support also lays the
groundwork for future features like client credentials grant.

## Constraints

- No SMS or email integration
- Access tokens only (no refresh token introspection)
- Client authentication via `client_secret_basic` and `client_secret_post`

## Design

### 1. Schema Change: `ClientTable`

Add an optional `client_secret` field to `ClientTable`:

```rust
pub struct ClientTable {
    pub client_id: String,
    pub client_secret: Option<String>,  // SHA-256 hashed; None = public client
    pub redirect_uris: Vec<String>,
    pub allowed_scopes: Vec<String>,
    pub client_name: String,
}
```

- `None` = public client (existing behavior, PKCE-only)
- `Some(hash)` = confidential client (can authenticate with secret)
- Secrets are SHA-256 hashed before storage (consistent with session tokens and auth codes)
- No DynamoDB migration needed — existing items without the field deserialize as `None`

### 2. Client Authentication Module (`src/client_auth.rs`)

New module that extracts and validates client credentials from:

- **`client_secret_basic`**: `Authorization: Basic base64(client_id:client_secret)`
- **`client_secret_post`**: `client_id` + `client_secret` as POST form params

Returns `AuthenticatedClient { client_id, client: ClientTable }` on success.

Error responses:
- Missing credentials: `401 Unauthorized` with `WWW-Authenticate: Basic` header
- Invalid credentials: `401 Unauthorized`
- Client not found: `401 Unauthorized` (don't leak whether client exists)
- Public client attempting secret auth: `401 Unauthorized`

Uses constant-time comparison for secret verification to prevent timing attacks.

### 3. Introspection Endpoint: `POST /token/introspect`

**Route**: `POST /token/introspect`
**Handler**: `src/routes/introspect.rs`

**Request** (application/x-www-form-urlencoded):
```
POST /token/introspect HTTP/1.1
Authorization: Basic base64(client_id:client_secret)
Content-Type: application/x-www-form-urlencoded

token=eyJhbGciOi...&token_type_hint=access_token
```

**Active token response** (200 OK):
```json
{
  "active": true,
  "scope": "openid profile email",
  "client_id": "my-app",
  "sub": "user-uuid",
  "exp": 1700000000,
  "iat": 1699999100,
  "iss": "https://auth.ericminassian.com",
  "token_type": "Bearer",
  "email": "user@example.com"
}
```

**Inactive token response** (200 OK):
```json
{
  "active": false
}
```

**Behavior**:
- Authenticate the calling client first (must be a confidential client)
- Decode the JWT using `JwtKeys::verify_access_token()`
- If verification fails, token is expired, or malformed: return `{"active": false}`
- Any authenticated confidential client can introspect any token (per RFC 7662)
- `token_type_hint` is accepted but optional; only `access_token` is supported
- Always include `Cache-Control: no-store` and `Pragma: no-cache` headers

### 4. OpenID Configuration Update

Add to `/.well-known/openid-configuration` response:

```json
{
  "introspection_endpoint": "https://auth.ericminassian.com/token/introspect",
  "introspection_endpoint_auth_methods_supported": [
    "client_secret_basic",
    "client_secret_post"
  ]
}
```

### 5. Router Integration

- Add `/token/introspect` to the `cors_routes` group (alongside `/token`, `/token/revoke`)
- Same CORS policy as other token endpoints
- Rate limiting inherited from global setup

### 6. Memory Backend Updates

- Update `MemoryDb` to handle `client_secret` field in client storage
- Ensure `insert_client` works with confidential clients for testing

### 7. Testing Strategy

**Unit tests** (inline `#[cfg(test)] mod tests`):
- Client auth: Basic header parsing, form body parsing, secret verification,
  public client rejection, missing credentials, invalid credentials
- Introspection: active token response, expired token, malformed token,
  missing token param, unknown token_type_hint

**Integration tests**:
- Full flow: register confidential client -> issue token -> introspect token
- Introspect expired token returns `{"active": false}`
- Public client cannot call introspection endpoint

## Files Changed

| File | Change |
|------|--------|
| `src/db/client.rs` | Add `client_secret: Option<String>` to `ClientTable` |
| `src/db/mod.rs` | Update client dispatch methods if needed |
| `src/db/memory.rs` | Handle `client_secret` in memory backend |
| `src/client_auth.rs` (new) | Client authentication extraction + validation |
| `src/lib.rs` | Add `pub mod client_auth;` |
| `src/routes/introspect.rs` (new) | `POST /token/introspect` handler |
| `src/routes/mod.rs` | Register introspect route in `cors_routes` |
| `src/routes/openid_config.rs` | Add introspection_endpoint fields |
| `tests/integration_test.rs` | Integration tests for introspection |
