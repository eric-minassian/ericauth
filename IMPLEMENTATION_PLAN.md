# EricAuth Implementation Plan

Each task is scoped to a single commit. Tasks within a phase are ordered by dependency. Tasks across phases are sequential unless noted otherwise.

**Architecture decision:** The service uses a **single Lambda binary** with an **axum Router** for all routes. This replaces the previous per-route Lambda approach, giving us shared state (DynamoDB client, JWT keys), tower middleware (auth, CSRF, security headers), and axum extractors. API Gateway uses a `{proxy+}` catch-all resource so all requests forward to the single Lambda — adding new routes requires only a Rust code change, no CDK updates.

**Key technical constraints:**
- `lambda_http` must be upgraded from `0.14.0` to `1.x` — version 0.14 uses `tower 0.4` which conflicts with axum 0.8's `tower 0.5` dependency
- API Gateway REST API `{proxy+}` does NOT match the root path `/` — we need both a root `ANY` method and the proxy resource
- Do NOT use `defaultCorsPreflightOptions` on the RestApi when using `anyMethod: true` on the proxy (conflicts on OPTIONS) — let axum handle CORS via `tower-http`
- Current DB modules (`src/db/user.rs`, `src/db/session.rs`) are private (`mod`) — must become `pub mod` for the routes to access them

---

## Phase 0: Restructure to Single axum Lambda

### 0.1 — ~~Replace `lambda_http` handlers with axum + single binary~~ DONE

**Context:** Currently the project has 3 separate binaries (`src/bin/health.rs`, `src/bin/signup.rs`, `src/bin/login.rs`), each a standalone Lambda function. We are consolidating into a single binary with an axum Router.

**Files to create:** `src/main.rs`, `src/routes/mod.rs`, `src/routes/health.rs`, `src/routes/signup.rs`, `src/routes/login.rs`, `src/state.rs`

**Files to delete:** `src/bin/health.rs`, `src/bin/signup.rs`, `src/bin/login.rs`

**Files to modify:** `Cargo.toml`

**Steps:**
1. Update `Cargo.toml`:
   - Remove all `[[bin]]` entries (if any explicit ones exist)
   - Add dependencies:
     ```toml
     axum = "0.8"
     tower-http = { version = "0.6", features = ["cors", "trace"] }
     tracing = "0.1"
     tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }
     ```
   - **Upgrade `lambda_http` from `"0.14.0"` to `"1"`** — required because `lambda_http` 0.14 depends on `tower 0.4` which is incompatible with axum 0.8's `tower 0.5`. Version 1.x aligns both on `tower 0.5` and `http 1.x`.
   - Keep all existing dependencies
2. Create `src/state.rs` with shared application state:
   ```rust
   #[derive(Clone)]
   pub struct AppState {
       pub db: Database,  // existing Database struct (DynamoDB client wrapper)
   }
   ```
   - Initialize the DynamoDB client once in `AppState::new()` (called at cold start)
3. Create `src/routes/mod.rs` that declares submodules and builds the router:
   ```rust
   pub fn router(state: AppState) -> Router {
       Router::new()
           .route("/health", get(health::handler))
           .route("/signup", post(signup::handler))
           .route("/login", post(login::handler))
           .with_state(state)
   }
   ```
4. Create `src/routes/health.rs` — migrate the health handler to an axum handler function:
   ```rust
   pub async fn handler() -> &'static str { "OK" }
   ```
5. Create `src/routes/signup.rs` — migrate `src/bin/signup.rs` to an axum handler:
   - Use `State(state): State<AppState>` for DB access
   - Use `Json(body): Json<SignupRequest>` for request parsing
   - Return `(StatusCode, HeaderMap, Json<...>)` or `impl IntoResponse`
   - Move the X-Forwarded-For extraction to use axum headers extractor
6. Create `src/routes/login.rs` — same migration pattern as signup
7. Create `src/main.rs`:
   ```rust
   #[tokio::main]
   async fn main() -> Result<(), lambda_http::Error> {
       tracing_subscriber::fmt()
           .with_env_filter(tracing_subscriber::EnvFilter::from_default_env())
           .json()
           .init();
       // Strip API Gateway stage prefix
       std::env::set_var("AWS_LAMBDA_HTTP_IGNORE_STAGE_IN_PATH", "true");
       let state = AppState::new().await;
       let app = routes::router(state);
       lambda_http::run(app).await
   }
   ```
8. Delete `src/bin/health.rs`, `src/bin/signup.rs`, `src/bin/login.rs` (and the `src/bin/` directory)
9. Verify: `cargo lambda build` produces a single binary
10. Verify locally: `cargo lambda watch` and test all 3 routes

---

### 0.2 — ~~Update CDK to deploy single Lambda~~ DONE

**Files:** `cdk/lib/constructs/lambda.ts`, `cdk/lib/constructs/api.ts`, `cdk/lib/cdk-stack.ts`

**Steps:**
1. Rewrite `cdk/lib/constructs/lambda.ts`:
   - Replace the 3 separate `RustFunction` constructs with a single one:
     ```typescript
     this.handler = new RustFunction(this, 'AuthFunction', {
       manifestPath,
       binaryName: 'ericauth',  // matches the package name in Cargo.toml
       environment: {
         USERS_TABLE_NAME: usersTable.tableName,
         SESSIONS_TABLE_NAME: sessionsTable.tableName,
       },
     });
     ```
   - Grant DynamoDB read/write on both tables to the single handler
   - Simplify the constructor to accept tables and return one handler
2. Rewrite `cdk/lib/constructs/api.ts`:
   - **Remove all individual resource/method definitions** — axum handles routing internally
   - Use a catch-all `{proxy+}` resource plus root `ANY` method:
     ```typescript
     interface ApiProps {
       domainName: string;
       certificate: ICertificate;
       handler: RustFunction;  // single handler, not multiple
     }

     // Inside the construct:
     const integration = new LambdaIntegration(props.handler);

     // Root path "/" — {proxy+} does NOT match the bare root
     this.api.root.addMethod('ANY', integration);

     // All sub-paths "/{proxy+}" — catches /health, /login, /.well-known/jwks.json, etc.
     this.api.root.addProxy({
       defaultIntegration: integration,
       anyMethod: true,
     });
     ```
   - **Do NOT set `defaultCorsPreflightOptions`** on the RestApi — it conflicts with `anyMethod: true` on the proxy resource (both try to add an OPTIONS method). CORS is handled by axum via `tower-http::CorsLayer` instead.
   - Paths starting with `.` (like `/.well-known/jwks.json`) work fine with the proxy resource
3. Update `cdk/lib/cdk-stack.ts`:
   - Simplify to pass a single `handler` to the Api construct instead of individual handlers
   - Remove the per-handler references from `Lambdas`
4. Verify: `cdk synth` succeeds and produces the expected CloudFormation

---

### 0.3 — ~~Make Database struct Clone-friendly for axum State~~ DONE

**Files:** `src/db/mod.rs`, `src/db/user.rs`, `src/db/session.rs`, `src/state.rs`

**Steps:**
1. **Fix module visibility:** Change `mod session; mod user;` to `pub mod session; pub mod user;` in `src/db/mod.rs` — currently these are private, but route handlers need to access the DB types and methods
2. The `Database` struct wraps `aws_sdk_dynamodb::Client`, which is already `Clone` (it uses `Arc` internally)
3. Derive or implement `Clone` on `Database`
4. Ensure `AppState` is `Clone` (required by axum's `State` extractor)
5. Update `Database::new()` to read table names from env vars once and store them as fields:
   ```rust
   #[derive(Clone)]
   pub struct Database {
       client: aws_sdk_dynamodb::Client,
       pub users_table: String,
       pub sessions_table: String,
   }
   ```
6. Update `src/db/user.rs` and `src/db/session.rs` to use `self.users_table` / `self.sessions_table` instead of the `LazyLock` static env var reads — the statics (`USERS_TABLE_NAME`, `SESSIONS_TABLE_NAME`, `USERS_TABLE_EMAIL_INDEX_NAME`) should be replaced with fields on `Database`
7. Remove `Database::new()` creating a *new* DynamoDB client each call — the existing handlers call `Database::new().await` on every request (see `signup.rs:70`, `login.rs:69`), which is wasteful. `AppState` initializes the client once at cold start.
8. Consolidate the `verify_email()` function — currently duplicated in both `signup.rs` and `login.rs`. Move to a shared `src/validation.rs` module or into `src/user.rs`
9. Remove the `SessionResponse` trait from `src/session.rs` — it extends `lambda_http::http::response::Builder` which won't be used in axum. Replace with a helper function that builds axum cookie headers.
10. Verify: `cargo build`

---

## Phase 1: Core Auth Hardening

### 1.1 — ~~Replace `.unwrap()` with proper error propagation~~ DONE

**Files:** `src/lib.rs`, `src/user.rs`, `src/password.rs`, `src/session.rs`, `src/encryption.rs`, `src/db/mod.rs`, `src/db/user.rs`, `src/db/session.rs`, `src/routes/signup.rs`, `src/routes/login.rs`

**Steps:**
1. Create `src/error.rs` with a custom `AuthError` enum:
   - Variants: `BadRequest(String)`, `Unauthorized(String)`, `NotFound(String)`, `Conflict(String)`, `Internal(String)`, `TooManyRequests(String)`
   - Implement `std::fmt::Display` and `std::error::Error`
   - Implement `axum::response::IntoResponse` for `AuthError` — maps each variant to the appropriate HTTP status code and JSON body `{"error": "...", "message": "..."}`
2. Replace all `.unwrap()` calls in `src/db/user.rs` and `src/db/session.rs` with `?` propagation returning `Result<_, AuthError>`
3. Replace all `.unwrap()` calls in `src/user.rs`, `src/password.rs`, `src/session.rs` with `?`
4. Update route handlers in `src/routes/signup.rs` and `src/routes/login.rs` to return `Result<impl IntoResponse, AuthError>` — axum handles the error conversion automatically
5. Remove the `error_response` helper from `lib.rs` (replaced by `AuthError`'s `IntoResponse` impl)
6. Export `error` module from `src/lib.rs`
7. Verify: `cargo lambda build`

---

### 1.2 — ~~Add `created_at` and `updated_at` timestamps to Users~~ DONE

**Files:** `src/user.rs`, `src/db/user.rs`

**Steps:**
1. Add `created_at: String` (ISO 8601) and `updated_at: String` fields to the `User` struct
2. Set both to `chrono::Utc::now().to_rfc3339()` in `create_user()`
3. Update `insert_user()` to write these fields to DynamoDB
4. Update `User` deserialization (via `serde_dynamo`) to include the new fields
5. Verify: `cargo build`

---

### 1.3 — ~~Add session validation as axum middleware~~ DONE

**Files:** new `src/middleware/mod.rs`, new `src/middleware/auth.rs`, `src/db/session.rs`, `src/session.rs`, `src/lib.rs`

**Steps:**
1. Add `get_session_by_token(token: &str) -> Result<Session, AuthError>` to `src/db/session.rs`:
   - SHA-256 hash the incoming raw token
   - Hex-encode the hash
   - `GetItem` from SessionsTable by the hashed ID
   - Check `expires_at` > now (application-level expiry check)
   - Return the `Session` struct or `AuthError::Unauthorized`
2. Create `src/middleware/auth.rs` with an axum extractor for authenticated sessions:
   ```rust
   pub struct AuthenticatedUser {
       pub user_id: String,
       pub session_id: String,
   }

   impl<S> FromRequestParts<S> for AuthenticatedUser
   where
       S: Send + Sync,
       AppState: FromRef<S>,
   {
       type Rejection = AuthError;
       async fn from_request_parts(parts: &mut Parts, state: &S) -> Result<Self, Self::Rejection> {
           let state = AppState::from_ref(state);
           // Extract Cookie header, parse "session=<token>" value
           // Call state.db.get_session_by_token(token)
           // Return AuthenticatedUser { user_id, session_id } or AuthError::Unauthorized
       }
   }
   ```
   Note: `#[axum::async_trait]` is NOT needed — axum 0.7+ uses native async in trait (Rust 1.75+).
3. This extractor can be added to any handler signature to require authentication — no middleware wiring needed per route
4. Create `src/middleware/mod.rs` exporting the `auth` module
5. Export `middleware` module from `src/lib.rs`

---

### 1.4 — ~~Add logout route~~ DONE

**Files:** new `src/routes/logout.rs`, `src/routes/mod.rs`, `src/db/session.rs`

**Steps:**
1. Add `delete_session(session_id: &str) -> Result<(), AuthError>` to `src/db/session.rs`
2. Create `src/routes/logout.rs`:
   ```rust
   pub async fn handler(
       State(state): State<AppState>,
       user: AuthenticatedUser,  // the extractor validates the session
   ) -> Result<impl IntoResponse, AuthError> {
       state.db.delete_session(&user.session_id).await?;
       // Return 204 with Set-Cookie clearing the session
   }
   ```
3. Register in `src/routes/mod.rs`: `.route("/logout", post(logout::handler))`
4. No CDK changes needed — the single Lambda already handles all routes

---

### 1.5 — ~~Add TTL to Sessions table~~ DONE

**Files:** `cdk/lib/constructs/database.ts`, `src/session.rs`, `src/db/session.rs`

**Steps:**
1. Add `timeToLiveAttribute: 'expires_at'` to the SessionsTable definition in CDK
2. Update `create_session()` to store `expires_at` as **Unix epoch seconds Number** (DynamoDB TTL requires this)
3. Update `insert_session()` to write `expires_at` as `AttributeValue::N(epoch_seconds.to_string())`
4. Update `get_session_by_token()` to compare against current epoch seconds
5. Note: breaking schema change — existing sessions will need invalidation

---

### 1.6 — ~~Add IP address tracking to sessions~~ DONE

**Files:** `src/session.rs`, `src/db/session.rs`, `src/routes/signup.rs`, `src/routes/login.rs`

**Steps:**
1. Add `ip_address: String` field to `Session` struct
2. Update `create_session()` to accept `ip_address: &str`
3. Update `insert_session()` to write the IP address
4. In signup and login handlers, extract IP from axum `ConnectInfo` or `X-Forwarded-For` header and pass to `create_session()`

---

## Phase 2: JWT Infrastructure

### 2.1 — ~~Add JWT dependencies and key loading~~ DONE

**Files:** `Cargo.toml`, new `src/jwt.rs`, `src/state.rs`

**Steps:**
1. Add to `Cargo.toml`:
   ```toml
   jsonwebtoken = { version = "10", features = ["p256"] }
   p256 = { version = "0.13", features = ["ecdsa", "pem"] }
   base64 = "0.22"
   serde_json = "1"
   ```
2. Create `src/jwt.rs` with:
   - `JwtKeys` struct: `encoding_key: EncodingKey`, `decoding_key: DecodingKey`, `kid: String`, `public_key_pem: String` (stored for JWKS construction)
   - `JwtKeys::from_pem(private_pem: &[u8], kid: &str) -> Result<Self, AuthError>` — loads keys from PEM bytes using `jsonwebtoken::EncodingKey::from_ec_pem()` and `DecodingKey::from_ec_pem()`
   - `generate_es256_keypair() -> (String, String)` — for initial provisioning, returns `(private_pem, public_pem)` using `p256::ecdsa::SigningKey::random(&mut OsRng)` and `to_pkcs8_pem()`
3. Add `jwt_keys: JwtKeys` to `AppState` — loaded once at cold start from `JWT_PRIVATE_KEY` env var
4. Export `jwt` module from `src/lib.rs`
5. Verify: `cargo build`

---

### 2.2 — ~~Implement JWT signing and verification~~ DONE

**Files:** `src/jwt.rs`

**Steps:**
1. Define `AccessTokenClaims` struct (serde Serialize/Deserialize):
   - Fields: `iss`, `sub`, `aud`, `exp`, `iat`, `scope`, `email`
2. Define `IdTokenClaims` struct:
   - Fields: `iss`, `sub`, `aud`, `exp`, `iat`, `auth_time`, `nonce` (Option), `email`, `email_verified`
3. Implement `JwtKeys::sign_access_token(&self, claims: &AccessTokenClaims) -> Result<String, AuthError>`:
   - Create `Header` with `alg: ES256` and `kid`
   - Call `jsonwebtoken::encode()`
4. Implement `JwtKeys::sign_id_token(&self, claims: &IdTokenClaims) -> Result<String, AuthError>`
5. Implement `JwtKeys::verify_access_token(&self, token: &str, audience: &str) -> Result<AccessTokenClaims, AuthError>`:
   - Create `Validation::new(Algorithm::ES256)` with issuer `"https://auth.ericminassian.com"` and audience checks
   - Call `jsonwebtoken::decode()`
6. Add unit tests for sign -> verify round-trip

---

### 2.3 — ~~Implement JWKS endpoint~~ DONE

**Files:** `src/jwt.rs`, new `src/routes/jwks.rs`, `src/routes/mod.rs`

**Steps:**
1. In `src/jwt.rs`, define `Jwk` and `JwkSet` structs (serde Serialize):
   ```rust
   pub struct Jwk {
       pub kty: &'static str,    // "EC"
       pub crv: &'static str,    // "P-256"
       pub x: String,            // base64url
       pub y: String,            // base64url
       pub use_: &'static str,   // "sig"
       pub alg: &'static str,    // "ES256"
       pub kid: String,
   }
   ```
2. Implement `JwtKeys::to_jwk(&self) -> Result<Jwk, AuthError>`:
   - Parse the stored public PEM with `p256::PublicKey::from_public_key_pem()`
   - Extract x,y from `to_encoded_point(false)`
   - Base64url-encode both coordinates
3. Create `src/routes/jwks.rs`:
   ```rust
   pub async fn handler(State(state): State<AppState>) -> impl IntoResponse {
       let jwk = state.jwt_keys.to_jwk()?;
       let jwks = JwkSet { keys: vec![jwk] };
       (
           [(header::CONTENT_TYPE, "application/json"),
            (header::CACHE_CONTROL, "public, max-age=3600")],
           Json(jwks),
       )
   }
   ```
4. Register: `.route("/.well-known/jwks.json", get(jwks::handler))`
5. Add `JWT_PRIVATE_KEY` env var to the Lambda in CDK (placeholder value for now)

---

### 2.4 — ~~Add scopes to user model~~ DONE

**Files:** `src/user.rs`, `src/db/user.rs`

**Steps:**
1. Add `scopes: Vec<String>` to `User` struct (default empty via `#[serde(default)]`)
2. Update `insert_user()` to write scopes as a DynamoDB List
3. Update `get_user_by_email()` to deserialize scopes
4. Add `update_user_scopes(user_id: &str, scopes: Vec<String>) -> Result<(), AuthError>` to `src/db/user.rs`
5. Verify: `cargo build`

---

### 2.5 — ~~Add refresh token storage and rotation~~ DONE

**Files:** new `src/refresh_token.rs`, new `src/db/refresh_token.rs`, `src/db/mod.rs`, `src/state.rs`, `cdk/lib/constructs/database.ts`, `cdk/lib/constructs/lambda.ts`

**Steps:**
1. In `cdk/lib/constructs/database.ts`, add `RefreshTokensTable`:
   ```typescript
   this.refreshTokensTable = new TableV2(this, 'RefreshTokensTable', {
     tableName: 'RefreshTokensTable',
     partitionKey: { name: 'token_hash', type: AttributeType.STRING },
     timeToLiveAttribute: 'expires_at',
   });
   ```
2. In `cdk/lib/constructs/lambda.ts`, add env var and grant permissions:
   ```typescript
   environment: {
     ...existing,
     REFRESH_TOKENS_TABLE_NAME: refreshTokensTable.tableName,
   },
   ```
   and `refreshTokensTable.grantReadWriteData(this.handler)`
3. Create `src/refresh_token.rs`:
   - `generate_refresh_token() -> String` — 32 random bytes, base64url-encoded
   - `RefreshToken` struct: `token_hash`, `user_id`, `client_id`, `scope`, `expires_at`, `revoked`
4. Create `src/db/refresh_token.rs`:
   - `insert_refresh_token()`, `get_refresh_token()` (check expiry + revoked), `revoke_refresh_token()`
5. Add `refresh_tokens_table: String` to `Database` struct, read from `REFRESH_TOKENS_TABLE_NAME` env var
6. Export modules from `src/db/mod.rs` and `src/lib.rs`

---

### 2.6 — ~~Implement `/token` endpoint (refresh_token grant only)~~ DONE

**Files:** new `src/routes/token.rs`, `src/routes/mod.rs`

**Note:** The `grant_type=authorization_code` flow depends on AuthCodesTable and Clients table, which are created in Phase 5. This task implements the token endpoint structure and `refresh_token` grant only. The `authorization_code` grant is wired in task 5.7.

**Steps:**
1. Create `src/routes/token.rs` handler that accepts `Form<TokenRequest>` (axum's `application/x-www-form-urlencoded` extractor)
2. Support `grant_type=refresh_token`:
   - Parse: `refresh_token`, `client_id`, `scope` (optional subset)
   - Hash token, look up in RefreshTokensTable, verify not expired/revoked, client_id matches
   - Revoke old refresh token
   - Issue new access token + new refresh token (rotation)
   - Return JSON: `{ access_token, token_type: "Bearer", expires_in: 900, refresh_token, scope }`
   - Set `Cache-Control: no-store`, `Pragma: no-cache`
3. For `grant_type=authorization_code`: return `{"error": "unsupported_grant_type"}` for now (implemented in Phase 5.7)
4. Return `{"error": "...", "error_description": "..."}` for all error cases per RFC 6749 Section 5.2
5. Register: `.route("/token", post(token::handler))`

---

### 2.7 — ~~Implement `/token/revoke` endpoint~~ DONE

**Files:** new `src/routes/token_revoke.rs`, `src/routes/mod.rs`

**Steps:**
1. Create handler accepting `Form<RevokeRequest>`: `token`, `token_type_hint` (optional)
2. Hash token, look up in RefreshTokensTable
3. If found: revoke. If not found: return 200 OK anyway (RFC 7009)
4. Always return 200 OK
5. Register: `.route("/token/revoke", post(token_revoke::handler))`

---

## Phase 3: WebAuthn Passkeys

### 3.1 — ~~Add WebAuthn dependencies and configuration~~ DONE

**Files:** `Cargo.toml`, new `src/webauthn_config.rs`, `src/state.rs`

**Steps:**
1. Add to `Cargo.toml`:
   ```toml
   webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
   url = "2"
   ```
2. Create `src/webauthn_config.rs`:
   - `build_webauthn() -> Result<webauthn_rs::Webauthn, AuthError>`:
     ```rust
     let rp_id = "auth.ericminassian.com";
     let rp_origin = Url::parse("https://auth.ericminassian.com")?;
     WebauthnBuilder::new(rp_id, &rp_origin)?
         .rp_name("EricAuth")
         .build()
     ```
   - Use `OnceLock` to cache the instance
3. Add `webauthn: webauthn_rs::Webauthn` to `AppState`
4. Export module from `src/lib.rs`
5. Verify: `cargo build` (note: may need OpenSSL dev libs or `openssl/vendored` feature)

---

### 3.2 — ~~Add Credentials and Challenges DynamoDB tables~~ DONE

**Files:** `cdk/lib/constructs/database.ts`, `cdk/lib/constructs/lambda.ts`, `src/db/mod.rs`, `src/state.rs`

**Steps:**
1. In `cdk/lib/constructs/database.ts`, add both tables:
   ```typescript
   this.credentialsTable = new TableV2(this, 'CredentialsTable', {
     tableName: 'CredentialsTable',
     partitionKey: { name: 'credential_id', type: AttributeType.STRING },
     globalSecondaryIndexes: [{
       indexName: 'userIdIndex',
       partitionKey: { name: 'user_id', type: AttributeType.STRING },
     }],
   });

   this.challengesTable = new TableV2(this, 'ChallengesTable', {
     tableName: 'ChallengesTable',
     partitionKey: { name: 'challenge_id', type: AttributeType.STRING },
     timeToLiveAttribute: 'expires_at',
   });
   ```
2. Expose both as `public readonly` properties on the `Database` construct
3. In `cdk/lib/constructs/lambda.ts`:
   - Add env vars: `CREDENTIALS_TABLE_NAME`, `CHALLENGES_TABLE_NAME`
   - Grant: `credentialsTable.grantReadWriteData(this.handler)`, `challengesTable.grantReadWriteData(this.handler)`
4. Add `credentials_table` and `challenges_table` fields to `Database` struct in Rust, read from env vars

---

### 3.3 — ~~Add Credentials and Challenges DB operations~~ DONE

**Files:** new `src/db/credential.rs`, new `src/db/challenge.rs`, `src/db/mod.rs`

**Steps:**
1. `src/db/credential.rs`:
   - `insert_credential(credential_id, user_id, passkey_json)` — with `attribute_not_exists(credential_id)` condition
   - `get_credentials_by_user_id(user_id)` — query GSI, return `Vec<(credential_id, passkey_json)>`
   - `update_credential(credential_id, passkey_json)` — for sign count updates
   - `delete_credential(credential_id)`
2. `src/db/challenge.rs`:
   - `insert_challenge(challenge_id, challenge_data, ttl_seconds)` — store with epoch TTL
   - `get_and_delete_challenge(challenge_id)` — atomic get + delete, check expiry

---

### 3.4 — ~~Implement passkey registration endpoints~~ DONE

**Files:** new `src/routes/passkey.rs`, `src/routes/mod.rs`

**Steps:**
1. `POST /passkeys/register/begin` handler:
   - Require `AuthenticatedUser` extractor (must be logged in)
   - Load existing credentials for the user, deserialize into `Vec<Passkey>`
   - Call `webauthn.start_passkey_registration(user_uuid, email, display_name, Some(exclude_cred_ids))`
   - Generate `challenge_id` (UUID), serialize `PasskeyRegistration` to JSON, store in ChallengesTable (5 min TTL)
   - Return `Json({ challenge_id, options })` (200 OK)
2. `POST /passkeys/register/complete` handler:
   - Require `AuthenticatedUser`
   - Parse `Json({ challenge_id, credential })` — where `credential` is `RegisterPublicKeyCredential`
   - Load + delete challenge from ChallengesTable
   - Deserialize `PasskeyRegistration`, call `webauthn.finish_passkey_registration()`
   - Extract `cred_id()`, base64url-encode for DynamoDB key
   - Store in CredentialsTable
   - Return 201 Created
3. Register routes in the router under `/passkeys/register/begin` and `/passkeys/register/complete`

---

### 3.5 — ~~Implement passkey authentication endpoints~~ DONE

**Files:** `src/routes/passkey.rs`

**Steps:**
1. `POST /passkeys/auth/begin` handler:
   - Parse optional `Json({ email })` for non-discoverable flow
   - Look up user by email, load credentials, deserialize into `Vec<Passkey>`
   - Call `webauthn.start_passkey_authentication(&passkeys)`
   - Store `PasskeyAuthentication` in ChallengesTable (5 min TTL)
   - Return `Json({ challenge_id, options })`
2. `POST /passkeys/auth/complete` handler:
   - Parse `Json({ challenge_id, credential })`
   - Load + delete challenge
   - Call `webauthn.finish_passkey_authentication()`
   - If `auth_result.needs_update()`: update credential in DB
   - Create session, set session cookie
   - Return 204 with `Set-Cookie`
3. Register both routes

---

### 3.6 — ~~Add recovery codes to signup flow~~ DONE

**Files:** `src/routes/signup.rs`, `src/user.rs`, `src/db/user.rs`

**Steps:**
1. In `create_user()`, generate 8 recovery codes using `generate_random_recovery_code()`
2. SHA-256 hash each code before storing in `recovery_codes` attribute
3. Update `insert_user()` to write `recovery_codes` as DynamoDB List
4. Return plaintext codes in signup response (only time user sees them):
   ```json
   { "recovery_codes": ["ABCD1234...", ...] }
   ```

---

### 3.7 — ~~Implement account recovery endpoint~~ DONE

**Files:** new `src/routes/recover.rs`, `src/db/user.rs`, `src/routes/mod.rs`

**Steps:**
1. Add `remove_recovery_code(user_id, code_hash)` to `src/db/user.rs`
2. Create `src/routes/recover.rs`:
   - Parse `Json({ email, recovery_code })`
   - Look up user, hash the recovery code, check against stored hashes
   - If match: remove used code, create session, return session cookie
   - If no match: return 401
3. Register: `.route("/recover", post(recover::handler))`

---

## Phase 4: Hosted Auth UI

### 4.1 — ~~Add Askama templates and base layout~~ DONE

**Files:** `Cargo.toml`, new `templates/base.html`, new `src/templates.rs`

**Steps:**
1. Add `askama = "0.15"` to `Cargo.toml`
2. Create `templates/base.html`:
   - HTML5 boilerplate, viewport meta, UTF-8
   - Inline `<style>`: system font stack, centered container (max-width 420px), form styling, button styling, error/success message styling, minimal color palette
   - `{% block title %}`, `{% block head %}`, `{% block content %}`
3. Create `src/templates.rs`:
   - Helper struct `HtmlResponse(String)` that implements `IntoResponse` with `Content-Type: text/html; charset=utf-8`
   - Helper function `render<T: Template>(tmpl: &T) -> Result<HtmlResponse, AuthError>`
4. Export module from `src/lib.rs`

---

### 4.2 — ~~Implement login page~~ DONE

**Files:** new `templates/login.html`, new `src/routes/login_page.rs`, `src/routes/mod.rs`

**Steps:**
1. Create `templates/login.html` extending `base.html`:
   - Email + password inputs, submit button
   - "Sign up" link, "Use a passkey" button (hidden, shown via JS if `PublicKeyCredential` exists)
   - Error display area, hidden OAuth2 pass-through fields (`redirect_uri`, `state`, etc.)
   - CSRF hidden field
2. Create handler using axum `Query` extractor for `redirect_uri`, `state`, `error` params
3. Render template with params, return HTML
4. Register: `.route("/login", get(login_page::handler))` (GET serves the page; existing POST processes the form)

---

### 4.3 — ~~Implement signup page~~ DONE

**Files:** new `templates/signup.html`, new `src/routes/signup_page.rs`, `src/routes/mod.rs`

**Steps:**
1. Create `templates/signup.html` extending `base.html`:
   - Email, password, confirm password inputs
   - Password strength requirements listed
   - Inline JS for client-side password match validation
   - Error display area
2. Create handler, register: `.route("/signup", get(signup_page::handler))`
3. Note: `GET /signup` serves the page, existing `POST /signup` processes the form — axum handles method routing naturally

---

### 4.4 — ~~Implement error page template~~ DONE

**Files:** new `templates/error.html`, `src/templates.rs`

**Steps:**
1. Create `templates/error.html` extending `base.html` — shows error title, message, "go back" link
2. Add `ErrorTemplate` struct to `src/templates.rs`
3. Optionally update `AuthError::IntoResponse` to render the error template for HTML requests (check `Accept` header)

---

### 4.5 — ~~Implement consent page~~ DONE

**Files:** new `templates/consent.html`, new `src/routes/consent.rs`, `src/routes/mod.rs`

**Steps:**
1. Create `templates/consent.html` extending `base.html`:
   - Client app name, requested scopes with descriptions
   - "Allow" and "Deny" buttons (form POST)
   - "Signed in as {email}"
   - Hidden OAuth2 fields
2. Create handler: requires `AuthenticatedUser`, uses `Query` for OAuth2 params, looks up client from DB
3. Register: `.route("/consent", get(consent::get_handler).post(consent::post_handler))`

---

### 4.6 — ~~Add WebAuthn JavaScript for login page~~ DONE

**Files:** `templates/login.html`

**Steps:**
1. Add inline `<script>` at bottom of `login.html`:
   - Feature-detect `window.PublicKeyCredential`, show passkey button if available
   - On click: `fetch POST /passkeys/auth/begin` -> `navigator.credentials.get()` -> `fetch POST /passkeys/auth/complete`
   - Handle base64url <-> ArrayBuffer conversions
   - On success: redirect. On failure: show error
2. Keep under 100 lines, no external deps, use `fetch()`

---

### 4.7 — ~~Add passkey management page~~ DONE

**Files:** new `templates/passkeys.html`, new `src/routes/passkeys_page.rs`, `src/routes/mod.rs`

**Steps:**
1. Create template listing passkeys with created_at, last_used_at, delete buttons, "Register new" button
2. Inline JS for registration flow
3. Handler requires `AuthenticatedUser`, loads credentials from DB
4. Register: `.route("/passkeys/manage", get(passkeys_page::handler))`

---

## Phase 5: OAuth2 / OIDC Provider

### 5.1 — ~~Add Clients and Auth Codes DynamoDB tables~~ DONE

**Files:** `cdk/lib/constructs/database.ts`, `cdk/lib/constructs/lambda.ts`, `src/db/mod.rs`, `src/state.rs`

**Steps:**
1. In `cdk/lib/constructs/database.ts`:
   ```typescript
   this.clientsTable = new TableV2(this, 'ClientsTable', {
     tableName: 'ClientsTable',
     partitionKey: { name: 'client_id', type: AttributeType.STRING },
   });

   this.authCodesTable = new TableV2(this, 'AuthCodesTable', {
     tableName: 'AuthCodesTable',
     partitionKey: { name: 'code', type: AttributeType.STRING },
     timeToLiveAttribute: 'expires_at',
   });
   ```
2. Expose both as `public readonly` on `Database` construct
3. In `cdk/lib/constructs/lambda.ts`:
   - Add env vars: `CLIENTS_TABLE_NAME`, `AUTH_CODES_TABLE_NAME`
   - Grant: `clientsTable.grantReadData(this.handler)` (clients are read-only from the app), `authCodesTable.grantReadWriteData(this.handler)`
4. Add `clients_table` and `auth_codes_table` fields to `Database` struct in Rust

---

### 5.2 — ~~Add Client and Auth Code DB operations + `get_user_by_id`~~ DONE

**Files:** new `src/db/client.rs`, new `src/db/auth_code.rs`, `src/db/mod.rs`, `src/db/user.rs`

**Steps:**
1. `src/db/client.rs`: `Client` struct + `get_client()`
2. `src/db/auth_code.rs`: `AuthCode` struct + `insert_auth_code()` + `redeem_auth_code()` (with conditional update `attribute_not_exists(used_at) AND expires_at > :now`)
3. Add `get_user_by_id(user_id: &str) -> Result<Option<UserTable>, AuthError>` to `src/db/user.rs` — this is needed by the `/userinfo` endpoint (Phase 5.6) and doesn't exist yet. Uses `GetItem` on the UsersTable PK directly (no GSI needed).

---

### 5.3 — ~~Implement `/authorize` endpoint~~ DONE

**Files:** new `src/routes/authorize.rs`, `src/routes/mod.rs`

**Steps:**
1. `GET /authorize` handler using axum `Query` extractor for all OAuth2 params
2. Validation order (critical for security):
   a. Validate `client_id` — invalid? render error page (do NOT redirect)
   b. Validate `redirect_uri` — exact match against registered URIs. Invalid? render error page (do NOT redirect)
   c. All other errors: redirect to `redirect_uri?error=...&state=...`
   d. Validate `response_type == "code"`, `code_challenge` present (43-128 chars), `code_challenge_method == "S256"`, scope contains `"openid"`, scopes in client's `allowed_scopes`
3. Session check:
   - No session or `prompt=login`: redirect to `GET /login?<oauth2_params>`
   - Session exists, needs consent: redirect to `GET /consent?<oauth2_params>`
   - Session exists, consent given: generate auth code, redirect to `redirect_uri?code=...&state=...`
4. Auth code generation: 32 random bytes -> base64url, hash for storage, 10 min TTL
5. Register: `.route("/authorize", get(authorize::handler))`

---

### 5.4 — ~~Wire login/signup POST handlers to OAuth2 flow~~ DONE

**Files:** `src/routes/login.rs`, `src/routes/signup.rs`

**Steps:**
1. Update `POST /login` to check for OAuth2 params in form body
2. If present: after successful auth, redirect to `GET /authorize?<params>` (session cookie set, so `/authorize` will find it)
3. If absent: keep existing behavior (set cookie, return 204)
4. Same for `POST /signup`

---

### 5.5 — ~~Implement OIDC discovery endpoint~~ DONE

**Files:** new `src/routes/openid_config.rs`, `src/routes/mod.rs`

**Steps:**
1. Create handler returning static JSON:
   ```json
   {
     "issuer": "https://auth.ericminassian.com",
     "authorization_endpoint": "https://auth.ericminassian.com/authorize",
     "token_endpoint": "https://auth.ericminassian.com/token",
     "userinfo_endpoint": "https://auth.ericminassian.com/userinfo",
     "jwks_uri": "https://auth.ericminassian.com/.well-known/jwks.json",
     "revocation_endpoint": "https://auth.ericminassian.com/token/revoke",
     "response_types_supported": ["code"],
     "subject_types_supported": ["public"],
     "id_token_signing_alg_values_supported": ["ES256"],
     "scopes_supported": ["openid", "profile", "email"],
     "token_endpoint_auth_methods_supported": ["none"],
     "claims_supported": ["sub", "iss", "aud", "exp", "iat", "email", "email_verified"],
     "code_challenge_methods_supported": ["S256"],
     "grant_types_supported": ["authorization_code", "refresh_token"]
   }
   ```
2. Set `Cache-Control: public, max-age=86400`
3. Register: `.route("/.well-known/openid-configuration", get(openid_config::handler))`

---

### 5.6 — ~~Implement `/userinfo` endpoint~~ DONE

**Files:** new `src/routes/userinfo.rs`, new `src/middleware/bearer.rs`, `src/middleware/mod.rs`, `src/routes/mod.rs`

**Steps:**
1. Create `src/middleware/bearer.rs` with a `BearerToken` axum extractor:
   - Parses `Authorization: Bearer <token>` header
   - Verifies the JWT via `JwtKeys::verify_access_token()`
   - On failure: returns 401 with `WWW-Authenticate: Bearer error="invalid_token"` header
   - On success: extracts `AccessTokenClaims` into the extractor struct
2. Handler uses `get_user_by_id()` (added in task 5.2):
   ```rust
   pub async fn handler(
       State(state): State<AppState>,
       token: BearerToken,
   ) -> Result<impl IntoResponse, AuthError> {
       let user = state.db.get_user_by_id(&token.claims.sub).await?
           .ok_or(AuthError::NotFound("user not found".into()))?;
       // Build response based on token scopes
   }
   ```
3. Return `sub` always; add `email`/`email_verified` if `email` scope; add `name` if `profile` scope
4. Register: `.route("/userinfo", get(userinfo::handler).post(userinfo::handler))` (OIDC spec requires support for both GET and POST)

---

### 5.7 — ~~Add `authorization_code` grant and ID token to `/token` endpoint~~ DONE

**Files:** `src/routes/token.rs`

**Steps:**
1. Add `grant_type=authorization_code` support (previously stubbed in Phase 2.6):
   - Parse: `code`, `redirect_uri`, `client_id`, `code_verifier`
   - Hash code, look up in AuthCodesTable via `redeem_auth_code()` (conditional single-use)
   - Verify: not expired, `client_id` matches, `redirect_uri` exact match
   - Validate PKCE: `BASE64URL(SHA256(code_verifier)) == stored code_challenge`
   - Load user, build `AccessTokenClaims`
   - Generate refresh token, store hashed
2. When scope contains `"openid"`, build `IdTokenClaims` and sign with `JwtKeys::sign_id_token()`:
   - `iss`: `"https://auth.ericminassian.com"`
   - `sub`: user_id
   - `aud`: client_id
   - `exp`: 1 hour from now
   - `iat`: now
   - `auth_time`: timestamp of authentication (store in auth code record at creation time)
   - `nonce`: echo from auth code if present
   - `email`, `email_verified`
3. Return full response: `{ access_token, token_type, expires_in, id_token, refresh_token, scope }`
4. Set `Cache-Control: no-store`, `Pragma: no-cache`

---

## Phase 6: Polish & Hardening

### 6.1 — ~~Add CSRF protection as tower middleware~~ DONE

**Files:** new `src/middleware/csrf.rs`, `src/middleware/mod.rs`, all templates

**Steps:**
1. Implement double-submit cookie CSRF as an axum `from_fn` middleware:
   - On GET requests to HTML pages: generate CSRF token, set `__csrf` cookie (`SameSite=Strict`, `Secure`), inject token into request extensions
   - On POST requests from forms: compare `__csrf` cookie against `csrf_token` form field
2. Apply the middleware layer only to the UI route group (not to API routes like `/token` or `/userinfo`)
3. Update all templates to include `<input type="hidden" name="csrf_token" value="{{ csrf_token }}">`

---

### 6.2 — ~~Add security headers as tower middleware~~ DONE

**Files:** new `src/middleware/security_headers.rs`, `src/routes/mod.rs`

**Steps:**
1. Create a tower `Layer`/`from_fn` middleware that adds to every response:
   - `Strict-Transport-Security: max-age=31536000; includeSubDomains`
   - `X-Content-Type-Options: nosniff`
   - `X-Frame-Options: DENY`
   - `Referrer-Policy: strict-origin-when-cross-origin`
   - `Content-Security-Policy: default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'`
2. Apply as a global layer on the router (applies to all routes automatically)

---

### 6.3 — ~~Add CORS configuration~~ DONE

**Files:** `src/routes/mod.rs`

**Steps:**
1. Use `tower_http::cors::CorsLayer` on the router:
   - Allow specific origins (your frontend domains)
   - Apply only to API routes (`/token`, `/token/revoke`, `/userinfo`, `/.well-known/*`)
   - Do NOT apply to `/authorize` (browser navigation)
2. Handle preflight `OPTIONS` automatically (tower-http does this)

---

### 6.4 — Add rate limiting

**Files:** new `src/middleware/rate_limit.rs`, `cdk/lib/constructs/database.ts`, `cdk/lib/constructs/lambda.ts`, `src/routes/mod.rs`

**Steps:**
1. In `cdk/lib/constructs/database.ts`, add `RateLimitsTable`:
   ```typescript
   this.rateLimitsTable = new TableV2(this, 'RateLimitsTable', {
     tableName: 'RateLimitsTable',
     partitionKey: { name: 'key', type: AttributeType.STRING },
     timeToLiveAttribute: 'expires_at',
     removalPolicy: RemovalPolicy.DESTROY,  // ephemeral data
   });
   ```
   In `cdk/lib/constructs/lambda.ts`: add `RATE_LIMITS_TABLE_NAME` env var + `grantReadWriteData()`
2. Create rate limit middleware using axum `from_fn`:
   - Key: `{ip}#{route}`, increment counter with conditional write
   - If over limit: return 429 with `Retry-After` header
3. Apply as route-specific layer:
   ```rust
   .route("/login", post(login::handler).layer(rate_limit(10, 60)))
   .route("/signup", post(signup::handler).layer(rate_limit(5, 60)))
   ```

---

### 6.5 — Add integration tests

**Files:** new `tests/integration_test.rs`

**Steps:**
1. Use `axum::test::TestServer` (or `axum_test` crate) to test the router directly without Lambda:
   - Construct `AppState` with a DynamoDB client pointing to local DynamoDB
   - Build the router, send requests via the test client
2. Test flows:
   - Signup -> login -> session validation
   - Passkey registration -> authentication
   - Full OAuth2: authorize -> login -> consent -> token exchange -> userinfo
   - Refresh token rotation
   - Auth code single-use enforcement
   - PKCE validation
   - Redirect URI mismatch rejection
3. Use `testcontainers-rs` with DynamoDB Local for realistic testing

---

### 6.6 — CDK tests

**Files:** `cdk/test/cdk.test.ts`

**Steps:**
1. Uncomment and update CDK test file
2. Assertions: correct DynamoDB tables, TTL on ephemeral tables, single Lambda with correct env vars, API Gateway routes, IAM permissions

---

### 6.7 — Secrets Manager integration for JWT keys

**Files:** `Cargo.toml`, `src/jwt.rs`, `src/state.rs`, `cdk/lib/cdk-stack.ts`, `cdk/lib/constructs/lambda.ts`

**Steps:**
1. Add `aws-sdk-secretsmanager = "1"` to `Cargo.toml`
2. In `cdk/lib/cdk-stack.ts`, create the secret:
   ```typescript
   import * as secretsmanager from 'aws-cdk-lib/aws-secretsmanager';

   const jwtSecret = new secretsmanager.Secret(this, 'JwtPrivateKey', {
     secretName: 'ericauth/jwt-private-key',
     description: 'ES256 private key PEM for JWT signing',
   });
   ```
3. In `cdk/lib/constructs/lambda.ts`:
   - Add env var `JWT_SECRET_ARN: jwtSecret.secretArn`
   - Grant: `jwtSecret.grantRead(this.handler)`
4. Update `AppState::new()` to:
   - Read `JWT_SECRET_ARN` env var
   - Call `aws_sdk_secretsmanager::Client::get_secret_value()` to load PEM
   - Pass PEM to `JwtKeys::from_pem()`
   - Cache in `AppState.jwt_keys` (loaded once at cold start, reused across warm invocations)
5. Remove the `JWT_PRIVATE_KEY` env var (no longer storing key material in env vars)
6. Create a one-time key generation script (`src/bin/generate_keys.rs`) that:
   - Calls `generate_es256_keypair()` from `src/jwt.rs`
   - Prints the private PEM (to be stored in Secrets Manager via AWS CLI or console)
   - Prints the public PEM (for reference/backup)

---

## Appendix A: Project Structure (Target)

```
ericauth/
├── Cargo.toml
├── Cargo.lock
├── Makefile
├── DESIGN_DOC.md
├── IMPLEMENTATION_PLAN.md
├── templates/
│   ├── base.html
│   ├── login.html
│   ├── signup.html
│   ├── consent.html
│   ├── error.html
│   └── passkeys.html
├── src/
│   ├── main.rs                    # Lambda entrypoint: build AppState, build router, run
│   ├── lib.rs                     # Module declarations
│   ├── state.rs                   # AppState (DB, JWT keys, WebAuthn)
│   ├── error.rs                   # AuthError enum + IntoResponse
│   ├── jwt.rs                     # JWT signing/verification, JWKS
│   ├── webauthn_config.rs         # WebAuthn Relying Party config
│   ├── user.rs                    # User model + creation
│   ├── password.rs                # Argon2 hashing + validation
│   ├── session.rs                 # Session model + creation
│   ├── refresh_token.rs           # Refresh token model
│   ├── encryption.rs              # AES-256-GCM utilities
│   ├── validation.rs              # Shared input validation (email, etc.)
│   ├── templates.rs               # Askama template structs + helpers
│   ├── db/
│   │   ├── mod.rs                 # Database struct (DynamoDB client)
│   │   ├── user.rs                # User CRUD
│   │   ├── session.rs             # Session CRUD
│   │   ├── credential.rs          # WebAuthn credential CRUD
│   │   ├── challenge.rs           # WebAuthn challenge CRUD
│   │   ├── client.rs              # OAuth2 client lookups
│   │   ├── auth_code.rs           # Auth code CRUD
│   │   └── refresh_token.rs       # Refresh token CRUD
│   ├── routes/
│   │   ├── mod.rs                 # Router construction
│   │   ├── health.rs              # GET /health
│   │   ├── signup.rs              # POST /signup
│   │   ├── signup_page.rs         # GET /signup
│   │   ├── login.rs               # POST /login
│   │   ├── login_page.rs          # GET /login
│   │   ├── logout.rs              # POST /logout
│   │   ├── passkey.rs             # POST /passkeys/*
│   │   ├── passkeys_page.rs       # GET /passkeys/manage
│   │   ├── recover.rs             # POST /recover
│   │   ├── authorize.rs           # GET /authorize
│   │   ├── consent.rs             # GET+POST /consent
│   │   ├── token.rs               # POST /token
│   │   ├── token_revoke.rs        # POST /token/revoke
│   │   ├── jwks.rs                # GET /.well-known/jwks.json
│   │   ├── openid_config.rs       # GET /.well-known/openid-configuration
│   │   └── userinfo.rs            # GET /userinfo
│   └── middleware/
│       ├── mod.rs
│       ├── auth.rs                # AuthenticatedUser extractor
│       ├── bearer.rs              # BearerToken extractor (JWT)
│       ├── csrf.rs                # CSRF middleware
│       ├── security_headers.rs    # Security headers middleware
│       └── rate_limit.rs          # Rate limiting middleware
├── cdk/
│   ├── lib/
│   │   ├── cdk-stack.ts
│   │   └── constructs/
│   │       ├── database.ts        # All DynamoDB tables
│   │       ├── lambda.ts          # Single RustFunction
│   │       └── api.ts             # API Gateway + all routes
│   └── ...
└── tests/
    └── integration_test.rs
```

## Appendix B: Crate Dependencies Summary

```toml
# Existing (upgraded)
lambda_http = "1"  # MUST upgrade from 0.14 — tower 0.4 vs 0.5 conflict with axum
tokio = { version = "1", features = ["macros", "rt-multi-thread"] }
aws-config = { version = "1", features = ["behavior-version-latest"] }
aws-sdk-dynamodb = "1"
serde = { version = "1", features = ["derive"] }
serde_dynamo = { version = "4", features = ["aws-sdk-dynamodb+1"] }
argon2 = "0.5"
sha2 = "0.10"
chrono = { version = "0.4", features = ["serde"] }
uuid = { version = "1", features = ["v4", "fast-rng", "serde"] }
hex = "0.4"
getrandom = "0.3"
rand = "0.9"
rand_core = { version = "0.6", features = ["std"] }
base32 = "0.5"
aes-gcm = "0.10"

# Phase 0: axum
axum = "0.8"
tower-http = { version = "0.6", features = ["cors", "trace"] }
tracing = "0.1"
tracing-subscriber = { version = "0.3", features = ["env-filter", "json"] }

# Phase 2: JWT
jsonwebtoken = { version = "10", features = ["p256"] }
p256 = { version = "0.13", features = ["ecdsa", "pem"] }
base64 = "0.22"
serde_json = "1"

# Phase 3: WebAuthn
webauthn-rs = { version = "0.5", features = ["danger-allow-state-serialisation"] }
url = "2"

# Phase 4: Templates
askama = "0.15"

# Phase 6: Secrets Manager
aws-sdk-secretsmanager = "1"
```

## Appendix C: DynamoDB Tables Summary

| Table | PK | GSI | TTL | Phase |
|-------|----|----|-----|-------|
| UsersTable (existing) | `id` | `emailIndex` on `email` | — | — |
| SessionsTable (existing) | `id` | — | `expires_at` | 1 |
| RefreshTokensTable | `token_hash` | — | `expires_at` | 2 |
| CredentialsTable | `credential_id` | `userIdIndex` on `user_id` | — | 3 |
| ChallengesTable | `challenge_id` | — | `expires_at` | 3 |
| ClientsTable | `client_id` | — | — | 5 |
| AuthCodesTable | `code` | — | `expires_at` | 5 |
| RateLimitsTable | `key` | — | `expires_at` | 6 |

## Appendix D: Route Summary

All routes handled by a single Lambda binary via axum Router.

| Method | Path | Auth | Handler Module | Phase |
|--------|------|------|----------------|-------|
| GET | `/health` | None | `routes::health` | 0 |
| POST | `/signup` | None | `routes::signup` | 0 |
| GET | `/signup` | None | `routes::signup_page` | 4 |
| POST | `/login` | None | `routes::login` | 0 |
| GET | `/login` | None | `routes::login_page` | 4 |
| POST | `/logout` | Session | `routes::logout` | 1 |
| POST | `/passkeys/register/begin` | Session | `routes::passkey` | 3 |
| POST | `/passkeys/register/complete` | Session | `routes::passkey` | 3 |
| POST | `/passkeys/auth/begin` | None | `routes::passkey` | 3 |
| POST | `/passkeys/auth/complete` | None | `routes::passkey` | 3 |
| POST | `/recover` | None | `routes::recover` | 3 |
| GET | `/authorize` | Session | `routes::authorize` | 5 |
| GET | `/consent` | Session | `routes::consent` | 5 |
| POST | `/consent` | Session | `routes::consent` | 5 |
| POST | `/token` | None* | `routes::token` | 2 |
| POST | `/token/revoke` | None* | `routes::token_revoke` | 2 |
| GET | `/userinfo` | Bearer JWT | `routes::userinfo` | 5 |
| GET | `/.well-known/jwks.json` | None | `routes::jwks` | 2 |
| GET | `/.well-known/openid-configuration` | None | `routes::openid_config` | 5 |
| GET | `/passkeys/manage` | Session | `routes::passkeys_page` | 4 |
