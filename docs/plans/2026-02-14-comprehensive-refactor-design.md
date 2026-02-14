# Comprehensive Codebase Refactor -- Design Doc

**Date:** 2026-02-14
**Status:** Approved
**Scope:** Rust code, CDK infrastructure, CI/CD pipelines, configuration

## Context

Full audit of the EricAuth codebase revealed improvements across every layer.
The codebase is functional and well-deployed, but has accumulated inconsistencies,
code duplication, and some safety issues that should be addressed in a coordinated
refactor. Each phase produces a passing build and is shipped as a separate PR.

## Phase 1: Foundation (Error types, config, safety)

Everything subsequent depends on these changes.

### 1.1 AppError Enum

Replace `Result<T, (StatusCode, String)>` in route handlers and `Result<T, String>`
in DB/business logic with a unified `AppError` enum.

```rust
// src/error.rs (replace existing)
use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};

pub enum AppError {
    NotFound(String),
    Unauthorized(String),
    BadRequest(String),
    Conflict(String),
    RateLimited,
    Internal(String),
}

impl IntoResponse for AppError {
    fn into_response(self) -> Response {
        let (status, message) = match &self {
            AppError::NotFound(msg) => (StatusCode::NOT_FOUND, msg.clone()),
            AppError::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg.clone()),
            AppError::BadRequest(msg) => (StatusCode::BAD_REQUEST, msg.clone()),
            AppError::Conflict(msg) => (StatusCode::CONFLICT, msg.clone()),
            AppError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limited".into()),
            AppError::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg.clone()),
        };
        (status, message).into_response()
    }
}

// Conversion from String for DB/business logic errors
impl From<String> for AppError {
    fn from(msg: String) -> Self {
        AppError::Internal(msg)
    }
}
```

All route handlers change return type to `Result<impl IntoResponse, AppError>`.
DB methods keep `Result<T, String>` but callers use `?` with the `From` impl.

### 1.2 Configurable Issuer URL

Remove hardcoded `https://auth.ericminassian.com` from jwt.rs, token.rs,
openid_config.rs, and bearer.rs. Add `ISSUER_URL` to:

- `AppState` (read from `env::var("ISSUER_URL")`)
- CDK Lambda environment variables (set per environment)
- Makefile `dev` target

### 1.3 Fix Safety Issues

| Issue | File | Fix |
|-------|------|-----|
| `std::env::set_var` in main.rs | main.rs:11 | Move to before tokio runtime starts, or use a static/config |
| `panic!` on missing ENCRYPTION_KEY | encryption.rs:17,21 | Return `Result`, propagate to caller |
| `.expect()` on WebAuthn init | state.rs:30 | Return `Result` from AppState::new() |
| `.unwrap()` in cookie parse | csrf.rs:82 | Use `?` or `.ok()` with fallback |
| `.unwrap_or_default()` in rate_limit | db/rate_limit.rs:34,39 | Acceptable -- keep as-is (these are fallbacks) |

### 1.4 Cargo.toml Improvements

- Add `[profile.release]`: `lto = true`, `codegen-units = 1`, `strip = true`
- Add clippy lint: `unwrap_used = "warn"` under `[lints.clippy]`
- Normalize version pinning to minor-level (e.g., `"0.10"` not `"0.10.3"`)
  since Cargo.lock pins exact versions anyway

### 1.5 Add rust-toolchain.toml

```toml
[toolchain]
channel = "stable"
```

## Phase 2: Rust Architecture (DB trait, deduplication)

### 2.1 Trait-based Database Abstraction

Replace the `Database` enum in `db/mod.rs` with an `async_trait`:

```rust
// src/db/mod.rs
#[async_trait]
pub trait Database: Send + Sync {
    // User operations
    async fn create_user(&self, ...) -> Result<(), String>;
    async fn get_user_by_email(&self, ...) -> Result<Option<User>, String>;
    async fn get_user_by_id(&self, ...) -> Result<Option<User>, String>;
    // ... all current methods
}
```

- `DynamoDb` struct implements `Database`
- `MemoryDb` struct implements `Database`
- `AppState` holds `Arc<dyn Database>` instead of `Database` enum
- Route handlers use `State<AppState>` unchanged -- the trait is behind the Arc

This eliminates ~400 lines of match-arm boilerplate. New DB backends (e.g.,
PostgreSQL) become a matter of implementing the trait.

### 2.2 Deduplicate Shared Code

| Duplication | Current Locations | Extracted To |
|-------------|-------------------|-------------|
| `build_oauth_qs()` | signup.rs:86, login.rs:77 | `src/oauth.rs` (new module) |
| `build_oauth_link_query()` | signup_page.rs:69, login_page.rs:69 | `src/oauth.rs` |
| `RecoveryCodesTemplate` | signup.rs:37, account.rs:67 | `src/templates.rs` |

### 2.3 Improve Email Validation

Replace the `contains('@') && len < 256` check in `validation.rs:3` with proper
validation: check for exactly one `@`, non-empty local and domain parts, domain
contains at least one `.`, and reasonable character constraints. No external crate
needed -- a stricter hand-rolled check is sufficient for this use case.

### 2.4 Import Cleanup

Audit all files for consistent import ordering:
1. `std` imports
2. External crate imports
3. Blank line
4. `crate::` imports

## Phase 3: CDK & Infrastructure

### 3.1 Version Alignment

Update `package.json` to align `aws-cdk` CLI with `aws-cdk-lib` version (both
should be `2.238.0` or latest compatible).

### 3.2 Fix Broken CDK Tests

Replace `AWS::ApiGateway::RestApi`, `AWS::ApiGateway::Resource`,
`AWS::ApiGateway::Method` assertions with `AWS::ApiGatewayV2::Api` and
`AWS::ApiGatewayV2::Route` assertions. Update the weak `>= 3` table count
assertion to `=== 8`.

### 3.3 Lambda Configuration

Add explicit `memorySize: 512` (MB) and `timeout: Duration.seconds(30)` to
the RustFunction construct. 512 MB provides adequate CPU for Argon2id hashing.
30 seconds is generous but safe.

### 3.4 Shared Constants for GSI Names

Create a `constants.ts` file in `lib/constructs/` exporting GSI names used by
both `database.ts` and `lambda.ts`:

```typescript
export const GSI_NAMES = {
  EMAIL_INDEX: "emailIndex",
  USER_ID_INDEX: "userIdIndex",
} as const;
```

### 3.5 Environment-Scoped API Name

Change `apiName: "eric-auth"` to `apiName: \`ericauth-${props.envName}\`` in
`api.ts`.

### 3.6 Explicit RemovalPolicy

Add `removalPolicy` to all DynamoDB tables:
- Dev: `RemovalPolicy.DESTROY`
- Beta/Prod: `RemovalPolicy.RETAIN` (explicit, not relying on default)

Pass `envName` into `DatabaseProps` to determine policy.

### 3.7 Add ISSUER_URL to Lambda Environment

Add `ISSUER_URL` to `LambdaProps` and set it per environment:
- Dev: `http://localhost:3000`
- Beta: the API Gateway URL (or custom domain if configured)
- Prod: `https://auth.ericminassian.com`

### 3.8 tsconfig.json Cleanup

- Remove `"dom"` from `lib`
- Remove `experimentalDecorators`
- Set `noUnusedLocals: true`
- Set `noFallthroughCasesInSwitch: true`
- Remove redundant strict-mode flags (keep just `strict: true`)

### 3.9 Fix import syntax

Change `import path = require("path")` in lambda.ts to
`import * as path from "path"`.

## Phase 4: CI/CD Alignment

### 4.1 Align Makefile with CI

- Change `make test` to use `cargo nextest run` (install nextest as dev dependency)
- Add `-D warnings` to `make lint` clippy invocation
- Add `--no-deps` to clippy in Makefile
- Add `make check` target (`cargo check --all-features`)
- Add `make clean` target (`cargo clean`)

### 4.2 Fix README Accuracy

Update the CI/CD section of README.md to accurately reflect what runs on PRs
(Rust lint + test only). Remove claims about CDK synth and Playwright E2E on
PRs unless we add those jobs.

### 4.3 Gitignore Additions

Add `.env*` to `.gitignore` as a preventive measure.

### 4.4 Dependabot Grouping

Add `groups` configuration to `.github/dependabot.yml` to batch minor/patch
updates per ecosystem, reducing PR noise.

## Phase 5: Documentation & Polish

### 5.1 Update AGENTS.md

Reflect new patterns:
- `AppError` enum for error handling
- `Database` trait instead of enum
- `ISSUER_URL` environment variable
- Updated error handling conventions
- cargo-nextest for local testing
- New `make check` and `make clean` targets

### 5.2 CDK README

Add content to `cdk/README.md` covering stack structure, deployment, and
construct hierarchy.

### 5.3 Final Verification

- `make lint` passes (including `-D warnings`)
- `make test` passes
- `make synth` passes (CDK synth)
- CDK tests pass (`cd cdk && pnpm test`)
- No `.unwrap()` in new code
- All hardcoded issuer references removed

## Out of Scope (Future Work)

These are real improvements but beyond the refactor scope:
- Adding monitoring/alarms (CloudWatch)
- Adding WAF to API Gateway
- Adding point-in-time recovery to DynamoDB
- Adding API Gateway access logging
- Test coverage for route handlers and DB modules
- haveibeenpwned password check (existing TODO)
