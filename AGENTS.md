# AGENTS.md — EricAuth

Self-hosted authentication/authorization service built in Rust, deployed as
an AWS Lambda (axum + lambda_http) behind API Gateway. Infrastructure managed
with AWS CDK (TypeScript) in `cdk/`.

## Git Workflow

- All changes go through a PR — never push directly to `main`.
- Each PR must have exactly 1 commit. Amend (`git commit --amend`) and
  force-push (`git push --force-with-lease`) to update a PR.
- Rebase onto `main` — never merge commits.
- Enable auto-merge on the PR; CI must pass before merging.
- **"Ship it"** (or any variation) means: commit, push, open PR, and enable auto-merge.

## Build / Lint / Test Commands

All primary commands are in the `Makefile` at the repo root.

### Rust (primary codebase)

```bash
# Run all tests (ENCRYPTION_KEY env var is required)
make test
# Which expands to:
ENCRYPTION_KEY="01234567890123456789012345678901" cargo nextest run --all-features

# Run a single test by name (substring match)
ENCRYPTION_KEY="01234567890123456789012345678901" cargo test <test_name> --all-features
# Example:
ENCRYPTION_KEY="01234567890123456789012345678901" cargo test test_encrypt_decrypt --all-features

# Run tests in a specific module
ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features -- encryption::tests

# Lint (formatting check + clippy)
make lint
# Which expands to:
cargo fmt --all -- --check
cargo clippy --all-targets --all-features --no-deps -- -D warnings

# Auto-format code
make fmt
# Which expands to:
cargo fmt --all

# Type-check without building
make check                  # cargo check --all-features

# Remove build artifacts
make clean                  # cargo clean

# Build (debug, for Lambda)
make build                  # cargo lambda build
make build-release          # cargo lambda build --release

# Local dev server (in-memory DB, no AWS credentials needed)
make dev
```

### CI Environment Flags

CI sets `RUSTFLAGS="-Dwarnings"` so all warnings are treated as errors.
Always ensure your code compiles without warnings before pushing.

### CDK (infrastructure, in `cdk/` directory)

```bash
# Synthesize CloudFormation templates
make synth                  # cd cdk && pnpm install && pnpm cdk synth --no-lookup

# CDK uses pnpm 9 + Node 22
cd cdk && pnpm install --frozen-lockfile
cd cdk && pnpm cdk synth --no-lookup
```

## Project Structure

```
src/
  main.rs           # Lambda entrypoint, initializes DB + runs axum router
  lib.rs            # Module declarations, recovery code generation
  state.rs          # AppState struct (holds Database)
  user.rs           # User model + create_user()
  oauth.rs          # Shared OAuth query string builders
  password.rs       # Argon2id hashing, password strength validation
  session.rs        # Session token generation, cookie building
  encryption.rs     # AES-256-GCM encrypt/decrypt utilities
  validation.rs     # Email validation
  db/
    mod.rs          # Database trait with DynamoDb and MemoryDb implementations
    user.rs         # DynamoDB user CRUD (UserTable)
    session.rs      # DynamoDB session operations (SessionTable)
    memory.rs       # In-memory DB backend for local dev/tests
  routes/
    mod.rs          # Router construction (health, signup, login)
    health.rs       # GET /health
    signup.rs       # POST /signup
    login.rs        # POST /login
cdk/                # AWS CDK infrastructure (TypeScript)
  lib/cdk-stack.ts  # Main stack (DynamoDB, Lambda, API Gateway)
  lib/oidc-stack.ts # GitHub OIDC deploy role
  lib/constructs/   # Database, Lambda, API constructs
```

## Code Style Guidelines

### Rust

**Formatting:** Default `rustfmt` — no custom config. Run `cargo fmt --all` before committing.

**Linting:** Default `clippy` with all targets/features. Fix all warnings — CI fails on warnings.

**Unsafe code is forbidden:** `[lints.rust] unsafe_code = "forbid"` in Cargo.toml. Never use `unsafe`.

### Imports

Group imports in this order, separated by a blank line:
1. External crate imports (std, third-party)
2. Internal crate imports (`crate::...`)

Use nested `{}` imports from the same crate:
```rust
use axum::{
    extract::State,
    http::{HeaderMap, StatusCode},
    response::IntoResponse,
    Json,
};

use crate::{
    password::verify_password_strength,
    session::{create_session, generate_session_token, session_cookie},
    state::AppState,
};
```

### Naming Conventions

| Element             | Convention       | Examples                                    |
|---------------------|------------------|---------------------------------------------|
| Structs             | PascalCase       | `AppState`, `UserTable`, `MemoryDb`         |
| Functions           | snake_case       | `create_user`, `hash_password`              |
| Modules             | snake_case       | `routes`, `db`, `password`                  |
| Constants           | UPPER_SNAKE_CASE | `NONCE_LENGTH`, `ENCRYPTION_KEY`            |
| Route handlers      | `handler`        | `health::handler`, `signup::handler`        |
| DB table structs    | `*Table` suffix  | `UserTable`, `SessionTable`                 |
| Request payloads    | `*Payload` suffix| `SignupPayload`, `LoginPayload`             |
| Props (CDK)         | `*Props` suffix  | `EricAuthStackProps`, `ApiProps`            |

### Types and Error Handling

- Route handlers return `Result<impl IntoResponse, AuthError>`
- `AuthError` is defined in `src/error.rs` with variants: `BadRequest`, `Unauthorized`,
  `NotFound`, `Conflict`, `Internal`, `TooManyRequests`
- `AuthError` implements `IntoResponse`, producing JSON `{"error": "kind", "message": "..."}`
- Database methods are defined by the `Database` trait in `src/db/mod.rs`
- Business logic / crypto functions return `Result<T, &'static str>`
- Use `?` operator to propagate errors — `From` impls handle conversion
- Avoid `.unwrap()` in new code — use `?` operator or explicit error handling

### Architecture Patterns

- **Database abstraction:** `Database` is a trait defined in `db/mod.rs`. `DynamoDb` and
  `MemoryDb` implement it. `AppState` holds `Arc<dyn Database>`. Add new operations by
  extending the trait and implementing on both backends.
- **State:** `AppState` is passed to handlers via axum `State` extractor.
- **Environment config:** Table names, `DATABASE_BACKEND`, `ENCRYPTION_KEY`, and `ISSUER_URL` are
  read from environment variables. Use `env::var()` with sensible defaults or
  explicit `.expect()` for required vars.
- **`ISSUER_URL`:** Base URL for JWT issuer claims and OIDC discovery (e.g., `https://auth.ericminassian.com`).
  Set via CDK Lambda environment variables for deployed environments, or `ISSUER_URL=http://localhost:9000` for local dev.
- **Security:** Passwords hashed with Argon2id. Session tokens SHA-256 hashed before
  storage. AES-256-GCM for field encryption. Session cookies are
  `HttpOnly; Secure; SameSite=Lax`.

### Tests

- Tests are inline `#[cfg(test)] mod tests` at the bottom of source files
- Import with `use super::*;`
- Prefix test function names with `test_` (e.g., `test_verify_email`, `test_hash_password`)
- Set required env vars in test helper functions (see `set_test_key()` in `encryption.rs`)
- No integration test directory yet — all tests are unit tests

### CDK / TypeScript Style

- TypeScript strict mode is enabled
- Named imports from `aws-cdk-lib` sub-packages
- Classes: PascalCase. Resource names: kebab-case (e.g., `ericauth-dev-users`)
- Stack IDs use PascalCase with hyphens (e.g., `EricAuth-Dev`, `EricAuth-Beta`)
- Package manager: pnpm 9, Node 22
