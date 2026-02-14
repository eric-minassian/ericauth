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

## CI/CD Architecture

- CI/CD workflow design and artifact flow are documented in
  `docs/ci-cd-architecture.md`.
- When changing workflow behavior in `.github/workflows/`, update
  `docs/ci-cd-architecture.md` in the same PR.

### Rust (primary codebase)

```bash
# Run all tests (ENCRYPTION_KEY env var is required)
make test
# Which expands to:
ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features

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
cargo clippy --all-targets --all-features

# Auto-format code
make fmt
# Which expands to:
cargo fmt --all

# Build (debug, for Lambda)
make build                  # cargo lambda build
make build-release          # cargo lambda build --release

# Local dev server (in-memory DB, no AWS credentials needed)
make dev                    # DATABASE_BACKEND=memory MEMORY_DB_FILE=.ericauth-dev-db.json cargo lambda watch
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
  password.rs       # Argon2id hashing, password strength validation
  session.rs        # Session token generation, cookie building
  encryption.rs     # AES-256-GCM encrypt/decrypt utilities
  validation.rs     # Email validation
  db/
    mod.rs          # Database enum (Dynamo | Memory) with method dispatch
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

- Route handlers return `Result<impl IntoResponse, (StatusCode, String)>`
- Database methods return `Result<T, String>`
- Business logic / crypto functions return `Result<T, &'static str>`
- Use `.map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?` to convert
  lower-level errors into HTTP responses in route handlers
- Avoid `.unwrap()` in new code — use `?` operator or explicit error handling

### Architecture Patterns

- **Database abstraction:** `Database` is an enum (`Dynamo | Memory`). Each variant
  implements the same methods; `db/mod.rs` dispatches via match. Add new operations
  to both variants.
- **State:** `AppState` is passed to handlers via axum `State` extractor.
- **Environment config:** Table names, `DATABASE_BACKEND`, and `ENCRYPTION_KEY` are
  read from environment variables. Use `env::var()` with sensible defaults or
  explicit `.expect()` for required vars.
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
