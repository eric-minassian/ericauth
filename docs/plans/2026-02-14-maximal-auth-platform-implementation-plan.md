# Maximal Auth Platform Implementation Plan

> **For Claude:** REQUIRED SUB-SKILL: Use superpowers:executing-plans to implement this plan task-by-task.

**Goal:** Implement full maximal-roadmap auth platform capabilities on top of EricAuth, including lifecycle, MFA, federation, enterprise governance, machine identity, and advanced security.

**Architecture:** Build in vertical slices using the existing Rust monolith (axum + Lambda), DynamoDB-backed trait abstraction, and Askama templates. Add enterprise and advanced capabilities as independent capability tracks with strict dependency gates so multiple worktrees/subagents can ship in parallel safely.

**Tech Stack:** Rust (axum, askama, serde), DynamoDB, AWS CDK (TypeScript), Playwright E2E, OAuth2/OIDC, WebAuthn, SAML, SCIM, TOTP.

---

## Worktree and Parallelization Setup (Required)

### Task 1: Create isolated worktrees per capability track

**Files:**
- Create: `.worktrees/track-a-identity-lifecycle/` (git worktree)
- Create: `.worktrees/track-b-federation/` (git worktree)
- Create: `.worktrees/track-c-security-compliance/` (git worktree)
- Create: `.worktrees/track-d-admin-dx/` (git worktree)
- Create: `.worktrees/track-e-machine-authz/` (git worktree)

**Step 1: Create branches and worktrees**

Run: `git worktree add .worktrees/track-a-identity-lifecycle -b feature/identity-lifecycle`
Expected: Worktree created.

**Step 2: Repeat for remaining tracks**

Run: `git worktree add .worktrees/track-b-federation -b feature/federation`
Run: `git worktree add .worktrees/track-c-security-compliance -b feature/security-compliance`
Run: `git worktree add .worktrees/track-d-admin-dx -b feature/admin-dx`
Run: `git worktree add .worktrees/track-e-machine-authz -b feature/machine-authz`

**Step 3: Verify all worktrees exist**

Run: `git worktree list`
Expected: 5 new worktrees listed.

**Step 4: Commit orchestration docs update (optional in main worktree)**

Run: `git add docs/plans/2026-02-14-maximal-auth-platform-roadmap-design.md docs/plans/2026-02-14-maximal-auth-platform-implementation-plan.md`
Run: `git commit -m "docs: add maximal auth roadmap and execution plan"`

---

## Track A: Identity Lifecycle + MFA

### Task 2: Add email verification flow

**Files:**
- Create: `src/routes/verify_email.rs`
- Create: `src/db/email_verification.rs`
- Modify: `src/db/mod.rs`
- Modify: `src/routes/mod.rs`
- Modify: `src/routes/signup.rs`
- Test: `src/routes/verify_email.rs`

**Step 1: Write failing tests**

Add tests for:
- verification token creation at signup
- valid token marks user verified
- expired/invalid token rejected

**Step 2: Run tests to verify failure**

Run: `ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features verify_email`
Expected: FAIL due to missing route/db functions.

**Step 3: Implement minimal DB + route support**

Add trait methods in `src/db/mod.rs` and implementation in memory/dynamo backends.

**Step 4: Wire route and signup token emission**

Update router and signup handler.

**Step 5: Run focused + full tests**

Run: `make test`
Expected: PASS.

**Step 6: Commit**

Run: `git add src/routes/verify_email.rs src/db/email_verification.rs src/db/mod.rs src/routes/mod.rs src/routes/signup.rs`
Run: `git commit -m "feat: add email verification flow"`

### Task 3: Add forgot/reset password flow

**Files:**
- Create: `src/routes/forgot_password.rs`
- Create: `src/routes/reset_password.rs`
- Create: `templates/forgot_password.html`
- Create: `templates/reset_password.html`
- Modify: `src/routes/mod.rs`
- Modify: `src/db/mod.rs`
- Test: `src/routes/reset_password.rs`

**Step 1: Write failing tests for token issue/consume/reset**

**Step 2: Run failing tests**

Run: `cargo test --all-features reset_password`

**Step 3: Implement token lifecycle + password update**

**Step 4: Add pages + route wiring**

**Step 5: Run `make test` and `make e2e`**

**Step 6: Commit**

Run: `git commit -m "feat: add forgot and reset password flows"`

### Task 4: Add TOTP MFA enrollment/challenge

**Files:**
- Create: `src/mfa.rs`
- Create: `src/routes/mfa.rs`
- Create: `templates/mfa_setup.html`
- Create: `templates/mfa_challenge.html`
- Modify: `src/routes/login.rs`
- Modify: `src/routes/mod.rs`
- Modify: `src/db/mod.rs`
- Test: `src/mfa.rs`

**Step 1: Write failing unit tests for TOTP generate/verify/window drift**

**Step 2: Run tests to fail**

Run: `cargo test --all-features mfa`

**Step 3: Implement minimal TOTP support and backup codes**

**Step 4: Add login step-up challenge path**

**Step 5: Run `make test` + targeted e2e MFA flow**

**Step 6: Commit**

Run: `git commit -m "feat: add TOTP MFA with login challenge"`

---

## Track B: Federation (SAML + SCIM)

### Task 5: Add SAML configuration model and metadata endpoints

**Files:**
- Create: `src/saml.rs`
- Create: `src/routes/saml_metadata.rs`
- Modify: `src/routes/mod.rs`
- Modify: `src/db/mod.rs`
- Test: `src/saml.rs`

**Step 1: Write failing tests for SP/IdP metadata serialization and validation**

**Step 2: Run failing tests**

Run: `cargo test --all-features saml_metadata`

**Step 3: Implement metadata model + endpoint**

**Step 4: Run tests**

Run: `make test`

**Step 5: Commit**

Run: `git commit -m "feat: add SAML metadata foundations"`

### Task 6: Add SCIM 2.0 users/groups provisioning endpoints

**Files:**
- Create: `src/routes/scim_users.rs`
- Create: `src/routes/scim_groups.rs`
- Modify: `src/routes/mod.rs`
- Modify: `src/db/mod.rs`
- Test: `src/routes/scim_users.rs`

**Step 1: Write failing tests for SCIM create/update/deactivate user**

**Step 2: Run failing tests**

Run: `cargo test --all-features scim`

**Step 3: Implement minimal SCIM routes + storage abstraction**

**Step 4: Add authz checks for SCIM admin token**

**Step 5: Run `make test` and SCIM e2e contract tests**

**Step 6: Commit**

Run: `git commit -m "feat: add SCIM user and group provisioning APIs"`

---

## Track C: Security, Compliance, and Auditability

### Task 7: Add structured audit event pipeline

**Files:**
- Create: `src/audit.rs`
- Create: `src/routes/audit_events.rs`
- Modify: `src/routes/login.rs`
- Modify: `src/routes/signup.rs`
- Modify: `src/routes/token.rs`
- Modify: `src/routes/mod.rs`
- Test: `src/audit.rs`

**Step 1: Write failing tests for append-only event record creation**

**Step 2: Run failing tests**

Run: `cargo test --all-features audit`

**Step 3: Implement audit event model and persistence API**

**Step 4: Instrument auth-critical routes**

**Step 5: Run tests + lint**

Run: `make lint && make test`

**Step 6: Commit**

Run: `git commit -m "feat: add audit event pipeline and auth instrumentation"`

### Task 8: Add admin RBAC policy enforcement

**Files:**
- Create: `src/admin_rbac.rs`
- Create: `src/middleware/admin_auth.rs`
- Modify: `src/routes/mod.rs`
- Modify: `src/error.rs`
- Test: `src/admin_rbac.rs`

**Step 1: Write failing tests for allow/deny matrix**

**Step 2: Run failing tests**

Run: `cargo test --all-features admin_rbac`

**Step 3: Implement role/permission checks and middleware**

**Step 4: Apply middleware to admin routes**

**Step 5: Run full verification**

Run: `make fmt && make lint && make test`

**Step 6: Commit**

Run: `git commit -m "feat: enforce admin RBAC across management endpoints"`

---

## Track D: Admin and Developer Experience

### Task 9: Add tenant/project domain model and APIs

**Files:**
- Create: `src/routes/admin_tenants.rs`
- Create: `src/db/tenant.rs`
- Modify: `src/db/mod.rs`
- Modify: `src/routes/mod.rs`
- Test: `src/routes/admin_tenants.rs`

**Step 1: Write failing tests for tenant CRUD and isolation**

**Step 2: Run failing tests**

Run: `cargo test --all-features admin_tenants`

**Step 3: Implement tenant storage and routes**

**Step 4: Wire tenant scoping into client lookup**

**Step 5: Run test/lint**

Run: `make lint && make test`

**Step 6: Commit**

Run: `git commit -m "feat: add tenant and project management APIs"`

### Task 10: Add admin UI pages for tenants, clients, users, policies

**Files:**
- Create: `templates/admin_tenants.html`
- Create: `templates/admin_clients.html`
- Create: `templates/admin_users.html`
- Create: `templates/admin_policies.html`
- Create: `src/routes/admin_pages.rs`
- Modify: `templates/base.html`
- Modify: `src/routes/mod.rs`
- Test: `tests/e2e/specs/admin_console.spec.ts`

**Step 1: Write failing Playwright e2e spec for admin list/create flow**

**Step 2: Run failing e2e**

Run: `make e2e`

**Step 3: Implement minimal admin pages + route handlers**

**Step 4: Add form-level CSRF and permission checks**

**Step 5: Re-run e2e and unit tests**

Run: `make test && make e2e`

**Step 6: Commit**

Run: `git commit -m "feat: add admin console pages for tenant operations"`

---

## Track E: Machine Identity + Advanced AuthZ

### Task 11: Add client credentials flow

**Files:**
- Modify: `src/routes/token.rs`
- Create: `src/client_credentials.rs`
- Modify: `src/db/client.rs`
- Test: `src/routes/token.rs`

**Step 1: Write failing tests for `grant_type=client_credentials`**

**Step 2: Run failing tests**

Run: `cargo test --all-features token::tests::test_client_credentials`

**Step 3: Implement minimal issuance path and scope checks**

**Step 4: Run tests**

Run: `make test`

**Step 5: Commit**

Run: `git commit -m "feat: support OAuth client credentials grant"`

### Task 12: Add API key lifecycle endpoints

**Files:**
- Create: `src/routes/api_keys.rs`
- Create: `src/db/api_key.rs`
- Modify: `src/routes/mod.rs`
- Modify: `src/db/mod.rs`
- Test: `src/routes/api_keys.rs`

**Step 1: Write failing tests for create/list/revoke API keys**

**Step 2: Run failing tests**

Run: `cargo test --all-features api_keys`

**Step 3: Implement key generation, hashing, and metadata storage**

**Step 4: Add UI/API exposure for last used/created/revoked states**

**Step 5: Run full test/lint suite**

Run: `make lint && make test && make e2e`

**Step 6: Commit**

Run: `git commit -m "feat: add API key lifecycle management"`

### Task 13: Add fine-grained authorization adapter

**Files:**
- Create: `src/authz.rs`
- Create: `src/routes/policy_simulate.rs`
- Modify: `src/routes/mod.rs`
- Test: `src/authz.rs`

**Step 1: Write failing tests for policy decision requests and deny-by-default**

**Step 2: Run failing tests**

Run: `cargo test --all-features authz`

**Step 3: Implement minimal adapter and policy simulation endpoint**

**Step 4: Add tracing fields for policy explainability**

**Step 5: Run tests**

Run: `make test`

**Step 6: Commit**

Run: `git commit -m "feat: add fine-grained authorization adapter and simulation"`

---

## Cross-Cutting Hardening

### Task 14: Add observability and SIEM/webhook event export

**Files:**
- Create: `src/routes/events_webhook.rs`
- Modify: `src/audit.rs`
- Modify: `src/routes/mod.rs`
- Test: `src/routes/events_webhook.rs`

**Step 1: Write failing tests for signed webhook delivery and retries**

**Step 2: Run failing tests**

Run: `cargo test --all-features events_webhook`

**Step 3: Implement webhook sink and delivery state tracking**

**Step 4: Run full verification**

Run: `make lint && make test`

**Step 5: Commit**

Run: `git commit -m "feat: add security event webhook export"`

### Task 15: Add compliance surfaces and data governance endpoints

**Files:**
- Create: `src/routes/compliance.rs`
- Modify: `src/routes/mod.rs`
- Modify: `src/db/mod.rs`
- Test: `src/routes/compliance.rs`

**Step 1: Write failing tests for account export/delete and audit evidence retrieval**

**Step 2: Run failing tests**

Run: `cargo test --all-features compliance`

**Step 3: Implement endpoints and access controls**

**Step 4: Run test + e2e**

Run: `make test && make e2e`

**Step 5: Commit**

Run: `git commit -m "feat: add compliance and governance APIs"`

---

## Final Program Verification

### Task 16: Run full validation and release readiness checks

**Files:**
- Modify: `README.md`
- Modify: `DESIGN_DOC.md`
- Modify: `docs/plans/2026-02-14-maximal-auth-platform-roadmap-design.md`

**Step 1: Run full command suite**

Run: `make fmt`
Run: `make lint`
Run: `make test`
Run: `make e2e`
Expected: all PASS.

**Step 2: Update docs for new capabilities and operator runbooks**

**Step 3: Verify migration/deployment safety in `cdk/`**

Run: `make synth`

**Step 4: Commit docs and release notes**

Run: `git commit -m "docs: publish maximal auth platform capability and ops guides"`
