# Maximal Auth Platform Roadmap Design

Date: 2026-02-14
Project: EricAuth
Goal: Evolve EricAuth from a strong self-hosted OIDC auth service into a maximal, industry-standard authentication platform with enterprise and advanced capabilities.

## 1. Context and Current State

EricAuth already provides a solid base:
- Password auth, passkeys, session management, recovery codes
- OIDC/OAuth core endpoints (`/authorize`, `/token`, `/userinfo`, discovery, JWKS)
- Hosted account/security pages
- Security middleware (CSRF, rate limiting, security headers)
- DynamoDB + in-memory backend abstraction

This roadmap targets maximal parity with platforms like Auth0/Okta/Cognito/Keycloak/Clerk/Supabase Auth while preserving EricAuth's self-hosted, Rust-first architecture.

## 2. Design Goals

1. Reach full table-stakes coverage for modern auth platforms.
2. Add enterprise deal-breaker capabilities (SAML, SCIM, admin RBAC, audit/compliance).
3. Add advanced differentiation (risk-adaptive auth, fine-grained authz, machine identity depth).
4. Execute safely through parallel tracks using isolated worktrees and subagents.
5. Keep production readiness at each phase via strict verification gates.

## 3. Architectural Direction

### 3.1 Product Surfaces

- **Identity Runtime API (existing Rust service):** all auth/protocol endpoints.
- **Admin API + Admin UI (new):** tenant/org/app/client/user/policy operations.
- **Event and Audit Pipeline (new):** immutable security/admin/auth events and export sinks.
- **Policy Layer (expanded):** authN policy, MFA policy, authZ policy, risk signals.

### 3.2 Data Model Expansion

Add tables/entities for:
- Organizations/tenants, memberships, roles, groups
- Admin roles/permissions and delegated scopes
- MFA enrollments (TOTP/SMS/email backup), trusted devices
- Email verification and password reset tokens
- SAML configs and assertions metadata
- SCIM identities, group mapping, provisioning state
- API keys and machine identities
- Audit events, security incidents, webhook delivery state
- Risk signals and adaptive policy artifacts

### 3.3 Execution Model

Use capability tracks with strict dependencies:
- Track A: Identity lifecycle + MFA
- Track B: Enterprise federation (SAML + SCIM)
- Track C: Security/compliance + observability
- Track D: Admin/developer experience
- Track E: Advanced authz + machine identity

Each track runs in dedicated worktrees with subagent parallelization for backend, UI, and tests.

## 4. Capability Roadmap (Maximal)

### Phase 1 - Identity Lifecycle and MFA Table Stakes

- Email verification flow and token lifecycle
- Forgot/reset password flow
- TOTP MFA enrollment/challenge/recovery
- Account state machine (invited/active/suspended/disabled/deleted)
- Trusted sessions/devices and session risk prompts

Exit criteria:
- End-user lifecycle complete for password + passkey + TOTP
- Full unit/e2e coverage for primary and recovery paths

### Phase 2 - Federation and Enterprise Onboarding

- SAML 2.0 IdP support for enterprise SSO
- Inbound social/enterprise OIDC federation and account linking
- SCIM 2.0 provisioning/deprovisioning/group sync
- JIT provisioning + claim/group mapping policies

Exit criteria:
- A customer app can onboard users via SAML or SCIM with policy controls

### Phase 3 - Security, Compliance, and Governance

- Immutable audit log model with export APIs
- SIEM/webhook integrations
- Admin RBAC with least-privilege roles
- Compliance support surfaces (data export/delete, policy evidence)
- Breached-password and anomaly detection hooks

Exit criteria:
- Security teams can monitor, audit, and control platform operations end-to-end

### Phase 4 - Developer and Tenant Platform

- Multi-tenant/project model with per-tenant configuration
- Public docs/SDK improvements and quickstarts
- Client/app lifecycle APIs and management UI
- Branding/localization/accessibility enhancements

Exit criteria:
- Teams can self-serve integration and operate tenants without code edits

### Phase 5 - Machine Identity and Advanced Authorization

- Client credentials and API key lifecycle management
- Token exchange and delegated service identity
- Fine-grained authorization integration (ABAC/ReBAC/FGA)
- Policy simulation and dry-run tooling

Exit criteria:
- Human and non-human auth flows are both first-class with enforceable policies

### Phase 6 - Advanced Differentiators

- Risk-adaptive step-up authentication
- Auth funnel and conversion analytics
- Data residency and key-management options (BYOK/HYOK strategy)
- Journey orchestration for login/recovery/migration flows

Exit criteria:
- Platform exceeds baseline parity and supports advanced enterprise/security needs

## 5. Parallelization and Worktree Strategy

For each phase:
1. Create one orchestration issue with dependency graph.
2. Create one worktree per independent epic.
3. Dispatch subagents in parallel per epic:
   - Backend/protocol agent
   - UI/UX/template agent
   - Test/verification agent
4. Merge only after verification gates pass.

Naming convention examples:
- `.worktrees/track-a-mfa-totp`
- `.worktrees/track-b-saml-idp`
- `.worktrees/track-c-audit-events`

## 6. Verification and Quality Gates

Every epic must include:
- Unit tests for new business logic and edge cases
- E2E tests for user-visible/auth-protocol flows
- Security checks for auth boundary behavior
- `make fmt`, `make lint`, `make test`, `make e2e`

Release gates per phase:
- Protocol conformance checks (OIDC/SAML/SCIM where applicable)
- Backward compatibility checks for existing clients
- Operational readiness checks (observability and runbooks)

## 7. Risks and Mitigations

- **Scope explosion:** enforce phase exit criteria and backlog grooming at every phase boundary.
- **Protocol complexity:** isolate SAML/SCIM in dedicated tracks with strict conformance tests.
- **Security regressions:** require threat-case tests and audit instrumentation in each auth feature.
- **Coordination overhead:** keep epics small and independent; use worktrees plus subagent ownership.

## 8. Execution Progress Snapshot (2026-02-14)

Current execution status across active feature worktrees (pre-merge):

| Track | Worktree | Fresh verification result |
|---|---|---|
| A - Identity lifecycle | `.worktrees/track-a-identity-lifecycle` | `make lint` + `make test` passed (94/94 tests) |
| B - Federation | `.worktrees/track-b-federation` | `make lint` + `make test` passed (85/85 tests); `make e2e` passed (6/6 tests); `make synth` passed |
| C - Security/compliance | `.worktrees/track-c-security-compliance` | `make lint` + `make test` passed (87/87 tests) |
| D - Admin/developer experience | `.worktrees/track-d-admin-dx` | `make lint` + `make test` passed (77/77 tests) |
| E - Machine authz | `.worktrees/track-e-machine-authz` | `make lint` + `make test` passed (90/90 tests) |

Execution and integration guidance:

- Keep all track branches isolated until integration sequencing is agreed.
- Use a convergence branch to combine tracks incrementally and resolve cross-track conflicts.
- After each merge into convergence, rerun `make lint`, `make test`, and relevant protocol checks (`make e2e`, `make synth`) before opening the final PR.
- Do not treat track-local green runs as merged `main` readiness; final readiness is established only after post-convergence validation.

## 9. Definition of Success

Success means EricAuth can:
- Compete on table-stakes features with mainstream auth providers
- Pass enterprise feature/security evaluations
- Support both developer velocity and governance needs
- Execute roadmap delivery with parallel, verifiable implementation slices
