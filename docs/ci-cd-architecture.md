# CI/CD Architecture

This document defines the target CI/CD design for EricAuth and serves as the
source of truth for workflow behavior in `.github/workflows/ci.yml` and
`.github/workflows/deploy.yml`.

## Goals

- Keep high PR fidelity: formatting, clippy, tests, synth, and E2E.
- Build the deployable Lambda package once per workflow run.
- Promote immutable artifacts across jobs instead of rebuilding.
- Run E2E against deployed environments in CI instead of local `cargo lambda watch`.
- Keep overall CI wall-clock time low through parallelism and caching.

## Core Rules

1. Use cache for dependencies and incremental speedups.
2. Use artifacts for deployable outputs and cross-job reuse.
3. Do not rely on cross-job `target/` sharing during the same run.
4. Keep one packaging build in PR workflow and one packaging build in deploy workflow.
5. Reuse one cloud assembly (`cdk.out`) for Beta and Prod deploy in main pipeline.

## Artifact Contract

- `lambda-package`: `dist/lambda/ericauth.zip`
  - Produced by Rust packaging job.
  - Consumed by CDK synth job.
- `cdk-assembly`: `cdk/cdk.out`
  - Produced by CDK synth job.
  - Consumed by deploy jobs.

## PR Workflow Design

### Job graph

1. `rust-quality-and-package`
2. `cdk-synth` (needs 1)
3. `deploy-preview` (needs 2)
4. `e2e-preview` (needs 3)
5. `destroy-preview` (always, needs 3 and 4)

### Job responsibilities

#### 1) `rust-quality-and-package`

- `cargo fmt --all -- --check`
- `cargo clippy --all-targets --all-features`
- `cargo test --all-features`
- `cargo lambda build --release`
- Zip `target/lambda/ericauth/bootstrap` to `dist/lambda/ericauth.zip`
- Upload `lambda-package`

#### 2) `cdk-synth`

- Download `lambda-package`
- Run `pnpm cdk synth --no-lookup -c lambdaZip=../dist/lambda/ericauth.zip -c prNumber=<PR_NUMBER>`
- Upload `cdk-assembly`

#### 3) `deploy-preview`

- Download `cdk-assembly`
- Deploy `EricAuth-Pr-<PR_NUMBER>` with `--app cdk.out`
- Capture `ApiUrl` output as `api_url`

#### 4) `e2e-preview`

- Run Playwright against `E2E_BASE_URL=<api_url>`
- Do not run local web server in CI preview tests

#### 5) `destroy-preview`

- Always attempt to destroy `EricAuth-Pr-<PR_NUMBER>` with `--app cdk.out`
- Run even when E2E fails to avoid orphan stacks

## Deploy Workflow Design (main)

### Job graph

1. `rust-quality-and-package`
2. `cdk-synth` (needs 1)
3. `deploy-beta` (needs 2)
4. `e2e-beta` (needs 3)
5. `deploy-prod` (needs 3 and 4)
6. `smoke-prod` (needs 5)

### Responsibilities

- `rust-quality-and-package`: same quality gates and single packaging build.
- `cdk-synth`: produce one `cdk.out` from packaged zip artifact.
- `deploy-beta`: deploy `EricAuth-Beta` from `cdk.out`.
- `e2e-beta`: run full E2E against Beta URL.
- `deploy-prod`: deploy `EricAuth-Prod` from the same `cdk.out`.
- `smoke-prod`: run smoke subset against Prod URL.

## CDK Integration Contract

- CDK app accepts context key `lambdaZip`.
- Lambda construct behavior:
  - If `lambdaZip` exists: use prebuilt zip via `Code.fromAsset(lambdaZip)`.
  - Otherwise: fallback to local `RustFunction` build for developer ergonomics.
- CDK app accepts `prNumber` context and creates ephemeral preview stack:
  - stack id: `EricAuth-Pr-<prNumber>`
  - env name: `pr-<prNumber>`

## Caching Strategy

- Rust: `Swatinem/rust-cache@v2`
- Node: `actions/setup-node` with pnpm cache
- Playwright: cache `~/.cache/ms-playwright`

## Operational Notes

- Preview deploy jobs are skipped for forked PRs where role assumption is unavailable.
- `destroy-preview` is best-effort and should not fail the entire workflow.
- Production deploy reuses the synthesized assembly from the same run.

## Evolution Path

- Add path-based conditional execution to skip expensive jobs on docs-only changes.
- Add `cargo nextest` for faster Rust test execution.
- Optionally add `sccache` when compile time dominates runtime.
