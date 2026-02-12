# ─── Local Development ──────────────────────────────────────────────

## Run the Lambda locally with in-memory database (no AWS needed)
watch:
	DATABASE_BACKEND=memory cargo lambda watch

## Run cargo tests
test:
	ENCRYPTION_KEY="01234567890123456789012345678901" cargo test --all-features

## Check formatting + clippy
lint:
	cargo fmt --all -- --check
	cargo clippy --all-targets --all-features

## Run browser end-to-end tests
e2e:
	cd tests/e2e && pnpm install && pnpm exec playwright install --with-deps chromium && pnpm test

## Format code
fmt:
	cargo fmt --all

# ─── Build ──────────────────────────────────────────────────────────

## Build Lambda binary (debug)
build:
	cargo lambda build

## Build Lambda binary (release)
build-release:
	cargo lambda build --release

# ─── Deploy ─────────────────────────────────────────────────────────

## Deploy to your personal dev AWS account
deploy-dev:
	cd cdk && pnpm install && pnpm cdk deploy EricAuth-Dev --require-approval never

## Deploy to beta
deploy-beta:
	cd cdk && pnpm install && pnpm cdk deploy EricAuth-Beta --require-approval never

## Deploy to production
deploy-prod:
	cd cdk && pnpm install && pnpm cdk deploy EricAuth-Prod --require-approval never

## Deploy GitHub OIDC provider + deploy role (run once per AWS account)
deploy-oidc-beta:
	cd cdk && pnpm install && pnpm cdk deploy EricAuth-Oidc-Beta --require-approval never

deploy-oidc-prod:
	cd cdk && pnpm install && pnpm cdk deploy EricAuth-Oidc-Prod --require-approval never

## CDK synth (preview all CloudFormation templates)
synth:
	cd cdk && pnpm install && pnpm cdk synth --no-lookup

# ─── AWS Auth ───────────────────────────────────────────────────────

## AWS SSO login
login:
	aws sso login --sso-session ericminassian

.PHONY: watch test lint e2e fmt build build-release deploy-dev deploy-beta deploy-prod deploy-oidc-beta deploy-oidc-prod synth login
