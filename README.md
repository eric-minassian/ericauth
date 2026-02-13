# EricAuth

Self-hosted authentication service built in Rust, deployed as a serverless Lambda on AWS.

## Prerequisites

- [Rust](https://rustup.rs/)
- [cargo-lambda](https://www.cargo-lambda.info/guide/installation.html)
- [Node.js 22+](https://nodejs.org/) and [pnpm](https://pnpm.io/)
- [AWS CLI](https://aws.amazon.com/cli/) (for deploying)

## Local Development

Run the service locally with an in-memory database -- no AWS account or Docker needed:

```sh
make watch
```

This starts the Lambda emulator at `http://localhost:9000`. Test it:

```sh
curl http://localhost:9000/health

curl -X POST http://localhost:9000/signup \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -d '{"email":"user@example.com","password":"MyP@ssw0rd!"}'

curl -X POST http://localhost:9000/login \
  -H "Content-Type: application/json" \
  -H "X-Forwarded-For: 127.0.0.1" \
  -d '{"email":"user@example.com","password":"MyP@ssw0rd!"}'
```

Other commands:

```sh
make test    # Run tests
make e2e     # Run Playwright browser E2E tests
make lint    # cargo fmt --check + clippy
make fmt     # Auto-format code
```

## Deploy to Your AWS Account

```sh
make login                                                                  # AWS SSO login
cd cdk && pnpm cdk bootstrap aws://ACCOUNT_ID/us-east-1 --profile PROFILE  # One-time CDK bootstrap
make deploy-dev                                                             # Deploy (uses API Gateway URL)
```

## CDK Stacks

All stacks are defined unconditionally in `cdk/bin/cdk.ts`. Deploy any stack by name:

| Stack | Description |
|---|---|
| `EricAuth-Dev` | Personal dev environment (uses CLI credentials) |
| `EricAuth-Beta` | Beta (account `216482851496`) |
| `EricAuth-Prod` | Prod (account `326884876551`) |
| `EricAuth-Oidc-Beta` | GitHub OIDC provider for beta account |
| `EricAuth-Oidc-Prod` | GitHub OIDC provider for prod account |

```sh
make synth           # Synth all stacks
make deploy-dev      # Deploy dev
make deploy-beta     # Deploy beta
make deploy-prod     # Deploy prod
```

## CI/CD Setup

CI runs on PRs (lint, unit/integration tests, Playwright E2E, CDK synth). Pushes to `main` rerun tests + local Playwright E2E, deploy to beta, run Playwright E2E against beta, deploy to prod, then run prod smoke tests.

### AWS OIDC Setup (once per account)

The deploy pipeline authenticates via GitHub OIDC. Run this once in each AWS account (beta and prod) to create the OIDC provider and deploy role:

```sh
# Authenticate to the target account
make login

# Bootstrap CDK (if not already done)
cd cdk && pnpm cdk bootstrap aws://ACCOUNT_ID/us-east-1 --profile PROFILE

# Deploy the OIDC stack
make deploy-oidc-beta   # or deploy-oidc-prod
```

The stack outputs a `DeployRoleArn`. Copy it and set it as `AWS_DEPLOY_ROLE_ARN` in the corresponding GitHub environment:

**Settings > Environments > `beta` (or `prod`) > Variables > Add `AWS_DEPLOY_ROLE_ARN`**
