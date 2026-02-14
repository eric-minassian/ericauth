#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { EricAuthStack } from "../lib/cdk-stack";
import { OidcStack } from "../lib/oidc-stack";

const app = new cdk.App();

// ─── Accounts ───────────────────────────────────────────────────────
const BETA_ACCOUNT = "216482851496";
const PROD_ACCOUNT = "326884876551";
const REGION = "us-east-1";
const GITHUB_REPO = "eric-minassian/ericauth";

// ─── App stacks (one per environment) ───────────────────────────────

// Dev — uses your local CLI credentials (CDK_DEFAULT_ACCOUNT/REGION)
new EricAuthStack(app, "EricAuth-Dev", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? REGION,
  },
  envName: "dev",
});

// Beta
new EricAuthStack(app, "EricAuth-Beta", {
  env: { account: BETA_ACCOUNT, region: REGION },
  envName: "beta",
  // domainName: "auth-beta.ericminassian.com",
  // hostedZoneDomain: "ericminassian.com",
});

// Prod
new EricAuthStack(app, "EricAuth-Prod", {
  env: { account: PROD_ACCOUNT, region: REGION },
  envName: "prod",
  // domainName: "auth.ericminassian.com",
  // hostedZoneDomain: "ericminassian.com",
});

// ─── OIDC stacks (one per account that needs CI/CD) ─────────────────

new OidcStack(app, "EricAuth-Oidc-Beta", {
  env: { account: BETA_ACCOUNT, region: REGION },
  githubRepo: GITHUB_REPO,
});

new OidcStack(app, "EricAuth-Oidc-Prod", {
  env: { account: PROD_ACCOUNT, region: REGION },
  githubRepo: GITHUB_REPO,
});
