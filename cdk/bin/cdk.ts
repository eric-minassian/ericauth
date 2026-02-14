#!/usr/bin/env node
import * as cdk from "aws-cdk-lib";
import { EricAuthStack } from "../lib/cdk-stack";
import { OidcStack } from "../lib/oidc-stack";

const app = new cdk.App();
const lambdaZipPath = app.node.tryGetContext("lambdaZip") as string | undefined;
const prNumber = app.node.tryGetContext("prNumber") as string | undefined;

// ─── Accounts ───────────────────────────────────────────────────────
const BETA_ACCOUNT = "216482851496";
const PROD_ACCOUNT = "326884876551";
const REGION = "us-east-1";

// ─── App stacks (one per environment) ───────────────────────────────

// Dev — uses your local CLI credentials (CDK_DEFAULT_ACCOUNT/REGION)
new EricAuthStack(app, "EricAuth-Dev", {
  env: {
    account: process.env.CDK_DEFAULT_ACCOUNT,
    region: process.env.CDK_DEFAULT_REGION ?? REGION,
  },
  envName: "dev",
  lambdaZipPath,
});

// Beta
new EricAuthStack(app, "EricAuth-Beta", {
  env: { account: BETA_ACCOUNT, region: REGION },
  envName: "beta",
  lambdaZipPath,
  // domainName: "auth-beta.ericminassian.com",
  // hostedZoneDomain: "ericminassian.com",
});

// Prod
new EricAuthStack(app, "EricAuth-Prod", {
  env: { account: PROD_ACCOUNT, region: REGION },
  envName: "prod",
  lambdaZipPath,
  // domainName: "auth.ericminassian.com",
  // hostedZoneDomain: "ericminassian.com",
});

if (prNumber) {
  new EricAuthStack(app, `EricAuth-Pr-${prNumber}`, {
    env: { account: BETA_ACCOUNT, region: REGION },
    envName: `pr-${prNumber}`,
    lambdaZipPath,
  });
}

// ─── OIDC stacks (one per account that needs CI/CD) ─────────────────

new OidcStack(app, "EricAuth-Oidc-Beta", {
  env: { account: BETA_ACCOUNT, region: REGION },
  githubRepo: "eric-minassian/ericauth",
});

new OidcStack(app, "EricAuth-Oidc-Prod", {
  env: { account: PROD_ACCOUNT, region: REGION },
  githubRepo: "eric-minassian/ericauth",
});
