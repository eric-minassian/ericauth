import { CfnOutput, Stack, StackProps } from "aws-cdk-lib";
import {
  Effect,
  OpenIdConnectProvider,
  PolicyStatement,
  Role,
  WebIdentityPrincipal,
} from "aws-cdk-lib/aws-iam";
import { Construct } from "constructs";

export interface OidcStackProps extends StackProps {
  /** GitHub org/repo, e.g. "ericminassian/ericauth" */
  githubRepo: string;
}

/**
 * Creates a GitHub Actions OIDC provider and deploy role in the target AWS
 * account. Deploy once per account before CI/CD can run.
 *
 * Usage:
 *   pnpm cdk deploy EricAuth-Oidc-Beta --profile beta
 *   pnpm cdk deploy EricAuth-Oidc-Prod --profile prod
 */
export class OidcStack extends Stack {
  constructor(scope: Construct, id: string, props: OidcStackProps) {
    super(scope, id, props);

    // GitHub's OIDC provider — one per AWS account
    const provider = new OpenIdConnectProvider(this, "GitHubOidc", {
      url: "https://token.actions.githubusercontent.com",
      clientIds: ["sts.amazonaws.com"],
    });

    // Deploy role that GitHub Actions assumes via OIDC
    const deployRole = new Role(this, "GitHubDeployRole", {
      roleName: "ericauth-github-deploy",
      assumedBy: new WebIdentityPrincipal(
        provider.openIdConnectProviderArn,
        {
          StringEquals: {
            "token.actions.githubusercontent.com:aud": "sts.amazonaws.com",
          },
          StringLike: {
            "token.actions.githubusercontent.com:sub": `repo:${props.githubRepo}:*`,
          },
        }
      ),
      description:
        "Role assumed by GitHub Actions to deploy EricAuth via CDK",
    });

    // CDK deploy needs broad permissions — scope down if desired
    deployRole.addToPolicy(
      new PolicyStatement({
        effect: Effect.ALLOW,
        actions: ["sts:AssumeRole"],
        resources: [`arn:aws:iam::${this.account}:role/cdk-*`],
      })
    );

    new CfnOutput(this, "DeployRoleArn", {
      value: deployRole.roleArn,
      description:
        "Set this as AWS_DEPLOY_ROLE_ARN in the GitHub environment variables",
    });
  }
}
