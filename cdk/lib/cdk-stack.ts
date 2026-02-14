import { CfnOutput, Stack, StackProps } from "aws-cdk-lib";
import {
  Certificate,
  CertificateValidation,
} from "aws-cdk-lib/aws-certificatemanager";
import { ARecord, HostedZone, RecordTarget } from "aws-cdk-lib/aws-route53";
import { ApiGatewayv2DomainProperties } from "aws-cdk-lib/aws-route53-targets";
import * as secretsmanager from "aws-cdk-lib/aws-secretsmanager";
import { Construct } from "constructs";
import { Api } from "./constructs/api";
import { Database } from "./constructs/database";
import { Lambda } from "./constructs/lambda";

export interface EricAuthStackProps extends StackProps {
  /** Environment name: beta, prod, or dev */
  envName: string;
  /** Optional path to a prebuilt Lambda zip artifact. */
  lambdaZipPath?: string;
  /** Custom domain name (e.g. auth.ericminassian.com). Omit for dev. */
  domainName?: string;
  /** Root hosted zone domain for DNS validation. Required if domainName is set. */
  hostedZoneDomain?: string;
}

export class EricAuthStack extends Stack {
  constructor(scope: Construct, id: string, props: EricAuthStackProps) {
    super(scope, id, props);

    const database = new Database(this, "Database", {
      envName: props.envName,
    });

    const jwtSecret = new secretsmanager.Secret(this, "JwtPrivateKey", {
      secretName: `ericauth-${props.envName}-jwt-private-key`,
      description: "ES256 private key PEM for JWT signing",
    });

    const lambda = new Lambda(this, "Lambda", {
      usersTable: database.usersTable,
      sessionsTable: database.sessionsTable,
      refreshTokensTable: database.refreshTokensTable,
      credentialsTable: database.credentialsTable,
      challengesTable: database.challengesTable,
      clientsTable: database.clientsTable,
      authCodesTable: database.authCodesTable,
      rateLimitsTable: database.rateLimitsTable,
      jwtSecret,
      lambdaZipPath: props.lambdaZipPath,
    });

    let api: Api;

    if (props.domainName && props.hostedZoneDomain) {
      // Custom domain with ACM + Route53
      const hostedZone = HostedZone.fromLookup(this, "HostedZone", {
        domainName: props.hostedZoneDomain,
      });

      const certificate = new Certificate(this, "Certificate", {
        domainName: props.domainName,
        validation: CertificateValidation.fromDns(hostedZone),
      });

      api = new Api(this, "ApiGateway", {
        handler: lambda.handler,
        domainName: props.domainName,
        certificate,
      });

      new ARecord(this, "ARecord", {
        zone: hostedZone,
        recordName: props.domainName,
        target: RecordTarget.fromAlias(
          new ApiGatewayv2DomainProperties(
            api.customDomainName!.regionalDomainName,
            api.customDomainName!.regionalHostedZoneId,
          ),
        ),
      });
    } else {
      // No custom domain — use API Gateway default URL
      api = new Api(this, "ApiGateway", {
        handler: lambda.handler,
      });
    }

    new CfnOutput(this, "ApiUrl", {
      value: props.domainName ? `https://${props.domainName}` : api.api.apiEndpoint,
      description: "Public base URL for EricAuth",
    });
  }
}
