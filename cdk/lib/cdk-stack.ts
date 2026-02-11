import { Stack, StackProps } from "aws-cdk-lib";
import {
  Certificate,
  CertificateValidation,
} from "aws-cdk-lib/aws-certificatemanager";
import { ARecord, HostedZone, RecordTarget } from "aws-cdk-lib/aws-route53";
import { ApiGateway } from "aws-cdk-lib/aws-route53-targets";
import { Construct } from "constructs";
import { Api } from "./constructs/api";
import { Database } from "./constructs/database";
import { Lambda } from "./constructs/lambda";

export interface EricAuthStackProps extends StackProps {
  /** Environment name: beta, prod, or dev */
  envName: string;
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

    const lambda = new Lambda(this, "Lambda", {
      usersTable: database.usersTable,
      sessionsTable: database.sessionsTable,
      refreshTokensTable: database.refreshTokensTable,
    });

    if (props.domainName && props.hostedZoneDomain) {
      // Custom domain with ACM + Route53
      const hostedZone = HostedZone.fromLookup(this, "HostedZone", {
        domainName: props.hostedZoneDomain,
      });

      const certificate = new Certificate(this, "Certificate", {
        domainName: props.domainName,
        validation: CertificateValidation.fromDns(hostedZone),
      });

      const api = new Api(this, "ApiGateway", {
        handler: lambda.handler,
        domainName: props.domainName,
        certificate,
      });

      new ARecord(this, "ARecord", {
        zone: hostedZone,
        recordName: props.domainName,
        target: RecordTarget.fromAlias(new ApiGateway(api.api)),
      });
    } else {
      // No custom domain — use API Gateway default URL
      new Api(this, "ApiGateway", {
        handler: lambda.handler,
      });
    }
  }
}
