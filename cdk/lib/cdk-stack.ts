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
import { Lambdas } from "./constructs/lambda";

export class CdkStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const DOMAIN_NAME = "auth.ericminassian.com";

    const hostedZone = HostedZone.fromLookup(this, "HostedZone", {
      domainName: DOMAIN_NAME,
    });

    const certificate = new Certificate(this, "Certificate", {
      domainName: DOMAIN_NAME,
      validation: CertificateValidation.fromDns(hostedZone),
    });

    const database = new Database(this, "Database");
    const lambdas = new Lambdas(
      this,
      "Lambdas",
      database.usersTable,
      database.sessionsTable
    );
    const api = new Api(this, "ApiGateway", {
      domainName: DOMAIN_NAME,
      certificate,
      healthHandler: lambdas.healthHandler,
      signupHandler: lambdas.signupHandler,
      loginHandler: lambdas.loginHandler,
    });

    new ARecord(this, "ARecord", {
      zone: hostedZone,
      recordName: DOMAIN_NAME,
      target: RecordTarget.fromAlias(new ApiGateway(api.api)),
    });
  }
}
