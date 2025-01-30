import { RemovalPolicy, Stack, StackProps } from "aws-cdk-lib";
import { LambdaIntegration, RestApi } from "aws-cdk-lib/aws-apigateway";
import {
  Certificate,
  CertificateValidation,
} from "aws-cdk-lib/aws-certificatemanager";
import { AttributeType, TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { ARecord, HostedZone, RecordTarget } from "aws-cdk-lib/aws-route53";
import { ApiGateway } from "aws-cdk-lib/aws-route53-targets";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";

import path = require("path");

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

    const usersTable = new TableV2(this, "UsersTable", {
      tableName: "UsersTable",
      partitionKey: { name: "email", type: AttributeType.STRING },
      removalPolicy: RemovalPolicy.RETAIN,
    });

    const healthHandler = new RustFunction(this, "HealthFunction", {
      manifestPath: path.join(__dirname, "..", ".."),
      binaryName: "health",
    });

    const loginHandler = new RustFunction(this, "LoginFunction", {
      manifestPath: path.join(__dirname, "..", ".."),
      binaryName: "login",
    });

    usersTable.grantReadWriteData(loginHandler);

    const api = new RestApi(this, "Api", {
      restApiName: "eric-auth",
      domainName: {
        domainName: DOMAIN_NAME,
        certificate,
      },
    });

    const health = api.root.addResource("health");
    health.addMethod("GET", new LambdaIntegration(healthHandler));

    // const users = api.root.addResource("user");
    // users.addMethod("POST");

    const login = api.root.addResource("login");
    login.addMethod("POST", new LambdaIntegration(loginHandler));

    new ARecord(this, "ARecord", {
      zone: hostedZone,
      recordName: DOMAIN_NAME,
      target: RecordTarget.fromAlias(new ApiGateway(api)),
    });
  }
}
