import { CfnOutput, Stack, StackProps } from "aws-cdk-lib";
import { EndpointType, LambdaRestApi } from "aws-cdk-lib/aws-apigateway";
import {
  Certificate,
  CertificateValidation,
} from "aws-cdk-lib/aws-certificatemanager";
import { ARecord, HostedZone, RecordTarget } from "aws-cdk-lib/aws-route53";
import { ApiGateway } from "aws-cdk-lib/aws-route53-targets";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";
import path = require("path");

export class CdkStack extends Stack {
  private readonly baseDomain = "ericminassian.com";
  private readonly subDomain = "auth";

  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    const hostedZone = HostedZone.fromLookup(this, "HostedZone", {
      domainName: `${this.subDomain}.${this.baseDomain}`,
    });

    const certificate = new Certificate(this, "Certificate", {
      domainName: `${this.subDomain}.${this.baseDomain}`,
      validation: CertificateValidation.fromDns(hostedZone),
    });

    const handler = new RustFunction(this, "eric-auth", {
      manifestPath: path.join(__dirname, "..", ".."),
    });

    const api = new LambdaRestApi(this, "Api", {
      handler,
      domainName: {
        domainName: `${this.subDomain}.${this.baseDomain}`,
        certificate,
        endpointType: EndpointType.REGIONAL,
      },
    });

    new ARecord(this, "ARecord", {
      zone: hostedZone,
      recordName: this.subDomain,
      target: RecordTarget.fromAlias(new ApiGateway(api)),
    });

    new CfnOutput(this, "Url", {
      value: `https://${this.subDomain}.${this.baseDomain}`,
      description: "URL",
    });
  }
}
