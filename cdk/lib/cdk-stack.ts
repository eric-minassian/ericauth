import { Stack, StackProps } from "aws-cdk-lib";
import { LambdaRestApi } from "aws-cdk-lib/aws-apigateway";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";
import path = require("path");

export class CdkStack extends Stack {
  constructor(scope: Construct, id: string, props?: StackProps) {
    super(scope, id, props);

    // const DOMAIN_NAME = "auth.ericminassian.com";

    // const hostedZone = HostedZone.fromLookup(this, "HostedZone", {
    //   domainName: DOMAIN_NAME,
    // });

    // const certificate = new Certificate(this, "Certificate", {
    //   domainName: DOMAIN_NAME,
    //   validation: CertificateValidation.fromDns(hostedZone),
    // });

    const handler = new RustFunction(this, "eric-auth", {
      manifestPath: path.join(__dirname, "..", ".."),
    });

    const api = new LambdaRestApi(this, "Api", {
      restApiName: "eric-auth",
      handler,
      // domainName: {
      //   domainName: DOMAIN_NAME,
      //   certificate,
      // },
      proxy: false,
    });

    const health = api.root.addResource("health");
    health.addMethod("GET");

    const users = api.root.addResource("users");
    users.addMethod("POST");

    const login = api.root.addResource("login");
    login.addMethod("POST");

    // new ARecord(this, "ARecord", {
    //   zone: hostedZone,
    //   recordName: DOMAIN_NAME,
    //   target: RecordTarget.fromAlias(new ApiGateway(api)),
    // });

    // new CfnOutput(this, "Url", {
    //   value: `https://${DOMAIN_NAME}`,
    //   description: "URL",
    // });
  }
}
