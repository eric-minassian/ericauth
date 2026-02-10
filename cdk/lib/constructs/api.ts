import {
  DomainNameOptions,
  LambdaIntegration,
  RestApi,
} from "aws-cdk-lib/aws-apigateway";
import { ICertificate } from "aws-cdk-lib/aws-certificatemanager";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";

interface ApiProps {
  handler: RustFunction;
  /** Custom domain name. Omit for dev deployments. */
  domainName?: string;
  /** ACM certificate for the custom domain. Required if domainName is set. */
  certificate?: ICertificate;
}

export class Api extends Construct {
  public readonly api: RestApi;

  constructor(scope: Construct, id: string, props: ApiProps) {
    super(scope, id);

    let domainName: DomainNameOptions | undefined;
    if (props.domainName && props.certificate) {
      domainName = {
        domainName: props.domainName,
        certificate: props.certificate,
      };
    }

    this.api = new RestApi(this, "Api", {
      restApiName: "eric-auth",
      ...(domainName && { domainName }),
    });

    const integration = new LambdaIntegration(props.handler);

    // Root path "/" — {proxy+} does NOT match the bare root
    this.api.root.addMethod("ANY", integration);

    // All sub-paths "/{proxy+}" — catches /health, /login, /.well-known/jwks.json, etc.
    this.api.root.addProxy({
      defaultIntegration: integration,
      anyMethod: true,
    });
  }
}
