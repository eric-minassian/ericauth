import { DomainName, HttpApi } from "aws-cdk-lib/aws-apigatewayv2";
import { HttpLambdaIntegration } from "aws-cdk-lib/aws-apigatewayv2-integrations";
import { ICertificate } from "aws-cdk-lib/aws-certificatemanager";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";

interface ApiProps {
  handler: RustFunction;
  envName: string;
  /** Custom domain name. Omit for dev deployments. */
  domainName?: string;
  /** ACM certificate for the custom domain. Required if domainName is set. */
  certificate?: ICertificate;
}

export class Api extends Construct {
  public readonly api: HttpApi;
  public readonly customDomainName?: DomainName;

  constructor(scope: Construct, id: string, props: ApiProps) {
    super(scope, id);

    const integration = new HttpLambdaIntegration("Integration", props.handler);

    let defaultDomainMapping;
    if (props.domainName && props.certificate) {
      this.customDomainName = new DomainName(this, "DomainName", {
        domainName: props.domainName,
        certificate: props.certificate,
      });
      defaultDomainMapping = { domainName: this.customDomainName };
    }

    this.api = new HttpApi(this, "HttpApi", {
      apiName: `ericauth-${props.envName}`,
      defaultIntegration: integration,
      ...(defaultDomainMapping && { defaultDomainMapping }),
    });
  }
}
