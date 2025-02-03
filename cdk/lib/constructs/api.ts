import { LambdaIntegration, RestApi } from "aws-cdk-lib/aws-apigateway";
import { ICertificate } from "aws-cdk-lib/aws-certificatemanager";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";

interface ApiProps {
  domainName: string;
  certificate: ICertificate;
  healthHandler: RustFunction;
  signupHandler: RustFunction;
  loginHandler: RustFunction;
}

export class Api extends Construct {
  public readonly api: RestApi;

  constructor(scope: Construct, id: string, props: ApiProps) {
    super(scope, id);

    this.api = new RestApi(this, "Api", {
      restApiName: "eric-auth",
      domainName: {
        domainName: props.domainName,
        certificate: props.certificate,
      },
    });

    const health = this.api.root.addResource("health");
    health.addMethod("GET", new LambdaIntegration(props.healthHandler));

    const signup = this.api.root.addResource("signup");
    signup.addMethod("POST", new LambdaIntegration(props.signupHandler));

    const login = this.api.root.addResource("login");
    login.addMethod("POST", new LambdaIntegration(props.loginHandler));
  }
}
