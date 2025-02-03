import { TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";

import path = require("path");

const manifestPath = path.join(__dirname, "..", "..", "..");

export class Lambdas extends Construct {
  public readonly healthHandler: RustFunction;
  public readonly signupHandler: RustFunction;
  public readonly loginHandler: RustFunction;

  constructor(scope: Construct, id: string, usersTable: TableV2) {
    super(scope, id);

    this.healthHandler = new RustFunction(this, "HealthFunction", {
      manifestPath,
      binaryName: "health",
    });

    this.signupHandler = new RustFunction(this, "SignupFunction", {
      manifestPath,
      binaryName: "signup",
    });

    this.loginHandler = new RustFunction(this, "LoginFunction", {
      manifestPath,
      binaryName: "login",
    });

    usersTable.grantReadWriteData(this.signupHandler);
    usersTable.grantReadWriteData(this.loginHandler);
  }
}
