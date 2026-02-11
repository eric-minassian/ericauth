import { TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";

import path = require("path");

const manifestPath = path.join(__dirname, "..", "..", "..");

interface LambdaProps {
  usersTable: TableV2;
  sessionsTable: TableV2;
  refreshTokensTable: TableV2;
}

export class Lambda extends Construct {
  public readonly handler: RustFunction;

  constructor(scope: Construct, id: string, props: LambdaProps) {
    super(scope, id);

    this.handler = new RustFunction(this, "AuthFunction", {
      manifestPath,
      binaryName: "ericauth",
      environment: {
        USERS_TABLE_NAME: props.usersTable.tableName,
        SESSIONS_TABLE_NAME: props.sessionsTable.tableName,
        REFRESH_TOKENS_TABLE_NAME: props.refreshTokensTable.tableName,
      },
    });

    props.usersTable.grantReadWriteData(this.handler);
    props.sessionsTable.grantReadWriteData(this.handler);
    props.refreshTokensTable.grantReadWriteData(this.handler);
  }
}
