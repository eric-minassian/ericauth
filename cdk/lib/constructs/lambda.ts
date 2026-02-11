import { TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";

import path = require("path");

const manifestPath = path.join(__dirname, "..", "..", "..");

interface LambdaProps {
  usersTable: TableV2;
  sessionsTable: TableV2;
  refreshTokensTable: TableV2;
  credentialsTable: TableV2;
  challengesTable: TableV2;
  rateLimitsTable: TableV2;
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
        CREDENTIALS_TABLE_NAME: props.credentialsTable.tableName,
        CHALLENGES_TABLE_NAME: props.challengesTable.tableName,
        RATE_LIMITS_TABLE_NAME: props.rateLimitsTable.tableName,
      },
    });

    props.usersTable.grantReadWriteData(this.handler);
    props.sessionsTable.grantReadWriteData(this.handler);
    props.refreshTokensTable.grantReadWriteData(this.handler);
    props.credentialsTable.grantReadWriteData(this.handler);
    props.challengesTable.grantReadWriteData(this.handler);
    props.rateLimitsTable.grantReadWriteData(this.handler);
  }
}
