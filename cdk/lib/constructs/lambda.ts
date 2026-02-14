import * as fs from "node:fs";
import { TableV2 } from "aws-cdk-lib/aws-dynamodb";
import {
  Architecture,
  Code,
  Function,
  IFunction,
  Runtime,
} from "aws-cdk-lib/aws-lambda";
import { ISecret } from "aws-cdk-lib/aws-secretsmanager";
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
  clientsTable: TableV2;
  authCodesTable: TableV2;
  rateLimitsTable: TableV2;
  jwtSecret: ISecret;
  lambdaZipPath?: string;
}

export class Lambda extends Construct {
  public readonly handler: IFunction;

  constructor(scope: Construct, id: string, props: LambdaProps) {
    super(scope, id);

    const environment = {
      USERS_TABLE_NAME: props.usersTable.tableName,
      SESSIONS_TABLE_NAME: props.sessionsTable.tableName,
      SESSIONS_USER_ID_INDEX_NAME: "userIdIndex",
      REFRESH_TOKENS_TABLE_NAME: props.refreshTokensTable.tableName,
      CREDENTIALS_TABLE_NAME: props.credentialsTable.tableName,
      CHALLENGES_TABLE_NAME: props.challengesTable.tableName,
      CLIENTS_TABLE_NAME: props.clientsTable.tableName,
      AUTH_CODES_TABLE_NAME: props.authCodesTable.tableName,
      RATE_LIMITS_TABLE_NAME: props.rateLimitsTable.tableName,
      JWT_SECRET_ARN: props.jwtSecret.secretArn,
    };

    if (props.lambdaZipPath && fs.existsSync(props.lambdaZipPath)) {
      this.handler = new Function(this, "AuthFunction", {
        architecture: Architecture.X86_64,
        runtime: Runtime.PROVIDED_AL2023,
        handler: "bootstrap",
        code: Code.fromAsset(props.lambdaZipPath),
        environment,
      });
    } else {
      this.handler = new RustFunction(this, "AuthFunction", {
        manifestPath,
        binaryName: "ericauth",
        environment,
      });
    }

    props.usersTable.grantReadWriteData(this.handler);
    props.sessionsTable.grantReadWriteData(this.handler);
    props.refreshTokensTable.grantReadWriteData(this.handler);
    props.credentialsTable.grantReadWriteData(this.handler);
    props.challengesTable.grantReadWriteData(this.handler);
    props.clientsTable.grantReadData(this.handler);
    props.authCodesTable.grantReadWriteData(this.handler);
    props.rateLimitsTable.grantReadWriteData(this.handler);
    props.jwtSecret.grantRead(this.handler);
  }
}
