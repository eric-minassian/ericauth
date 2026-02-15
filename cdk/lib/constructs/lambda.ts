import { Duration } from "aws-cdk-lib";
import { TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { ISecret } from "aws-cdk-lib/aws-secretsmanager";
import { RustFunction } from "cargo-lambda-cdk";
import { Construct } from "constructs";
import { GSI_NAMES } from "./constants";

import * as path from "path";

const manifestPath = path.join(__dirname, "..", "..", "..");

interface LambdaProps {
  usersTable: TableV2;
  sessionsTable: TableV2;
  refreshTokensTable: TableV2;
  auditEventsTable: TableV2;
  credentialsTable: TableV2;
  challengesTable: TableV2;
  clientsTable: TableV2;
  authCodesTable: TableV2;
  rateLimitsTable: TableV2;
  jwtSecret: ISecret;
  issuerUrl: string;
}

export class Lambda extends Construct {
  public readonly handler: RustFunction;

  constructor(scope: Construct, id: string, props: LambdaProps) {
    super(scope, id);

    this.handler = new RustFunction(this, "AuthFunction", {
      manifestPath,
      binaryName: "ericauth",
      memorySize: 512,
      timeout: Duration.seconds(30),
      environment: {
        USERS_TABLE_NAME: props.usersTable.tableName,
        SESSIONS_TABLE_NAME: props.sessionsTable.tableName,
        SESSIONS_USER_ID_INDEX_NAME: GSI_NAMES.USER_ID_INDEX,
        REFRESH_TOKENS_TABLE_NAME: props.refreshTokensTable.tableName,
        AUDIT_EVENTS_TABLE_NAME: props.auditEventsTable.tableName,
        CREDENTIALS_TABLE_NAME: props.credentialsTable.tableName,
        CHALLENGES_TABLE_NAME: props.challengesTable.tableName,
        CLIENTS_TABLE_NAME: props.clientsTable.tableName,
        AUTH_CODES_TABLE_NAME: props.authCodesTable.tableName,
        RATE_LIMITS_TABLE_NAME: props.rateLimitsTable.tableName,
        JWT_SECRET_ARN: props.jwtSecret.secretArn,
        ISSUER_URL: props.issuerUrl,
      },
    });

    props.usersTable.grantReadWriteData(this.handler);
    props.sessionsTable.grantReadWriteData(this.handler);
    props.refreshTokensTable.grantReadWriteData(this.handler);
    props.auditEventsTable.grantReadWriteData(this.handler);
    props.credentialsTable.grantReadWriteData(this.handler);
    props.challengesTable.grantReadWriteData(this.handler);
    props.clientsTable.grantReadData(this.handler);
    props.authCodesTable.grantReadWriteData(this.handler);
    props.rateLimitsTable.grantReadWriteData(this.handler);
    props.jwtSecret.grantRead(this.handler);
  }
}
