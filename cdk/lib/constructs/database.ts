import { AttributeType, TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";

interface DatabaseProps {
  envName: string;
}

export class Database extends Construct {
  public readonly usersTable: TableV2;
  public readonly sessionsTable: TableV2;
  public readonly refreshTokensTable: TableV2;
  public readonly credentialsTable: TableV2;
  public readonly challengesTable: TableV2;

  constructor(scope: Construct, id: string, props: DatabaseProps) {
    super(scope, id);

    const prefix = `ericauth-${props.envName}`;

    this.usersTable = new TableV2(this, "UsersTable", {
      tableName: `${prefix}-users`,
      partitionKey: { name: "id", type: AttributeType.STRING },
      globalSecondaryIndexes: [
        {
          indexName: "emailIndex",
          partitionKey: { name: "email", type: AttributeType.STRING },
        },
      ],
    });

    this.sessionsTable = new TableV2(this, "SessionsTable", {
      tableName: `${prefix}-sessions`,
      partitionKey: { name: "id", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
    });

    this.refreshTokensTable = new TableV2(this, "RefreshTokensTable", {
      tableName: `${prefix}-refresh-tokens`,
      partitionKey: { name: "token_hash", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
    });

    this.credentialsTable = new TableV2(this, "CredentialsTable", {
      tableName: `${prefix}-credentials`,
      partitionKey: { name: "credential_id", type: AttributeType.STRING },
      globalSecondaryIndexes: [
        {
          indexName: "userIdIndex",
          partitionKey: { name: "user_id", type: AttributeType.STRING },
        },
      ],
    });

    this.challengesTable = new TableV2(this, "ChallengesTable", {
      tableName: `${prefix}-challenges`,
      partitionKey: { name: "challenge_id", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
    });
  }
}
