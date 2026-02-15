import { RemovalPolicy } from "aws-cdk-lib";
import { AttributeType, TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";
import { GSI_NAMES } from "./constants";

interface DatabaseProps {
  envName: string;
}

export class Database extends Construct {
  public readonly usersTable: TableV2;
  public readonly sessionsTable: TableV2;
  public readonly emailVerificationsTable: TableV2;
  public readonly passwordResetsTable: TableV2;
  public readonly refreshTokensTable: TableV2;
  public readonly auditEventsTable: TableV2;
  public readonly credentialsTable: TableV2;
  public readonly challengesTable: TableV2;
  public readonly clientsTable: TableV2;
  public readonly tenantsTable: TableV2;
  public readonly authCodesTable: TableV2;
  public readonly rateLimitsTable: TableV2;

  constructor(scope: Construct, id: string, props: DatabaseProps) {
    super(scope, id);

    const prefix = `ericauth-${props.envName}`;
    const removalPolicy =
      props.envName === "dev"
        ? RemovalPolicy.DESTROY
        : RemovalPolicy.RETAIN;

    this.usersTable = new TableV2(this, "UsersTable", {
      tableName: `${prefix}-users`,
      partitionKey: { name: "id", type: AttributeType.STRING },
      globalSecondaryIndexes: [
        {
          indexName: GSI_NAMES.EMAIL_INDEX,
          partitionKey: { name: "email", type: AttributeType.STRING },
        },
      ],
      removalPolicy,
    });

    this.sessionsTable = new TableV2(this, "SessionsTable", {
      tableName: `${prefix}-sessions`,
      partitionKey: { name: "id", type: AttributeType.STRING },
      globalSecondaryIndexes: [
        {
          indexName: GSI_NAMES.USER_ID_INDEX,
          partitionKey: { name: "user_id", type: AttributeType.STRING },
        },
      ],
      timeToLiveAttribute: "expires_at",
      removalPolicy,
    });

    this.emailVerificationsTable = new TableV2(
      this,
      "EmailVerificationsTable",
      {
        tableName: `${prefix}-email-verifications`,
        partitionKey: { name: "token", type: AttributeType.STRING },
        timeToLiveAttribute: "expires_at",
        removalPolicy,
      },
    );

    this.passwordResetsTable = new TableV2(this, "PasswordResetsTable", {
      tableName: `${prefix}-password-resets`,
      partitionKey: { name: "token", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
      removalPolicy,
    });

    this.refreshTokensTable = new TableV2(this, "RefreshTokensTable", {
      tableName: `${prefix}-refresh-tokens`,
      partitionKey: { name: "token_hash", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
      removalPolicy,
    });

    this.auditEventsTable = new TableV2(this, "AuditEventsTable", {
      tableName: `${prefix}-audit-events`,
      partitionKey: { name: "id", type: AttributeType.STRING },
      removalPolicy,
    });

    this.credentialsTable = new TableV2(this, "CredentialsTable", {
      tableName: `${prefix}-credentials`,
      partitionKey: { name: "credential_id", type: AttributeType.STRING },
      globalSecondaryIndexes: [
        {
          indexName: GSI_NAMES.USER_ID_INDEX,
          partitionKey: { name: "user_id", type: AttributeType.STRING },
        },
      ],
      removalPolicy,
    });

    this.challengesTable = new TableV2(this, "ChallengesTable", {
      tableName: `${prefix}-challenges`,
      partitionKey: { name: "challenge_id", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
      removalPolicy,
    });

    this.clientsTable = new TableV2(this, "ClientsTable", {
      tableName: `${prefix}-clients`,
      partitionKey: { name: "client_id", type: AttributeType.STRING },
      removalPolicy,
    });

    this.tenantsTable = new TableV2(this, "TenantsTable", {
      tableName: `${prefix}-tenants`,
      partitionKey: { name: "tenant_id", type: AttributeType.STRING },
      removalPolicy,
    });

    this.authCodesTable = new TableV2(this, "AuthCodesTable", {
      tableName: `${prefix}-auth-codes`,
      partitionKey: { name: "code", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
      removalPolicy,
    });

    this.rateLimitsTable = new TableV2(this, "RateLimitsTable", {
      tableName: `${prefix}-rate-limits`,
      partitionKey: { name: "key", type: AttributeType.STRING },
      timeToLiveAttribute: "expires_at",
      removalPolicy: RemovalPolicy.DESTROY,
    });
  }
}
