import { AttributeType, TableV2 } from "aws-cdk-lib/aws-dynamodb";
import { Construct } from "constructs";

export class Database extends Construct {
  public readonly usersTable: TableV2;
  public readonly sessionsTable: TableV2;

  constructor(scope: Construct, id: string) {
    super(scope, id);

    this.usersTable = new TableV2(this, "UsersTable", {
      tableName: "UsersTable",
      partitionKey: { name: "email", type: AttributeType.STRING },
    });

    this.sessionsTable = new TableV2(this, "SessionsTable", {
      tableName: "SessionsTable",
      partitionKey: { name: "id", type: AttributeType.STRING },
    });
  }
}
