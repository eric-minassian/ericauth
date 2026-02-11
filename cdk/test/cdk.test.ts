import * as cdk from "aws-cdk-lib";
import { Template, Match } from "aws-cdk-lib/assertions";
import { EricAuthStack } from "../lib/cdk-stack";

function createTestStack(): Template {
  const app = new cdk.App();
  const stack = new EricAuthStack(app, "TestStack", {
    envName: "test",
    env: { account: "123456789012", region: "us-east-1" },
  });
  return Template.fromStack(stack);
}

// --- DynamoDB Tables ---

test("creates users table with email GSI", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::DynamoDB::GlobalTable", {
    TableName: "ericauth-test-users",
    KeySchema: [{ AttributeName: "id", KeyType: "HASH" }],
    GlobalSecondaryIndexes: [
      Match.objectLike({
        IndexName: "emailIndex",
        KeySchema: [{ AttributeName: "email", KeyType: "HASH" }],
      }),
    ],
  });
});

test("creates sessions table with TTL", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::DynamoDB::GlobalTable", {
    TableName: "ericauth-test-sessions",
    KeySchema: [{ AttributeName: "id", KeyType: "HASH" }],
    TimeToLiveSpecification: {
      AttributeName: "expires_at",
      Enabled: true,
    },
  });
});

test("creates refresh tokens table with TTL", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::DynamoDB::GlobalTable", {
    TableName: "ericauth-test-refresh-tokens",
    KeySchema: [{ AttributeName: "token_hash", KeyType: "HASH" }],
    TimeToLiveSpecification: {
      AttributeName: "expires_at",
      Enabled: true,
    },
  });
});

test("creates at least 3 DynamoDB tables", () => {
  const template = createTestStack();
  const tables = template.findResources("AWS::DynamoDB::GlobalTable");
  expect(Object.keys(tables).length).toBeGreaterThanOrEqual(3);
});

// --- Lambda ---

test("creates Lambda function with table name env vars", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::Lambda::Function", {
    Environment: {
      Variables: Match.objectLike({
        USERS_TABLE_NAME: Match.anyValue(),
        SESSIONS_TABLE_NAME: Match.anyValue(),
        REFRESH_TOKENS_TABLE_NAME: Match.anyValue(),
      }),
    },
  });
});

// --- API Gateway ---

test("creates REST API", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::ApiGateway::RestApi", {
    Name: "eric-auth",
  });
});

test("creates proxy resource with ANY method", () => {
  const template = createTestStack();
  template.resourceCountIs("AWS::ApiGateway::Resource", 1);

  template.hasResourceProperties("AWS::ApiGateway::Method", {
    HttpMethod: "ANY",
  });
});

// --- IAM Permissions ---

test("grants Lambda read-write access to DynamoDB tables", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::IAM::Policy", {
    PolicyDocument: {
      Statement: Match.arrayWith([
        Match.objectLike({
          Action: Match.arrayWith([
            "dynamodb:BatchGetItem",
            "dynamodb:GetItem",
            "dynamodb:PutItem",
            "dynamodb:DeleteItem",
          ]),
          Effect: "Allow",
        }),
      ]),
    },
  });
});
