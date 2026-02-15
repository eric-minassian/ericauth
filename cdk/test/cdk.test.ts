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

test("creates exactly 9 DynamoDB tables", () => {
  const template = createTestStack();
  const tables = template.findResources("AWS::DynamoDB::GlobalTable");
  expect(Object.keys(tables).length).toBe(9);
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
        AUDIT_EVENTS_TABLE_NAME: Match.anyValue(),
      }),
    },
  });
});

test("Lambda has ISSUER_URL environment variable", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::Lambda::Function", {
    Environment: {
      Variables: Match.objectLike({
        ISSUER_URL: Match.anyValue(),
      }),
    },
  });
});

test("Lambda has 512 MB memory", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::Lambda::Function", {
    MemorySize: 512,
  });
});

test("creates JWT secret in Secrets Manager", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::SecretsManager::Secret", {
    Name: "ericauth-test-jwt-private-key",
  });
});

// --- API Gateway ---

test("creates HTTP API", () => {
  const template = createTestStack();

  template.hasResourceProperties("AWS::ApiGatewayV2::Api", {
    Name: "ericauth-test",
    ProtocolType: "HTTP",
  });
});

test("creates API route with Lambda integration", () => {
  const template = createTestStack();

  template.resourceCountIs("AWS::ApiGatewayV2::Route", 1);
  template.hasResourceProperties("AWS::ApiGatewayV2::Integration", {
    IntegrationType: "AWS_PROXY",
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
