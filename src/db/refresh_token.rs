use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct RefreshTokenTable {
    pub token_hash: String,
    pub user_id: String,
    pub scope: String,
    pub expires_at: i64,
    pub revoked: bool,
}

impl DynamoDb {
    pub async fn insert_refresh_token(&self, token: &RefreshTokenTable) -> Result<(), AuthError> {
        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(token)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize refresh token: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.refresh_tokens_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert refresh token: {e}")))?;

        Ok(())
    }

    pub async fn get_refresh_token(
        &self,
        token_hash: &str,
    ) -> Result<Option<RefreshTokenTable>, AuthError> {
        let response = self
            .client
            .get_item()
            .table_name(&self.refresh_tokens_table)
            .key("token_hash", AttributeValue::S(token_hash.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB get refresh token failed: {e}")))?;

        match response.item {
            Some(item) => {
                let token = serde_dynamo::aws_sdk_dynamodb_1::from_item::<RefreshTokenTable>(item)
                    .map_err(|e| {
                        AuthError::Internal(format!("Failed to deserialize refresh token: {e}"))
                    })?;

                if token.revoked {
                    return Ok(None);
                }

                if token.expires_at <= chrono::Utc::now().timestamp() {
                    return Ok(None);
                }

                Ok(Some(token))
            }
            None => Ok(None),
        }
    }

    pub async fn revoke_refresh_token(&self, token_hash: &str) -> Result<(), AuthError> {
        self.client
            .update_item()
            .table_name(&self.refresh_tokens_table)
            .key("token_hash", AttributeValue::S(token_hash.to_string()))
            .update_expression("SET revoked = :revoked")
            .expression_attribute_values(":revoked", AttributeValue::Bool(true))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to revoke refresh token: {e}")))?;

        Ok(())
    }
}
