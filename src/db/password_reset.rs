use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct PasswordResetTable {
    pub token: String,
    pub user_id: String,
    pub expires_at: i64,
}

impl DynamoDb {
    pub async fn insert_password_reset_token(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + ttl_seconds;
        let token_hash = hash_password_reset_token(token);

        let record = PasswordResetTable {
            token: token_hash,
            user_id: user_id.to_string(),
            expires_at,
        };

        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(&record).map_err(|e| {
            AuthError::Internal(format!("Failed to serialize password reset token: {e}"))
        })?;

        self.client
            .put_item()
            .table_name(&self.password_resets_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| {
                AuthError::Internal(format!("Failed to insert password reset token: {e}"))
            })?;

        Ok(())
    }

    pub async fn redeem_password_reset_token(
        &self,
        token: &str,
    ) -> Result<Option<PasswordResetTable>, AuthError> {
        let token_hash = hash_password_reset_token(token);

        let response = self
            .client
            .delete_item()
            .table_name(&self.password_resets_table)
            .key("token", AttributeValue::S(token_hash))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(|e| {
                AuthError::Internal(format!("Failed to redeem password reset token: {e}"))
            })?;

        if let Some(item) = response.attributes {
            let record = serde_dynamo::aws_sdk_dynamodb_1::from_item::<PasswordResetTable>(item)
                .map_err(|e| {
                    AuthError::Internal(format!("Failed to deserialize password reset token: {e}"))
                })?;

            if record.expires_at <= chrono::Utc::now().timestamp() {
                return Ok(None);
            }

            Ok(Some(record))
        } else {
            Ok(None)
        }
    }
}

fn hash_password_reset_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
