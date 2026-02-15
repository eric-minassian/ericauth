use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct EmailVerificationTable {
    pub token: String,
    pub user_id: String,
    pub expires_at: i64,
}

impl DynamoDb {
    pub async fn insert_email_verification(
        &self,
        token: &str,
        user_id: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + ttl_seconds;
        let token_hash = hash_email_verification_token(token);

        let record = EmailVerificationTable {
            token: token_hash,
            user_id: user_id.to_string(),
            expires_at,
        };

        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(&record).map_err(|e| {
            AuthError::Internal(format!("Failed to serialize email verification token: {e}"))
        })?;

        self.client
            .put_item()
            .table_name(&self.email_verifications_table)
            .set_item(Some(item))
            .send()
            .await
            .map_err(|e| {
                AuthError::Internal(format!("Failed to insert email verification token: {e}"))
            })?;

        Ok(())
    }

    pub async fn get_email_verification_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        let mut exclusive_start_key = None;

        loop {
            let response = self
                .client
                .scan()
                .table_name(&self.email_verifications_table)
                .filter_expression("user_id = :user_id")
                .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
                .set_exclusive_start_key(exclusive_start_key)
                .send()
                .await
                .map_err(|e| {
                    AuthError::Internal(format!("Failed to query email verification tokens: {e}"))
                })?;

            if let Some(item) = response.items.and_then(|items| items.into_iter().next()) {
                let record =
                    serde_dynamo::aws_sdk_dynamodb_1::from_item::<EmailVerificationTable>(item)
                        .map_err(|e| {
                            AuthError::Internal(format!(
                                "Failed to deserialize email verification token: {e}"
                            ))
                        })?;
                return Ok(Some(record));
            }

            if response.last_evaluated_key.is_none() {
                return Ok(None);
            }

            exclusive_start_key = response.last_evaluated_key;
        }
    }

    pub async fn redeem_email_verification(
        &self,
        token: &str,
    ) -> Result<Option<EmailVerificationTable>, AuthError> {
        let token_hash = hash_email_verification_token(token);

        let response = self
            .client
            .delete_item()
            .table_name(&self.email_verifications_table)
            .key("token", AttributeValue::S(token_hash))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllOld)
            .send()
            .await
            .map_err(|e| {
                AuthError::Internal(format!("Failed to redeem email verification token: {e}"))
            })?;

        if let Some(item) = response.attributes {
            let record =
                serde_dynamo::aws_sdk_dynamodb_1::from_item::<EmailVerificationTable>(item)
                    .map_err(|e| {
                        AuthError::Internal(format!(
                            "Failed to deserialize email verification token: {e}"
                        ))
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

fn hash_email_verification_token(token: &str) -> String {
    hex::encode(Sha256::digest(token.as_bytes()))
}
