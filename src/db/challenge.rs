use aws_sdk_dynamodb::types::AttributeValue;

use crate::error::AuthError;

use super::DynamoDb;

impl DynamoDb {
    pub async fn insert_challenge(
        &self,
        challenge_id: &str,
        challenge_data: &str,
        ttl_seconds: i64,
    ) -> Result<(), AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + ttl_seconds;

        self.client
            .put_item()
            .table_name(&self.challenges_table)
            .item("challenge_id", AttributeValue::S(challenge_id.to_string()))
            .item(
                "challenge_data",
                AttributeValue::S(challenge_data.to_string()),
            )
            .item("expires_at", AttributeValue::N(expires_at.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert challenge: {e}")))?;

        Ok(())
    }

    pub async fn get_and_delete_challenge(&self, challenge_id: &str) -> Result<String, AuthError> {
        // Get the challenge
        let response = self
            .client
            .get_item()
            .table_name(&self.challenges_table)
            .key("challenge_id", AttributeValue::S(challenge_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB get challenge failed: {e}")))?;

        let item = response
            .item
            .ok_or_else(|| AuthError::NotFound("challenge not found".into()))?;

        // Check expiry
        let expires_at = item
            .get("expires_at")
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse::<i64>().ok())
            .ok_or_else(|| AuthError::Internal("invalid challenge expiry".into()))?;

        if expires_at <= chrono::Utc::now().timestamp() {
            return Err(AuthError::NotFound("challenge expired".into()));
        }

        let challenge_data = item
            .get("challenge_data")
            .and_then(|v| v.as_s().ok())
            .ok_or_else(|| AuthError::Internal("invalid challenge data".into()))?
            .clone();

        // Delete the challenge (single-use)
        self.client
            .delete_item()
            .table_name(&self.challenges_table)
            .key("challenge_id", AttributeValue::S(challenge_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to delete challenge: {e}")))?;

        Ok(challenge_data)
    }
}
