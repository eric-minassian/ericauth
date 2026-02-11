use aws_sdk_dynamodb::types::AttributeValue;

use crate::error::AuthError;

use super::DynamoDb;

impl DynamoDb {
    /// Increment a rate limit counter in DynamoDB. Returns the new count.
    ///
    /// Uses `UpdateItem` with `ADD` to atomically increment the counter.
    /// Sets a TTL so stale entries are automatically cleaned up.
    pub async fn increment_rate_limit(
        &self,
        key: &str,
        window_seconds: i64,
    ) -> Result<i64, AuthError> {
        let expires_at = chrono::Utc::now().timestamp() + window_seconds;

        let result = self
            .client
            .update_item()
            .table_name(&self.rate_limits_table)
            .key("key", AttributeValue::S(key.to_string()))
            .update_expression("ADD #count :inc SET #exp = if_not_exists(#exp, :exp)")
            .expression_attribute_names("#count", "count")
            .expression_attribute_names("#exp", "expires_at")
            .expression_attribute_values(":inc", AttributeValue::N("1".to_string()))
            .expression_attribute_values(":exp", AttributeValue::N(expires_at.to_string()))
            .return_values(aws_sdk_dynamodb::types::ReturnValue::AllNew)
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("failed to increment rate limit: {e}")))?;

        let attrs = result.attributes.unwrap_or_default();
        let count = attrs
            .get("count")
            .and_then(|v| v.as_n().ok())
            .and_then(|n| n.parse::<i64>().ok())
            .unwrap_or(1);

        Ok(count)
    }
}
