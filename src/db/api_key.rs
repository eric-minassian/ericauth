use aws_sdk_dynamodb::types::AttributeValue;
use serde::{Deserialize, Serialize};

use crate::error::AuthError;

use super::DynamoDb;

#[derive(Clone, Serialize, Deserialize)]
pub struct ApiKeyTable {
    pub key_id: String,
    pub user_id: String,
    pub name: String,
    pub key_hash: String,
    pub created_at: String,
    #[serde(default)]
    pub last_used_at: Option<String>,
    #[serde(default)]
    pub revoked_at: Option<String>,
}

impl DynamoDb {
    pub async fn insert_api_key(&self, api_key: &ApiKeyTable) -> Result<(), AuthError> {
        let item = serde_dynamo::aws_sdk_dynamodb_1::to_item(api_key)
            .map_err(|e| AuthError::Internal(format!("Failed to serialize API key: {e}")))?;

        self.client
            .put_item()
            .table_name(&self.api_keys_table)
            .set_item(Some(item))
            .condition_expression("attribute_not_exists(key_id)")
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("Failed to insert API key: {e}")))?;

        Ok(())
    }

    pub async fn get_api_keys_by_user_id(
        &self,
        user_id: &str,
    ) -> Result<Vec<ApiKeyTable>, AuthError> {
        let response = self
            .client
            .query()
            .table_name(&self.api_keys_table)
            .index_name(&self.api_keys_user_id_index)
            .key_condition_expression("user_id = :uid")
            .expression_attribute_values(":uid", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|e| AuthError::Internal(format!("DynamoDB query API keys failed: {e}")))?;

        let items = response.items.unwrap_or_default();

        items
            .into_iter()
            .map(|item| {
                serde_dynamo::aws_sdk_dynamodb_1::from_item::<ApiKeyTable>(item)
                    .map_err(|e| AuthError::Internal(format!("Failed to deserialize API key: {e}")))
            })
            .collect()
    }

    pub async fn revoke_api_key(
        &self,
        key_id: &str,
        user_id: &str,
        revoked_at: &str,
    ) -> Result<(), AuthError> {
        self.client
            .update_item()
            .table_name(&self.api_keys_table)
            .key("key_id", AttributeValue::S(key_id.to_string()))
            .update_expression("SET revoked_at = :revoked_at")
            .condition_expression(
                "attribute_exists(key_id) AND user_id = :user_id AND attribute_not_exists(revoked_at)",
            )
            .expression_attribute_values(":revoked_at", AttributeValue::S(revoked_at.to_string()))
            .expression_attribute_values(":user_id", AttributeValue::S(user_id.to_string()))
            .send()
            .await
            .map_err(|e| {
                let service_err = e.into_service_error();
                if service_err.is_conditional_check_failed_exception() {
                    AuthError::NotFound("api key not found".to_string())
                } else {
                    AuthError::Internal("failed to revoke api key".to_string())
                }
            })?;

        Ok(())
    }
}
